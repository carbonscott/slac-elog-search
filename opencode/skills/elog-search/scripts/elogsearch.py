#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["requests", "lcls-krtc", "snowballstemmer"]
# ///
"""Search the LCLS eLog as yourself, read-only, with the search scope always stated.

Read-only by construction: every HTTP call this script can make is routed through
`_get()`, which refuses any route not present in READ_ROUTES below.  There is no
code path that posts, edits, deletes or cross-posts an entry.

Scope is an engineering decision, not an authorization one.  The eLog has no
cross-experiment search primitive -- each experiment is its own MongoDB database
and `search_elog` is per-experiment -- so a "search the eLog" request is a fan-out
over a chosen set of experiments.  This script always chooses that set explicitly
and always prints how many experiments it searched and how the set was chosen.

Credential: your own, always.  There is no shared-account fallback anywhere in the
resolution chain.  If no credential of yours is usable the script says so and names
the exact command YOU must run; it never authenticates on your behalf.
"""

import argparse
import concurrent.futures
import glob
import json
import os
import pwd
import re
import stat
import subprocess
import sys
import time
from datetime import datetime

BASE = "https://pswww.slac.stanford.edu"

# The complete set of routes this script is permitted to call.  Every one is a
# GET and every one is read-only.  _get() refuses anything not listed here, so
# the read-only guarantee is enforced in code rather than promised in a comment.
READ_ROUTES = {
    "experiments",                      # global: experiments the caller may read
    "get_cached_experiment_names",      # global: all experiment names (anonymous)
    "experiment_names_updated_within",  # global: recently-active names (anonymous)
    "search_elog",                      # per-experiment: the search itself
}

# Fan-out concurrency.  Fixed, not tunable from the command line: this is the
# production logbook the hutches depend on during beam time, and a miss costs the
# server a collection scan.  Four parallel requests was measured as safe.
CONCURRENCY = 4

# Refuse to fan out beyond this many experiments in one invocation.  A full-corpus
# sweep is a load event, not a query.
DEFAULT_SCOPE_CAP = 150

DEFAULT_DAYS = 180

# Above this many returned entries the result set is a haystack, not an answer.
# Not a refusal -- by the time it is known the requests are already paid for --
# but silence here would let a stopword masquerade as a search.
BROAD_RESULT_WARNING = 2000

CACHE_VERSION = 2          # bump whenever the cached record shape changes
CACHE_TTL_SECONDS = 6 * 3600
EXCERPT_CHARS = 400


# --------------------------------------------------------------------------
# credential resolution -- yours, or nothing
# --------------------------------------------------------------------------

class CredentialError(Exception):
    """No credential of the invoking user's is usable.  Carries the fix."""


def _home_dir():
    """Where THIS user's state lives: $HOME when $HOME is really theirs.

    This used to read passwd unconditionally, on the reasoning that $HOME is
    inherited and can point at another user's tree in a sudo or batch context.
    The threat is real; the remedy was too broad.  Passwd answers "who am I",
    which is not the same question as "where is my state", and the two answers
    diverge whenever the filesystem namespace can differ from the passwd
    database -- the container case, where $HOME is a scratch home and passwd
    still says /sdf/home.

    It also disagreed with the tool that WRITES the credential.  s3df-login
    resolves S3DF_TOKEN_FILE from $HOME; a reader resolving from passwd cannot
    find what that writer wrote.

    So: take $HOME when it is a directory owned by the invoking uid -- which
    rejects exactly the inherited-someone-else's-$HOME case the original guard
    was aimed at -- and fall back to passwd otherwise.
    """
    home = os.environ.get("HOME")
    if home:
        try:
            st = os.stat(home)
            if stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid():
                return home
        except OSError:
            pass
    return pwd.getpwuid(os.getuid()).pw_dir


def _s3df_token_paths():
    """(token, metadata) paths, resolved the way `s3df login` resolves them.

    s3df-login documents S3DF_TOKEN_FILE and S3DF_TOKEN_META in its own --help
    and defaults both from $HOME.  This reader honours the same two names with
    the same precedence.  Inventing a parallel knob here (ELOG_S3DF_TOKEN_FILE
    or similar) would guarantee drift: anyone who set the documented variable
    would get a token that `s3df login` writes and this skill cannot find.
    """
    home = _home_dir()
    return (os.environ.get("S3DF_TOKEN_FILE") or os.path.join(home, ".s3df-access-token"),
            os.environ.get("S3DF_TOKEN_META") or os.path.join(home, ".s3df-token.json"))


def _username():
    return pwd.getpwuid(os.getuid()).pw_name


def _refuse_if_readable_by_others(path):
    """A credential readable by anyone but you is not a credential.  Name the fix."""
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise CredentialError(
            "credential file %s is mode %04o -- readable by group or world.\n"
            "  Refusing to use it.  Fix it with:  chmod 600 %s" % (path, mode, path)
        )


def _klist_is_valid(cache_path):
    """Does this cache hold a live TGT?  Ask klist, do not parse clocks.

    `klist -s` exits 0 for "exists, readable, unexpired TGT" and 1 for expired,
    missing or unreadable alike.  That is the whole test.  Deliberately not done
    by parsing the expiry: klist prints local times with no zone and no locale
    marker, so a script that compares them to its own clock is guessing.
    """
    env = dict(os.environ)
    env["KRB5CCNAME"] = "FILE:" + cache_path
    try:
        return subprocess.run(["klist", "-s"], env=env, capture_output=True,
                              timeout=15).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _klist_describe(cache_path):
    """(principal, expiry_string) for display.  Never used to decide validity."""
    env = dict(os.environ)
    env["KRB5CCNAME"] = "FILE:" + cache_path
    try:
        out = subprocess.run(["klist"], env=env, capture_output=True,
                             text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None, None

    principal = None
    for line in out.splitlines():
        if line.startswith("Default principal:"):
            principal = line.split(":", 1)[1].strip()
            break
    if not principal or "@" not in principal:
        return principal, None

    # A cache can hold TGTs for SEVERAL realms -- here, SLAC.STANFORD.EDU and
    # SDF.SLAC.STANFORD.EDU with different expiries.  Taking the last krbtgt line
    # picks an arbitrary one.  The ticket that matters is the one for the
    # principal's OWN realm.
    realm = principal.split("@", 1)[1]
    want = "krbtgt/%s@%s" % (realm, realm)
    for line in out.splitlines():
        fields = line.split()
        if len(fields) == 5 and fields[4] == want:
            return principal, fields[2] + " " + fields[3]
    return principal, None


def _sortable(expiry_string):
    """Rank caches by expiry.  Same host, same clock, so comparison is sound."""
    try:
        return datetime.strptime(expiry_string, "%m/%d/%Y %H:%M:%S")
    except (TypeError, ValueError):
        return datetime.min


def _candidate_cache_paths():
    """Every credential cache belonging to THIS uid.  Never anyone else's.

    Two traps this walks around:

    * The default cache is often the stale one.  An ssh login with GSSAPI
      delegation drops a fresh ticket in a suffixed sibling cache and leaves
      KRB5CCNAME unset, so a resolver that reads only the default reports "no
      credential" while a valid ticket sits beside it.  `klist -l` and `klist -A`
      do not help: with a FILE-type default they only ever show the one cache
      already selected.
    * /tmp is world-listable and holds other users' caches.  Ownership is tested
      with lstat before the file is ever opened, so a foreign cache is dropped
      without a permission error, and a symlink pointing at one is rejected by
      the regular-file test rather than followed.
    """
    uid = os.getuid()
    paths, refused = [], []

    def add(path):
        if not path or path in paths:
            return
        try:
            st = os.lstat(path)               # lstat: do not follow a symlink
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode):      # symlink or directory: not ours to trust
            return
        if st.st_uid != uid:                  # somebody else's ticket
            return
        if stat.S_IMODE(st.st_mode) & 0o077:
            refused.append((path, stat.S_IMODE(st.st_mode)))
            return
        paths.append(path)

    # An explicitly-set KRB5CCNAME is the user's own choice and is tried first.
    env_cc = os.environ.get("KRB5CCNAME", "")
    if env_cc.startswith("FILE:"):
        add(env_cc[5:])
    elif env_cc and env_cc.startswith("/"):
        add(env_cc)

    add("/tmp/krb5cc_%d" % uid)
    for pattern in ("/tmp/krb5cc_*",
                    "/run/user/%d/krb5cc*" % uid,
                    os.path.join(_home_dir(), ".krb5cc*")):
        for path in sorted(glob.glob(pattern)):
            add(path)
    return paths, refused


def _resolve_kerberos():
    """Every own cache holding a live TGT, most-distant expiry first."""
    paths, refused = _candidate_cache_paths()
    for path, mode in refused:
        print("WARNING: ignoring credential cache %s -- mode %04o is readable by "
              "group or world.  Fix it with:  chmod 600 %s" % (path, mode, path),
              file=sys.stderr)

    found = []
    for path in paths:
        if not _klist_is_valid(path):
            continue
        principal, expires = _klist_describe(path)
        if not principal:
            continue
        found.append({"mechanism": "kerberos", "prefix": "ws-kerb", "cache": path,
                      "identity": principal, "expires": expires})
    found.sort(key=lambda c: _sortable(c["expires"]), reverse=True)
    return found


def _resolve_jwt():
    """The S3DF OAuth2 token written by `s3df login`.  Yours, mode 0600, or nothing.

    Paths come from _s3df_token_paths(), so S3DF_TOKEN_FILE and S3DF_TOKEN_META
    are honoured under the names their writer documents.

    An expired token is treated as no token.  s3df-login records `expires_at`
    (epoch seconds) in its metadata, so unlike a Kerberos cache this can be
    decided outright rather than guessed at -- and `s3df login` renews from the
    stored refresh_token without a browser, so the fix costs the user nothing.
    Without that metadata the expiry is simply unknown and the token is tried.
    """
    path, meta_path = _s3df_token_paths()
    try:
        st = os.lstat(path)
    except OSError:
        return []
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
        return []
    _refuse_if_readable_by_others(path)

    identity, expires = None, None
    if os.path.exists(meta_path):
        _refuse_if_readable_by_others(meta_path)
        try:
            with open(meta_path) as fh:
                meta = json.load(fh)
            identity = meta.get("email") or meta.get("sub")
            if meta.get("expires_at") is not None:
                expires_at = float(meta["expires_at"])
                if expires_at <= time.time():
                    return []
                expires = time.strftime("%m/%d/%Y %H:%M:%S",
                                        time.localtime(expires_at))
        except (OSError, ValueError, TypeError):
            pass
    return [{"mechanism": "jwt", "prefix": "ws-jwt", "cache": path,
             "identity": identity or _username(), "expires": expires}]


def resolve_credential(prefer=None):
    """Resolve the INVOKING USER's credential.  No shared-account fallback exists.

    Order: Kerberos first (it is what works today), then the S3DF JWT.  Both are
    per-user files owned by the caller.  There is deliberately no third option:
    a skill that quietly falls back to a shared operator account would report
    somebody else's read access as yours.

    Returns the best candidate with the remaining ones attached as `alternates`,
    because "the cache holds a live TGT" and "the GSS library can build a header
    from it" are not the same test -- the second can still fail, and the right
    answer then is the next cache, not an error.
    """
    # --auth FORCES a mechanism.  It used to be a preference, so `--auth jwt` on a
    # host with no token silently produced a Kerberos session and reported success
    # -- the one flag that could exercise the JWT path could not report its own
    # failure.  That flag is how the JWT path was finally verified.
    order = [prefer] if prefer else ["kerberos", "jwt"]

    candidates = []
    for mech in order:
        candidates += _resolve_kerberos() if mech == "kerberos" else _resolve_jwt()

    if not candidates and prefer:
        raise CredentialError(
            "you asked for --auth %s and no usable %s credential of yours exists.\n"
            "  %s\n"
            "  Drop --auth to let the skill choose, or create that credential yourself."
            % (prefer, prefer,
               "Run: kinit %s@SLAC.STANFORD.EDU" % _username() if prefer == "kerberos"
               else "Run: /sdf/sw/s3df-cli/bin/s3df login   "
                    "(an expired token counts as absent here; that command renews\n"
                    "  it from the stored refresh_token, without a browser)"))

    if not candidates:
        raise CredentialError(
            "no usable credential of your own was found for user '%s'.\n"
            "  Checked, for uid %d only: $KRB5CCNAME, /tmp/krb5cc_*, "
            "/run/user/%d/krb5cc*, %s/.krb5cc*, and %s\n"
            "  This skill cannot authenticate for you -- kinit needs your password,\n"
            "  and a FIRST s3df login needs you at a browser.  An expired token is\n"
            "  cheaper: s3df login renews it from the stored refresh_token with no\n"
            "  browser at all.  Run ONE of these yourself:\n"
            "      kinit %s@SLAC.STANFORD.EDU        # Kerberos, ~24 h\n"
            "      /sdf/sw/s3df-cli/bin/s3df login   # S3DF OAuth2 token, 12 h\n"
            "  then re-run this command."
            % (_username(), os.getuid(), os.getuid(), _home_dir(),
               _s3df_token_paths()[0], _username())
        )

    best = candidates[0]
    best["alternates"] = candidates[1:]
    return best


def _headers_for(cred):
    """Build the Authorization header for one candidate.  May raise."""
    if cred["mechanism"] == "kerberos":
        # krtc does all its GSS work in KerberosTicket.__init__, reading
        # KRB5CCNAME from the process environment at that moment -- so setting it
        # here selects the cache, and a retry needs a NEW KerberosTicket.
        os.environ["KRB5CCNAME"] = "FILE:" + cred["cache"]
        from krtc import KerberosTicket
        return KerberosTicket("HTTP@pswww.slac.stanford.edu").getAuthHeaders()
    with open(cred["cache"]) as fh:
        token = fh.read().strip()
    return {"Authorization": "Bearer " + token}   # token is never printed or logged


def auth_headers(cred):
    """Header for the best credential, falling back through your other caches."""
    tried = []
    for candidate in [cred] + cred.get("alternates", []):
        try:
            headers = _headers_for(candidate)
        except Exception as exc:                                  # noqa: BLE001
            tried.append("%s (%s): %s" % (candidate["cache"], candidate["mechanism"],
                                          type(exc).__name__))
            continue
        cred.update({k: candidate[k] for k in
                     ("mechanism", "prefix", "cache", "identity", "expires")})
        return headers
    raise CredentialError(
        "every credential of your own failed to produce an auth header:\n    %s\n"
        "  Run `kinit %s@SLAC.STANFORD.EDU` yourself and try again."
        % ("\n    ".join(tried), _username()))


# --------------------------------------------------------------------------
# HTTP -- read routes only
# --------------------------------------------------------------------------

def _get(session, prefix, route, experiment=None, params=None, timeout=120):
    if route not in READ_ROUTES:
        raise RuntimeError(
            "refusing to call '%s': not in this skill's read-only route allowlist %s"
            % (route, sorted(READ_ROUTES)))
    if experiment:
        url = "%s/%s/lgbk/lgbk/%s/ws/%s" % (BASE, prefix, experiment, route)
    else:
        url = "%s/%s/lgbk/lgbk/ws/%s" % (BASE, prefix, route)
    return session.get(url, params=params or {}, timeout=timeout)


def _unwrap(response):
    payload = response.json()
    if isinstance(payload, dict) and "value" in payload:
        return payload["value"]
    return payload


# --------------------------------------------------------------------------
# scope -- chosen explicitly, reported always
# --------------------------------------------------------------------------

def _cache_path():
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(_home_dir(), ".cache")
    return os.path.join(base, "elog-search", "experiments.json")


def _load_metadata_cache():
    path = _cache_path()
    try:
        if time.time() - os.stat(path).st_mtime > CACHE_TTL_SECONDS:
            return None
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _save_metadata_cache(records):
    """Cache experiment METADATA only.  Entry content is never written to disk."""
    path = _cache_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(records, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        pass


def readable_experiments(session, cred, refresh=False):
    """The experiments THIS account may read, from the server's own answer.

    This is the authorization boundary made visible: the server returns the set
    the caller's roles allow, so the count is a property of the caller, never a
    property of the eLog.
    """
    if not refresh:
        cached = _load_metadata_cache()
        # The version guard is not ceremony: an older cache lacked the `key`
        # field, and silently reading it produced a scope of "0 of 0 readable
        # experiments" -- a wrong answer that looked like a legitimate one.
        if (cached and cached.get("identity") == cred["identity"]
                and cached.get("version") == CACHE_VERSION):
            return cached["records"]

    response = _get(session, cred["prefix"], "experiments", timeout=300)
    response.raise_for_status()
    records = []
    for exp in _unwrap(response):
        last_run = exp.get("last_run") or {}
        # `_id` is the URL-safe key; `name` is the display name, and for 14 of the
        # 2240 they differ -- the instrument and site-spanning logbooks are named
        # "AMO Instrument", "Sample Delivery System" and so on.  Putting the
        # display name in the path returns HTTP 500, so the key is what travels.
        records.append({
            "key": exp.get("_id") or exp.get("name"),
            "name": exp.get("name") or exp.get("_id"),
            "instrument": exp.get("instrument"),
            "start_time": exp.get("start_time"),
            "end_time": exp.get("end_time"),
            "last_run_begin_time": last_run.get("begin_time"),
        })
    _save_metadata_cache({"version": CACHE_VERSION, "identity": cred["identity"],
                          "records": records})
    return records


def recently_active_names(session, days):
    """Names active within `days`, from the anonymous endpoint.

    Keyed on last_run.begin_time, so it selects experiments that recently TOOK
    DATA -- an experiment can have recent eLog entries without new runs.  That
    caveat is printed with the scope line, never hidden.
    """
    response = _get(session, "ws", "experiment_names_updated_within",
                    params={"offset_secs": int(days * 86400)}, timeout=120)
    response.raise_for_status()
    return set(_unwrap(response))


def choose_scope(session, cred, args):
    """Decide which experiments to search and record WHY, for the scope line."""
    records = readable_experiments(session, cred, refresh=args.refresh)
    records = [r for r in records if r.get("key")]
    total_readable = len(records)
    by_key = {r["key"]: r for r in records}
    # Accept either spelling from the user: the key or the display name.
    by_any = dict(by_key)
    for record in records:
        by_any.setdefault(record["name"], record)

    if getattr(args, "logbooks", False):
        # The standing operational logbooks have no runs, so the recency rule can
        # never reach them and `--instrument OPS` silently matches nothing.  They
        # are exactly the records whose display name differs from their key.
        chosen = [r["key"] for r in records if r["name"] != r["key"]]
        selection = ("the %d standing operational logbooks (instrument and "
                     "site-spanning); recency does not apply, they have no runs"
                     % len(chosen))
    elif args.experiments:
        requested = [e.strip() for e in args.experiments.split(",") if e.strip()]
        chosen = [by_any[e]["key"] for e in requested if e in by_any]
        unknown = [e for e in requested if e not in by_any]
        selection = "explicit --experiments list (%d named)" % len(requested)
        if unknown:
            selection += "; %d not in your readable set: %s" % (
                len(unknown), ", ".join(sorted(unknown)))
    else:
        active = recently_active_names(session, args.days)
        chosen = [r["key"] for r in records
                  if r["key"] in active or r["name"] in active]
        selection = ("active within %d days (last run start) INTERSECT readable by you"
                     % args.days)
        if args.instrument:
            want = args.instrument.lower()
            known = sorted({(r.get("instrument") or "").upper()
                            for r in records if r.get("instrument")})
            if want.upper() not in known:
                # An unknown instrument used to yield "0 of 2240" -- the same
                # shape as a legitimately empty result.  Name the valid values.
                raise ValueError(
                    "unknown instrument %r.  Known instruments: %s"
                    % (args.instrument, ", ".join(known)))
            chosen = [k for k in chosen
                      if (by_key[k].get("instrument") or "").lower() == want
                      or k.lower().startswith(want)]
            selection += "; filtered to instrument %s" % args.instrument.upper()

    chosen = sorted(set(chosen))
    return chosen, total_readable, selection


# --------------------------------------------------------------------------
# search + result classification
# --------------------------------------------------------------------------

DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")


def _normalise_date(text, flag):
    """Parse a user-supplied date, or refuse loudly.

    A date this function cannot read used to be compared as a raw string, which
    silently excluded every entry and produced a confident "0 matches" — a typo
    indistinguishable from an empty eLog, which is exactly the failure this skill
    exists to prevent.
    """
    if not text:
        return None
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            continue
    raise ValueError(
        "%s: cannot read the date %r.\n"
        "  Accepted forms: 2026-08-01, 2026-08-01T12:00:00, "
        "2026-08-01T12:00:00.000000Z" % (flag, text))


def _within_window(doc, since, until):
    """Client-side date filter on insert_time.  ISO-8601 strings compare correctly."""
    stamp = doc.get("insert_time") or ""
    if since and stamp < since:
        return False
    if until and stamp > until:
        return False
    return True


def search_one(session, cred, experiment, args):
    """One read-only search_elog call.  Returns (experiment, status, docs, secs).

    The date window is applied HERE, not sent to the server.  Measured: when
    start_date and end_date are supplied, the server ignores search_text entirely
    and returns every entry in the window -- 'run', 'knife' and a nonsense word
    all came back byte-identical.  Sending the window would silently turn a text
    search into a date dump.  (A single-sided window is ignored outright, and a
    bare YYYY-MM-DD date returns HTTP 500.)
    """
    params = {"search_text": args.query}
    started = time.time()
    try:
        response = _get(session, cred["prefix"], "search_elog",
                        experiment=experiment, params=params, timeout=args.timeout)
    except Exception as exc:                                  # noqa: BLE001
        return experiment, type(exc).__name__, [], time.time() - started
    elapsed = time.time() - started
    if response.status_code != 200:
        return experiment, response.status_code, [], elapsed
    try:
        return experiment, 200, _unwrap(response), elapsed
    except ValueError:
        return experiment, "bad-json", [], elapsed


try:
    import snowballstemmer
    _STEMMER = snowballstemmer.stemmer("english")

    def _stem(word):
        return _STEMMER.stemWord(word)
except Exception:                                                 # noqa: BLE001
    _STEMMER = None

    def _stem(word):
        """Crude fallback if snowballstemmer is unavailable.  Under-stems safely.

        Under-stemming only ever costs a `[thread context]` label on a document
        that is shown anyway; over-stemming would hide a genuine hit, so the
        fallback errs short.
        """
        w = word.lower()
        for suffix in ("ments", "ment", "ings", "ing", "edly", "ed", "es", "s"):
            if len(w) > len(suffix) + 2 and w.endswith(suffix):
                return w[:-len(suffix)]
        return w


_WORD = re.compile(r"[A-Za-z0-9_]+")
_QUOTED = re.compile(r'"([^"]*)"')


def _split_query(query):
    """Split a query into quoted phrases and bare terms.

    `"jet clog" nozzle` -> (["jet clog"], ["nozzle"]).  MongoDB `$text` treats a
    quoted run as a phrase that must appear intact, and it is the only way to get
    a conjunction out of this search -- `jet clog` returns 966 entries where
    `"jet clog"` returns 2.
    """
    phrases = [p.strip() for p in _QUOTED.findall(query) if p.strip()]
    terms = [t for t in _QUOTED.sub(" ", query).split() if t]
    return phrases, terms
_TAG_RE = re.compile(r"<[^>]+>")
_DATA_URI = re.compile(r"data:[^;]+;base64,[A-Za-z0-9+/=]+")


def _plain_text(doc):
    """Entry content as readable text.

    Content is HTML, not plain text: image-bearing entries are mostly
    `<p><img src="data:image/png;base64,...">`, and a raw excerpt of one shows a
    screenful of base64 and no prose.  Both the excerpt and the match test read
    the stripped form.
    """
    raw = (doc.get("content") or "") + " " + (doc.get("title") or "")
    raw = _DATA_URI.sub(" ", raw)
    raw = _TAG_RE.sub(" ", raw)
    return raw


def _matches_query(doc, query):
    """Does this document answer the query on its own, by the server's rules?

    Mirrors what `search_elog` actually does, which is three different tests on
    three different fields:

    * content and title -- MongoDB `$text`, which is OR-of-terms, case-insensitive,
      and STEMMED (Snowball English).  Stemming is the part a naive substring test
      gets wrong: the server returns "alignment" for a search of `aligned`, and
      "moving" for `moved`, where neither raw term appears.  Three clauses are
      needed and all three are load-bearing -- raw substring catches `timing` in
      "timing", stem-substring catches `aser` inside "laser", and stem-to-stem
      word equality catches `moved` against "moving", which neither substring
      test can reach.
    * tags -- exact whole-string equality, CASE-SENSITIVE, not tokenised and not
      stemmed.  `SCREENSHOT` and `screenshot` are different tags, and searching
      `align` does not return entries tagged `alignment`.
    * author -- exact equality.

    Getting this wrong is not cosmetic.  A document that matches by stemming but
    fails this test, and which some other returned document happens to point at,
    is demoted to `[thread context]` -- a genuine hit presented as background.
    """
    query = (query or "").strip()
    tags = doc.get("tags") or []

    if query.startswith("t:"):
        return query[2:].strip() in tags          # case-sensitive, like the server

    text = _plain_text(doc)
    if query.startswith("x:"):
        # The server's `x:` regex is case-SENSITIVE.  (What is case-insensitive is
        # the server's internal fallback regex on a $text miss -- a different thing.)
        try:
            return re.search(query[2:], text) is not None
        except re.error:
            return True                           # unparseable regex: never demote

    if not query:
        return True
    if query == (doc.get("author") or ""):
        return True
    if query in tags:
        return True

    lowered = text.lower()
    phrases, terms = _split_query(query)

    # A quoted phrase is matched by the server as a phrase, and must be tested as
    # one.  Testing it with the quote characters still attached finds nothing --
    # which used to brand every correct phrase hit as unexplained image noise.
    for phrase in phrases:
        if phrase.lower() in lowered:
            return True

    words = None
    for term in terms:
        term = term.lower()
        if term in lowered:
            return True
        stemmed = _stem(term)
        if stemmed in lowered:
            return True
        if words is None:
            words = {_stem(w) for w in _WORD.findall(lowered)}
        if stemmed in words:
            return True
    return False


def classify(docs, query):
    """Split a per-experiment result set into shown / deleted / thread context.

    Two things the server does that a reader must not be shown naively:

    * Deletion is LOGICAL.  The server's removal route sets `deleted_by` and
      `deleted_time` on the document and no read query filters on either, so
      entries somebody deliberately removed come back in search results.  Any
      document carrying `deleted_by` is suppressed here.

    * Thread hydration.  After matching, the server pulls every hit's root and
      parent ancestors into the result set until closure.  Those ancestors do NOT
      match the query and arrive indistinguishable from genuine hits.  A hydrated
      ancestor is exactly: a returned document whose `_id` is referenced by
      another returned document's `root` or `parent`, and which does not itself
      match the query.  It is labelled, not hidden -- it is the context the
      matching reply was written under.
    """
    returned = len(docs)
    kept = [d for d in docs if not d.get("deleted_by")]
    suppressed_deleted = returned - len(kept)

    # Built from EVERY returned document, including the deleted ones: hydration
    # happened server-side over the whole set, and an ancestor whose only
    # referrer is a tombstone was still pulled in as context, not as a match.
    ancestor_ids = set()
    for doc in docs:
        for field in ("root", "parent"):
            if doc.get(field):
                ancestor_ids.add(doc[field])

    matches, context, invisible = [], [], 0
    for doc in kept:
        visible = _matches_query(doc, query)
        if doc.get("_id") in ancestor_ids and not visible:
            context.append(doc)
        else:
            if not visible:
                # The server returned it but the query appears nowhere in the
                # readable text.  Measured cause: on a $text miss the server
                # falls back to a case-insensitive unanchored regex over the RAW
                # content, and an inline screenshot is hundreds of kilobytes of
                # base64 in which "clog" turns up as ClOg, CLOG or clOG.  Real
                # entries, genuinely returned, matched on image noise.
                doc["_no_visible_match"] = True
                invisible += 1
            matches.append(doc)
    return {"returned": returned, "matches": matches, "context": context,
            "suppressed_deleted": suppressed_deleted, "no_visible_match": invisible}


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def _excerpt(doc, chars, query=""):
    """A readable excerpt, centred on the match where one can be located.

    A head truncation is the wrong default here: an image-bearing entry starts
    with a base64 data URI, so the first N characters are unreadable and the
    reader cannot see WHY the entry matched.  HTML and data URIs are stripped
    first, then the window is centred on the earliest query term found.
    """
    text = " ".join(_plain_text(doc).split())
    if not text:
        return "(no text content -- the entry is attachments or images only)"
    start = 0
    lowered = text.lower()
    for term in (query or "").lower().replace("t:", "").replace("x:", "").split():
        where = lowered.find(term)
        if where == -1:
            where = lowered.find(_stem(term))
        if where != -1:
            start = max(0, where - chars // 3)
            break
    piece = text[start:start + chars]
    return ("..." if start else "") + piece + ("..." if start + chars < len(text) else "")


def print_entry(experiment, doc, kind, chars, query=""):
    if kind == "context":
        tag = "  [thread context -- did not match the query]"
    elif doc.get("_no_visible_match"):
        tag = "  [server matched this, but not in its readable text]"
    else:
        tag = ""
    print("-" * 78)
    print("experiment : %s%s" % (experiment, tag))
    print("author     : %s" % doc.get("author"))
    print("insert_time: %s" % doc.get("insert_time"))
    if doc.get("title"):
        print("title      : %s" % doc["title"])
    if doc.get("tags"):
        print("tags       : %s" % ", ".join(doc["tags"]))
    if doc.get("run_num") is not None:
        print("run        : %s" % doc["run_num"])
    print("id         : %s" % doc.get("_id"))
    print("excerpt    : %s" % _excerpt(doc, chars, query))


def print_scope_line(searched, total_readable, identity, prefix, selection,
                     skipped, days_note):
    print()
    print("=" * 78)
    print("SCOPE: searched %d of %d experiments readable as %s (%s)"
          % (searched, total_readable, identity, prefix))
    print("  selection: %s" % selection)
    if days_note:
        print("  caveat   : %s" % days_note)
    if skipped:
        print("  skipped  : %d experiment(s) -- %s"
              % (len(skipped), ", ".join("%s (%s)" % (e, s) for e, s in skipped)))
    else:
        print("  skipped  : none -- every experiment in scope answered")
    print("=" * 78)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_whoami(args):
    import requests
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))
    records = readable_experiments(session, cred, refresh=args.refresh)
    print("identity            : %s" % cred["identity"])
    print("mechanism           : %s" % cred["mechanism"])
    print("credential source   : %s" % cred["cache"])
    print("credential expires  : %s   (host local time, %s)"
          % (cred.get("expires") or "unknown",
             "as klist reports it" if cred["mechanism"] == "kerberos"
             else "from expires_at in the token metadata"))
    if cred.get("alternates"):
        print("other own credentials: %d also valid, unused -- %s"
              % (len(cred["alternates"]),
                 ", ".join(c["cache"] for c in cred["alternates"])))
    print("endpoint prefix     : %s   (%s/%s/lgbk/lgbk/...)"
          % (cred["prefix"], BASE, cred["prefix"]))
    print("readable experiments: %d" % len(records))
    print()
    print("The count above is a property of THIS account's roles, not of the eLog.")
    print("Another user running the same command will see a different number.")
    return 0


def cmd_scope(args):
    import requests
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))
    chosen, total_readable, selection = choose_scope(session, cred, args)
    print("identity : %s (%s)" % (cred["identity"], cred["prefix"]))
    print("in scope : %d of %d readable experiments" % (len(chosen), total_readable))
    print("selection: %s" % selection)
    print("cap      : %d (%s)"
          % (args.cap, "within cap" if len(chosen) <= args.cap else "OVER CAP"))
    print()
    for name in chosen:
        print("  %s" % name)
    return 0


def cmd_search(args):
    import requests
    # An empty search_text is not an empty search: the server returns the WHOLE
    # collection -- 2953 entries and 7.2 MB from a single instrument logbook.
    # Multiply that by a fan-out and it is a denial of service written in
    # punctuation, so it is refused here rather than sent.
    query = (args.query or "").strip()
    if not query:
        print("REFUSING: an empty search text returns every entry in every "
              "experiment in scope.", file=sys.stderr)
        print("  Give a word to search for, or name one experiment and use the "
              "eLog web UI to browse.", file=sys.stderr)
        return 2
    if query in ("x:", "t:") or query.rstrip(".*") in ("x:",):
        # `x:` with no pattern is the empty query wearing a prefix: it matches
        # every entry in every experiment in scope.
        print("REFUSING: %r matches everything, which is the empty search with a "
              "prefix on it." % query, file=sys.stderr)
        print("  Give the prefix something to match, e.g. x:[Jj]et.*clog",
              file=sys.stderr)
        return 2
    if args.limit < 0:
        print("REFUSING: --limit %d is negative.  As a slice bound that silently "
              "drops entries off the END of the results." % args.limit, file=sys.stderr)
        return 2
    if query.startswith("x:"):
        try:
            re.compile(query[2:])
        except re.error as exc:
            # An invalid regex used to come back as a clean zero -- identical to a
            # term that genuinely is not there, and the likeliest silent wrong
            # answer in normal use, since the regex is case-sensitive and readers
            # end up editing bracket classes.
            print("REFUSING: %r is not a valid regular expression: %s"
                  % (query, exc), file=sys.stderr)
            return 2
    try:
        args.start_date = _normalise_date(args.start_date, "--start-date")
        args.end_date = _normalise_date(args.end_date, "--end-date")
    except ValueError as exc:
        print("REFUSING: %s" % exc, file=sys.stderr)
        return 2
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))

    chosen, total_readable, selection = choose_scope(session, cred, args)

    if not chosen:
        print("SCOPE: 0 of %d readable experiments matched the selection rule."
              % total_readable)
        print("  selection: %s" % selection)
        print("  Nothing was searched.  Widen with --days N or name experiments with")
        print("  --experiments a,b,c.  This skill does not silently widen scope for you.")
        return 1

    if len(chosen) > args.cap:
        print("REFUSING: the selection rule chose %d experiments, over the cap of %d."
              % (len(chosen), args.cap))
        print("  selection: %s" % selection)
        print("  Not because it would be slow for you -- measured, a miss costs the")
        print("  client no more than a hit, and the whole 2240-experiment corpus")
        print("  extrapolates to about 27 s at this concurrency.  The cap is there")
        print("  because each of those is a database query against the production")
        print("  logbook the hutches use during beam time, the server-side cost of a")
        print("  missing query has not been measured, and fifteen years of dormant")
        print("  archives mostly return noise.  Narrowing is a relevance decision.")
        print("  Narrow it, then re-run:")
        print("    --days N            fewer days of activity (currently %d)" % args.days)
        print("    --instrument MFX    one instrument")
        print("    --experiments a,b   an explicit list")
        print("    --cap N             raise the cap deliberately, if you mean it")
        return 2

    started = time.time()
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(search_one, session, cred, name, args)
                   for name in chosen]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    wall = time.time() - started

    totals = {"returned": 0, "shown": 0, "suppressed_deleted": 0, "context": 0,
              "outside_window": 0, "no_visible_match": 0}
    skipped, hits = [], []
    for experiment, status, docs, _elapsed in results:
        if status != 200:
            skipped.append((experiment, status))
            continue
        if not docs:
            continue
        totals["returned"] += len(docs)
        if args.start_date or args.end_date:
            inside = [d for d in docs
                      if _within_window(d, args.start_date, args.end_date)]
            totals["outside_window"] += len(docs) - len(inside)
            docs = inside
            if not docs:
                continue
        split = classify(docs, args.query)
        totals["suppressed_deleted"] += split["suppressed_deleted"]
        totals["context"] += len(split["context"])
        totals["shown"] += len(split["matches"])
        totals["no_visible_match"] += split["no_visible_match"]
        for doc in split["matches"]:
            hits.append((experiment, doc, "match"))
        if not args.hide_context:
            for doc in split["context"]:
                hits.append((experiment, doc, "context"))

    hits.sort(key=lambda h: (h[1].get("insert_time") or ""), reverse=True)
    printed = hits[:args.limit]

    print('QUERY: "%s"' % args.query)
    for experiment, doc, kind in printed:
        print_entry(experiment, doc, kind, args.chars, args.query)

    experiments_with_hits = len({h[0] for h in hits if h[2] == "match"})
    print()
    print("COUNTS  (over every experiment searched, not just what was printed)")
    print("  entries returned by the API    : %d" % totals["returned"])
    print("  entries shown as matches       : %d" % totals["shown"])
    print("  entries suppressed as deleted  : %d" % totals["suppressed_deleted"])
    print("  entries labelled thread context: %d%s"
          % (totals["context"], " (not printed: --hide-context)" if args.hide_context else ""))
    if totals["no_visible_match"]:
        print("  of those, with no visible match: %d (server matched inside embedded "
              "image data)" % totals["no_visible_match"])
    if args.start_date or args.end_date:
        print("  entries outside the date window: %d (filtered here, not server-side)"
              % totals["outside_window"])
    print("  entries printed below --limit  : %d of %d" % (len(printed), len(hits)))
    print("  experiments with at least one match: %d" % experiments_with_hits)
    print("  fan-out wall time              : %.1f s at concurrency %d"
          % (wall, CONCURRENCY))
    if totals["returned"] > BROAD_RESULT_WARNING:
        print()
        print("  !! %d entries is not an answer, it is a haystack.  A common word "
              "matches" % totals["returned"])
        print("     most of the logbook.  Narrow it: a distinctive word, a quoted")
        print('     "exact phrase", t:TAG, an author name, or fewer experiments.')

    days_note = None
    if not args.experiments:
        days_note = ("recency is keyed on the last RUN start time, so an experiment "
                     "with recent eLog activity but no new runs is not in this set")
    print_scope_line(len(chosen), total_readable, cred["identity"], cred["prefix"],
                     selection, skipped, days_note)
    return 0


SELFTEST_CASES = [
    ("a thread ancestor that does not match is context",
     [{"_id": "A", "content": "setting up the sample delivery"},
      {"_id": "B", "content": "laser aligned", "root": "A", "parent": "A"}],
     "laser", ["B"], ["A"], 0),
    ("a deleted entry is suppressed, never shown",
     [{"_id": "A", "content": "laser aligned"},
      {"_id": "D", "content": "laser aligned", "deleted_by": "someone"}],
     "laser", ["A"], [], 1),
    ("an ancestor referenced only by a deleted tombstone is still context",
     [{"_id": "R", "content": "sample delivery setup"},
      {"_id": "D", "content": "laser", "deleted_by": "x", "root": "R", "parent": "R"},
      {"_id": "M", "content": "laser again"}],
     "laser", ["M"], ["R"], 1),
    ("a title-only match is not demoted to context",
     [{"_id": "A", "content": "MCP bias scan", "title": "Run 245"},
      {"_id": "B", "content": "child entry", "root": "A", "parent": "A"}],
     "run", ["A", "B"], [], 0),
    ("a tag-matched ancestor stays a match (server's exact-tag case)",
     [{"_id": "A", "content": "no keyword here", "tags": ["laser"]},
      {"_id": "B", "content": "laser stuff", "root": "A", "parent": "A"}],
     "laser", ["A", "B"], [], 0),
    ("an author-matched ancestor stays a match (server's author case)",
     [{"_id": "A", "content": "no keyword here", "author": "schaferd"},
      {"_id": "B", "content": "schaferd wrote this", "root": "A", "parent": "A"}],
     "schaferd", ["A", "B"], [], 0),
    ("an unreferenced non-match stays a match (conservative)",
     [{"_id": "A", "content": "setup notes"}, {"_id": "B", "content": "laser aligned"}],
     "laser", ["A", "B"], [], 0),
    ("multi-word is OR-of-terms, so a partial match is not demoted",
     [{"_id": "A", "content": "jet only"},
      {"_id": "B", "content": "clog only", "root": "A", "parent": "A"}],
     "jet clog", ["A", "B"], [], 0),
    ("stemmed hit: 'aligned' matches an entry saying 'alignment'",
     [{"_id": "A", "content": "Be lens set 2 alignment for 9 keV"},
      {"_id": "B", "content": "aligned it", "root": "A", "parent": "A"}],
     "aligned", ["A", "B"], [], 0),
    ("stemmed hit neither substring can reach: 'moved' against 'moving'",
     [{"_id": "A", "content": "yag1.y motor not moving"},
      {"_id": "B", "content": "moved it", "root": "A", "parent": "A"}],
     "moved", ["A", "B"], [], 0),
    ("stem-substring: 'lasers' matches an entry saying 'laser'",
     [{"_id": "A", "content": "laser table realigned"},
      {"_id": "B", "content": "lasers off", "root": "A", "parent": "A"}],
     "lasers", ["A", "B"], [], 0),
    ("tags are case-SENSITIVE, as the server has them",
     [{"_id": "A", "content": "no keyword", "tags": ["SCREENSHOT"]},
      {"_id": "B", "content": "screenshot attached", "root": "A", "parent": "A"}],
     "SCREENSHOT", ["A", "B"], [], 0),
    # The regression: with the quote marks left on, the phrase was never found in
    # the text, so a correct phrase hit that happened to be a thread root was
    # branded as context and counted as unexplained image noise.
    ("a quoted phrase hit that IS an ancestor stays a match",
     [{"_id": "A", "content": "the jet clogged again"},
      {"_id": "B", "content": "replying", "root": "A", "parent": "A"}],
     '"jet clog"', ["A", "B"], [], 0),
    ("a quoted phrase that is genuinely absent is not a match",
     [{"_id": "A", "content": "jet fine, nozzle clogged"},
      {"_id": "B", "content": "jet clog seen", "root": "A", "parent": "A"}],
     '"jet clog"', ["B"], ["A"], 0),
    ("HTML and base64 are stripped before matching",
     [{"_id": "A", "content": '<p><img src="data:image/png;base64,QUJDbG9nWFla"></p>'},
      {"_id": "B", "content": "clog seen", "root": "A", "parent": "A"}],
     "clog", ["B"], ["A"], 0),
]


def cmd_selftest(_args):
    """Check the result classifier offline.  No credential, no network, no eLog."""
    failures = 0
    for name, docs, query, want_m, want_c, want_d in SELFTEST_CASES:
        split = classify(docs, query)
        got_m = sorted(d["_id"] for d in split["matches"])
        got_c = sorted(d["_id"] for d in split["context"])
        ok = (got_m == sorted(want_m) and got_c == sorted(want_c)
              and split["suppressed_deleted"] == want_d)
        failures += 0 if ok else 1
        print("%s %s" % ("PASS" if ok else "FAIL", name))
        if not ok:
            print("     wanted matches=%s context=%s deleted=%d"
                  % (sorted(want_m), sorted(want_c), want_d))
            print("     got    matches=%s context=%s deleted=%d"
                  % (got_m, got_c, split["suppressed_deleted"]))
    print()
    print("%d of %d cases passed" % (len(SELFTEST_CASES) - failures, len(SELFTEST_CASES)))
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(
        prog="elogsearch.py",
        description="Search the LCLS eLog as yourself, read-only, with scope stated.")
    parser.add_argument("--auth", choices=["kerberos", "jwt"], default=None,
                        help="force a credential mechanism (default: kerberos, then jwt)")
    parser.add_argument("--refresh", action="store_true",
                        help="re-fetch the readable-experiment list instead of the cache")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_global_flags(p):
        """Accept --auth/--refresh AFTER the subcommand as well as before it.

        SUPPRESS is what makes this safe: without it the subcommand's own default
        would overwrite a value the user gave before the subcommand, so
        `--refresh search foo` would silently stop refreshing.
        """
        p.add_argument("--auth", choices=["kerberos", "jwt"],
                       default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        p.add_argument("--refresh", action="store_true",
                       default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    who = sub.add_parser("whoami", help="who am I to the eLog, and what may I read")
    add_global_flags(who)
    who.set_defaults(func=cmd_whoami)

    st = sub.add_parser("selftest",
                        help="check the result classifier offline (no credential needed)")
    st.set_defaults(func=cmd_selftest)

    def add_scope_flags(p):
        p.add_argument("--days", type=int, default=DEFAULT_DAYS,
                       help="experiments whose last run started within N days "
                            "(default %d)" % DEFAULT_DAYS)
        p.add_argument("--instrument", default=None, help="restrict to one instrument")
        p.add_argument("--experiments", default=None,
                       help="explicit comma-separated experiment names")
        p.add_argument("--logbooks", action="store_true",
                       help="the standing operational logbooks (Sample Delivery "
                            "System, MEC Laser System, the per-instrument logs); "
                            "the recency rule cannot reach these")
        p.add_argument("--cap", type=int, default=DEFAULT_SCOPE_CAP,
                       help="refuse to fan out beyond this many experiments "
                            "(default %d)" % DEFAULT_SCOPE_CAP)

    scope = sub.add_parser("scope", help="show which experiments a search would cover")
    add_global_flags(scope)
    add_scope_flags(scope)
    scope.set_defaults(func=cmd_scope)

    search = sub.add_parser("search", help="search the eLog across the chosen scope")
    add_global_flags(search)
    search.add_argument("query", help="search text ('t:tag' searches tags, 'x:' regex)")
    add_scope_flags(search)
    search.add_argument("--start-date", dest="start_date", default=None,
                        help="%%Y-%%m-%%dT%%H:%%M:%%S.%%fZ")
    search.add_argument("--end-date", dest="end_date", default=None,
                        help="%%Y-%%m-%%dT%%H:%%M:%%S.%%fZ")
    search.add_argument("--limit", type=int, default=20,
                        help="entries to print, newest first (default 20)")
    search.add_argument("--chars", type=int, default=EXCERPT_CHARS,
                        help="excerpt length in characters")
    search.add_argument("--hide-context", action="store_true",
                        help="omit thread-context entries (still counted)")
    search.add_argument("--timeout", type=int, default=120,
                        help="per-experiment HTTP timeout in seconds")
    search.set_defaults(func=cmd_search)

    args = parser.parse_args()
    try:
        return args.func(args)
    except CredentialError as exc:
        print("CREDENTIAL BLOCKED: %s" % exc, file=sys.stderr)
        return 3
    except ValueError as exc:
        print("REFUSING: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
