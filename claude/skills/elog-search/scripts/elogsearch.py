#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["requests", "lcls-krtc", "snowballstemmer"]
# ///
"""Search the LCLS eLog as yourself, read-only, with the search scope always stated.

Read-only by construction: every HTTP call this script can make is routed through
`_get()`, which refuses any route the vendored inventory below does not classify
read-only -- including the 27 explgbk routes that accept GET and yet write.  There is no
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
from urllib.parse import quote

BASE = "https://pswww.slac.stanford.edu"

# >>> ROUTE POLICY (generated block; edit gen_inventory.py, not this) >>>
# --------------------------------------------------------------------------
# route policy -- a deny-list model, enforced in code
# --------------------------------------------------------------------------
#
# The rule this skill enforces is "does not mutate eLog state", NOT "is an HTTP
# GET".  explgbk answers GET on routes that end runs, close shifts, cross-post
# entries, subscribe people to email, toggle collaborator roles, kill analysis
# jobs and force cache rebuilds.  A skill that allowed every GET would be able
# to do all of that to the production logbook, live, during beam time.
#
# So the inventory below classifies EVERY GET-accepting route explgbk exposes
# into exactly one of three classes, and _get() refuses anything not readonly:
#
#   readonly   the skill may call it
#   mutating   it accepts GET and changes server state -- never called, and the
#              refusal is proven offline in selftest rather than against the
#              live server
#   denied     read-only by the letter of the rule, refused anyway: it leaves
#              the logbook, mints a credential, or has nothing to read.  The
#              reason is named in DENIAL_REASONS, one per route.
#
# The inventory is VENDORED, not discovered at run time.  A copy of the upstream
# route list is checked in at reference/explgbk-get-routes.txt and `selftest`
# fails when the two disagree.  That pin is the whole mitigation for the one
# weakness of a deny-list model: a future explgbk release adding a 28th mutating
# GET would otherwise fall inside the permitted set in silence.

ROUTE_INVENTORY = (
    # DENIED -- read-only by the letter of the rule, refused anyway.
    # Each one is refused for a reason named in DENIAL_REASONS below.
    ("denied", "/lgbk/<experiment_name>/ws/ext_preview/<path:path>"),
    ("denied", "/lgbk/<experiment_name>/ws/generate_arp_token"),
    ("denied", "/lgbk/ws/empty"),
    ("denied", "/lgbk/ws/lookup_experiment_in_urawi"),

    # MUTATING -- these accept GET and CHANGE SERVER STATE.  They are the
    # reason this skill classifies by effect and not by HTTP method.
    ("mutating", "/lgbk/<experiment_name>/migrate_attachments"),
    ("mutating", "/lgbk/<experiment_name>/ws/add_collaborator"),
    ("mutating", "/lgbk/<experiment_name>/ws/change_sample_for_run"),
    ("mutating", "/lgbk/<experiment_name>/ws/check_and_move_run_files_to_location"),
    ("mutating", "/lgbk/<experiment_name>/ws/clone_sample"),
    ("mutating", "/lgbk/<experiment_name>/ws/clone_system_template_run_tables"),
    ("mutating", "/lgbk/<experiment_name>/ws/close_shift"),
    ("mutating", "/lgbk/<experiment_name>/ws/cross_post_elogs"),
    ("mutating", "/lgbk/<experiment_name>/ws/delete_workflow_job"),
    ("mutating", "/lgbk/<experiment_name>/ws/elog_email_subscribe"),
    ("mutating", "/lgbk/<experiment_name>/ws/elog_email_unsubscribe"),
    ("mutating", "/lgbk/<experiment_name>/ws/file_available_at_location"),
    ("mutating", "/lgbk/<experiment_name>/ws/kill_workflow_job"),
    ("mutating", "/lgbk/<experiment_name>/ws/make_sample_current"),
    ("mutating", "/lgbk/<experiment_name>/ws/remove_collaborator"),
    ("mutating", "/lgbk/<experiment_name>/ws/stop_current_sample"),
    ("mutating", "/lgbk/<experiment_name>/ws/sync_collaborators_with_user_portal"),
    ("mutating", "/lgbk/<experiment_name>/ws/sync_posix_group"),
    ("mutating", "/lgbk/<experiment_name>/ws/toggle_role"),
    ("mutating", "/lgbk/ws/projects/<prjid>/grids/<gridid>/linksession"),
    ("mutating", "/lgbk/ws/rebuild_experiment_cache_for_experiment"),
    ("mutating", "/lgbk/ws/reload_experiment_cache"),
    ("mutating", "/lgbk/ws/reload_named_cache"),
    ("mutating", "/lgbk/ws/sync_collaborators_with_user_portal_for_upcoming_experiments"),
    ("mutating", "/run_control/<experiment_name>/ws/end_run"),
    ("mutating", "/run_control/<experiment_name>/ws/start_run"),

    # READ-ONLY -- everything the skill is permitted to call.
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/current_files_for_live_mode"),
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/current_files_for_live_mode_at_location"),
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/daq_run_params"),
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/files"),
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/files_for_live_mode"),
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/files_for_live_mode_at_location"),
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/get_params_matching_prefix"),
    ("readonly", "/lgbk/<experiment_name>/ws/<run_num>/get_tags_for_run"),
    ("readonly", "/lgbk/<experiment_name>/ws/attachment"),
    ("readonly", "/lgbk/<experiment_name>/ws/collaborators"),
    ("readonly", "/lgbk/<experiment_name>/ws/current_files_for_live_mode_at_location"),
    ("readonly", "/lgbk/<experiment_name>/ws/current_run"),
    ("readonly", "/lgbk/<experiment_name>/ws/current_sample_name"),
    ("readonly", "/lgbk/<experiment_name>/ws/dm_locations"),
    ("readonly", "/lgbk/<experiment_name>/ws/elog"),
    ("readonly", "/lgbk/<experiment_name>/ws/elog/<entry_id>/complete_elog_tree"),
    ("readonly", "/lgbk/<experiment_name>/ws/elog_email_subscriptions"),
    ("readonly", "/lgbk/<experiment_name>/ws/elog_emails"),
    ("readonly", "/lgbk/<experiment_name>/ws/exp_posix_group_members"),
    ("readonly", "/lgbk/<experiment_name>/ws/file_counts_by_extension"),
    ("readonly", "/lgbk/<experiment_name>/ws/files"),
    ("readonly", "/lgbk/<experiment_name>/ws/files_for_live_mode_at_location"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_elog_tags"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_feedback_document"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_instrument_elogs"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_latest_shift"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_modal_param_definitions"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_run_params_for_all_runs"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_runs_matching_editable"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_runs_to_tags"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_runs_with_tag"),
    ("readonly", "/lgbk/<experiment_name>/ws/get_tags_to_runs"),
    ("readonly", "/lgbk/<experiment_name>/ws/has_role"),
    ("readonly", "/lgbk/<experiment_name>/ws/info"),
    ("readonly", "/lgbk/<experiment_name>/ws/internalinfo"),
    ("readonly", "/lgbk/<experiment_name>/ws/map_param_editable_to_run_nums"),
    ("readonly", "/lgbk/<experiment_name>/ws/run_param_descriptions"),
    ("readonly", "/lgbk/<experiment_name>/ws/run_table_data"),
    ("readonly", "/lgbk/<experiment_name>/ws/run_table_sources"),
    ("readonly", "/lgbk/<experiment_name>/ws/run_tables"),
    ("readonly", "/lgbk/<experiment_name>/ws/runs"),
    ("readonly", "/lgbk/<experiment_name>/ws/runs/<run_num>"),
    ("readonly", "/lgbk/<experiment_name>/ws/runs_for_calib"),
    ("readonly", "/lgbk/<experiment_name>/ws/runtables/export_as_csv"),
    ("readonly", "/lgbk/<experiment_name>/ws/samples"),
    ("readonly", "/lgbk/<experiment_name>/ws/samples/"),
    ("readonly", "/lgbk/<experiment_name>/ws/samples/<sample_name>"),
    ("readonly", "/lgbk/<experiment_name>/ws/search_elog"),
    ("readonly", "/lgbk/<experiment_name>/ws/shifts"),
    ("readonly", "/lgbk/<experiment_name>/ws/workflow/<job_id>/<path:action>"),
    ("readonly", "/lgbk/<experiment_name>/ws/workflow_definitions"),
    ("readonly", "/lgbk/<experiment_name>/ws/workflow_jobs"),
    ("readonly", "/lgbk/<experiment_name>/ws/workflow_triggers"),
    ("readonly", "/lgbk/filemanager_file_types"),
    ("readonly", "/lgbk/get_modal_param_definitions"),
    ("readonly", "/lgbk/naming_conventions"),
    ("readonly", "/lgbk/ws/activeexperiment_for_instrument_station"),
    ("readonly", "/lgbk/ws/activeexperiments"),
    ("readonly", "/lgbk/ws/api_endpoints"),
    ("readonly", "/lgbk/ws/experiment_daily_data_breakdown"),
    ("readonly", "/lgbk/ws/experiment_names_updated_within"),
    ("readonly", "/lgbk/ws/experiment_stats"),
    ("readonly", "/lgbk/ws/experiments"),
    ("readonly", "/lgbk/ws/experiments_to_proposal"),
    ("readonly", "/lgbk/ws/experiments_with_user_as_collaborator"),
    ("readonly", "/lgbk/ws/get_cached_experiment_names"),
    ("readonly", "/lgbk/ws/get_matching_groups"),
    ("readonly", "/lgbk/ws/get_matching_uids"),
    ("readonly", "/lgbk/ws/get_params_matching_prefix"),
    ("readonly", "/lgbk/ws/global_roles"),
    ("readonly", "/lgbk/ws/instrument_station_list"),
    ("readonly", "/lgbk/ws/instrument_switch_history"),
    ("readonly", "/lgbk/ws/instruments"),
    ("readonly", "/lgbk/ws/ops_search_exp_infos"),
    ("readonly", "/lgbk/ws/poc_feedback/experiments"),
    ("readonly", "/lgbk/ws/poc_feedback/schema"),
    ("readonly", "/lgbk/ws/postable_experiments"),
    ("readonly", "/lgbk/ws/potentiallyactiveusers"),
    ("readonly", "/lgbk/ws/projects"),
    ("readonly", "/lgbk/ws/projects/<prjid>"),
    ("readonly", "/lgbk/ws/projects/<prjid>/grids"),
    ("readonly", "/lgbk/ws/projects/<prjid>/grids/<gridid>"),
    ("readonly", "/lgbk/ws/projects/<prjid>/sessions"),
    ("readonly", "/lgbk/ws/search_experiment_info"),
    ("readonly", "/lgbk/ws/sorted_experiment_ids"),
    ("readonly", "/lgbk/ws/usergroups"),
    ("readonly", "/run_control/<experiment_name>/ws/current_run"),

)

# The upstream revision this inventory was read from.  `routes` prints it and
# reference/explgbk-get-routes.txt names it too, so a stale vendored list is
# visible rather than merely wrong.
UPSTREAM_COMMIT = "slaclab/explgbk@e5484aa"

# Why each denied route is denied.  These are the four that pass the literal
# include rule and are refused anyway; the reason travels with the refusal so a
# caller is never left guessing whether it is a bug.
DENIAL_REASONS = {
    "/lgbk/<experiment_name>/ws/generate_arp_token":
        "it mints a bearer credential for the job daemon.  Issuing credentials "
        "is outside what a read-only search skill should be able to do, even "
        "though the route writes nothing to the eLog.",
    "/lgbk/<experiment_name>/ws/ext_preview/<path:path>":
        "it is not an attachment fetch: it 302-redirects to an external host "
        "and sets a cookie holding an MD5 of the experiment name plus a "
        "server-side secret.  The same bytes are reachable through "
        "attachment?prefer_preview=true, so nothing is lost.",
    "/lgbk/ws/lookup_experiment_in_urawi":
        "it reaches URAWI, an external system, not the logbook -- an unbounded "
        "outside dependency with nothing to do with searching the eLog.",
    "/lgbk/ws/empty":
        "it returns {}.  A convenience for the web UI's JavaScript with "
        "nothing in it to read.",
}

# One read-only route has a query parameter that changes state, so the refusal
# has to be finer-grained than the route.  `/lgbk/ws/experiments?legacy_cutoff=N`
# reaches `cat.set_legacy_cutoff(N)` (services/explgbk.py:335-339), which rebinds
# a field on the module-level `CategorizerWithLegacy()` singleton in
# `categorizers["instrument_runperiod"]`.  That is in-process presentation state,
# not eLog state -- nothing is persisted and a worker restart clears it -- so the
# route stays read-only.  But one caller would change how that worker buckets the
# experiment list for every later request, which is not this skill's business.
# The route is needed (it IS the authorization boundary: it answers "what may I
# read"), so the parameter is refused rather than the route.
REFUSED_PARAMS = {
    "/lgbk/ws/experiments": {
        "legacy_cutoff":
            "it rebinds a shared server-side categorizer object, changing how "
            "that worker process buckets experiments for every later request",
    },
}

ROUTE_CLASS = dict((rule, klass) for klass, rule in ROUTE_INVENTORY)
READONLY_ROUTES = frozenset(r for k, r in ROUTE_INVENTORY if k == "readonly")
MUTATING_ROUTES = frozenset(r for k, r in ROUTE_INVENTORY if k == "mutating")
DENIED_ROUTES = frozenset(r for k, r in ROUTE_INVENTORY if k == "denied")

# Routes named often enough in code and documentation to deserve a name.
R_EXPERIMENTS = "/lgbk/ws/experiments"
R_NAMES_UPDATED_WITHIN = "/lgbk/ws/experiment_names_updated_within"
R_SEARCH_ELOG = "/lgbk/<experiment_name>/ws/search_elog"
# <<< ROUTE POLICY <<<

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

    Order: the S3DF token (ws-jwt) first, then Kerberos.  The token is the
    documented path and the only one that survives a container, so it leads.
    Kerberos stays as an undocumented fallback -- it still works, and nobody
    holding only a ticket should be locked out by a documentation decision --
    and `--auth kerberos` forces it outright.  Both are per-user files owned by
    the caller.  There is deliberately no third option: a skill that quietly
    falls back to a shared operator account would report somebody else's read
    access as yours.

    Returns the best candidate with the remaining ones attached as `alternates`,
    because "the cache holds a live TGT" and "the GSS library can build a header
    from it" are not the same test -- the second can still fail, and the right
    answer then is the next cache, not an error.
    """
    # --auth FORCES a mechanism.  It used to be a preference, so `--auth jwt` on a
    # host with no token silently produced a Kerberos session and reported success
    # -- the one flag that could exercise the JWT path could not report its own
    # failure.  That flag is how the JWT path was finally verified.
    order = [prefer] if prefer else ["jwt", "kerberos"]

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
            "  Checked, for uid %d only: %s\n"
            "  (S3DF_TOKEN_FILE / S3DF_TOKEN_META move that path; an expired token\n"
            "  counts as absent.)\n"
            "  This skill cannot authenticate for you: a FIRST login needs you at a\n"
            "  browser.  Renewing is cheaper -- the same command refreshes an expired\n"
            "  token from the stored refresh_token, with no browser at all.  Run:\n"
            "      /sdf/sw/s3df-cli/bin/s3df login   # S3DF OAuth2 token, 12 h\n"
            "  then re-run this command."
            % (_username(), os.getuid(), _s3df_token_paths()[0])
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

_PATH_PARAM = re.compile(r"<(?:[a-z]+:)?([A-Za-z_][A-Za-z0-9_]*)>")


def _fill_rule(rule, path_params):
    """Substitute a flask rule's path parameters, refusing to leave one unfilled.

    A half-filled rule is the dangerous case, not the empty one: it would send a
    literal `<run_num>` to the server and read back whatever that happens to
    match.  So an unsubstituted parameter is an error, never a request.
    """
    filled = rule
    for name, value in (path_params or {}).items():
        for token in ("<%s>" % name, "<path:%s>" % name, "<int:%s>" % name):
            if token in filled:
                # A path parameter is one segment, so '/' must not survive it --
                # except for the <path:...> converter, which is defined to eat
                # slashes and whose only user here is a denied route anyway.
                safe = "/" if token.startswith("<path:") else ""
                filled = filled.replace(token, quote(str(value), safe=safe))
                break
        else:
            raise ValueError("route %s has no path parameter %r" % (rule, name))
    missing = _PATH_PARAM.findall(filled)
    if missing:
        raise ValueError("route %s still needs path parameter(s): %s"
                         % (rule, ", ".join(missing)))
    return filled


def _get(session, prefix, rule, path_params=None, params=None, timeout=120,
         stream=False):
    """The single HTTP choke point.  Every call the skill can make passes here.

    The refusals below are the read-only guarantee.  They are checked BEFORE the
    URL is built and before any socket is opened, which is what lets `selftest`
    prove them without a credential and without touching the server.
    """
    klass = ROUTE_CLASS.get(rule)
    if klass is None:
        raise ValueError(
            "refusing to call %r: it is not in this skill's vendored inventory of "
            "explgbk routes.  `elogsearch.py routes` lists all %d."
            % (rule, len(ROUTE_INVENTORY)))
    if klass == "mutating":
        raise ValueError(
            "refusing to call %r: it accepts GET but CHANGES SERVER STATE.  This "
            "skill is read-only by construction, and %d of explgbk's GET routes "
            "mutate; every one of them is refused here."
            % (rule, len(MUTATING_ROUTES)))
    if klass == "denied":
        raise ValueError("refusing to call %r: %s"
                         % (rule, DENIAL_REASONS.get(rule, "denied by this skill")))
    for name in sorted(params or {}):
        reason = REFUSED_PARAMS.get(rule, {}).get(name)
        if reason:
            raise ValueError("refusing to send %r to %r: %s" % (name, rule, reason))
    url = "%s/%s/lgbk%s" % (BASE, prefix, _fill_rule(rule, path_params))
    return session.get(url, params=params or {}, timeout=timeout, stream=stream)


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

    response = _get(session, cred["prefix"], R_EXPERIMENTS, timeout=300)
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
    response = _get(session, "ws", R_NAMES_UPDATED_WITHIN,
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
        response = _get(session, cred["prefix"], R_SEARCH_ELOG,
                        path_params={"experiment_name": experiment},
                        params=params, timeout=args.timeout)
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
    # Only alternates of the SAME mechanism are worth showing.  A fallback of a
    # different mechanism is an implementation detail of resolution, not
    # something the caller chooses between, and naming its file here would put a
    # credential path in front of a user the documentation never mentions.
    same = [c for c in cred.get("alternates", [])
            if c["mechanism"] == cred["mechanism"]]
    if same:
        print("other own credentials: %d also valid, unused -- %s"
              % (len(same), ", ".join(c["cache"] for c in same)))
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


# --------------------------------------------------------------------------
# route inventory + the generic reader
# --------------------------------------------------------------------------

def _resolve_rule(text):
    """Accept a full route rule, or the shortest unambiguous tail of one.

    `runs` is what a person types; `/lgbk/<experiment_name>/ws/runs` is what the
    server routes on.  Resolving here keeps the inventory the single source of
    truth -- there is no second table of nicknames to drift out of step.
    """
    if text in ROUTE_CLASS:
        return text
    wanted = text.strip("/")
    hits = [rule for rule in ROUTE_CLASS
            if rule.strip("/").endswith("/" + wanted) or rule.strip("/") == wanted]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise ValueError(
            "no explgbk route matches %r.  `elogsearch.py routes` lists all %d."
            % (text, len(ROUTE_INVENTORY)))
    raise ValueError("%r matches %d routes; name one exactly:\n    %s"
                     % (text, len(hits), "\n    ".join(sorted(hits))))


def _api(session, cred, rule, path_params=None, params=None, timeout=120):
    """One read-only call, unwrapped.  Raises on a non-200 with the body attached."""
    response = _get(session, cred["prefix"], rule, path_params=path_params,
                    params=params, timeout=timeout)
    if response.status_code != 200:
        raise ValueError("%s returned HTTP %d: %s"
                         % (rule, response.status_code, response.text[:200]))
    return _unwrap(response)


def _suppress_deleted(docs):
    """Drop logically-deleted documents, returning (kept, how_many_suppressed).

    Deletion in the eLog is logical: the delete route sets `deleted_by` and no
    read query filters on it.  Every content-returning route in this script goes
    through here, so nothing the API hands back can quote an entry someone
    deliberately removed.
    """
    if not isinstance(docs, list):
        return docs, 0
    kept = [d for d in docs if not (isinstance(d, dict) and d.get("deleted_by"))]
    return kept, len(docs) - len(kept)


def cmd_routes(args):
    """Print the vendored route inventory.  Offline: no credential, no network."""
    order = ("denied", "mutating", "readonly")
    titles = {
        "denied": "DENIED -- read-only by the letter of the rule, refused anyway",
        "mutating": "MUTATING -- accept GET and CHANGE SERVER STATE; never called",
        "readonly": "READ-ONLY -- what this skill is permitted to call",
    }
    counts = dict((k, 0) for k in order)
    for klass, _rule in ROUTE_INVENTORY:
        counts[klass] += 1

    print("explgbk GET routes, vendored from %s" % UPSTREAM_COMMIT)
    print("classified by EFFECT, not by HTTP method: the include rule is")
    print("'does not mutate eLog state'.")
    print()
    for klass in order:
        if args.only and args.only != klass:
            continue
        print("%s  (%d)" % (titles[klass], counts[klass]))
        for this, rule in ROUTE_INVENTORY:
            if this != klass:
                continue
            print("  %s" % rule)
            reason = DENIAL_REASONS.get(rule)
            if reason and klass == "denied":
                for line in _wrap(reason, 72):
                    print("      %s" % line)
        print()
    print("allowed %d, mutating-refused %d, denied %d"
          % (counts["readonly"], counts["mutating"], counts["denied"]))
    return 0


def _wrap(text, width):
    words, line, out = text.split(), "", []
    for word in words:
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = (line + " " + word) if line else word
    if line:
        out.append(line)
    return out


def cmd_get(args):
    """Call one read-only route by name.  The long tail the recipes do not cover.

    This is deliberately NOT an escape hatch from the policy: it goes through the
    same `_get()` as everything else, so a mutating or denied route is refused
    here exactly as it is refused everywhere.
    """
    import requests
    rule = _resolve_rule(args.route)
    path_params = dict(_pair(p, "--path") for p in (args.path or []))
    if args.experiment and "<experiment_name>" in rule:
        path_params.setdefault("experiment_name", args.experiment)
    params = dict(_pair(p, "--param") for p in (args.param or []))

    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))
    started = time.time()
    response = _get(session, cred["prefix"], rule, path_params=path_params,
                    params=params, timeout=args.timeout)
    elapsed = time.time() - started
    print("route  : %s" % rule)
    print("status : %d   bytes %d   %.3fs   %s"
          % (response.status_code, len(response.content), elapsed,
             response.headers.get("Content-Type", "")))
    print()
    if response.status_code != 200:
        print(response.text[:2000])
        return 1
    try:
        payload = _unwrap(response)
    except ValueError:
        print(response.text[:args.chars])
        return 0
    if args.suppress_deleted:
        payload, dropped = _suppress_deleted(payload)
        if dropped:
            print("(%d logically-deleted document(s) suppressed)" % dropped)
    text = json.dumps(payload, indent=2, default=str)
    if args.limit and isinstance(payload, list) and len(payload) > args.limit:
        text = json.dumps(payload[:args.limit], indent=2, default=str)
        print("(showing the first %d of %d; raise with --limit)"
              % (args.limit, len(payload)))
    print(text[:args.chars] if args.chars else text)
    return 0


def _pair(text, flag):
    if "=" not in text:
        raise ValueError("%s expects key=value, got %r" % (flag, text))
    key, value = text.split("=", 1)
    return key, value


# --------------------------------------------------------------------------
# eLog reading -- entries, threads, tags, logbooks, attachments
# --------------------------------------------------------------------------

R_ELOG = "/lgbk/<experiment_name>/ws/elog"
R_ELOG_TREE = "/lgbk/<experiment_name>/ws/elog/<entry_id>/complete_elog_tree"
R_ELOG_TAGS = "/lgbk/<experiment_name>/ws/get_elog_tags"
R_INSTRUMENT_ELOGS = "/lgbk/<experiment_name>/ws/get_instrument_elogs"
R_ATTACHMENT = "/lgbk/<experiment_name>/ws/attachment"

# The whole-logbook route has NO server-side limit, so the cap lives here.  This
# is the same failure the empty-query refusal already closed for search: a route
# that will happily return an entire experiment's logbook is a load event unless
# the client bounds it.
ENTRIES_CAP = 200


def cmd_entries(args):
    """The newest entries of one logbook, capped, with deletions suppressed."""
    import requests
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))
    docs = _api(session, cred, R_ELOG,
                path_params={"experiment_name": args.experiment},
                timeout=args.timeout)
    returned = len(docs) if isinstance(docs, list) else 0
    docs, dropped = _suppress_deleted(docs)
    docs = sorted(docs, key=lambda d: d.get("relevance_time") or d.get("insert_time") or "",
                  reverse=True)
    limit = min(args.limit, ENTRIES_CAP)
    print("experiment : %s" % args.experiment)
    print("identity   : %s (%s)" % (cred["identity"], cred["prefix"]))
    print("route      : %s  (whole logbook; the server applies no limit)" % R_ELOG)
    print("returned   : %d entries; %d suppressed as deleted; showing newest %d"
          % (returned, dropped, min(limit, len(docs))))
    print()
    for doc in docs[:limit]:
        print_entry(args.experiment, doc, "entry", args.chars)
    return 0


def cmd_thread(args):
    """One entry with its complete thread, the server's own tree walk."""
    import requests
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))
    docs = _api(session, cred, R_ELOG_TREE,
                path_params={"experiment_name": args.experiment,
                             "entry_id": args.entry_id},
                timeout=args.timeout)
    if isinstance(docs, dict):
        docs = [docs]
    returned = len(docs)
    docs, dropped = _suppress_deleted(docs)
    docs = sorted(docs, key=lambda d: d.get("insert_time") or "")
    print("experiment : %s" % args.experiment)
    print("entry      : %s" % args.entry_id)
    print("thread     : %d document(s); %d suppressed as deleted" % (returned, dropped))
    print()
    for doc in docs:
        kind = "entry" if doc.get("_id") == args.entry_id else "thread"
        print_entry(args.experiment, doc, kind, args.chars)
    return 0


def cmd_tags(args):
    """The tag vocabulary of one logbook -- what `t:` searches can match."""
    import requests
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))
    tags = _api(session, cred, R_ELOG_TAGS,
                path_params={"experiment_name": args.experiment},
                timeout=args.timeout)
    print("experiment : %s" % args.experiment)
    print("tags       : %d" % (len(tags) if hasattr(tags, "__len__") else 0))
    print()
    for tag in sorted(tags or []):
        print("  %s" % tag)
    print()
    print("Tags are case-SENSITIVE, as the server stores them.")
    return 0


def cmd_logbooks(args):
    """The standing operational logbooks -- the ones recency can never reach.

    With --experiment it asks the server which logbooks that experiment posts
    into.  Without one it lists the standing logbooks from the caller's own
    readable set, selected by the property that actually identifies them: their
    display name differs from their URL key.  The recency rule cannot find them
    because they have no runs.
    """
    import requests
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))
    if args.experiment:
        elogs = _api(session, cred, R_INSTRUMENT_ELOGS,
                     path_params={"experiment_name": args.experiment},
                     timeout=args.timeout)
        print("experiment : %s" % args.experiment)
        print("route      : %s" % R_INSTRUMENT_ELOGS)
        print()
        print(json.dumps(elogs, indent=2, default=str)[:args.chars])
        return 0
    records = readable_experiments(session, cred, refresh=args.refresh)
    standing = [r for r in records if r.get("key") and r["name"] != r["key"]]
    print("identity : %s (%s)" % (cred["identity"], cred["prefix"]))
    print("standing operational logbooks readable by you: %d of %d experiments"
          % (len(standing), len(records)))
    print("(selected by display-name != key; they have no runs, so the recency")
    print(" rule and --instrument cannot reach them)")
    print()
    for record in sorted(standing, key=lambda r: r["name"]):
        print("  %-28s  key %s" % (record["name"], record["key"]))
    return 0


# An attachment's recorded `type` is whatever the uploader's browser claimed.  It
# is untrusted input, so the saved extension comes from this map and never from
# the server's string.
ATTACHMENT_EXTENSIONS = {
    "image/png": ".png", "image/jpeg": ".jpg", "image/jpg": ".jpg",
    "image/gif": ".gif", "image/bmp": ".bmp", "image/tiff": ".tif",
    "image/webp": ".webp", "image/svg+xml": ".svg",
    "application/pdf": ".pdf", "application/json": ".json",
    "application/zip": ".zip", "application/gzip": ".gz",
    "application/x-hdf5": ".h5", "application/octet-stream": ".bin",
    "text/plain": ".txt", "text/csv": ".csv", "text/html": ".html",
}

# The server returns a generic icon INSTEAD of the attachment whenever a preview
# is asked for and the attachment has none (services/explgbk.py:1165, a bare
# `send_file('static/attachment.png')`).  It arrives as an ordinary image/png
# with no marker of any kind, so it cannot be recognised from the response.  The
# skill therefore looks the attachment up first and refuses the preview when the
# record has no `preview_url` -- the only place the difference is visible.
#
# One attachment per invocation, on purpose.  Attachment bytes come from the
# image store, not the logbook database; fanning out over them turns a query into
# a transfer.
ATTACHMENT_MAX_BYTES = 64 * 1024 * 1024


def _find_attachment(session, cred, experiment, entry_id, attachment_id, timeout):
    """The attachment's own record, from the entry that carries it.

    The fetch route takes entry_id AND attachment_id and joins them server-side,
    so the entry has to be read anyway to ask a sensible question.  Reading it
    here also surfaces `preview_url`, which is the only way to know in advance
    that --preview would return the placeholder icon.
    """
    docs = _api(session, cred, R_ELOG_TREE,
                path_params={"experiment_name": experiment, "entry_id": entry_id},
                timeout=timeout)
    if isinstance(docs, dict):
        docs = [docs]
    for doc in docs or []:
        if doc.get("_id") != entry_id:
            continue
        for attachment in doc.get("attachments") or []:
            if str(attachment.get("_id")) == attachment_id:
                return attachment
    return None


def cmd_attachment(args):
    """Fetch ONE attachment to a path the caller named.  Never a side effect."""
    import requests
    cred = resolve_credential(args.auth)
    session = requests.Session()
    session.headers.update(auth_headers(cred))

    record = _find_attachment(session, cred, args.experiment, args.entry_id,
                              args.attachment_id, args.timeout)
    if record is None:
        print("entry %s in %s carries no attachment %s"
              % (args.entry_id, args.experiment, args.attachment_id))
        return 1
    print("experiment  : %s" % args.experiment)
    print("entry       : %s" % args.entry_id)
    print("attachment  : %s   %s" % (args.attachment_id, record.get("name") or "?"))
    print("server type : %s   (recorded at upload; not trusted for the filename)"
          % record.get("type"))
    if args.preview and not record.get("preview_url"):
        print()
        print("REFUSING --preview: this attachment has no preview, and the server")
        print("answers that case with its generic placeholder icon rather than an")
        print("error.  Re-run without --preview for the real bytes.")
        return 1

    params = {"entry_id": args.entry_id, "attachment_id": args.attachment_id}
    if args.preview:
        params["prefer_preview"] = "true"
    started = time.time()
    response = _get(session, cred["prefix"], R_ATTACHMENT,
                    path_params={"experiment_name": args.experiment},
                    params=params, timeout=args.timeout)
    body = response.content
    elapsed = time.time() - started
    ctype = (response.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    print("status      : %d   bytes %d   %.3fs   %s"
          % (response.status_code, len(body), elapsed, ctype))
    disposition = response.headers.get("Content-Disposition")
    if disposition:
        print("disposition : %s" % disposition)
    if response.status_code != 200:
        return 1
    if len(body) > ATTACHMENT_MAX_BYTES:
        print()
        print("REFUSING to save %d bytes: over this skill\'s %d-byte cap."
              % (len(body), ATTACHMENT_MAX_BYTES))
        return 2
    if not args.out:
        print()
        print("Not saved: no --out given.  Writing an attachment to disk is a")
        print("deliberate act, so this skill only does it when you name the path.")
        return 0
    out = args.out
    if os.path.isdir(out):
        out = os.path.join(out, args.attachment_id)
    root, ext = os.path.splitext(out)
    if not ext:
        out = root + ATTACHMENT_EXTENSIONS.get(ctype, ".bin")
    with open(out, "wb") as handle:
        handle.write(body)
    print()
    print("saved       : %s  (%d bytes)" % (out, len(body)))
    print("extension chosen from this skill\'s own type map, not the server\'s string.")
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


# --------------------------------------------------------------------------
# selftest -- three groups, all offline, no credential and no network
# --------------------------------------------------------------------------
#
#   1. the result classifier, on hand-built documents
#   2. the route policy: every mutating and denied route is refused by _get()
#      BEFORE a socket is opened, plus the pin against the vendored upstream list
#   3. every subcommand: it is registered, and every route it calls is still
#      classified read-only
#
# Group 2 is why this file exists in the shape it does.  The refusals must be
# provable without calling the production logbook, because demonstrating them
# live would mean ending a run or closing a shift to show that the skill can.


class _NoHTTPSession(object):
    """A session stand-in that makes any attempted request a test failure.

    _get() checks the route class before it builds a URL, so a correctly refused
    route never reaches this object.  If one ever does, the test says so instead
    of quietly succeeding.
    """

    def get(self, *_args, **_kwargs):
        raise AssertionError(
            "HTTP was attempted for a route that must be refused offline")


def _reference_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, os.pardir, "reference", "explgbk-get-routes.txt")


def _read_reference_routes():
    """The checked-in copy of upstream's GET route list: {rule: methods}."""
    routes = {}
    with open(_reference_path()) as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            methods, _, rule = line.partition("\t")
            routes[rule] = tuple(methods.split(","))
    return routes


# One case per subcommand: the routes it reaches, which the policy must still
# permit.  A policy edit that would break a subcommand fails here rather than in
# front of a user mid-question.
SUBCOMMAND_CASES = [
    ("whoami", [R_EXPERIMENTS]),
    ("scope", [R_EXPERIMENTS, R_NAMES_UPDATED_WITHIN]),
    ("search", [R_SEARCH_ELOG]),
    ("routes", []),
    ("get", []),
    ("entries", [R_ELOG]),
    ("thread", [R_ELOG_TREE]),
    ("tags", [R_ELOG_TAGS]),
    ("logbooks", [R_INSTRUMENT_ELOGS]),
    ("attachment", [R_ATTACHMENT, R_ELOG_TREE]),
]


def _selftest_classifier():
    results = []
    for name, docs, query, want_m, want_c, want_d in SELFTEST_CASES:
        split = classify(docs, query)
        got_m = sorted(d["_id"] for d in split["matches"])
        got_c = sorted(d["_id"] for d in split["context"])
        ok = (got_m == sorted(want_m) and got_c == sorted(want_c)
              and split["suppressed_deleted"] == want_d)
        detail = ""
        if not ok:
            detail = ("\n     wanted matches=%s context=%s deleted=%d"
                      "\n     got    matches=%s context=%s deleted=%d"
                      % (sorted(want_m), sorted(want_c), want_d,
                         got_m, got_c, split["suppressed_deleted"]))
        results.append((ok, name, detail))
    return results


def _selftest_policy():
    results = []
    session = _NoHTTPSession()
    for klass, rule in ROUTE_INVENTORY:
        if klass == "readonly":
            continue
        label = "%s route refused offline: %s" % (klass, rule)
        try:
            _get(session, "ws-jwt", rule,
                 path_params={"experiment_name": "x", "run_num": "1", "entry_id": "e",
                              "job_id": "j", "path": "p", "prjid": "p", "gridid": "g",
                              "sample_name": "s", "insid": "i"})
            results.append((False, label, "\n     _get() returned instead of raising"))
        except ValueError as exc:
            expected = "CHANGES SERVER STATE" if klass == "mutating" else "refusing to call"
            ok = expected in str(exc)
            results.append((ok, label,
                            "" if ok else "\n     raised, but not with the %s reason: %s"
                            % (klass, exc)))
        except AssertionError as exc:
            results.append((False, label, "\n     %s" % exc))

    # The parameter-level refusal.  One read-only route carries a query parameter
    # that changes shared server-side state, so route class alone is not a fine
    # enough guarantee, and the test has to prove the finer one too.
    for rule, refused in sorted(REFUSED_PARAMS.items()):
        for name in sorted(refused):
            label = "parameter refused offline: %s?%s" % (rule, name)
            try:
                _get(session, "ws-jwt", rule, params={name: "1"})
                results.append((False, label, "\n     _get() returned instead of raising"))
            except ValueError as exc:
                ok = "refusing to send" in str(exc)
                results.append((ok, label,
                                "" if ok else "\n     raised for another reason: %s" % exc))
            except AssertionError as exc:
                results.append((False, label, "\n     %s" % exc))

    # The pin.  A deny-list model is permissive by construction: a future explgbk
    # release adding a 28th mutating GET would land inside the allowed set in
    # silence.  This is the tripwire, and it is the reason the upstream list is
    # vendored under reference/ instead of being trusted from memory.
    label = "inventory pin: vendored routes == reference/explgbk-get-routes.txt"
    try:
        reference = _read_reference_routes()
        vendored = set(ROUTE_CLASS)
        missing = sorted(set(reference) - vendored)
        extra = sorted(vendored - set(reference))
        ok = not missing and not extra
        detail = ""
        if not ok:
            detail = ("\n     %d upstream route(s) absent from the inventory: %s"
                      "\n     %d inventory route(s) absent upstream: %s"
                      % (len(missing), ", ".join(missing[:5]) or "-",
                         len(extra), ", ".join(extra[:5]) or "-"))
        results.append((ok, label, detail))
    except (OSError, IOError) as exc:
        results.append((False, label, "\n     cannot read %s: %s" % (_reference_path(), exc)))
    return results


def _selftest_subcommands():
    results = []
    parser = build_parser()
    registered = set()
    for action in parser._subparsers._group_actions:              # noqa: SLF001
        registered.update(action.choices)
    for name, rules in SUBCOMMAND_CASES:
        label = "subcommand %-11s registered, and its routes still read-only" % name
        problems = []
        if name not in registered:
            problems.append("not registered in the parser")
        for rule in rules:
            klass = ROUTE_CLASS.get(rule)
            if klass != "readonly":
                problems.append("%s is classified %s" % (rule, klass))
        if name == "routes":
            # The summary line is a done-condition of this skill, so it is tested
            # rather than trusted: the three counts must partition the inventory.
            counts = {}
            for klass, _rule in ROUTE_INVENTORY:
                counts[klass] = counts.get(klass, 0) + 1
            if sum(counts.values()) != len(ROUTE_INVENTORY):
                problems.append("class counts do not partition the inventory")
            if counts.get("denied") != len(DENIAL_REASONS):
                problems.append("%d denied routes but %d denial reasons"
                                % (counts.get("denied", 0), len(DENIAL_REASONS)))
        if name == "get":
            # The tail-resolver must not become a way around the policy: a
            # mutating route still resolves, and _get() still refuses it.
            if _resolve_rule("runs") != "/lgbk/<experiment_name>/ws/runs":
                problems.append("'runs' does not resolve to the runs route")
            mutating_rule = _resolve_rule("end_run")
            if ROUTE_CLASS.get(mutating_rule) != "mutating":
                problems.append("'end_run' does not resolve to a mutating route")
            try:
                _get(_NoHTTPSession(), "ws-jwt", mutating_rule,
                     path_params={"experiment_name": "x"})
                problems.append("get resolved a mutating route and did not refuse it")
            except ValueError:
                pass
        results.append((not problems, label,
                        "" if not problems else "\n     " + "; ".join(problems)))
    return results


def cmd_selftest(_args):
    """Check the classifier, the route policy and the subcommands.  All offline."""
    groups = [
        ("result classifier", _selftest_classifier()),
        ("route policy (refusals proven without any HTTP call)", _selftest_policy()),
        ("subcommands", _selftest_subcommands()),
    ]
    total = failures = 0
    for title, results in groups:
        print("-- %s" % title)
        for ok, name, detail in results:
            total += 1
            failures += 0 if ok else 1
            print("%s %s%s" % ("PASS" if ok else "FAIL", name, detail))
        print()
    print("%d of %d cases passed" % (total - failures, total))
    return 1 if failures else 0


def build_parser():
    """The CLI, built separately so `selftest` can inspect it without running it."""
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

    rt = sub.add_parser("routes",
                        help="the vendored explgbk route inventory and what this "
                             "skill will and will not call (offline)")
    rt.add_argument("--only", choices=["readonly", "mutating", "denied"], default=None,
                    help="print just one class")
    rt.set_defaults(func=cmd_routes)

    gt = sub.add_parser("get",
                        help="call one read-only route by name -- the long tail the "
                             "named subcommands do not cover")
    add_global_flags(gt)
    gt.add_argument("route",
                    help="route rule, or its unambiguous tail (e.g. 'runs', "
                         "'run_tables', 'ws/instruments')")
    gt.add_argument("--experiment", default=None,
                    help="fills <experiment_name> for a per-experiment route")
    gt.add_argument("--path", action="append", default=None, metavar="KEY=VALUE",
                    help="fill another path parameter, e.g. --path run_num=45")
    gt.add_argument("--param", action="append", default=None, metavar="KEY=VALUE",
                    help="query parameter, repeatable")
    gt.add_argument("--limit", type=int, default=20,
                    help="print at most N list elements (default 20)")
    gt.add_argument("--chars", type=int, default=6000,
                    help="truncate the printed JSON at N characters (0 = no limit)")
    gt.add_argument("--suppress-deleted", dest="suppress_deleted", action="store_true",
                    help="drop logically-deleted documents from a list result")
    gt.add_argument("--timeout", type=int, default=120)
    gt.set_defaults(func=cmd_get)

    en = sub.add_parser("entries",
                        help="the newest entries of one logbook, capped and with "
                             "deleted entries suppressed")
    add_global_flags(en)
    en.add_argument("experiment")
    en.add_argument("--limit", type=int, default=20,
                    help="entries to print, newest first (default 20, cap %d)"
                         % ENTRIES_CAP)
    en.add_argument("--chars", type=int, default=EXCERPT_CHARS)
    en.add_argument("--timeout", type=int, default=300)
    en.set_defaults(func=cmd_entries)

    th = sub.add_parser("thread",
                        help="one entry with its complete thread, as the server "
                             "walks it")
    add_global_flags(th)
    th.add_argument("experiment")
    th.add_argument("entry_id")
    th.add_argument("--chars", type=int, default=EXCERPT_CHARS)
    th.add_argument("--timeout", type=int, default=120)
    th.set_defaults(func=cmd_thread)

    tg = sub.add_parser("tags", help="the tag vocabulary of one logbook")
    add_global_flags(tg)
    tg.add_argument("experiment")
    tg.add_argument("--timeout", type=int, default=120)
    tg.set_defaults(func=cmd_tags)

    lb = sub.add_parser("logbooks",
                        help="the standing operational logbooks recency cannot reach")
    add_global_flags(lb)
    lb.add_argument("--experiment", default=None,
                    help="instead ask which logbooks this experiment posts into")
    lb.add_argument("--chars", type=int, default=6000)
    lb.add_argument("--timeout", type=int, default=120)
    lb.set_defaults(func=cmd_logbooks)

    at = sub.add_parser("attachment",
                        help="fetch ONE attachment to a path you name")
    add_global_flags(at)
    at.add_argument("experiment")
    at.add_argument("entry_id", help="the eLog entry that carries the attachment")
    at.add_argument("attachment_id",
                    help="the attachment's _id, as it appears in that entry's "
                         "attachments array")
    at.add_argument("--out", default=None,
                    help="save here.  Without it nothing is written: putting an "
                         "attachment on disk is a deliberate act, never a side "
                         "effect of reading")
    at.add_argument("--preview", action="store_true",
                    help="ask for the preview rendition instead of the original")
    at.add_argument("--timeout", type=int, default=300)
    at.set_defaults(func=cmd_attachment)

    return parser


def main():
    args = build_parser().parse_args()
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
