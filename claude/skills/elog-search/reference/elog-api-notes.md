# LCLS eLog API notes

Background for anyone extending `elogsearch.py`. Everything here is about *reading*.

## Host and prefixes

Base host `https://pswww.slac.stanford.edu`, SLAC-internal only. The path shape has a
doubled `lgbk`:

```
{prefix}/lgbk/lgbk/ws/{call}                     global calls
{prefix}/lgbk/lgbk/{experiment_id}/ws/{call}     experiment-scoped calls
                                                 -- the `_id`, never the `name`
```

| Prefix | Authentication | Observed unauthenticated response |
|---|---|---|
| `ws` | none | `403` on any route needing an identity; anonymous routes work |
| `ws-kerb` | SPNEGO / Kerberos | `401 WWW-Authenticate: Negotiate` |
| `ws-jwt` | Bearer token | `401 {"error":"Unauthorized"}`; `{"error":"Invalid token"}` for a malformed bearer |
| `ws-auth` | HTTP Basic, **shared hutch operator accounts** | `401 Basic realm` |
| `ws-token` | browser SSO | `302` to vouch.slac.stanford.edu |

`ws-auth` is deliberately unused by this skill: those are shared operator accounts, so a
result set obtained through one is somebody else's read access wearing your name, and the
accounts are added to and removed from experiments automatically as beam time starts and
ends, which no user can reproduce.

The `ws-jwt` ingress validates tokens itself, before the application is reached. It does
trust a Dex token minted by `s3df login`: confirmed on 2026-08-14, where `--auth jwt`
authenticated as the same account and returned the same readable-experiment count as the
Kerberos path through `ws-kerb` — 2240 on that date, 2245 when re-measured on 2026-08-28.
The count moves; what matters is that the two mechanisms agree.

## Kerberos: still working, deliberately undocumented

`ws-kerb` is tried only after the token, and SKILL.md does not mention it. That is a
documentation decision, not a deprecation: Kerberos is expected to be phased out, it
cannot be made to work in a container, and a skill whose first-line instructions send
people to `kinit` teaches a habit with a shelf life. The code path stays because a ticket
is a real credential and nobody holding one should be locked out — `--auth kerberos`
forces it, and `whoami` will report `mechanism: kerberos` when the fallback fires.

What that path knows, for whoever maintains it:

* Own caches only. Every candidate is `lstat`ed before it is opened: not a regular file,
  or `st_uid != getuid()`, and it is dropped — so a foreign cache in world-listable
  `/tmp` never produces a permission error, and a symlink pointing at one is refused
  rather than followed.
* **The default cache is often the stale one.** An ssh login with GSSAPI delegation
  drops a fresh ticket in a suffixed sibling such as `/tmp/krb5cc_18262_sMq1XS` and
  leaves `KRB5CCNAME` unset, so a resolver reading only the default reports "no
  credential" while a valid ticket sits beside it. `klist -l` and `klist -A` do not
  help: with a FILE-type default they only show the cache already selected.
* Validity is `klist -s`, never a parsed clock. `klist` prints local times with no zone
  and no locale marker; comparing them to your own clock is guessing.
* Searched, for the invoking uid only: `$KRB5CCNAME`, `/tmp/krb5cc_<uid>`,
  `/tmp/krb5cc_*`, `/run/user/<uid>/krb5cc*`, `~/.krb5cc*` — the last using the same
  owned-`$HOME` rule as the token paths. Tickets last about 24 h.
* Candidates are sorted most-distant-expiry first, and the losers ride along as
  `alternates`: "the cache holds a live TGT" and "the GSS library can build a header
  from it" are different tests, and the right answer when the second fails is the next
  cache, not an error.

## The application never authenticates

`flask_authnz.FlaskAuthnz.get_current_user_id` reads a proxy header
(`REMOTE-USER` by default); the reverse proxy in front of each prefix authenticates and
sets it. Authorization is then `has_slac_user_role(user, 'LogBook', role, experiment,
instrument)`, cached per role and experiment in the Flask session.

Consequence worth knowing: the authorization behaviour is identical whichever
authenticated prefix you use, so moving from Kerberos to JWT changes header construction
and nothing else.

## The route model

The skill calls 87 routes, and the enumeration is not here: it lives in the script's
vendored `ROUTE_INVENTORY` (printable with `elogsearch.py routes`) and in
`reference/explgbk-get-routes.txt`. What follows is the model those lists implement.

**The include criterion is "does not mutate eLog state", never "is an HTTP GET."**
explgbk answers GET on routes that end and start runs, close shifts, cross-post entries,
subscribe and unsubscribe people from email, toggle collaborator roles, kill and delete
analysis jobs, and force experiment-cache rebuilds. A skill that allowed every GET could do
all of that to the production logbook, live, during beam time.

So every GET-accepting route is classified into exactly one of three classes. In
explgbk@e5484aa there are **117** GET rules: **87 readonly**, **26 mutating**, **4 denied**.

Those 117 are the rules of the **web-service blueprint** (`services/explgbk.py`,
`@explgbk_blueprint.route`), which is the whole of the JSON API and the only thing this
skill calls. The application registers a second blueprint in `start.py`: `pages.py`'s
`pages_api`, 15 more GET rules that render HTML for the browser UI (`/`, `/status`,
`/lgbk/ops`, `/lgbk/logout`, `/lgbk/<exp>/<tabname>` and so on). They are deliberately
absent from the inventory, and `_get()` refuses them as unknown routes rather than
classified ones, so nothing can reach them by accident.

Worth knowing about two of them if you ever do extend the skill that way. `pages.py`
contains **no write of any kind** — no Mongo call, no Kafka publish, no outbound POST — so
none of the 15 mutates. But `/lgbk/logout` is a GET that hands back a 302 to
`vouch.slac.stanford.edu/logout`, which ends the caller's SSO session if the client follows
it; it belongs with `ext_preview` as a route to refuse rather than classify read-only. This
skill does not follow redirects, so it could not complete that sequence even if the route
were reachable.

| Denied route | Why |
|---|---|
| `<exp>/ws/generate_arp_token` | mints a bearer credential |
| `<exp>/ws/ext_preview/<path:path>` | `302`s to an external host, setting a cookie that holds an MD5 of the experiment name plus a server-side secret; the same bytes come from `attachment?prefer_preview=true` |
| `ws/lookup_experiment_in_urawi` | reaches URAWI, an external system, not the logbook |
| `ws/empty` | returns `{}` — a convenience for the web UI's JavaScript with nothing to read |

**Enforcement is one function.** Every HTTP call the script can make goes through `_get()`,
which looks up the route's class *before* it builds a URL or opens a socket. That is why
`selftest` can prove each mutating and denied refusal offline, with no credential and no
request to the server.

**URL shape** is `BASE` + `/` + prefix + `/lgbk` + the route rule exactly as flask declares
it, so the doubled `lgbk` above is the rule's own first segment:

```
https://pswww.slac.stanford.edu/ws-jwt/lgbk  +  /lgbk/<experiment_name>/ws/info
```

Path parameters are substituted and URL-quoted at that point. A rule left with an
unsubstituted `<...>` raises — it is never sent as a literal.

**One refusal is finer-grained than a route.** `/lgbk/ws/experiments` is read-only and is
the authorization boundary itself, so it has to stay callable. But its `legacy_cutoff` query
parameter reaches `cat.set_legacy_cutoff()` on the module-level categorizer singleton
(`services/explgbk.py:274-347`), rebinding how *that worker process* buckets the experiment
list for every later request from anybody. Nothing is persisted and a worker restart clears
it, so the route is allowed and the parameter is refused.

**Why the pin exists.** `reference/explgbk-get-routes.txt` is a checked-in copy of upstream's
GET route list, and `selftest` fails when the script's vendored inventory disagrees with it.
A deny-list model has exactly one weakness — a route nobody classified is a route nobody
refused — so a future explgbk release adding a 27th mutating GET would otherwise land inside
the permitted set in silence. The pin converts that into a failing test.

**`ws/api_endpoints` is a docstring filter, not an inventory.** It returned 96 endpoints, 66
of them GET-accepting, against the 117 web-service GET rules in the source; every one of the 51 absent rules
maps to a view function with no `__doc__`. Use it to read a route's documentation, never to
learn what exists.

### Notable routes and their traps

Not the whole 87 — the ones whose behaviour surprises a reader.

| Route | Trap |
|---|---|
| `<exp>/ws/elog` | returns the whole logbook. No server-side limit, no pagination |
| `<exp>/ws/attachment` | takes `entry_id` **and** `attachment_id`; a missing preview is answered with a generic icon that is an ordinary `image/png` carrying no marker, so it cannot be told from a real one after the fact — check `preview_url` on the record first |
| `<exp>/ws/workflow/<job_id>/<path:action>` | proxies only `job_statuses`, `job_details`, `job_log_file` (`405` otherwise); its status is the LOGBOOK's, not the job daemon's — the body can be a 404 page under a 200 — and it `500`s when the job's `def.location` is absent from that experiment's `dm_locations` |
| `ws/global_roles` | gated on `manage_groups`; ordinary readers get `403` |
| `ws/search_experiment_info` | a MongoDB `$text` search over whole stemmed words, so `crystallography` matches and the instrument prefix `cxi` does not |

## search_elog semantics

Parameters: `search_text`, `run_num`, `start_run_num`, `end_run_num`, `start_date`,
`end_date` (`%Y-%m-%dT%H:%M:%S.%fZ`), `tag`, `_id`. Inside `search_text`, a `t:` prefix
searches tags and `x:` is a regex.

* **No limit and no pagination.** A broad query returns every matching document.
* **The only text index is `[('content','text'), ('title','text')]`.** Author and tag are
  not indexed; the server special-cases a `search_text` that exactly equals a known author
  or a known tag before falling back to text search. Measured behaviour of the three paths:
  content and title are case-insensitive, OR-of-terms and **stemmed** (Snowball English —
  `aligned` matches "alignment", `moved` matches "moving"); tags are **case-sensitive**,
  exact and not tokenised (`SCREENSHOT` != `screenshot`, `SHIFT_GOALS` is not found by
  `GOALS`); author is exact. The `x:` regex prefix is **case-sensitive** — it is the
  server's internal miss-fallback regex that is case-insensitive, which is a different
  mechanism.
* **An empty `search_text` returns the entire collection** — 2953 entries and 7.2 MB from
  one instrument logbook.
* **A miss triggers a fallback regex scan, and it is observable.** When the `$text` query
  returns nothing the server re-queries with a case-insensitive unanchored `$regex`, which
  is a collection scan. Measured 2026-08-14 (TTFB, medians of 3): on ordinary
  per-experiment logbooks a miss costs 0.8-1.3x a hit, i.e. nothing — but on the 14
  standing operational logbooks it costs **2.1-5.4x**, worst 0.29 s on XPP_Instrument
  against a 0.057 s hit. Absolute cost stays under 0.3 s throughout.
  An earlier round of this work measured only experiments ranked by `run_count` and
  concluded misses were free. The standing logbooks all have `run_count` 0, so that
  ranking structurally excluded every collection where the penalty lives. Beware any
  "largest experiment" ranking built on `run_count`, and beware sizing a collection by how
  many documents a common term returns: "run" undercounts AMO_Instrument 12.9x
  (229 returned against 2953 held) and Sample_Delivery_System 12.7x.
* **The regex is a FALLBACK, not a union.** Tested directly: xpp101605526 contains base64
  documents whose raw bytes hold "scan", yet a search for `scan` returned 171 documents,
  all genuine word matches, with zero bytes of base64 in the returned set — those
  documents were not returned. The same collection searched for `clog`, which has no
  genuine matches, returned 3 documents matching only inside base64. So the regex runs
  only when the text query finds nothing. (Not excluded: a result-count threshold rather
  than strict zero would look identical in this data.)
* **Whole documents come back**, not excerpts, so there is no second fetch per hit.
  Content is **HTML**, despite `content_type` reading `TEXT`: image-bearing entries are
  `<p><img src="data:image/png;base64,...">` and can run to hundreds of kilobytes of
  base64. Strip tags and data URIs before matching or excerpting.

Entry document fields: `_id`, `insert_time`, `relevance_time`, `author`, `content`,
`content_type`, and optionally `title`, `tags`, `run_num`, `shift`, `attachments`,
`root`, `parent`, `post_to_elogs`, `jira_ticket`, `deleted_by`, `deleted_time`.
Cross-posted copies also carry `src_id` and `src_expname`.

Responses are wrapped: `{"success": true, "value": [...]}`.

A nonexistent experiment name returns `404`.

## Two behaviours that will mislead a reader

**Logical deletion.** The delete route sets `deleted_by` and `deleted_time`; no read query
filters on either, and the web UI hides them client-side. Anything reading the API
directly must suppress them itself or it will quote back entries that were deliberately
removed.

**Thread hydration.** After matching, `search_elog_for_text` walks each hit's `root` and
`parent` until closure and adds those ancestors to the result set. They do not match the
query and are otherwise indistinguishable from hits. A root entry has no `root` field of
its own — it is identified by *other* documents pointing at it — so an ancestor is
detected as: a returned document referenced by another returned document's `root`/`parent`
that does not itself match the query.

## Corpus shape

Each experiment is its own MongoDB database with an `elog` collection inside it. That is
the architectural reason no cross-experiment search route exists, and why searching
"the eLog" is a fan-out the client has to scope.

Beyond the per-experiment logbooks there are instrument-level logbooks (they appear in
`ws/experiments` alongside experiments — `AMO_Instrument` and friends) and site-spanning
logbooks such as the sample-delivery log, resolved through `get_instrument_elogs`. They
hold the operational content that spans experiments and are often what someone is
actually looking for, and **this skill can search them**: name them with `--experiments`,
in either spelling.

Fourteen have a `name` that differs from their `_id` by containing a space
(`Sample Delivery System` versus `Sample_Delivery_System`), and the spaced form in a URL
path returns HTTP 500 — so a client that builds paths from `name` rather than `_id`
silently loses exactly these fourteen, which are the most valuable ones.

Most of the corpus is dormant — the archive spans about fifteen years — so "search
everything" mostly means "scan fifteen years of archives", which is a different question
from "what did the last shift say".

## Rate limits

30 sequential anonymous GETs to a trivial route took 0.87 s (~34 req/s) with no `429`.
That was the anonymous prefix against a trivial route: an authenticated `search_elog`
does real database work, so the per-request *cost* is far higher even where the request
*budget* looks unpoliced. Published guidance for polling loops is "every few seconds or
slower is fine". This skill fans out at a fixed concurrency of 4.
