---
name: elog-search
description: Search the LCLS eLog (pswww logbook) across experiments, read-only, using the invoking user's own S3DF token. Use when asked what the elog / logbook says about a topic, error, sample, detector or shift, or to find eLog entries by text, tag, run or date. Always reports which experiments it searched and why.
---

# elog-search

Search the LCLS eLog live, as **yourself**, read-only, and always say what was searched.

```bash
SKILL_DIR=~/.claude/skills/elog-search   # wherever this SKILL.md lives
$SKILL_DIR/scripts/elogsearch.py whoami            # who am I, and what may I read?
$SKILL_DIR/scripts/elogsearch.py selftest          # check the classifier, no credential needed
$SKILL_DIR/scripts/elogsearch.py scope --days 180  # which experiments would a search cover?
$SKILL_DIR/scripts/elogsearch.py search "clog"     # search that scope
$SKILL_DIR/scripts/elogsearch.py search "clog" --instrument cxi
$SKILL_DIR/scripts/elogsearch.py search "timing" --experiments mfxlv4920,cxilv4418
```

Set `SKILL_DIR` once and the commands run from any directory. Every example above was run
and returns rows: `search "clog" --instrument cxi --days 180` gave 11 entries across 2
experiments on 2026-08-13.

**Exit codes**: `0` success, including a legitimate zero hits · `1` nothing was searched
(the scope rule selected no experiments) · `2` refused (empty query, invalid regex,
unreadable date, unknown instrument, negative `--limit`, over the cap) · `3`
`CREDENTIAL BLOCKED`. Note `scope` exits `0` when it selects nothing, where `search`
exits `1`.

`reference/elog-api-notes.md`, next to this file, documents the underlying API — endpoint
prefixes, the entry document shape, and the server-side search semantics this skill has to
work around. Read it before extending the script.

## The one thing to understand before using this

**There is no eLog-wide search.** Each experiment is its own MongoDB database and the
server's `search_elog` route is per-experiment. A "search the eLog" request is therefore
a fan-out: one HTTP request per experiment, over a set of experiments that *this skill
chooses*. Scope is an engineering decision, not something the server decides for you.

So every result set here carries a **scope line** stating how many experiments were
searched, out of how many you may read, and how that set was chosen:

```
SCOPE: searched 111 of 2240 experiments readable as cwang31 (ws-jwt)
  selection: active within 180 days (last run start) INTERSECT readable by you
  caveat   : recency is keyed on the last RUN start time, so an experiment with recent
             eLog activity but no new runs is not in this set
  skipped  : none -- every experiment in scope answered
```

Never restate a count from that line as a property of the eLog. `readable as <you>` is a
property of *your* roles: a colleague running the identical command may search a
different number of experiments and get different results.

## Scope: what it searches by default, and what it refuses

| Selection | How to ask for it |
|---|---|
| Default: experiments active in the last 180 days **and** readable by you | `search "text"` |
| A different activity window | `search "text" --days 30` |
| One instrument | `search "text" --instrument mfx` |
| Named experiments (bypasses the recency rule) | `search "text" --experiments a,b,c` |
| The 14 standing operational logbooks | `search "text" --logbooks` |
| Preview the set without searching | `scope --days 180`, `scope --logbooks` |

The fan-out is capped at **150 experiments** per invocation. Past that the skill refuses
and tells you how to narrow. `--cap N` raises it if you genuinely mean to.

**A query that misses is the expensive one**, and where it is expensive is not where you
would guess. When the full-text query finds nothing, the server re-runs it as an unanchored
regex over the whole collection. Independently measured on 2026-08-14 across 12 experiments,
3 repeats each, comparing server time (TTFB) so the body transfer does not confuse it:

| Kind of logbook | Miss versus hit | Worst observed |
|---|---|---|
| Ordinary per-experiment logbooks | 0.8–1.3× — no penalty | 0.13 s (`diamcc14`, 2792 entries) |
| The 14 standing operational logbooks | **2.1–5.4×** | 0.29 s (`XPP Instrument`) |

An earlier round of this work concluded misses were free everywhere. That was wrong, and it
was wrong for an instructive reason: it ranked experiments by `run_count` to find the worst
case, and the standing logbooks all have `run_count` 0, so the ranking excluded every one of
the collections where the penalty actually lives.

The cost is real but small in absolute terms — no miss exceeded 0.3 s. So the cap is not
protecting *you* from a slow command. It is there because each request is a database query
against the production logbook the hutches depend on during beam time, because a sweep is
mostly *misses* and misses are what make the server scan, and because roughly fifteen years
of dormant archives mostly return noise. Narrowing is a relevance decision at least as much
as a load one.

The often-quoted figure of ~27 s to sweep all 2240 is an **extrapolation** from 40
experiments drawn uniformly at random (0.486 s at concurrency 4). No full sweep has been
run, so nothing here rules out throttling that would only appear hundreds of calls in.

If nothing matches, the skill reports zero hits **within the stated scope**. It never
silently widens the search and then tells you it "looked everywhere".

## Instrument and site-spanning logbooks

Fourteen of the 2240 are not experiments at all but standing operational logbooks —
`Sample Delivery System`, `MEC Laser System`, `Detector Group`, `AMO Instrument`,
`NEH Laser Hall Laser Systems` and others. They hold the cross-experiment operational
content that is often what someone is actually looking for, and they are searchable here:

```bash
$SKILL_DIR/scripts/elogsearch.py search "gas jet alignment" --logbooks
$SKILL_DIR/scripts/elogsearch.py search "gas jet" --experiments "Sample Delivery System"
```

They are the one place where the display name and the URL key differ (`Sample Delivery
System` versus `Sample_Delivery_System`). Either spelling works — the skill resolves it —
but note that putting the *spaced* name straight into an API path returns HTTP 500, so a
script that uses the `name` field rather than `_id` silently loses exactly these fourteen.

All fourteen: `AMO/CXI/DIA/MEC/MFX/SXR/XCS/XPP Instrument`, `Detector Group`,
`FEL Simulator`, `MEC Laser System`, `MEC Laser Daily Ops`, `NEH Laser Hall Laser Systems`,
`Sample Delivery System`. Reach them all at once with **`--logbooks`**; the default recency
rule can never select them, because it keys on the last *run* and they have no runs, and
`--instrument OPS` matches nothing for the same reason.

They are also heavily threaded. A search of `Sample Delivery System` for `laser` returned
582 entries, of which 275 were labelled hydrated thread roots and 3 suppressed as deleted:
nearly as much context as matches.
That is honest output, not a bug — the counts say so plainly, and `--hide-context` drops
them if you only want hits.

## What it filters, and what it tells you it filtered

Read `entries shown as matches` precisely: it means **returned by the server, not deleted,
and not detected as a thread ancestor**. It does not mean "contains your word". The server
decides what matched, and it can match on a tag, an author, or a stemmed form.

Sometimes it matches on nothing readable at all, and the skill says so:

```
  of those, with no visible match: 3 (server matched inside embedded image data)
```

Those entries carry `[server matched this, but not in its readable text]`. The cause is
measurable: when the full-text query finds nothing in an experiment, the server falls back
to a case-insensitive unanchored regex over the *raw* content — and an inline screenshot is
hundreds of kilobytes of base64, in which a search for `clog` finds `ClOg`, `CLOG` and
`clOG`. Three such entries came back for `clog` in `xpp101605526`, all matching only inside
image payloads. They are real entries, genuinely returned; they are simply not about your
query. Treat that count as a signal your term missed the experiment entirely.

Entry content is **HTML**, and image-heavy entries are mostly `<img src="data:...base64">`.
The skill strips tags and data URIs before matching and before excerpting, and centres the
excerpt on the first matching term rather than truncating from the start — otherwise an
entry that begins with an inline screenshot shows a screenful of base64 and no prose.
`--chars N` widens the excerpt (default 400); `--limit N` sets how many entries are printed
(default 20, newest first, across the whole scope); `--timeout N` sets the per-experiment
HTTP timeout.

Every run ends with four counts:

```
COUNTS
  entries returned by the API   : 137
  entries shown as matches      : 118
  entries suppressed as deleted : 10
  entries labelled thread context: 9
```

**Deleted entries.** Deletion in this eLog is *logical*: the delete route sets
`deleted_by` and `deleted_time` on the document and no read query filters on it, so
entries somebody deliberately removed still come back from a search. The web UI hides
them client-side. This skill suppresses any document carrying `deleted_by` and counts
what it suppressed, so a removed entry is never quoted back at you as current.

**Thread ancestors.** After matching, the server walks each hit's `root` and `parent`
links and pulls those ancestors into the result set until closure. They arrive
indistinguishable from genuine hits and *do not match your query*. This skill labels
them `[thread context -- did not match the query]` rather than hiding them: they are the
message the matching reply was written under, which is usually what you actually want to
read. `--hide-context` drops them from the output; they stay in the counts.

The rule used: a hydrated ancestor is a returned document whose `_id` is referenced by
another returned document's `root` or `parent` **and** which does not itself contain the
query text. The rule only ever demotes a document that something else in the result set
points at, so a document matched through MongoDB's word stemming (`running` for `run`)
is never mistaken for context.

## Credential: yours, or none

The skill authenticates with **your own S3DF token** (`ws-jwt`) — the one
`/sdf/sw/s3df-cli/bin/s3df login` writes. There is **no shared-account fallback at any
step**: a skill that quietly used an operator account would report somebody else's read
access as yours.

Paths come from **`S3DF_TOKEN_FILE`** and **`S3DF_TOKEN_META`**, the two variables that
tool documents in its own `--help`, defaulting to `~/.s3df-access-token` and
`~/.s3df-token.json`. Tokens last 12 h, and an **expired token counts as no token**: the
metadata records `expires_at`, so this is decided outright rather than guessed, and
`whoami` prints a real expiry instead of `unknown`.

Home is resolved from **`$HOME` when `$HOME` is a directory you own**, and from the
passwd database otherwise. Ownership is the test that matters: it rejects an inherited
`$HOME` pointing into somebody else's tree, which is the sudo and batch case worth
guarding against, while still working inside a container whose home is a scratch path
the passwd database knows nothing about. Resolving from passwd unconditionally would
disagree with `s3df login`, which writes from `$HOME` — a reader that resolves
differently from its writer cannot find what the writer wrote. **In a container this
means no bind mount is needed**: copy the skill in and export the two variables.

A credential file that is group- or world-readable is **refused**, and the message names
the `chmod 600` that fixes it. Tokens are never printed, logged or echoed.

The skill will not authenticate on your behalf. A *first* `s3df login` needs you at a
browser; an expired token is cheaper, renewing from the stored refresh token with no
browser at all. When the skill finds nothing usable it prints `CREDENTIAL BLOCKED` and
the exact command for you to run:

```
/sdf/sw/s3df-cli/bin/s3df login      # S3DF OAuth2 token, 12 h
```

### Never announce a missing credential you have not observed

**Do not tell the user to log in unless a command you actually ran just failed on the
credential.** Most users on an S3DF node already hold a usable credential, and being told
to redo setup they never needed is worse than useless. If you are unsure whether auth
works, run one cheap command and read the output:

```bash
scripts/elogsearch.py whoami
```

An identity and a non-zero experiment count means auth is fine — proceed with the real
query. Only a command that exited with `CREDENTIAL BLOCKED` makes the setup instructions
relevant, and when that happens, quote the error you actually got.

If `whoami` reports a `mechanism` other than `jwt`, that is a working fallback for hosts
configured differently. It is not a problem and needs no action from you: report the
results, not the mechanism.

Run scripts with **`uv`**, which the shebang does for you (`#!/usr/bin/env -S uv run
--script`). The system `python3` on some SLAC login nodes is too old, and the script
declares its own dependencies (`requests`, `lcls-krtc`) in a PEP 723 header that only uv
reads.

## Read-only by construction

Every HTTP call this skill can make goes through one function, `_get()`, and that function
refuses any route the vendored inventory does not classify **read-only**. The inventory
covers every GET-accepting route the logbook service exposes, classified by **effect, not
by HTTP method** — because explgbk answers GET on routes that end runs, close shifts,
cross-post entries, subscribe people to email, toggle collaborator roles, kill analysis
jobs and force cache rebuilds. A skill that allowed "any GET" could do all of that to the
production logbook during beam time.

```bash
$SKILL_DIR/scripts/elogsearch.py routes            # the whole inventory and why
$SKILL_DIR/scripts/elogsearch.py routes --only denied
```

The last line of `routes` is the summary, and it is what to quote when someone asks what
this skill is allowed to do. The three classes are:

| class | meaning |
|---|---|
| **read-only** | callable |
| **mutating** | accepts GET and changes server state — refused, always |
| **denied** | read-only by the letter of the rule, refused anyway: it leaves the logbook, mints a credential, or has nothing to read |

The four **denied** routes are `generate_arp_token` (mints a bearer credential),
`ext_preview` (302s to an external host with a secret-derived cookie), `lookup_experiment_in_urawi`
(reaches an external system) and `empty` (returns `{}`).

`selftest` proves the refusals **offline**: it asserts that `_get()` raises for every
mutating and denied route before any socket is opened. That is deliberate — demonstrating
these refusals against the live server would mean ending a run to show that the skill
cannot end a run.

`selftest` also **pins the inventory**. A deny-list model is permissive by construction: a
future logbook release that added a new mutating GET would fall inside the allowed set in
silence. So a copy of the upstream route list is checked in at
`reference/explgbk-get-routes.txt`, and the pin case fails when the script's inventory and
that file disagree. If it fails, re-read the new routes' handlers before touching the
inventory.

### Writing to disk

Entry **content is never written to disk as a side effect of searching** — not cached, not
logged, not spilled into a scratch file while a search runs. The one deliberate exception
is `attachment --out PATH`: fetching an attachment to a path the user named is the thing
the user asked for, not a side effect, and without `--out` nothing is written at all. The
saved file's extension comes from this skill's own type map, never from the `type` string
the server returns, because that string is whatever the uploader's browser claimed.

Only experiment metadata (names, instruments, dates) is cached, at mode 0600 with a 6 h
TTL, in `$XDG_CACHE_HOME/elog-search/experiments.json` — falling back to
`~/.cache/elog-search/experiments.json` only when `XDG_CACHE_HOME` is unset, which on S3DF
it usually is not. `--refresh` re-fetches it.

### Load rules

The logbook is production and live during beam time, so these are limits, not preferences:

* **One attachment or workflow-proxy call at a time.** Never fan out over them. Attachment
  bytes come from the image store rather than the logbook database, and the workflow proxy
  makes an outbound call to the job daemon; both are far heavier than a logbook query.
* **`CONCURRENCY = 4` and `DEFAULT_SCOPE_CAP = 150` are measured limits and are not
  exposed as flags.** Do not raise them, and do not sweep all ~2240 experiments: a full
  sweep is a load event, not a query.
* **`entries` caps client-side.** The whole-logbook route has no server-side limit, so the
  skill applies its own.

## Search syntax

`search_text` goes to the server as-is. The server indexes `content` and `title` only:

**Several bare words mean OR, not a phrase.** MongoDB's `$text` matches any term, stemmed,
so `jet clog` returns entries that say only "jet": across the 113-experiment default scope
it gave 966 matches in 44 experiments, mostly about jets generally. **Quote it** to get the
conjunction — `"jet clog"` gave 2.

| Form | Meaning | Case |
|---|---|---|
| `jet clogged` | full-text over content and title, stemmed, **any** term (OR) | insensitive |
| `"jet clog"` | that exact phrase — the precise mode, and usually what you want | insensitive |
| `t:DAQ` | entries carrying exactly the tag `DAQ` | **sensitive** |
| `x:[Jj]et.*clog` | regex over content | **sensitive** |
| an exact author name | entries by that author | sensitive |

Two of those are easy to get wrong, because only the full-text one is case-insensitive:

* **`x:` regex is case-sensitive.** `x:jet.*clog` misses "Jet clogged". Write
  `x:[Jj]et.*clog`. (What *is* case-insensitive is the server's internal fallback regex on
  a full-text miss — a different mechanism you never invoke directly.)
* **Tags are case-sensitive, exact and not tokenised.** `t:SCREENSHOT` and `t:screenshot`
  are different searches and return different entries; `t:SHIFT_GOALS` is not found by
  `t:GOALS`; and `align` does not find entries tagged `alignment`. (How many each returns
  depends entirely on the scope you run it in, so no count is quoted here.)

**Stemming is real and the skill mirrors it.** The server returns an entry saying
"alignment" for a search of `aligned`, and "moving" for `moved`. The skill stems too, so it
does not mistake such an entry for thread context. Measured over 12 experiment/term pairs
and 2708 documents, that corrected 15 of 593 context labels — but the effect is entirely
concentrated in inflected queries, where per-pair it ranged from a few percent
(`lasers`: 8 of 283) to all of them (`aligned`: 1 of 1). A query whose term is already its
own stem is unaffected.

Author and tag are not in the text index; the server special-cases a `search_text` that
exactly equals a known author or tag.

There is no server-side limit or pagination: a broad query returns every matching
document. `--limit` controls how many are *printed*; the counts always reflect
everything returned.

An **empty search text is refused**, and so are `x:` and `t:` with nothing after them: the
server reads those as "match everything" and returns the whole collection — 2953 entries
and 7.2 MB from one instrument logbook alone. An invalid regex after `x:` is refused too,
because it used to come back as a clean zero, indistinguishable from a word that genuinely
is not there.

Those refusals are **typo guards, not load guards**. A single common word is still a legal
search and will still sweep the corpus: `search "a"` returned 41,956 entries across 112
experiments. When a result set passes 2000 entries the skill says so and tells you how to
narrow, but it does not refuse — by then the requests are already paid for.

### Date windows are applied here, not by the server

`--start-date 2024-12-01T00:00:00.000000Z --end-date 2024-12-05T00:00:00.000000Z` filters
on `insert_time` **client-side**, and the run reports how many entries the window removed.

That is deliberate. The server's own `start_date`/`end_date` parameters *silently discard
`search_text`*: on `rixx1016923`, a windowed query for `run`, for `knife`, for a nonsense
word, and with no `search_text` at all returned four byte-identical 112-document responses
— every entry in the window, not the matching ones. Single-sided windows and camelCase
spellings are ignored outright, and a bare `2024-12-01` returns HTTP 500. Passing a window
to the server would quietly turn your search into a date dump, so this skill never does.
The same trap applies to the server's `run_num` and `start_run_num`/`end_run_num`
parameters, which is why they are not exposed here.

## Reporting results to a user

State the scope line's numbers alongside any answer, and attribute every quoted entry to
its experiment, author and `insert_time`. If the answer is "nothing found", say
*nothing found in the N experiments searched* -- and offer the narrowing or widening flag
that would change that -- rather than "there is nothing in the eLog".

## Installing

Shared deployment and per-user setup are separate steps. Deployment is one world-readable
copy of this directory; there is nothing per-user in it, because the credential comes
from the invoking user's own token file at run time. Each user's own setup is exactly
one command -- `s3df login` -- run by that user.
