# elog-search

An agent skill that searches the LCLS eLog live, read-only, as **the user who
invokes it** — never through a shared account — and always reports which
experiments it searched and why.

```
$ elogsearch.py search '"jet clog"' --days 180

experiment : cxi101184426
author     : cxiopr
insert_time: 2026-06-21T10:40:08.567000+00:00
excerpt    : jet clogged

COUNTS
  entries returned by the API    : 2
  entries shown as matches       : 2
  entries suppressed as deleted  : 0
  entries labelled thread context: 0

SCOPE: searched 113 of 2240 experiments readable as <you> (ws-kerb)
  selection: active within 180 days (last run start) INTERSECT readable by you
```

## Why the scope line is not decoration

There is no eLog-wide search. Each experiment is its own MongoDB database and
the server's `search_elog` route is per-experiment, so "search the eLog" is a
fan-out over a set of experiments *this skill chooses*. Every result therefore
carries how many experiments were searched, out of how many you may read, and
how that set was picked. A colleague running the identical command may search a
different number and get different results, because `readable by you` is a
property of your roles.

The skill also suppresses logically-deleted entries (the eLog only sets
`deleted_by`; no read query filters on it, so deleted entries still come back
from a search), labels thread ancestors the server hydrates into results, and
counts both.

`claude/skills/elog-search/reference/elog-api-notes.md` documents the API
underneath — endpoint prefixes, the entry document shape, and the server-side
search semantics the skill has to work around.

## Install

```bash
./install.sh                 # Claude Code: symlinks into ~/.claude/skills
./install.sh --opencode      # shared opencode tree: copy + agents/ symlink + ps-users
./install.sh --uninstall     # remove it again
./install.sh --help          # every flag
```

Then, only if you do not already hold a credential:

```bash
kinit <you>@SLAC.STANFORD.EDU        # Kerberos, ~24 h
/sdf/sw/s3df-cli/bin/s3df login      # S3DF token, 12 h
```

`install.sh` runs a credential-free `selftest` after deploying and then probes
`whoami`. It prints the `kinit` instructions **only** if that probe actually
fails — most people on an S3DF node already hold a ticket, and being told to
redo setup you never needed is worse than useless.

## Layout

```
claude/skills/elog-search/       SKILL.md + scripts/ + reference/
opencode/skills/elog-search/     identical copy
install.sh                       deploys either one
```

The duplication is required, not cosmetic: the central deployer
(`deploy-opencode/deploy.sh`) rsyncs `opencode/skills/<name>/` by that exact
path. Keep the trees in step with `./install.sh --sync`, and check them with
`./install.sh --verify`. `--opencode` refuses to deploy a drifted tree unless
you pass `--force`.

## Deployment routes

| Route | Command | When |
|---|---|---|
| Personal | `./install.sh` | your own Claude Code |
| Shared, from this clone | `./install.sh --opencode` | you want the deployed copy to move now |
| Shared, from GitHub | add to `deploy-opencode/skills.manifest.json`, then `./deploy.sh elog-search` | the maintained route |

The manifest route is the one other skills use: `deploy.sh` clones the repo from
GitHub at a ref, rsyncs `opencode/skills/<name>/` into
`/sdf/group/lcls/ds/dm/apps/dev/opencode/skills/`, fixes group ownership to
`ps-users`, and ensures `agents/<name> -> ../skills/<name>`. `--opencode` does
the same steps from a local clone.

## The credential is never shared

The skill resolves, in order: your own Kerberos ticket cache under `/tmp` whose
owner uid equals yours (checking sibling caches, not just the default — an ssh
login with GSSAPI delegation leaves a valid ticket in a suffixed cache with
`KRB5CCNAME` unset), then `~/.s3df-access-token`. There is no shared-account
fallback at any step. A credential file that is group- or world-readable is
refused with the `chmod 600` that fixes it. Tokens are never printed or logged.

Entry content is never written to disk. Only experiment metadata (names,
instruments, dates) is cached, mode 0600 with a 6 h TTL.

## Read-only by construction

Every HTTP call goes through one function that refuses any route outside a
four-entry allowlist — `experiments`, `get_cached_experiment_names`,
`experiment_names_updated_within`, `search_elog`. All four are GETs. No route
that creates, edits, removes or cross-posts an entry appears anywhere in this
repo.
