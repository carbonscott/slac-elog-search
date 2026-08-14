# elog-search

Ask Claude what the eLog says and get answers that name the experiment, the
author and the time — and state exactly what was searched.

It searches the LCLS eLog **live**, as you, read-only. It sees every experiment
your own account can read, and it never quotes back an entry somebody deleted.
Works in Claude Code and in the shared LCLS opencode install.

---

## Quick start

**1. Get the skill.** Using the shared opencode install on S3DF? It is already
there — skip to step 2. Setting up your own Claude Code:

```bash
git clone git@github.com:carbonscott/slac-elog-search.git
cd slac-elog-search && ./install.sh          # links it into ~/.claude/skills
```

**2. Get a token.** Nobody can do this for you: results are filtered by *your*
roles, so a shared token would show you someone else's read access wearing your
name. Tokens last 12 h, and the same command renews an expired one with no
browser.

```bash
/sdf/sw/s3df-cli/bin/s3df login
```

**3. Check it worked.** An identity and a non-zero experiment count means you
are done.

```bash
~/.claude/skills/elog-search/scripts/elogsearch.py whoami
```

**4. Ask it something.**

> `@elog-search` what does the elog say about jet clogs in mfx?

> `@elog-search` which detectors were used in mfx101592326?

---

## The one thing to understand

**There is no eLog-wide search.** Each experiment is its own database, so a
search is a fan-out over a set of experiments the skill *chooses* — by default
those active in the last 180 days that you can read. Every answer therefore
carries a scope line:

```
SCOPE: searched 111 of 2240 experiments readable as you (ws-jwt)
  selection: active within 180 days (last run start) INTERSECT readable by you
```

Never repeat that count as a fact about the eLog — a colleague running the same
command may search a different number and get different results. Runs also end
with four counts: returned by the API, shown as matches, suppressed as deleted,
labelled thread context.

---

## Repo layout

```
claude/skills/elog-search/     for Claude Code users
opencode/skills/elog-search/   identical copy, for the shared opencode tree
install.sh                     deploys either one; --help for flags
```

The duplication is what the shared deploy expects. `./install.sh --sync` makes
the second match the first and `--verify` fails if they have drifted; both must
be in step before you commit.

---

## Under the hood

It queries the logbook's own search route per experiment, with your token, and
never writes entry text to disk. Every HTTP call goes through one function that
refuses any route outside a four-entry read-only allowlist, so no code path can
create, edit or delete an entry.

[reference/elog-api-notes.md](claude/skills/elog-search/reference/elog-api-notes.md)
has the endpoint prefixes, the entry document shape, the server-side search
semantics the skill works around, and the credential mechanics.
