# elog-search

Ask Claude about an experiment and get a grounded answer: what the eLog says,
which runs there were and how the detectors were configured, which files landed,
which sample was mounted, why an analysis job died — each answer naming the
experiment, the author and the time, and stating exactly what was looked at.

It reads the LCLS logbook **live**, as you, read-only. It sees every experiment
your own account can read, and it never quotes back an entry somebody deleted.
Full-text search is one of the things it does, not the whole of it: most
questions about an experiment are answered by the run table, the file list or
the job log rather than by grepping prose. Works in Claude Code and in the
shared LCLS opencode install.

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

> `@elog-search` which detectors were used in mfx101592326, and at what settings?

> `@elog-search` which runs of cxilv4418 used sample GFP, and did they write xtc?

> `@elog-search` job 65f3a1 in mfxlv4920 failed — what does its log say?

That last one is the shape worth knowing about: the skill proxies a single call
to the job daemon (`workflows <exp> --job ID --action job_log_file`) and reads
the log back, so "why did that analysis fail" is a question you can just ask.

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
  scripts/elogsearch.py                the whole tool
  reference/elog-api-notes.md          the API as it actually behaves
  reference/explgbk-get-routes.txt     upstream's own route list, vendored so
                                       selftest can pin the policy against it
opencode/skills/elog-search/   identical copy, for the shared opencode tree
install.sh                     deploys either one; --help for flags
```

The duplication is what the shared deploy expects. `./install.sh --sync` makes
the second match the first and `--verify` fails if they have drifted; both must
be in step before you commit.

---

## Under the hood

It calls the logbook's own routes with your token, and never writes entry text
to disk; saving an attachment takes an explicit `--out`.

Every HTTP call goes through one function, and that function decides by
**effect, not by HTTP method**. The logbook service answers GET on routes that
end runs, close shifts, cross-post entries, kill analysis jobs and rebuild
caches — a tool that allowed every GET could do all of that to the production
logbook during beam time. So all 117 GET-accepting routes are classified in the
source: 87 read-only and callable, 26 that accept GET and change state, and 4
that are read-only by the letter of the rule but refused anyway, each for a
named reason — they leave the logbook, mint a credential, or have nothing to
read. Anything outside the read-only set is refused before a URL is built, let
alone a socket opened.

`elogsearch.py routes` prints that inventory. `elogsearch.py selftest` proves
the refusals with no credential and no network, and fails if the vendored copy
of upstream's route list has drifted from the classification — the tripwire for
the one weakness of a deny-list model, a future release adding a 27th mutating
GET that would otherwise land inside the permitted set in silence.

[reference/elog-api-notes.md](claude/skills/elog-search/reference/elog-api-notes.md)
has the endpoint prefixes, the entry document shape, the server-side search
semantics the skill works around, and the credential mechanics.
