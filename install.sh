#!/usr/bin/env bash
# Deploy the elog-search agent skill.
#
# This script does ONE job: put the skill where an agent will find it. It never
# touches credentials, because there is nothing here to install per user — the
# skill authenticates with the caller's own Kerberos ticket or S3DF token, and
# both `kinit` and `s3df login` need the user in person.
#
#   maintainer, once   clone this repo somewhere group-readable
#   maintainer/user    ./install.sh                deploy for Claude Code
#   maintainer         ./install.sh --opencode     deploy into the shared opencode tree
#   each user, once    kinit  (or  s3df login)     only if they have no ticket
#
# The code is shared; the credential never is.
#
# The central opencode tree is normally fed by deploy-opencode/deploy.sh, which
# clones this repo from GitHub and rsyncs opencode/skills/<name>/ into place.
# --opencode does the same thing from a local clone, for when you want the
# deployed copy to move before a push, or there is no GitHub route at all.
set -euo pipefail

SKILL_NAME="elog-search"
REPO_ROOT="$(cd "$(dirname "$0")" && pwd -P)"

# claude/ and opencode/ hold identical copies of the skill. The split is not
# cosmetic: deploy.sh rsyncs from opencode/skills/<name>/ specifically, so the
# tree has to exist under that name. --sync keeps the two in step; --verify
# fails if they have drifted.
CLAUDE_SRC="$REPO_ROOT/claude/skills/$SKILL_NAME"
OPENCODE_SRC="$REPO_ROOT/opencode/skills/$SKILL_NAME"

DEST_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
OPENCODE_ROOT="${OPENCODE_ROOT:-/sdf/group/lcls/ds/dm/apps/dev/opencode}"
# ps-users (~3700 employees), not ps-data (~60). Deploying group ps-data into
# the shared tree silently locks out almost everyone who would use the skill.
SHARED_GROUP="${PS_USERS_GROUP:-ps-users}"

MODE=""                  # empty = decide from the destination; see below
FORCE=0
UNINSTALL=0
OPENCODE=0
RUN_CHECKS=1

usage() {
  cat <<EOF
usage: install.sh [options]

Deploys the skill. Does not touch credentials — the skill uses the invoking
user's own Kerberos ticket or S3DF token at run time.

  --copy        copy the skill (default for a destination outside your home)
  --symlink     symlink the skill (default for a destination under your home)
  --dir DIR     deploy into DIR instead of \$CLAUDE_SKILLS_DIR or ~/.claude/skills
  --opencode    deploy into the shared opencode tree instead: copies into
                \$OPENCODE_ROOT/skills/, adds the agents/ symlink, and fixes
                group ownership to $SHARED_GROUP
  --force       replace whatever is already at the destination
  --uninstall   remove the deployed skill
  --sync        copy claude/skills/$SKILL_NAME/ over opencode/skills/$SKILL_NAME/, then exit
  --verify      report whether the two source trees are identical, then exit
  --no-check    skip the post-install selftest and credential probe

Symlinking a shared multi-user tree back into a personal clone gives every other
user a link they cannot read, so the default flips to copying when the
destination is not under your home directory. Override either way.

Environment: CLAUDE_SKILLS_DIR, OPENCODE_ROOT, PS_USERS_GROUP.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --copy)      MODE="copy"; shift ;;
    --symlink)   MODE="symlink"; shift ;;
    --dir)       DEST_DIR="${2:?--dir needs a directory}"; shift 2 ;;
    --opencode)  OPENCODE=1; shift ;;
    --force)     FORCE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --no-check)  RUN_CHECKS=0; shift ;;
    --sync)      SYNC=1; shift ;;
    --verify)    VERIFY=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *)           echo "install.sh: unknown option '$1'" >&2; usage >&2; exit 2 ;;
  esac
done

# --- tree parity ------------------------------------------------------------
tree_diff() { diff -r "$CLAUDE_SRC" "$OPENCODE_SRC"; }

if [ "${SYNC:-0}" = "1" ]; then
  mkdir -p "$(dirname "$OPENCODE_SRC")"
  rm -rf "$OPENCODE_SRC"
  cp -R "$CLAUDE_SRC" "$OPENCODE_SRC"
  echo "synced claude/skills/$SKILL_NAME -> opencode/skills/$SKILL_NAME"
  exit 0
fi

if [ "${VERIFY:-0}" = "1" ]; then
  if tree_diff; then
    echo "identical: claude/skills/$SKILL_NAME and opencode/skills/$SKILL_NAME"
    exit 0
  fi
  echo "install.sh: the two source trees have drifted (see diff above)." >&2
  echo "            run './install.sh --sync' to make opencode/ match claude/." >&2
  exit 1
fi

# --- which source, which destination ----------------------------------------
if [ "$OPENCODE" -eq 1 ]; then
  SRC="$OPENCODE_SRC"
  DEST_DIR="$OPENCODE_ROOT/skills"
  if [ "$MODE" = "symlink" ]; then
    echo "install.sh: --symlink into the shared opencode tree would give ~3700" >&2
    echo "            users a link into your clone. Refusing." >&2
    exit 2
  fi
  MODE="copy"
  # Deploying a stale opencode/ tree is the failure this catches: you edit
  # claude/, forget --sync, and ship yesterday's skill to everyone.
  if ! tree_diff >/dev/null 2>&1; then
    echo "install.sh: opencode/skills/$SKILL_NAME differs from claude/skills/$SKILL_NAME." >&2
    echo "            run './install.sh --sync' first, or --force to deploy it anyway." >&2
    [ "$FORCE" -eq 1 ] || exit 1
  fi
else
  SRC="$CLAUDE_SRC"
fi

DEST="$DEST_DIR/$SKILL_NAME"
AGENT_LINK="$OPENCODE_ROOT/agents/$SKILL_NAME"

# --- symlink or copy? -------------------------------------------------------
# A symlink points back into this clone. That is what you want for your own
# ~/.claude/skills, and wrong for a shared multi-user tree: every other user
# then follows a link into a directory they usually cannot read. Default on
# where the destination lives, not on what is convenient here.
if [ -z "$MODE" ]; then
  home="$(getent passwd "$(id -u)" 2>/dev/null | cut -d: -f6 || true)"
  home="${home:-$HOME}"
  # Check the path as written AND as resolved. A personal ~/.claude is often a
  # symlink into a project directory; resolving first would call that "shared"
  # and silently downgrade a personal deployment to a copy.
  dest_abs="$(realpath -m "$DEST_DIR" 2>/dev/null || printf '%s' "$DEST_DIR")"
  MODE="copy"
  case "$DEST_DIR/" in "$home"/*) MODE="symlink" ;; esac
  case "$dest_abs/" in "$home"/*) MODE="symlink" ;; esac
  if [ "$MODE" = "copy" ]; then
    echo "note: $DEST_DIR is outside your home directory, so deploying a copy."
    echo "      A symlink there would point into"
    echo "      $REPO_ROOT,"
    echo "      which other users may not be able to read."
    echo "      Pass --symlink to override, and re-run after a git pull to"
    echo "      update the copy."
  fi
fi

# --- whose deployment is this? ----------------------------------------------
# "Ours" is either a symlink pointing anywhere inside this clone — including a
# dangling one, since moving the skill within the repo breaks every previous
# deployment — or a real directory whose SKILL.md declares this skill's name.
# Replacing or removing our own deployment must not need --force; touching a
# stranger's must.
is_ours() {
  if [ -L "$1" ]; then
    case "$(readlink "$1")" in "$REPO_ROOT"/*) return 0 ;; esac
    return 1
  fi
  [ -d "$1" ] && [ -f "$1/SKILL.md" ] &&
    grep -qE "^name:[[:space:]]*$SKILL_NAME[[:space:]]*$" "$1/SKILL.md"
}

if [ "$UNINSTALL" -eq 1 ]; then
  # A --opencode deployment is always a copy, so uninstall has to use the same
  # ownership test the install path uses or it could never remove one.
  if [ ! -e "$DEST" ] && [ ! -L "$DEST" ]; then
    echo "not deployed: $DEST"
  elif [ -L "$DEST" ] || is_ours "$DEST" || [ "$FORCE" -eq 1 ]; then
    rm -rf "$DEST"
    echo "removed $DEST"
  else
    echo "install.sh: $DEST is a real directory and its SKILL.md does not" >&2
    echo "            declare '$SKILL_NAME'. Re-run with --force if you are sure." >&2
    exit 1
  fi
  if [ "$OPENCODE" -eq 1 ] && [ -L "$AGENT_LINK" ]; then
    rm -f "$AGENT_LINK"
    echo "removed $AGENT_LINK"
  fi
  echo "note: your Kerberos ticket and S3DF token were left alone. This script"
  echo "      never created them and does not remove them."
  exit 0
fi

# --- sanity: is the source actually here and intact? ------------------------
for f in "$SRC/SKILL.md" "$SRC/scripts/elogsearch.py" "$SRC/reference/elog-api-notes.md"; do
  [ -f "$f" ] || { echo "install.sh: missing $f — run this from the clone" >&2; exit 1; }
done
chmod +x "$SRC/scripts/elogsearch.py" 2>/dev/null || true

mkdir -p "$DEST_DIR"

if [ -e "$DEST" ] || [ -L "$DEST" ]; then
  if [ -L "$DEST" ] && [ "$(readlink "$DEST")" = "$SRC" ]; then
    echo "already deployed: $DEST -> $SRC"
  elif is_ours "$DEST"; then
    [ -e "$DEST" ] || echo "note: $DEST was a dangling link into this clone"
    rm -rf "$DEST"
    echo "replacing previous deployment at $DEST"
  elif [ "$FORCE" -ne 1 ]; then
    echo "install.sh: $DEST already exists and is not ours." >&2
    echo "            re-run with --force to replace it." >&2
    exit 1
  else
    rm -rf "$DEST"
  fi
fi

if [ ! -e "$DEST" ] && [ ! -L "$DEST" ]; then
  case "$MODE" in
    symlink) ln -s "$SRC" "$DEST"; echo "deployed $DEST -> $SRC" ;;
    copy)
      cp -R "$SRC" "$DEST"
      # A copy into a shared tree is useless if the group cannot read it, which
      # is what an inherited umask of 027 produces. Group ownership comes from
      # the setgid parent on most of these trees; the shared opencode tree is
      # the exception and is set explicitly below.
      chmod -R g+rX "$DEST" 2>/dev/null || true
      echo "deployed $SRC -> $DEST (copy)"
      ;;
  esac
fi

# --- shared-tree extras: group, agents/ symlink -----------------------------
if [ "$OPENCODE" -eq 1 ]; then
  chgrp -R "$SHARED_GROUP" "$DEST" 2>/dev/null ||
    echo "WARN: chgrp $SHARED_GROUP failed on $DEST — other users may not be able to read it" >&2
  chmod -R g+rX "$DEST" 2>/dev/null ||
    echo "WARN: chmod g+rX failed on $DEST" >&2

  # opencode reads agents/ for what it may invoke; skills/ alone is not enough.
  mkdir -p "$(dirname "$AGENT_LINK")"
  if [ ! -e "$AGENT_LINK" ] && [ ! -L "$AGENT_LINK" ]; then
    ln -s "../skills/$SKILL_NAME" "$AGENT_LINK"
    echo "linked $AGENT_LINK -> ../skills/$SKILL_NAME"
  elif [ -L "$AGENT_LINK" ]; then
    current="$(readlink "$AGENT_LINK")"
    if [ "$current" = "../skills/$SKILL_NAME" ]; then
      echo "already linked: $AGENT_LINK -> $current"
    else
      echo "WARN: $AGENT_LINK points to '$current', expected '../skills/$SKILL_NAME'" >&2
      echo "      (not auto-repaired)" >&2
    fi
  else
    echo "WARN: $AGENT_LINK exists and is not a symlink (not auto-repaired)" >&2
  fi
fi

# --- environment notes ------------------------------------------------------
# uv is the supported path: the skill's PEP 723 metadata pins python>=3.9 and uv
# provisions exactly that. A bare python3 is often the system one — 3.6 on these
# login nodes — which cannot even parse the script.
if ! command -v uv >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1 &&
     python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    :
  else
    echo
    echo "warning: no usable interpreter."
    echo "         uv is not installed, and python3 is $(python3 -V 2>&1 || echo absent),"
    echo "         but this skill needs python >= 3.9. The skill is deployed but"
    echo "         will not run until you install uv (https://docs.astral.sh/uv/)."
  fi
  RUN_CHECKS=0
elif [ -z "${UV_CACHE_DIR:-}" ]; then
  echo
  echo "note: UV_CACHE_DIR is unset, so uv caches under ~/.cache/uv."
  echo "      On quota'd home directories set UV_CACHE_DIR=/tmp/uv-cache-\$USER."
fi

# --- post-install checks ----------------------------------------------------
# selftest needs no credential, so it always runs: it proves the deployed copy
# parses and its result classifier still behaves.
#
# The credential probe is deliberately shaped so this script never tells you to
# run kinit on a hunch. Most people on an S3DF node already hold a ticket, and
# being sent to redo setup you did not need is worse than silence. Only an
# observed failure prints the instructions — the same rule the skill itself
# follows when reporting to a user.
if [ "$RUN_CHECKS" -eq 1 ]; then
  echo
  if "$DEST/scripts/elogsearch.py" selftest >/dev/null 2>&1; then
    echo "selftest: pass (no credential needed)"
  else
    echo "selftest: FAILED — the deployed copy is not sound" >&2
    "$DEST/scripts/elogsearch.py" selftest 2>&1 | tail -20 >&2
    exit 1
  fi

  if who_out="$("$DEST/scripts/elogsearch.py" whoami 2>&1)"; then
    printf '%s\n' "$who_out" | sed -n '1,3p' | sed 's/^/credential: /'
  else
    echo "credential: none usable on this account yet. The skill is deployed and"
    echo "            will work as soon as you run one of:"
    echo
    echo "              kinit \$USER@SLAC.STANFORD.EDU        # Kerberos, ~24 h"
    echo "              /sdf/sw/s3df-cli/bin/s3df login      # S3DF token, 12 h"
    echo
    echo "            Nobody can run these for you, and no shared account is"
    echo "            used as a fallback. What it reported:"
    printf '%s\n' "$who_out" | tail -5 | sed 's/^/              /'
  fi
fi

cat <<EOF

Deployed to $DEST

Nothing further is required of a user who already holds a Kerberos ticket.
Search results are scoped to whoever is invoking the skill, so the credential
step cannot be done on anyone else's behalf.
EOF
