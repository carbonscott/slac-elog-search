#!/bin/bash
# Environment for elog-search skill.
# Puts the shared uv on PATH and configures the uv cache, so the scripts here
# run from any shell. Override any variable via env.local or by exporting
# before sourcing.

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Facility detection: sets ELOG_SEARCH_BIN to the directory holding the
# shared uv and puts it on PATH. Off-site it sets nothing and PATH's own uv
# is used.
if [ -f "$SKILL_DIR/facility-env.sh" ]; then
    source "$SKILL_DIR/facility-env.sh"
fi

# Shared uv-managed Python installs, when the facility provides them.
if [ -d /sdf/group/lcls/ds/dm/apps/dev/python ]; then
    export UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-/sdf/group/lcls/ds/dm/apps/dev/python}"
fi

# uv cache per user (avoids permission issues in shared deploys)
export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache-${USER:-$(id -un)}}"

# User overrides last
if [ -f "$SKILL_DIR/env.local" ]; then
    source "$SKILL_DIR/env.local"
fi
