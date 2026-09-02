#!/bin/bash
# Site detection for elog-search skill.
# Sets ELOG_SEARCH_BIN with a facility-appropriate default: the directory
# holding the shared uv, so the PEP 723 scripts' `uv run --script` shebang
# resolves without a personal ~/.local/bin/uv.
# Can always be overridden by setting ELOG_SEARCH_BIN before sourcing.

if [ -d /sdf ]; then
    # S3DF (SLAC)
    export ELOG_SEARCH_BIN="${ELOG_SEARCH_BIN:-/sdf/group/lcls/ds/dm/apps/dev/bin}"
elif [ -d /lustre/orion ]; then
    # OLCF (Frontier)
    export ELOG_SEARCH_BIN="${ELOG_SEARCH_BIN:-/ccs/home/cwang31/.local/bin}"
fi

if [ -n "${ELOG_SEARCH_BIN:-}" ]; then
    export PATH="$ELOG_SEARCH_BIN:$PATH"
fi
