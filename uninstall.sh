#!/bin/sh
# Remove the auto-mode gate from a project.
#
#   sh uninstall.sh
#   GATE_TARGET=/path/to/project sh uninstall.sh
#
# Removes the hook entry from .claude/settings.local.json and deletes the hook
# files. .claude/auto-mode.json is left in place; delete it by hand if you want.

set -u
TARGET="${GATE_TARGET:-$PWD}"

if [ -f "$TARGET/.claude/hooks/gate_settings.py" ]; then
    python3 "$TARGET/.claude/hooks/gate_settings.py" remove "$TARGET"
else
    echo "gate_settings.py is not in $TARGET/.claude/hooks;" >&2
    echo "remove the hook entry from .claude/settings.local.json by hand." >&2
    exit 1
fi

echo
echo "restart Claude Code in $TARGET if the hook still fires."
