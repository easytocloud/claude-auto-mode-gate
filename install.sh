#!/bin/sh
# claude-auto-mode-gate installer.
#
#   curl -sL https://raw.githubusercontent.com/easytocloud/claude-auto-mode-gate/main/install.sh | sh
#
# Installs into the directory you run it from. Override with:
#
#   GATE_TARGET=/path/to/project   which project to install into
#   GATE_REF=main                  branch, tag or commit to install from
#   GATE_FORCE=1                   replace an existing .claude/auto-mode.json
#   GATE_LOCAL=/some/dir           install from a local checkout instead of the net
#
# Idempotent: re-running refreshes the hook files and never duplicates the
# hook entry in settings. Existing hooks and permissions are left alone.

set -u

REF="${GATE_REF:-main}"
RAW="https://raw.githubusercontent.com/easytocloud/claude-auto-mode-gate/${REF}"
TARGET="${GATE_TARGET:-$PWD}"

fetch() {
    if [ -n "${GATE_LOCAL:-}" ]; then
        cat "$GATE_LOCAL/$1"
    elif command -v curl >/dev/null 2>&1; then
        curl -fsSL "$RAW/$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO - "$RAW/$1"
    else
        echo "install.sh needs curl or wget" >&2
        return 1
    fi
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required: the gate is a Python hook" >&2
    exit 1
fi
if [ ! -d "$TARGET" ]; then
    echo "target directory does not exist: $TARGET" >&2
    exit 1
fi

echo "installing into $TARGET (ref $REF)"
mkdir -p "$TARGET/.claude/hooks"

for f in hooks/auto_mode.py hooks/fastpath.sh gate_settings.py; do
    if ! fetch "$f" > "$TARGET/.claude/hooks/$f"; then
        echo "failed to download $f from $RAW/$f" >&2
        exit 1
    fi
done
chmod 0755 "$TARGET/.claude/hooks/fastpath.sh" "$TARGET/.claude/hooks/auto_mode.py"

if [ -f "$TARGET/.claude/auto-mode.json" ] && [ "${GATE_FORCE:-0}" != "1" ]; then
    echo "keeping the existing .claude/auto-mode.json (set GATE_FORCE=1 to replace it)"
else
    if ! fetch config/auto-mode.json > "$TARGET/.claude/auto-mode.json"; then
        echo "failed to download config/auto-mode.json" >&2
        exit 1
    fi
fi

python3 "$TARGET/.claude/hooks/gate_settings.py" install "$TARGET"

echo
echo "verify:"
echo "  python3 -m py_compile \"$TARGET/.claude/hooks/auto_mode.py\""
echo "  sh -n \"$TARGET/.claude/hooks/fastpath.sh\""
echo "  printf '{\"tool_name\":\"Read\",\"tool_input\":{\"file_path\":\"README.md\"},\"cwd\":\"%s\"}' \"$TARGET\" | sh \"$TARGET/.claude/hooks/fastpath.sh\""
echo
echo "Claude Code reloads settings files, so the gate is active in running"
echo "sessions. If it is not, restart Claude Code in $TARGET."
