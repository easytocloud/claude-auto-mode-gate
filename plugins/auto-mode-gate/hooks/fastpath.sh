#!/bin/sh
# fastpath.sh - deterministic pre-filter for the auto-mode gate.
#
# File reads and edits inside the project are the overwhelming majority of tool
# calls. Answering them here costs ~7 ms instead of the ~100 ms of Python
# startup plus rule tables. This script can only say "allow"; anything it
# cannot prove safe is handed to auto_mode.py, which is where denies and asks
# come from. POSIX sh, no subprocesses for parsing.

IN=$(cat)
BASE="${CLAUDE_PROJECT_DIR:-.}"

# Extract a string value for a JSON key, tolerating pretty-printed input.
get() {
    key=$1
    for pat in "\"$key\":\"" "\"$key\": \"" "\"$key\" : \""; do
        r=${IN#*"$pat"}
        if [ "$r" != "$IN" ]; then
            printf '%s' "${r%%\"*}"
            return 0
        fi
    done
    printf ''
}

# The working directory is what the file tools resolve relative paths against,
# so use it as the boundary when the hook provides it.
cwd=$(get cwd)
[ -n "$cwd" ] && BASE="$cwd"

# Where the classifier lives: the plugin that registered this hook, or the
# project's own .claude/hooks when the gate was installed with install.sh.
if [ -n "${CLAUDE_PLUGIN_ROOT:-}" ] && [ -f "${CLAUDE_PLUGIN_ROOT}/hooks/auto_mode.py" ]; then
    AUTO_MODE="${CLAUDE_PLUGIN_ROOT}/hooks/auto_mode.py"
else
    AUTO_MODE="${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/auto_mode.py"
fi

delegate() {
    printf '%s' "$IN" | python3 -I "$AUTO_MODE"
    exit $?
}

tool=$(get tool_name)

# Keep the audit trail complete: fastpath allows are recorded too. A plugin's
# data directory survives updates, the project hooks directory is where a
# curl install keeps its log.
if [ -n "${CLAUDE_PLUGIN_DATA:-}" ]; then
    AUDIT_DIR="$CLAUDE_PLUGIN_DATA"
else
    AUDIT_DIR="${CLAUDE_PROJECT_DIR:-.}/.claude/hooks"
fi
AUDIT="$AUDIT_DIR/audit.jsonl"
sid=$(get session_id)

log() {
    [ -d "$AUDIT_DIR" ] || mkdir -p "$AUDIT_DIR" 2>/dev/null || return 0
    printf '{"ts":%s,"session_id":"%s","tool":"%s","decision":"allow","rule":"fastpath","tier":"fastpath","path":"%s"}\n' \
        "$(date +%s)" "$sid" "$1" "$2" >> "$AUDIT"
}

answer() {
    log "$1" "$2"
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"fastpath: %s"}}\n' "$3"
    exit 0
}

case "$tool" in
    Read|Glob|Grep|LS|Write|Edit|MultiEdit|NotebookEdit)
        path=$(get file_path)
        [ -n "$path" ] || path=$(get notebook_path)

        if [ -n "$path" ]; then
            case "$path" in
                *".."*)                      ;;   # escapes the directory, delegate
                */.claude/*|*/.git/*)        ;;   # the gate protects these
                .claude/*|.git/*|.env*)      ;;
                "$BASE"/*)                   answer "$tool" "$path" "path inside the working directory" ;;
                /*)                          ;;   # absolute path elsewhere
                *)                           answer "$tool" "$path" "path relative to the working directory" ;;
            esac
        fi

        # Glob/Grep/LS with no path argument search the working directory.
        case "$tool" in
            Glob|Grep|LS) answer "$tool" "" "search rooted at the working directory" ;;
        esac
        ;;
esac

delegate
