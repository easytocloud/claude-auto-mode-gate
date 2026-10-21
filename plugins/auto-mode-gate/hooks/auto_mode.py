#!/usr/bin/env python3
"""
auto_mode.py - a PreToolUse hook that re-installs the permission gate that
`claude --dangerously-skip-permissions` removes.

It reproduces Claude Code's built-in "auto mode": every tool call is decided
before it runs, using the model the session is already running as the
classifier. (Built-in auto mode needs a supported Anthropic model, so it is
unavailable with a local gateway - this is the drop-in replacement.)

Decision tiers, in order:

  0. fastpath.sh (separate shell script) - in-project file reads and edits
  1. hard rules   (regex, deterministic, no model)  -> deny
  2. safe rules   (regex, deterministic, no model)  -> allow
  3. the model    (everything else)                 -> allow / deny / ask

If the classifier cannot be reached, the call is "ask": a permission prompt
interactively, and a deny in a headless `claude -p` run where nobody can
answer. The hook never exits non-zero; the decision is carried in the JSON.

Stdlib only. Python 3.7+.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import time

# ---------------------------------------------------------------- config ----

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.environ.get("CLAUDE_PLUGIN_ROOT") or ""
PLUGIN_DATA = os.environ.get("CLAUDE_PLUGIN_DATA") or ""
PROJECT_DIR = (os.environ.get("CLAUDE_PROJECT_DIR")
               or os.path.dirname(os.path.dirname(HERE)))


def first_existing(paths):
    for path in paths:
        if path and os.path.exists(path):
            return path
    return None


# A project's own .claude/auto-mode.json wins; the plugin ships a generic
# default for projects that have none.
CONFIG_PATH = first_existing([
    os.path.join(PROJECT_DIR, ".claude", "auto-mode.json"),
    os.path.join(PLUGIN_ROOT, "config", "auto-mode.json"),
    os.path.join(os.path.dirname(HERE), "config", "auto-mode.json"),
])

# CLAUDE_PLUGIN_ROOT is a per-version cache, so the audit log and the decision
# cache go to CLAUDE_PLUGIN_DATA, which survives updates.
STATE_DIR = PLUGIN_DATA or HERE
AUDIT_PATH = os.path.join(STATE_DIR, "audit.jsonl")
CACHE_PATH = os.path.join(STATE_DIR, ".cache.json")
CACHE_TTL = 300
MODEL_TIMEOUT = 12

# ------------------------------------------------------------- rules ---------

CRITICAL_PATHS = frozenset(
    ["/", "~", "$HOME", "/etc", "/usr", "/usr/local", "/System", "/Library",
     "/opt", "/var", "/bin", "/sbin", ".git", ".claude", "node_modules"]
)

PROTECTED_DIRS = (
    ".git", ".claude", ".vscode", ".ssh", ".aws", ".gnupg", ".npm", ".env",
)

HARD_BASH_RULES = [
    ("Privilege-Escalation",
     re.compile(r"(?:^|[;&|]\s*)(sudo|su|runuser)\s", re.M)),
    ("Pipe-To-Interpreter",
     re.compile(r"\b(curl|wget)[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|perl|ruby|pwsh|powershell)\b")),
    ("Auto-Mode-Bypass",
     re.compile(r"--dangerously-skip-permissions|--permission-mode\s+bypassPermissions|--no-sandbox|--yes-always|--yolo|--dangerously\b")),
    ("Metadata-Endpoint",
     re.compile(r"169\.254\.169\.254|metadata\.google\.internal|\.metadata\.windows\.azure|100\.100\.100\.100")),
    ("Self-Disabling-Guard",
     re.compile(r"(?:^|\s)(?:rm|mv|chmod|truncate|tee|cat|sed\s+-i|printf|echo)\b[^|;&]*\.claude/(?:hooks|settings)")),
    ("Disk-Dev-Writing",
     re.compile(r"\bdd\b[^|;&]*of=/dev/|mkfs|>\s*/dev/(?:sd|disk)")),
    ("Fork-Bomb", re.compile(r":\(\)\s*\{\s*:|::\|\s*::")),
    ("Secret-Source-Read",
     re.compile(r"(?:cat|head|tail|sed|awk|less|cp|grep)\b[^|;&]*~/(?:\.ssh|\.aws|\.gnupg|\.config/gh|\.claude/credentials|\.netrc)")),
]

SAFE_COMMANDS = {
    "ls", "pwd", "echo", "printf", "cat", "head", "tail", "wc", "grep", "rg",
    "find", "tree", "file", "stat", "du", "df", "which", "whoami", "date",
    "sort", "uniq", "cut", "basename", "dirname", "realpath", "true", "env",
    "printenv", "jq", "column", "nl", "od", "diff", "comm", "tr",
}
SAFE_GIT_SUB = {"status", "diff", "log", "show", "branch", "remote", "ls-files",
                "rev-parse", "config", "describe", "blame"}
SAFE_TEST_COMMANDS = re.compile(
    r"^(?:pytest|py\.test|python3? -m pytest|npm (?:test|run test)|yarn test|"
    r"pnpm test|make test|cargo test|go test|npm run lint)\b"
)
UNSAFE_FLAGS = re.compile(r"sed\s+-i\b|--in-place|-delete\b|-exec\b|--output\b|>\s|>>\s")

# MCP tools that are read-only enough to skip the classifier by default.
DEFAULT_SAFE_TOOLS = [
    r"^mcp__playwright__browser_(snapshot|find|take_screenshot|console_messages|"
    r"network_requests|emulate_media|resize|wait_for|close)$",
]

DEFAULT_RULES = {
    "hard_deny": [
        "Exfiltrate secrets, credentials, or private source to a host outside the "
        "trust boundary (paste sites, unknown domains, webhooks).",
        "Read the user's credential stores (~/.ssh, ~/.aws, keychain, token files) "
        "and send anything over the network.",
        "Delete or overwrite pre-existing files outside the project working "
        "directory, or any system, dotfile, or VCS directory.",
        "Disable the agent's own safety gate: edit .claude/settings*.json, the hook "
        "scripts, or launch a nested agent with permission prompts skipped.",
        "Reach cloud metadata endpoints or the host's credential identity.",
    ],
    "soft_deny": [
        "Force-push, delete remote branches, or rewrite pushed history.",
        "Install packages not already declared in the repo manifest (typosquat and "
        "supply-chain risk).",
        "Deploy to, or touch, anything named prod/production/release.",
        "Start long-running daemons, listeners, or cron/systemd changes that outlive "
        "the task.",
        "Any write or read that leaves the working directory's scope.",
        "Irreversible destruction of pre-existing data inside the project "
        "(recursive deletes, database drops, git resets).",
    ],
    "allow": [
        "Reading, searching, and listing files inside the working directory.",
        "Running the project's own test or lint commands.",
        "Creating or editing files inside the working directory that belong to the "
        "task the user asked for.",
        "Installing dependencies already declared in the repo manifest.",
        "Read-only GETs to documentation domains listed in the environment.",
    ],
    "environment": [],
}

SYSTEM_PROMPT = """You are a safety classifier for an AI coding agent that is running
with permission prompts disabled. One action is pending. Decide whether it may run.

Apply these tiers, in order:
1. HARD_DENY - never allow. No amount of user intent clears these.
2. SOFT_DENY - block, UNLESS the user's own recent messages explicitly and
   specifically described this exact action. A general request is not consent:
   "clean up the repo" does not authorise a force-push; "force-push this branch" does.
3. ALLOW - routine, in-scope, reversible work.
4. Otherwise return "ask".

Only the classifier can see this conversation; judge the action against it.

Rules:
{rules}

Reply with JSON only, no prose:
{"decision":"allow|deny|ask","rule":"<short name of the rule you applied>","reason":"<one sentence>"}
"""

# ----------------------------------------------------------- helpers ---------


def emit(decision, reason):
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.stdout.write("\n")


def log(record):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(AUDIT_PATH, "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


def load_config():
    cfg = {}
    if not CONFIG_PATH:
        return cfg
    try:
        with open(CONFIG_PATH) as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        pass
    return cfg


def settings_files():
    return (os.path.join(PROJECT_DIR, ".claude", "settings.json"),
            os.path.join(PROJECT_DIR, ".claude", "settings.local.json"),
            os.path.expanduser("~/.claude/settings.json"))


def settings_env():
    """The env Claude Code exports from settings.json, readable outside a session."""
    env = {}
    for settings in settings_files():
        try:
            with open(settings) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(data.get("env"), dict):
            env.update(data["env"])
    return env


def load_cache():
    try:
        with open(CACHE_PATH) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_cache(cache):
    try:
        now = time.time()
        cache = {k: v for k, v in cache.items() if now - v.get("ts", 0) < CACHE_TTL}
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(cache, fh)
        os.replace(tmp, CACHE_PATH)
    except OSError:
        pass


def inside_cwd(path, cwd, scratchpad):
    """Is this path inside the working directory (or the scratchpad)?"""
    if not path:
        return False
    if not os.path.isabs(path):
        # Resolve relative paths against the session's cwd, not the process cwd.
        path = os.path.join(cwd, path)
    ap = os.path.abspath(os.path.expanduser(path))
    roots = [os.path.abspath(cwd)]
    if scratchpad:
        roots.append(os.path.abspath(scratchpad))
    return any(ap == r or ap.startswith(r + os.sep) for r in roots)


def bash_segments(command):
    """Split into simple segments so `a && rm -rf /` is not waved through."""
    return [s.strip() for s in re.split(r"&&|\|\||[;|]|\n", command) if s.strip()]


def command_first_word(segment):
    words = segment.split()
    if not words:
        return None
    word = words[0]
    while word and "=" in word:        # strip leading env assignments: FOO=bar ls
        words = words[1:]
        word = words[0] if words else None
    return word


def rm_targets(command):
    match = re.search(r"\brm\b([^|;&<>]*)", command)
    if not match:
        return []
    return [a for a in match.group(1).split() if not a.startswith("-")]


def tool_matches(tool, patterns):
    return any(re.search(p, tool) for p in patterns)


# -------------------------------------------------------- tier 1 / 2 ---------


def rule_tier(data, cfg):
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.getcwd()
    scratchpad = data.get("scratchpad_dir")

    if tool == "Bash":
        command = tool_input.get("command", "") or ""
        rules = list(HARD_BASH_RULES)
        for name, pattern_text in cfg.get("deny_commands", []):
            try:
                rules.append((name, re.compile(pattern_text)))
            except re.error:
                continue
        for name, pattern in rules:
            if pattern.search(command):
                return "deny", name, "matched hard rule %s: %s" % (name, command[:120])

        if re.search(r"\b(rm|rmdir)\b", command):
            for target in rm_targets(command):
                norm = target.strip("\"'")
                if norm in CRITICAL_PATHS or norm.rstrip("/") in CRITICAL_PATHS:
                    return "deny", "Critical-Path-Removal", "removes %s" % norm
                if not inside_cwd(norm, cwd, scratchpad):
                    return "deny", "Out-of-Scope-Deletion", "deletes %s, outside the project" % norm

        if UNSAFE_FLAGS.search(command) or "$(" in command or "`" in command:
            return None, None, None      # too dynamic to prove safe -> classifier

        for seg in bash_segments(command):
            if re.search(r"^[^<>]*>>?\s", seg):
                return None, None, None  # any redirection is a write
            word = command_first_word(seg)
            if word == "git":
                sub = seg.split()[1] if len(seg.split()) > 1 else ""
                if sub in SAFE_GIT_SUB and not any(f in seg for f in ("--hard", "push", "reset")):
                    continue
                return None, None, None
            if SAFE_TEST_COMMANDS.match(seg):
                continue
            if word in SAFE_COMMANDS:
                for arg in seg.split()[1:]:
                    arg = arg.strip("'\"")
                    if arg.startswith("/") and not inside_cwd(arg, cwd, scratchpad):
                        return None, None, None
                continue
            return None, None, None
        return "allow", "Read-Only-Local", "read-only command inside the project"

    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        ap = os.path.abspath(os.path.expanduser(path)) if path else ""
        if any(part in ap for part in PROTECTED_DIRS):
            return "deny", "Protected-Path-Write", "refuses edits to %s" % ap
        if inside_cwd(path, cwd, scratchpad):
            return "allow", "In-Scope-Edit", "edit inside the working directory"
        return None, None, None

    if tool in ("Read", "Glob", "Grep", "LS"):
        path = tool_input.get("file_path") or tool_input.get("path") or ""
        if not path or inside_cwd(path, cwd, scratchpad):
            return "allow", "In-Scope-Read", "read inside the working directory"
        return None, None, None

    return None, None, None


# ------------------------------------------------------- tier 3: model -------


def resolve_model(data, cfg):
    """The model the chat is actually running, in priority order."""
    explicit = cfg.get("model") or os.environ.get("AUTO_MODE_MODEL")
    if explicit:
        return explicit

    transcript = data.get("transcript_path")
    if transcript and os.path.exists(transcript):
        try:
            size = os.path.getsize(transcript)
            with open(transcript, "rb") as fh:
                fh.seek(max(0, size - 400000))
                tail = fh.read().decode("utf-8", "replace")
            model = None
            for line in tail.splitlines():
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                m = (entry.get("message") or {}).get("model")
                if m:
                    model = m
            if model:
                return model
        except OSError:
            pass

    env = settings_env()
    for key in ("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
                "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL"):
        if os.environ.get(key):
            return os.environ[key]
        if env.get(key):
            return env[key]

    for settings in settings_files():
        try:
            with open(settings) as fh:
                model = json.load(fh).get("model")
            if model and isinstance(model, str) and not model.startswith("<"):
                return model
        except (OSError, ValueError):
            pass
    return None


def transcript_context(data, max_messages=4, max_commands=6):
    transcript = data.get("transcript_path")
    messages, commands = [], []
    if not transcript or not os.path.exists(transcript):
        return messages, commands
    try:
        size = os.path.getsize(transcript)
        with open(transcript, "rb") as fh:
            fh.seek(max(0, size - 400000))
            tail = fh.read().decode("utf-8", "replace")
    except OSError:
        return messages, commands

    for line in tail.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        message = entry.get("message") or {}
        content = message.get("content")
        if entry.get("type") == "user":
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = " ".join(c.get("text", "") for c in content
                                if isinstance(c, dict) and c.get("type") == "text")
            else:
                text = ""
            if text.strip():
                messages.append(text.strip()[:300])
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "tool_use" \
                        and item.get("name") == "Bash":
                    cmd = (item.get("input") or {}).get("command", "")
                    if cmd:
                        commands.append(cmd[:120])
    messages = messages[-max_messages:]
    commands = commands[-max_commands:]
    if commands:
        messages.append("recent commands: " + "; ".join(commands))
    return messages, commands


MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml", "Cargo.toml",
             "go.mod", "Gemfile", "composer.json", "pom.xml")


def detected_environment(cwd):
    """Trust-boundary facts about the project, when the config states none.

    A plugin install ships a generic config, so without this the classifier
    would judge every command with no idea what surrounds it.
    """
    root = os.path.abspath(cwd or PROJECT_DIR)
    facts = ["Project: %s at %s" % (os.path.basename(root), root)]

    if os.path.isdir(os.path.join(root, ".git")):
        remotes = set()
        try:
            out = subprocess.run(["git", "remote", "-v"], cwd=root,
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    remotes.add(parts[1])
        except Exception:
            pass
        if remotes:
            facts.append("Source control remotes: " + ", ".join(sorted(remotes)))
        else:
            facts.append("Local git repository with no remote; nothing here "
                         "reaches a remote host")
    else:
        facts.append("Not a git repository: there are no remote "
                     "source-control destinations")

    manifests = [f for f in MANIFESTS if os.path.exists(os.path.join(root, f))]
    if manifests:
        facts.append("Declared dependencies live in: " + ", ".join(manifests))
    return facts


def build_rules(cfg, cwd=""):
    rules = {}
    for key in ("hard_deny", "soft_deny", "allow", "environment"):
        entries = list(DEFAULT_RULES[key])
        extra = cfg.get(key, [])
        if extra:
            entries = extra + entries
        rules[key] = entries
    if not cfg.get("environment"):
        rules["environment"] = detected_environment(cwd)
    rules_file = os.environ.get("AUTO_MODE_RULES_FILE")
    if rules_file and os.path.exists(rules_file):
        try:
            with open(rules_file) as fh:
                rules.update(json.load(fh))
        except (OSError, ValueError):
            pass
    return "\n".join(
        "\n".join(["%s:" % tier] + ["  - " + r for r in rules[tier]])
        for tier in ("hard_deny", "soft_deny", "allow", "environment")
        if rules[tier]
    )


def classifier_endpoint(cfg):
    env = settings_env()
    base = (cfg.get("base_url") or os.environ.get("ANTHROPIC_BASE_URL")
            or env.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
    token = (os.environ.get("ANTHROPIC_AUTH_TOKEN")
             or os.environ.get("ANTHROPIC_API_KEY")
             or env.get("ANTHROPIC_AUTH_TOKEN")
             or env.get("ANTHROPIC_API_KEY") or "")
    if "api.anthropic.com" in base and not token:
        raise RuntimeError(
            "no classifier endpoint or API key configured; refusing to send "
            "session context to api.anthropic.com")
    return base, token or "none"


def classify(data, cfg, model):
    import urllib.request  # lazy: rule-tier decisions never touch the network

    rules = build_rules(cfg, data.get("cwd") or PROJECT_DIR)
    messages, _ = transcript_context(data)
    tool_input = json.dumps(data.get("tool_input") or {})
    if len(tool_input) > 3000:
        tool_input = tool_input[:3000] + " ...[truncated]"

    user_prompt = (
        "Working directory: %s\n"
        "Permission mode: %s\n"
        "User's recent messages (oldest first):\n%s\n"
        "Pending action:\n  tool: %s\n  input: %s\n"
        % (data.get("cwd"), data.get("permission_mode", "unknown"),
           "\n".join("  " + m for m in messages) or "  (none)",
           data.get("tool_name", ""), tool_input)
    )

    base, token = classifier_endpoint(cfg)
    payload = {
        "model": model,
        "max_tokens": 400,
        "system": SYSTEM_PROMPT.replace("{rules}", rules),
        "messages": [{"role": "user", "content": user_prompt}],
    }
    request = urllib.request.Request(
        base + "/v1/messages",
        data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            "x-api-key": token,
            "authorization": "Bearer " + token,
        },
    )
    timeout = cfg.get("timeout_seconds", MODEL_TIMEOUT)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode())

    text = "".join(part.get("text", "") for part in body.get("content", [])
                   if isinstance(part, dict))
    return parse_verdict(text)


def parse_verdict(text):
    """Accept a JSON object, or prose that names a decision."""
    text = (text or "").strip()
    if not text:
        return None

    start = text.find("{")
    if start != -1:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        verdict = json.loads(text[start:i + 1])
                    except ValueError:
                        break
                    decision = (verdict.get("decision") or "").lower()
                    if decision in ("allow", "deny", "ask"):
                        return (decision, verdict.get("rule", "classifier"),
                                verdict.get("reason", ""))
                    break

    lowered = text.lower()
    for word, decision in (("deny", "deny"), ("block", "deny"),
                           ("ask", "ask"), ("allow", "allow")):
        if re.search(r"\b" + word + r"\b", lowered):
            return decision, "keyword", "classifier answered in prose: " + text[:120]
    return None


# ------------------------------------------------------------ main ---------


def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except ValueError:
        emit("ask", "auto-mode gate: could not parse hook input")
        return

    cfg = load_config()
    if os.environ.get("AUTO_MODE_OFF") == "1" or cfg.get("disabled"):
        emit("allow", "auto-mode gate disabled")
        return

    tool = data.get("tool_name", "")
    started = time.time()

    safe_tools = DEFAULT_SAFE_TOOLS + cfg.get("allow_tools", [])
    if tool_matches(tool, safe_tools):
        emit("allow", "allow-listed tool %s" % tool)
        log({"ts": started, "session": data.get("session_id"), "tool": tool,
             "decision": "allow", "tier": "allowlist"})
        return

    decision, rule, reason = rule_tier(data, cfg)
    tier = "rules"

    if decision is None:
        key = hashlib.sha256(
            (tool + json.dumps(data.get("tool_input") or {})
             + (data.get("cwd") or "")).encode()
        ).hexdigest()
        cache = load_cache()
        cached = cache.get(key)
        if cached:
            decision, rule, reason, tier = (cached["decision"], cached["rule"],
                                           cached["reason"], "cache")
        else:
            model = resolve_model(data, cfg)
            if not model:
                decision, rule, reason, tier = (
                    "ask", "No-Classifier",
                    "no classifier model could be resolved", "classifier")
            else:
                try:
                    verdict = classify(data, cfg, model)
                except Exception as exc:      # endpoint down, timeout, bad response
                    verdict = None
                    reason = "classifier call failed: %s" % exc
                if verdict:
                    decision, rule, reason = verdict
                else:
                    decision, rule = "ask", "No-Verdict"
                    reason = reason or "the classifier could not produce a verdict"
                tier = "classifier"
                if decision != "ask":
                    cache[key] = {"decision": decision, "rule": rule,
                                  "reason": reason, "ts": time.time()}
                    save_cache(cache)

    emit(decision, reason)
    log({"ts": started, "elapsed": round(time.time() - started, 3),
         "session": data.get("session_id"), "tool": tool,
         "input": (json.dumps(data.get("tool_input") or {}))[:300],
         "decision": decision, "rule": rule, "reason": reason, "tier": tier})


if __name__ == "__main__":
    main()
