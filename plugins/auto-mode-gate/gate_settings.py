#!/usr/bin/env python3
"""Register the auto-mode gate in a project's Claude Code settings.

Used by install.sh and uninstall.sh, and by selftest.py. Kept as a module so
the JSON merge can be tested without touching a real project.

    python3 gate_settings.py install <target-dir>
    python3 gate_settings.py remove  <target-dir>
"""

import json
import os
import subprocess
import sys

DENY_FALLBACK = (
    '{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
    '"permissionDecision":"deny",'
    '"permissionDecisionReason":"auto-mode gate could not run; denying by default"}}'
)

# The shell fallback matters: if fastpath.sh is missing or broken, the hook
# still emits a deny rather than silently allowing the tool call.
HOOK_COMMAND = (
    'sh "${CLAUDE_PROJECT_DIR:-.}/.claude/hooks/fastpath.sh" '
    "|| printf %s '" + DENY_FALLBACK + "'"
)

MARKERS = ("fastpath.sh", "auto_mode.py")

MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml", "Cargo.toml",
             "go.mod", "Gemfile", "composer.json", "pom.xml")


def is_gate_handler(handler):
    command = handler.get("command", "")
    return any(marker in command for marker in MARKERS)


def load_settings(path):
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def register_hook(settings):
    """Add (or replace) the gate handler. Idempotent."""
    hooks = settings.setdefault("hooks", {})
    pre = hooks.setdefault("PreToolUse", [])

    group = next((g for g in pre if any(is_gate_handler(h) for h in g.get("hooks", []))),
                 None)
    if group is None:
        group = {"matcher": "", "hooks": []}
        pre.append(group)

    group["hooks"] = [h for h in group.get("hooks", []) if not is_gate_handler(h)]
    group["hooks"].insert(0, {
        "type": "command",
        "command": HOOK_COMMAND,
        "timeout": 20,
        "onFailure": "block",
        "statusMessage": "auto-mode gate",
    })
    return settings


def remove_hook(settings):
    """Remove the gate handler, leaving every other hook alone."""
    pre = settings.get("hooks", {}).get("PreToolUse", [])
    kept = []
    for group in pre:
        hooks = [h for h in group.get("hooks", []) if not is_gate_handler(h)]
        if hooks:
            group["hooks"] = hooks
            kept.append(group)
    if "hooks" in settings:
        settings["hooks"]["PreToolUse"] = kept
    return settings


def project_environment(target, base_url=None):
    """Describe the project so the classifier has a trust boundary to work with."""
    target = os.path.normpath(target)
    environment = ["Project: %s at %s" % (os.path.basename(target), target)]

    if os.path.isdir(os.path.join(target, ".git")):
        remotes = set()
        try:
            out = subprocess.run(["git", "remote", "-v"], cwd=target,
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    remotes.add(parts[1])
        except Exception:
            pass
        if remotes:
            environment.append("Source control remotes: " + ", ".join(sorted(remotes)))
        else:
            environment.append("Local git repository with no remote; nothing here "
                               "reaches a remote host")
    else:
        environment.append("Not a git repository: there are no remote "
                           "source-control destinations")

    manifests = [f for f in MANIFESTS if os.path.exists(os.path.join(target, f))]
    if manifests:
        environment.append("Declared dependencies live in: " + ", ".join(manifests))

    if base_url:
        environment.append("The agent's model endpoint is %s. That is the "
                           "classifier itself, not an external service" % base_url)
    return environment


def install(target):
    os.makedirs(os.path.join(target, ".claude", "hooks"), exist_ok=True)
    settings_path = os.path.join(target, ".claude", "settings.local.json")
    settings = load_settings(settings_path)
    register_hook(settings)
    with open(settings_path, "w") as fh:
        json.dump(settings, fh, indent=2)
        fh.write("\n")
    print("registered the hook in .claude/settings.local.json")

    config_path = os.path.join(target, ".claude", "auto-mode.json")
    if os.path.exists(config_path):
        print("keeping the existing .claude/auto-mode.json")
        return
    with open(config_path) as fh:
        cfg = json.load(fh)
    base_url = os.environ.get("ANTHROPIC_BASE_URL")
    if base_url:
        cfg["base_url"] = base_url.rstrip("/")
    cfg["environment"] = project_environment(target, cfg.get("base_url"))
    with open(config_path, "w") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    print("wrote .claude/auto-mode.json for this project")


def uninstall(target):
    settings_path = os.path.join(target, ".claude", "settings.local.json")
    settings = load_settings(settings_path)
    if not settings:
        print("no settings.local.json to clean")
        return
    register_removed = remove_hook(settings)
    with open(settings_path, "w") as fh:
        json.dump(register_removed, fh, indent=2)
        fh.write("\n")
    print("removed the hook from settings.local.json")
    for name in ("auto_mode.py", "fastpath.sh", "audit.jsonl", ".cache.json"):
        path = os.path.join(target, ".claude", "hooks", name)
        if os.path.exists(path):
            os.remove(path)
    print("deleted the hook files")


def main(argv):
    if len(argv) < 3 or argv[1] not in ("install", "remove"):
        print(__doc__)
        return 2
    target = argv[2]
    if not os.path.isdir(target):
        print("target directory does not exist: " + target)
        return 1
    (install if argv[1] == "install" else uninstall)(target)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
