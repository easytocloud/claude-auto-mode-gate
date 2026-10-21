# claude-auto-mode-gate

A `PreToolUse` hook that puts the permission gate back when you run Claude Code
with `--dangerously-skip-permissions`.

Claude Code's built-in **auto mode** decides every tool call with a
second model. It only works with a supported Anthropic model, so if you are
pointing Claude Code at a local gateway (Ollama, llama.cpp, LM Studio, vLLM, a
Bedrock proxy) you get no gate at all in bypass mode. This hook is the
drop-in replacement: it classifies every tool call with **the model the session
is already running**.

```bash
curl -sL https://raw.githubusercontent.com/easytocloud/claude-auto-mode-gate/main/install.sh | sh
```

Run it from the project directory you want to protect, then:

```bash
claude --dangerously-skip-permissions
```

Pin the install to a tag if you want a fixed version:

```bash
curl -sL https://raw.githubusercontent.com/easytocloud/claude-auto-mode-gate/v1.0.0/install.sh | sh
```

## What gets installed

| File | Role |
|---|---|
| `.claude/hooks/fastpath.sh` | Pre-filter: answers in-project file reads and edits in ~7 ms, no Python |
| `.claude/hooks/auto_mode.py` | The gate: hard rules, safe rules, then the model |
| `.claude/auto-mode.json` | Trust boundary and extra rules for this project |
| `.claude/hooks/audit.jsonl` | Every decision, written at runtime |
| `.claude/hooks/.cache.json` | Repeat-decision cache, 5-minute TTL |

The installer registers the hook in `.claude/settings.local.json` (creating it
if needed), without touching your existing hooks or permissions. Re-running it
is safe; it updates the files and never duplicates the hook entry.

## How a tool call is decided

| Tier | Cost | Outcome |
|---|---|---|
| 0. fastpath (shell) | ~7 ms | `allow` for `Read`/`Glob`/`Grep`/`LS`/`Write`/`Edit`/`MultiEdit`/`NotebookEdit` on a path inside the working directory, with no `..`, not under `.claude/` or `.git/` |
| 1. hard rules (regex) | ~1 ms | `deny`: `sudo`, piping a download into a shell, recursive delete of a critical or out-of-project path, touching the hook or settings files, cloud metadata endpoints, reading credential stores, re-launching the agent in bypass mode |
| 2. safe rules (regex) | ~1 ms | `allow`: read-only commands inside the project, `git status/diff/log`, the project's test and lint commands, allow-listed MCP tools |
| 3. the model | 1-15 s | `allow`, `deny` or `ask` |

Everything the fastpath cannot prove safe is piped to `auto_mode.py`, which is
the only place a `deny` or `ask` can come from.

If the classifier cannot be reached - endpoint down, timeout, unparseable
output - the call returns **`ask`**. In an interactive session that prompts you;
in a headless `claude -p` run there is nobody to answer, so the call is denied.
A hook that crashes is denied by the shell fallback in its command line.

## Verified behaviour

Tested on claude 2.1.303 with a local GGUF model behind `localhost:8000`:

- A hook `deny` blocks the tool call under `--dangerously-skip-permissions`.
- A hook `ask` blocks it too: it prompts interactively, and in `-p` runs it
  appears in `permission_denials` and the tool never executes.
- Hooks fire for every tool call, including in `claude -p` runs and in agents
  spawned by the `Agent` tool.
- `claude --bare` and `--safe-mode` skip hooks entirely, so the gate is not
  present there.

To confirm the `ask` path yourself, force the no-verdict route:

```bash
AUTO_MODE_MODEL=nonexistent-model claude -p "Run exactly this: touch probe2.txt" \
  --dangerously-skip-permissions --output-format json | jq '.permission_denials'
ls probe2.txt          # should not exist
```

## Tuning

`.claude/auto-mode.json` - every list is prepended to the hook's built-in rules:

```json
{
  "environment": ["Source control: github.com/acme and everything under it"],
  "allow": ["Pushing to the staging branch is routine for this project"],
  "soft_deny": ["Never touch anything under infra/terraform/prod/"],
  "hard_deny": [],
  "deny_commands": [["Ban-Downloads", "https://downloads\\.internal\\.acme\\.com"]],
  "allow_tools": ["^mcp__playwright__browser_evaluate$"],
  "model": "claude-sonnet-5-5",
  "base_url": "http://localhost:8000",
  "timeout_seconds": 8,
  "disabled": false
}
```

The installer fills in `environment` from the project it lands in (git remotes,
dependency manifests) and pins `base_url` to `ANTHROPIC_BASE_URL` if that
variable is set, so the classifier talks to the same endpoint the session does.

**Model resolution**, first match wins: `model` in the config → `AUTO_MODE_MODEL`
→ the `model` field of the last assistant message in the transcript →
`ANTHROPIC_MODEL` / `ANTHROPIC_DEFAULT_*_MODEL` → the `model` key in settings.

**Endpoint**: `base_url` in the config, then `ANTHROPIC_BASE_URL`, then the `env`
block in settings, then `api.anthropic.com`. If it resolves to
`api.anthropic.com` with no API key, the hook refuses to send session context
there and falls back to `ask`.

Run without the gate for one command:

```bash
AUTO_MODE_OFF=1 claude --dangerously-skip-permissions
```

## Self-test

```bash
python3 selftest.py
```

Offline and deterministic: it exercises the hard rules, the safe rules, path
containment, the verdict parser, and the shell fastpath, with the classifier
pointed at a closed port so the ambiguous cases resolve to `ask`.

## Removing it

```bash
sh uninstall.sh                      # from the project directory
GATE_TARGET=/path/to/project sh uninstall.sh
```

## Known limits

- **The gate protects itself.** Edits to anything under `.claude/` are denied,
  including its own files. Maintain it from a plain terminal or with
  `AUTO_MODE_OFF=1`.
- **Judgements are not deterministic.** Tier 3 is a model call; the same action
  can be allowed once and denied the next. Tiers 0-2 are deterministic - put the
  cases you want guaranteed in `deny_commands` and `allow_tools`.
- **Not covered:** `--bare`, `--safe-mode`, and sessions where workspace trust
  has not been accepted. `defer` requires `-p`.
- **Read-only ≠ harmless:** a `cat` of an out-of-project file is not waved
  through; it goes to the classifier.

## Requirements

Python 3.7+ (stdlib only), a POSIX shell, and `curl` or `wget` for the
installer. Claude Code 2.1.295+ for `onFailure: "block"`; everything else works
on any recent version.

## Licence

MIT.
