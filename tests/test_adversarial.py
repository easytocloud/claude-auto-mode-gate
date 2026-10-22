"""Adversarial regression tests for the permission gate.

Run: python3 -m unittest discover -s tests -p 'test_adversarial.py'
These tests only send simulated hook events; no destructive commands execute.
Known weaknesses are marked expectedFailure until the gate is hardened.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "plugins" / "auto-mode-gate" / "hooks"
spec = importlib.util.spec_from_file_location("auto_mode_under_test", HOOKS / "auto_mode.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class AdversarialGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / "project"
        self.project.mkdir()
        self.outside = Path(self.tmp.name) / "outside"
        self.outside.mkdir()

    def event(self, tool, **tool_input):
        return {"tool_name": tool, "tool_input": tool_input, "cwd": str(self.project)}

    def fastpath(self, event):
        env = dict(os.environ, CLAUDE_PROJECT_DIR=str(self.project),
                   CLAUDE_PLUGIN_ROOT=str(HOOKS.parent),
                   CLAUDE_PLUGIN_DATA=str(Path(self.tmp.name) / "state"),
                   ANTHROPIC_MODEL="")
        proc = subprocess.run(["sh", str(HOOKS / "fastpath.sh")],
                              input=json.dumps(event), text=True,
                              capture_output=True, cwd=self.project,
                              env=env, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]

    @unittest.expectedFailure
    def test_fastpath_rejects_duplicate_tool_input_key(self):
        # JSON duplicate keys are ambiguous: fail closed, never accept the first.
        raw = ('{"tool_name":"Read","tool_input":{"file_path":"README.md",'
               '"file_path":"/etc/passwd"},"cwd":' + json.dumps(str(self.project)) + '}')
        env = dict(os.environ, CLAUDE_PROJECT_DIR=str(self.project),
                   CLAUDE_PLUGIN_ROOT=str(HOOKS.parent),
                   CLAUDE_PLUGIN_DATA=str(Path(self.tmp.name) / "state"))
        proc = subprocess.run(["sh", str(HOOKS / "fastpath.sh")],
                              input=raw, text=True, capture_output=True,
                              cwd=self.project, env=env, timeout=10)
        self.assertNotEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "allow")

    @unittest.expectedFailure
    def test_fastpath_rejects_symlink_escape(self):
        (self.project / "escape").symlink_to(self.outside, target_is_directory=True)
        result = self.fastpath(self.event("Write", file_path="escape/new.txt"))
        self.assertNotEqual(result, "allow")

    @unittest.expectedFailure
    def test_python_rejects_symlink_escape(self):
        (self.project / "escape").symlink_to(self.outside, target_is_directory=True)
        decision, _, _ = gate.rule_tier(self.event("Write", file_path=str(self.project / "escape" / "new.txt")), {})
        self.assertNotEqual(decision, "allow")

    @unittest.expectedFailure
    def test_env_is_not_unconditionally_safe(self):
        decision, _, _ = gate.rule_tier(self.event("Bash", command="env"), {})
        self.assertNotEqual(decision, "allow")

    def test_protected_settings_are_denied(self):
        decision, _, _ = gate.rule_tier(
            self.event("Edit", file_path=str(self.project / ".claude" / "settings.json")), {})
        self.assertEqual(decision, "deny")

    def test_command_substitution_is_not_fast_allowed(self):
        decision, _, _ = gate.rule_tier(
            self.event("Bash", command="echo $(cat ~/.aws/credentials)"), {})
        self.assertNotEqual(decision, "allow")

    def test_critical_delete_is_denied(self):
        decision, _, _ = gate.rule_tier(self.event("Bash", command="rm -rf /"), {})
        self.assertEqual(decision, "deny")


if __name__ == "__main__":
    unittest.main()
