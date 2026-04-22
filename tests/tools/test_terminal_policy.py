"""Tests for terminal policy allow/block enforcement before shell execution."""

import json
from unittest.mock import MagicMock, patch

import tools.approval as approval_module


def _clear_policy_state():
    approval_module._permanent_approved.clear()
    approval_module.clear_session("default")
    approval_module.clear_session("test-session")


class TestTerminalPolicyChecks:
    def setup_method(self):
        _clear_policy_state()

    def teardown_method(self):
        _clear_policy_state()

    def test_unknown_command_blocked_when_default_deny(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        monkeypatch.setenv("HERMES_SESSION_KEY", "test-session")

        with patch(
            "hermes_cli.config.load_config",
            return_value={
                "terminal_policy": {
                    "enabled": True,
                    "default": "deny",
                    "allow_commands": ["git"],
                    "block_commands": [],
                    "allow_rules": [],
                    "allow_workdirs": [],
                    "deny_shell_features": True,
                    "allow_env_assignments": False,
                }
            },
        ):
            result = approval_module.check_terminal_policy("rg TODO src/")

        assert result["approved"] is False
        assert result["status"] == "blocked"
        assert "not in terminal policy allowlist" in result["message"].lower()

    def test_unknown_command_can_be_approved_for_session(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        monkeypatch.setenv("HERMES_SESSION_KEY", "test-session")

        with patch(
            "hermes_cli.config.load_config",
            return_value={
                "terminal_policy": {
                    "enabled": True,
                    "default": "ask",
                    "allow_commands": ["git"],
                    "block_commands": [],
                    "allow_rules": [],
                    "allow_workdirs": [],
                    "deny_shell_features": True,
                    "allow_env_assignments": False,
                }
            },
        ):
            result = approval_module.check_terminal_policy(
                "rg TODO src/",
                approval_callback=lambda *_args, **_kwargs: "session",
            )
            followup = approval_module.check_terminal_policy("rg FIXME src/")

        assert result["approved"] is True
        assert result["user_approved"] is True
        assert followup["approved"] is True

    def test_shell_metacharacters_blocked_even_for_allowed_command(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")

        with patch(
            "hermes_cli.config.load_config",
            return_value={
                "terminal_policy": {
                    "enabled": True,
                    "default": "deny",
                    "allow_commands": ["git"],
                    "block_commands": [],
                    "allow_rules": [],
                    "allow_workdirs": [],
                    "deny_shell_features": True,
                    "allow_env_assignments": False,
                }
            },
        ):
            result = approval_module.check_terminal_policy("git status && whoami")

        assert result["approved"] is False
        assert result["status"] == "blocked"
        assert "shell metacharacters" in result["message"].lower()

    def test_quoted_metacharacters_do_not_trigger_shell_block(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")

        with patch(
            "hermes_cli.config.load_config",
            return_value={
                "terminal_policy": {
                    "enabled": True,
                    "default": "deny",
                    "allow_commands": ["grep"],
                    "block_commands": [],
                    "allow_rules": [],
                    "allow_workdirs": [],
                    "deny_shell_features": True,
                    "allow_env_assignments": False,
                }
            },
        ):
            result = approval_module.check_terminal_policy('grep "foo|bar" file.txt')

        assert result["approved"] is True

    def test_command_substitution_blocked(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")

        with patch(
            "hermes_cli.config.load_config",
            return_value={
                "terminal_policy": {
                    "enabled": True,
                    "default": "allow",
                    "allow_commands": ["echo"],
                    "block_commands": [],
                    "allow_rules": [],
                    "allow_workdirs": [],
                    "deny_shell_features": True,
                    "allow_env_assignments": False,
                }
            },
        ):
            result = approval_module.check_terminal_policy("echo $(whoami)")

        assert result["approved"] is False
        assert result["status"] == "blocked"
        # Either message is acceptable — shlex may split $( into $ and ( tokens,
        # in which case the generic metacharacter guard triggers first.
        msg = result["message"].lower()
        assert "substitution" in msg or "metacharacters" in msg

    def test_block_commands_override_allowlist(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")

        with patch(
            "hermes_cli.config.load_config",
            return_value={
                "terminal_policy": {
                    "enabled": True,
                    "default": "allow",
                    "allow_commands": ["git", "rm"],
                    "block_commands": ["rm"],
                    "allow_rules": [],
                    "allow_workdirs": [],
                    "deny_shell_features": True,
                    "allow_env_assignments": False,
                }
            },
        ):
            result = approval_module.check_terminal_policy("rm file.txt")

        assert result["approved"] is False
        assert result["status"] == "blocked"
        assert "blocklisted" in result["message"].lower()


class TestNarrowAllowRulePersistence:
    def test_build_narrow_rule_for_subcommand(self):
        rule = approval_module._build_terminal_policy_narrow_rule("git", ["status"])
        assert rule == {"exe": "git", "args_regex": r"^status(\s|$)"}

    def test_build_narrow_rule_flag_only(self):
        rule = approval_module._build_terminal_policy_narrow_rule("python", ["-V"])
        assert rule == {"exe": "python"}

    def test_build_narrow_rule_no_args(self):
        rule = approval_module._build_terminal_policy_narrow_rule("rg", [])
        assert rule == {"exe": "rg"}

    def test_always_persists_narrow_rule(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        monkeypatch.setenv("HERMES_SESSION_KEY", "test-session")

        initial_config = {
            "terminal_policy": {
                "enabled": True,
                "default": "ask",
                "allow_commands": [],
                "block_commands": [],
                "allow_rules": [],
                "allow_workdirs": [],
                "deny_shell_features": True,
                "allow_env_assignments": False,
            }
        }
        saved = {}

        def fake_save(cfg):
            saved["cfg"] = cfg

        _clear_policy_state()
        with patch("hermes_cli.config.load_config", return_value=initial_config), patch(
            "hermes_cli.config.save_config", side_effect=fake_save
        ):
            result = approval_module.check_terminal_policy(
                "git status",
                approval_callback=lambda *_a, **_kw: "always",
            )

        assert result["approved"] is True
        assert saved["cfg"]["terminal_policy"]["allow_rules"] == [
            {"exe": "git", "args_regex": r"^status(\s|$)"}
        ]

    def test_narrow_rule_matches_subcommand_variants(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")

        config = {
            "terminal_policy": {
                "enabled": True,
                "default": "deny",
                "allow_commands": [],
                "block_commands": [],
                "allow_rules": [{"exe": "git", "args_regex": r"^status(\s|$)"}],
                "allow_workdirs": [],
                "deny_shell_features": True,
                "allow_env_assignments": False,
            }
        }

        with patch("hermes_cli.config.load_config", return_value=config):
            allowed = approval_module.check_terminal_policy("git status")
            allowed_with_flag = approval_module.check_terminal_policy("git status --short")
            denied_other = approval_module.check_terminal_policy("git push origin main")

        assert allowed["approved"] is True
        assert allowed_with_flag["approved"] is True
        assert denied_other["approved"] is False


class TestTerminalToolIntegration:
    def test_terminal_tool_blocks_before_execution_when_policy_denies(self, monkeypatch):
        monkeypatch.setenv("HERMES_INTERACTIVE", "1")
        monkeypatch.setenv("HERMES_SESSION_KEY", "test-session")

        from tools import terminal_tool as terminal_tool_module

        env_config = {
            "env_type": "local",
            "timeout": 180,
            "cwd": "/tmp",
            "host_cwd": None,
            "modal_mode": "auto",
            "docker_image": "",
            "singularity_image": "",
            "modal_image": "",
            "daytona_image": "",
        }

        mock_env = MagicMock()
        mock_env.execute.return_value = {"output": "should not run", "returncode": 0}

        with patch(
            "hermes_cli.config.load_config",
            return_value={
                "terminal_policy": {
                    "enabled": True,
                    "default": "deny",
                    "allow_commands": ["git"],
                    "block_commands": [],
                    "allow_rules": [],
                    "allow_workdirs": [],
                    "deny_shell_features": True,
                    "allow_env_assignments": False,
                }
            },
        ), patch("tools.terminal_tool._get_env_config", return_value=env_config), patch(
            "tools.terminal_tool._start_cleanup_thread"
        ), patch("tools.terminal_tool._active_environments", {"default": mock_env}), patch(
            "tools.terminal_tool._last_activity", {"default": 0}
        ):
            result = json.loads(terminal_tool_module.terminal_tool(command="rg TODO src/"))

        assert result["status"] == "blocked"
        assert "terminal policy" in result["error"].lower()
        mock_env.execute.assert_not_called()
