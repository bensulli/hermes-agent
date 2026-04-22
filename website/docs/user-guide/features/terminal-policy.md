---
sidebar_position: 7
title: "Terminal Policy"
description: "Allow/block list for the terminal tool — enforce which shell commands Hermes can run, with interactive approval for new executables."
---

# Terminal Policy

`terminal_policy` is a per-command allow/block list applied **before** the
terminal tool spawns a shell. It runs before the existing dangerous-command
detector, so blocked commands never execute — regardless of approval mode or
`--yolo`.

Use terminal policy when you want Hermes to:

- execute only a fixed set of binaries
- reject shell features (pipes, redirection, command substitution)
- ask permission when it tries to run a new command, and optionally persist
  that approval to config

## Quick start

Add a `terminal_policy` block to `~/.hermes/config.yaml`:

```yaml
terminal_policy:
  enabled: true
  default: ask
  allow_commands:
    - git
    - ls
    - pwd
    - python
    - pytest
  block_commands:
    - rm
    - sudo
    - dd
    - mkfs
    - shutdown
    - reboot
  allow_rules:
    - exe: git
      args_regex: "^(status|diff|log|show)(\\s|$)"
  allow_workdirs:
    - /home/hermes/projects
    - /tmp
  deny_shell_features: true
  allow_env_assignments: false
```

Restart the CLI or the gateway for the change to take effect.

## How it works

1. The command string is tokenized with `shlex` (quote-aware).
2. If `deny_shell_features: true`, unquoted shell control tokens are rejected:
   `|`, `||`, `&`, `&&`, `;`, `<`, `>`, `(`, `)`, command substitution `$(...)`,
   process substitution `<(...)`/`>(...)`, and backticks.  Quoted characters
   (`grep "foo|bar"`) are left alone.
3. If `allow_env_assignments: false`, leading `FOO=bar …` prefixes are
   rejected.
4. The executable is normalized to its basename (so `/usr/bin/git` is
   treated as `git`).
5. Decision order:
   - `block_commands` always wins (hard deny).
   - `allow_workdirs` — if set and the `workdir` parameter is outside every
     approved root, deny.
   - Allow if the executable is in `allow_commands`, already session-approved,
     or matches any entry in `allow_rules`.
   - Otherwise apply `default`:
     - `deny` — block the command.
     - `ask` — request user approval (see below).
     - `allow` — let it run.

## Approval modes for new commands

When `default: ask`, an unknown executable triggers the standard Hermes
approval flow:

| Choice | Effect |
|--------|--------|
| `once` | Allow this single invocation. Nothing persisted. |
| `session` | Allow the executable for the rest of this session. |
| `always` | Persist a **narrow `allow_rules` entry** to config. |

### What `always` actually writes

`always` does **not** dump the full command into the config. It writes the
smallest rule that still matches similar invocations:

| Approved command | Rule written to `terminal_policy.allow_rules` |
|------------------|-----------------------------------------------|
| `git status` | `{exe: git, args_regex: "^status(\\s|$)"}` |
| `git log --oneline` | `{exe: git, args_regex: "^log(\\s|$)"}` |
| `rg TODO src/` | `{exe: rg}` (no narrow subcommand) |
| `python -V` | `{exe: python}` (first arg is a flag) |
| `pytest` (no args) | `{exe: pytest}` |

So approving `git status` once **does not** silently enable `git push --force`.
A later `git push` will trigger a fresh approval prompt.

### Gateway approvals

In gateway mode the approval request is delivered to the chat that initiated
the command. Respond with `/approve`, `/approve session`, `/approve always`,
or `/deny` — same UX as the existing dangerous-command approval flow.

## Config reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for the policy. |
| `default` | enum | `"deny"` | One of `"deny"`, `"ask"`, `"allow"`. |
| `allow_commands` | list[str] | `[]` | Executable names (basename) that are always allowed. |
| `block_commands` | list[str] | `[]` | Executable names that are always blocked. |
| `allow_rules` | list[dict] | `[]` | Per-executable rules with optional `args_regex`. |
| `allow_workdirs` | list[str] | `[]` | Absolute paths; when set, commands must run inside one of these trees. |
| `deny_shell_features` | bool | `true` | Reject unquoted pipes, redirection, substitution, and job control. |
| `allow_env_assignments` | bool | `false` | Allow `FOO=bar command ...` prefixes. |

### `allow_rules` entry shape

```yaml
allow_rules:
  - exe: git
    args_regex: "^(status|diff|log|show)(\\s|$)"
  - exe: python
    args_regex: "^-m\\s+pytest(\\s|$)"
  - exe: rg           # no args_regex → any invocation of rg
```

`args_regex` is matched against the space-joined remaining arguments with
`re.match` (so it anchors at the start). An entry with no `args_regex` allows
any invocation of that executable.

## Interactions with other guards

- Terminal policy runs **before** the dangerous-command detector. A command
  blocked by policy never reaches pattern detection.
- `--yolo` / `HERMES_YOLO_MODE` bypasses dangerous-command approvals but
  **does not** bypass terminal policy. Policy is an explicit user-configured
  access control list, so it applies even in yolo mode.
- Non-local backends (`docker`, `singularity`, `modal`, `daytona`) rely on
  sandbox isolation for safety, but the policy still enforces allow/block
  decisions if you enable it. Disable it for those backends if the sandbox
  is your only trust boundary.
- MCP servers and tools that shell out on their own are **not** subject to
  terminal policy — it wraps the built-in `terminal` tool only.

## Tips

- Start with `default: ask` and let the approval prompts teach Hermes your
  real working set. Over a few sessions `allow_rules` becomes an accurate
  allow list tailored to how you use Hermes.
- Keep `deny_shell_features: true` unless you have a specific reason to pipe
  or redirect from the agent. Most tasks can be split into multiple terminal
  calls.
- For risky interpreters (`python`, `node`, `perl`, `ruby`), prefer a narrow
  `args_regex` rule over a bare `allow_commands` entry — bare allow permits
  `python -c "..."` which is arbitrary code execution.
- `allow_workdirs` entries are resolved via `Path.resolve()`, which follows
  symlinks. Don't use an allow_workdir that contains a symlink pointing
  outside the tree you intend to trust.
