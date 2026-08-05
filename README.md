<div align="center">

# 🛡️ trivy-remediator

**Fix Trivy findings without making them worse.**

A Claude Code plugin that remediates [Trivy](https://github.com/aquasecurity/trivy) vulnerability
findings through a **fail-closed, dual-agent workflow**: Claude writes narrow, evidence-backed
fixes while **OpenAI Codex independently challenges** the plan, the patch, and the final diff at
mandatory gates — no suppressions, no force upgrades, no invented evidence, no unreviewed pushes.

[![Claude Code Plugin](https://img.shields.io/badge/Claude_Code-Plugin-D97757?logo=anthropic&logoColor=white)](https://docs.claude.com/en/docs/claude-code)
[![Powered by ask-codex](https://img.shields.io/badge/dual--agent-ask--codex-412991?logo=openai&logoColor=white)](https://github.com/emirdegirmenci/ask-codex)
[![Trivy](https://img.shields.io/badge/scanner-Trivy-1904DA)](https://github.com/aquasecurity/trivy)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/emirdegirmenci/trivy-remediator/releases)

`#trivy` · `#cve` · `#vulnerability-remediation` · `#container-security` · `#devsecops` · `#codex` · `#claude-code`

</div>

---

## Why

Most "fix the CVEs" automation makes things worse: it edits `.trivyignore`, force-bumps a major
version, migrates a package manager, or claims `FIXED` without ever rescanning. **trivy-remediator**
does the opposite. It treats *no change* as better than an unverified one, and it never trusts a
single agent's judgment on a security fix.

The core idea: **two agents, one writer.** Claude Code plans and applies the change; OpenAI Codex —
through the [`ask-codex`](https://github.com/emirdegirmenci/ask-codex) plugin — reviews it as a
skeptical adversary at three mandatory gates. Silence, timeout, or "looks good" is **not** approval.

## What it does

- **Accepts any report form** — pasted table, log, screenshot, JSON, CSV, SARIF, or a fresh repo scan.
- **Normalizes without inventing** — never fabricates a version, CVE, package origin, or command.
- **Maps each finding to the controlling file** — Dockerfile, `pyproject.toml`, lockfile, `package.json`, …
- **Applies one narrow group at a time** — minimal manifest/lockfile edits, no force flags, no broad rewrites.
- **Gates every step through Codex** — `PLAN_GATE`, `PATCH_GATE`, `FINAL_GATE` with evidence-backed consensus.
- **Verifies for real** — rebuild, run tests, fresh Trivy scan, before/after comparison; fail-closed threshold.
- **Reviews before push** — `/code-review` + `/security-review` + final Codex gate, and only pushes when explicitly asked.

## Requirements

| Dependency | Why |
|---|---|
| [Claude Code](https://docs.claude.com/en/docs/claude-code) | host runtime |
| **[`ask-codex` plugin](https://github.com/emirdegirmenci/ask-codex)** | provides the `/ask-codex` reviewer used at every gate — **required** |
| [Trivy](https://github.com/aquasecurity/trivy) | to run fresh scans + before/after comparison (not needed for report-only analysis) |
| Python 3.9+ | for the bundled parse / diff-guard / compare scripts |

> Without `ask-codex` installed and reachable, the skill reports `BLOCKED` by design — it will not
> silently degrade to a single agent. Install it first.

## Install

```
# 1. the required reviewer
/plugin marketplace add emirdegirmenci/ask-codex
/plugin install ask-codex@ask-codex

# 2. this plugin
/plugin marketplace add emirdegirmenci/trivy-remediator
/plugin install trivy-remediator@trivy-remediator
```

Or copy `skills/trivy-remediator/` into `~/.claude/skills/` for a personal, all-projects install.

## Use it

Paste a Trivy report or point Claude at a repo/image:

- *"Here's my Trivy scan output — remediate the HIGH/CRITICAL findings."*
- *"Scan this image with Trivy and fix what's safely fixable."*

It will scope the repo, normalize the findings, build a remediation plan, and **stop at the Codex
plan gate** before touching a file — then proceed one narrow group at a time through patch and final
gates, rescanning and comparing before/after, and pushing only if you explicitly ask and every gate
passed.

## Guardrails (the invariants)

1. Never suppress a finding or weaken scan policy (`.trivyignore`, thresholds, CI exit codes).
2. Never force-upgrade, broad-update, migrate package managers, or do unrelated refactors.
3. Never make a major jump / OS-family change / package removal without explicit approval.
4. Never claim `FIXED` without passing tests, a rebuilt artifact, a fresh scan, and a clean comparison.
5. Never push until `/code-review`, `/security-review`, and the final Codex gate all pass.
6. Preserve unrelated working-tree changes; stop on overlapping edits.

Full policy: [`skills/trivy-remediator/references/`](./skills/trivy-remediator/references/).

## License

[MIT](./LICENSE) © Emir Degirmenci

---

<div align="center">
<sub>Not affiliated with Aqua Security, OpenAI, or Anthropic. "Trivy", "Codex", and "Claude" are trademarks of their respective owners.</sub>
</div>
