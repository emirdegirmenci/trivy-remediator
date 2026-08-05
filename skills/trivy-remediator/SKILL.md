---
name: trivy-remediator
description: Analyze and safely remediate Trivy findings supplied as pasted chat text, Markdown or terminal tables, logs, screenshots, JSON, CSV, SARIF, or repository scan output. Coordinate the primary coding agent with the user's `/ask-codex` reviewer at mandatory plan, patch, and final gates; apply only narrow evidence-backed fixes; rebuild, test, rescan, and compare results; and require `/code-review` plus `/security-review` before any push. Use when Trivy repeatedly reports CVEs or when a Claude/Codex workflow must fix vulnerabilities without suppressions, force upgrades, invented evidence, or unreviewed pushes.
---

# Trivy Remediator

Remediate Trivy findings through a fail-closed, dual-agent workflow. Treat the primary agent, normally Claude Code, as the single writer. Treat `/ask-codex` as an independent reviewer and challenger. Prefer no change over an unverified, disputed, or broad change.

## Core invariants

1. Accept a Trivy report in any readable form. Do not require JSON or CSV.
2. Never invent missing cells, versions, CVEs, package origins, scan flags, commands, or test suites.
3. Never suppress a finding automatically. Do not modify `.trivyignore`, ignore YAML, scanner filters, severity thresholds, or CI exit codes.
4. Never use force flags, broad dependency updates, package-manager migration, or unrelated refactors.
5. Never make a major dependency jump, OS-family change, package removal/replacement, or structural container rewrite without explicit approval.
6. Require `/ask-codex` at the plan gate, patch gate, and final gate. Do not treat silence, timeout, or tool failure as approval.
7. Never claim `FIXED` without successful tests, artifact rebuild, fresh Trivy scan, and passing before/after comparison.
8. Never push until `/code-review`, `/security-review`, and final `/ask-codex` review all pass after the last code change.
9. Never commit, push, publish, or open a pull request unless explicitly requested.
10. Preserve unrelated working-tree changes and stop on overlapping edits.
11. Read [references/remediation-policy.md](references/remediation-policy.md) and [references/dual-agent-protocol.md](references/dual-agent-protocol.md) before editing files.

## Workflow

### 1. Establish scope and repository state

- Identify the repository root, supplied report, target artifact, scanner command/configuration when available, and severity threshold.
- Run `git status --short`. List dirty files and avoid unrelated changes.
- Do not install Trivy, package managers, slash commands, plugins, or system packages without explicit permission.
- Verify that `/ask-codex` is available before making changes. If it is unavailable, report `BLOCKED`; do not silently continue as a single agent.
- If only a report is supplied, analyze it first. Do not assume the repository, Dockerfile, or image is available.

### 2. Normalize the report without format assumptions

Determine the input path:

- **JSON or CSV file:** run `scripts/parse_trivy_report.py`.
- **SARIF or another structured file:** read the relevant findings and normalize them in memory; do not discard fields merely because the parser does not support the format.
- **Pasted Markdown/terminal table or log:** extract rows directly from the conversation and preserve the visible headers and values.
- **Screenshot or rendered table:** transcribe only clearly readable values. Mark unclear values `UNKNOWN`; do not use OCR guesses as remediation evidence.
- **Repository or image with no supplied report:** run the repository's existing Trivy command, preferably producing JSON for deterministic comparison.

For JSON or CSV, run:

```bash
python <skill-root>/scripts/parse_trivy_report.py <report> -o /tmp/trivy-normalized.json
```

For every input form, normalize at least:

- Target/artifact when visible
- Result class/type or ecosystem when proven
- Package name
- Installed version
- Vulnerability ID
- Severity
- Fixed version and status when visible
- Layer/source path when visible

Follow [references/report-contract.md](references/report-contract.md). If the report is truncated or omits fields, state the limitation and classify affected groups conservatively. A fresh scan may supplement the supplied report, but never pretend the original input contained data it did not contain.

For each package, calculate a single `required_fixed_version` that satisfies all visible CVEs using the correct ecosystem comparator. If the comparator or ecosystem is unknown, use `UNKNOWN` and classify the group as `REPORT_ONLY`.

### 3. Map findings to repository-controlled sources

Inspect evidence before proposing a fix:

- OS packages: Dockerfile, base image tag/digest, apt layers, Trivy layer DiffID, and image history.
- Python: `pyproject.toml`, requirement/constraint files, lockfiles, and CI install commands.
- Node.js: `package.json`, lockfile, workspace configuration, and CI install commands.
- Other ecosystems: manifest, lockfile, and repository-native package tooling.
- Unknown packages: search manifests and lockfiles; do not infer the ecosystem from the package name alone.

Assign exactly one decision from [references/remediation-policy.md](references/remediation-policy.md): `SAFE_AUTO`, `NEEDS_APPROVAL`, `NO_FIX_AVAILABLE`, or `REPORT_ONLY`.

### 4. Build the primary remediation plan

Produce the plan table defined in [references/report-contract.md](references/report-contract.md). Include:

- Package and ecosystem
- Installed and required minimum versions
- Covered CVEs
- Repository source controlling the version
- Decision class and rationale
- Exact build, test, and rescan steps

Do not edit anything yet.

### 5. Pass the mandatory Codex plan gate

Invoke `/ask-codex` using the `PLAN_GATE` template in [references/dual-agent-protocol.md](references/dual-agent-protocol.md). Ask Codex to challenge:

- Report transcription and grouping
- Package origin and controlling file
- Version comparison and chosen minimum
- Major/breaking-change classification
- Scope of the proposed patch
- Verification and rescan plan
- Missing evidence or safer alternatives

Verify Codex's claims against the report and repository. Do not obey feedback blindly. Reach evidence-backed agreement on every `SAFE_AUTO` group.

- If both agents agree, continue.
- If Codex identifies a valid issue, revise the plan and invoke `/ask-codex` again.
- If disagreement remains unresolved, downgrade the group to `NEEDS_APPROVAL` or `REPORT_ONLY` and do not edit it.
- If `/ask-codex` fails, times out, returns no substantive review, or cannot access enough context, report `BLOCKED`.

### 6. Apply one narrow remediation group at a time

- Keep one writer. The primary agent applies the patch; Codex reviews and proposes corrections.
- Change only the controlling manifest/Dockerfile and the minimum lockfile entries required.
- Preserve the package manager, base-image family, build system, and formatting.
- Do not combine unrelated CVE groups in one speculative change.
- After each group, inspect the diff and run the smallest relevant validation.
- If the resolver requests a major jump, force flag, peer override, broad lockfile rewrite, or unrelated package changes, revert that group and classify it as `NEEDS_APPROVAL`.

Use ecosystem rules from [references/remediation-policy.md](references/remediation-policy.md). Use [references/command-playbook.md](references/command-playbook.md) only when repository-native commands are absent and all inputs are known.

### 7. Guard the diff

Run:

```bash
python <skill-root>/scripts/guard_diff.py -o /tmp/trivy-diff-guard.json
```

- Stop on any blocker.
- Review every warning and remove or justify the risky change.
- Treat a passing guard as necessary but insufficient.

### 8. Pass the mandatory Codex patch gate

Invoke `/ask-codex` using the `PATCH_GATE` template. Supply the exact diff, report groups addressed, commands already run, and unresolved warnings.

Require Codex to inspect:

- Whether the diff fixes the stated findings rather than hiding them
- Unrelated or generated changes
- Lockfile blast radius
- Docker/runtime regressions
- Security-sensitive behavior changes
- Missing tests or scan steps

Resolve every blocking finding. After any code change, rerun the diff guard and invoke the patch gate again. Do not proceed on unresolved disagreement.

### 9. Verify locally

Run, in this order:

1. Frozen/locked dependency installation or lock validation.
2. Repository-configured lint, static analysis, and type checks relevant to changed files.
3. Relevant unit/integration tests, followed by the full documented test gate when feasible.
4. Container build with refreshed base and no stale cache when remediating an image.
5. Existing health check or smoke test against the rebuilt artifact.

On any failure, stop. Do not hide, skip, weaken, or relabel the check. Report `NOT_VERIFIED` unless the patch is reverted.

### 10. Rescan and enforce the comparison gate

Generate a fresh Trivy report using the same or stricter scanner settings. Prefer JSON for machine comparison, regardless of the original report format.

When a machine-readable before report exists, run:

```bash
python <skill-root>/scripts/compare_trivy_reports.py <before-report> <after-report> --minimum-severity HIGH -o /tmp/trivy-comparison.json
```

When the original report is only a pasted table/log/screenshot:

- Compare each normalized target CVE/package/version against the fresh scan.
- Record which original findings disappeared, remain, or cannot be matched.
- Treat ambiguous matching as failure, not success.
- Fail if any new finding appears at or above the agreed threshold.

Never lower the threshold merely to pass. If the Trivy database changed and introduced unrelated findings, report them separately while keeping the gate fail-closed.

### 11. Run the mandatory pre-push review loop

Run this loop after tests and rescan pass and after the last code change:

1. Invoke `/code-review`.
2. Resolve every blocking or high-confidence actionable finding.
3. Rerun affected tests, build, rescan, comparison, diff guard, and Codex patch gate after any change.
4. Invoke `/code-review` again until it passes with no unresolved blocking finding.
5. Invoke `/security-review`.
6. Resolve every blocking or high-confidence actionable security finding.
7. Rerun the full affected verification chain and both reviews after any change.
8. Invoke final `/ask-codex` using the `FINAL_GATE` template.

Treat a missing command, failed review, incomplete review, unresolved finding, or review performed before the last change as a failed gate. Do not push.

### 12. Push only through the final gate

Before `git push`, require all of the following after the final code change:

- Diff guard passed
- Tests/build/smoke checks passed
- Fresh Trivy scan and comparison passed
- `/code-review` passed
- `/security-review` passed
- Final `/ask-codex` review passed
- `git diff --check` passed
- `git status --short` contains only intended changes
- User explicitly requested a push

If any condition is false, set `Push gate: BLOCKED` and do not push. Never use `--no-verify`, force push, or bypass hooks.

### 13. Report results

Follow [references/report-contract.md](references/report-contract.md). Include actual commands and exit codes, before/after counts, remaining/new CVEs, files changed, Codex disagreements and resolutions, review results, and approval-required items.

Use only these remediation statuses: `FIXED`, `PARTIALLY_FIXED`, `BLOCKED`, `NOT_VERIFIED`, or `NO_CHANGE`.

Also report one push-gate state: `PASSED`, `BLOCKED`, or `NOT_REQUESTED`.

## Stop conditions

Stop modifying files and report `BLOCKED` or `REPORT_ONLY` when any condition applies:

- `/ask-codex` is unavailable or a required Codex gate cannot complete.
- No fixed version exists.
- Package origin cannot be mapped confidently.
- Required values in an unstructured report are unreadable or ambiguous.
- The required update crosses a major release or OS family.
- The fix requires a force/resolver bypass, package replacement/removal, or suppression.
- Tests are missing for a breaking-risk change.
- The repository contains overlapping uncommitted edits.
- Required tools, credentials, registry access, or source repositories are unavailable.
- Rebuild or rescan cannot be reproduced with equivalent settings.
- `/code-review` or `/security-review` is unavailable or has unresolved findings before a requested push.
