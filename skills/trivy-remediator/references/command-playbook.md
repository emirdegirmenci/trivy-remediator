# Command Playbook

Use repository-native commands from `Makefile`, task runners, CI workflows, or contributor documentation. The examples below are safe defaults, not permission to guess.

## Analyze chat/table/log input

Normalize visible rows into the plan table in `report-contract.md`. Keep missing fields `UNKNOWN`. Do not force unstructured input through a lossy parser merely to create JSON.

When repository access exists, supplement incomplete input with the existing Trivy command or a fresh scan. Clearly separate supplied-report evidence from newly generated evidence.

## Normalize JSON or CSV

```bash
python scripts/parse_trivy_report.py trivy-report.json -o /tmp/trivy-normalized.json
python scripts/parse_trivy_report.py trivy-report.csv -o /tmp/trivy-normalized.json
```

Inspect every warning. Unknown class/type blocks automatic ecosystem selection.

## Mandatory collaboration gates

Invoke these as slash commands, not shell commands:

```text
/ask-codex <PLAN_GATE prompt>
/ask-codex <PATCH_GATE prompt>
/code-review
/security-review
/ask-codex <FINAL_GATE prompt>
```

Use the full templates in `dual-agent-protocol.md`. A missing or non-substantive response is a failed gate.

## Check the patch for forbidden shortcuts

```bash
python scripts/guard_diff.py -o /tmp/trivy-diff-guard.json
```

Treat exit code 2 as a hard stop. Review warnings manually.

## Compare machine-readable scans

```bash
python scripts/compare_trivy_reports.py before.json after.json --minimum-severity HIGH -o /tmp/trivy-comparison.json
```

Exit code 0 means the threshold gate passed. Exit code 2 means target findings remain or new findings at/above the threshold appeared.

For an unstructured original report, compare the normalized original rows manually against the fresh JSON scan and record exact matching logic. Ambiguity fails closed.

## Container rebuild and rescan

Prefer the repository's documented build command. When no wrapper exists and the Dockerfile/image name are known:

```bash
docker build --pull --no-cache -t local/trivy-remediation:verify .
trivy image --format json --output /tmp/trivy-after.json local/trivy-remediation:verify
```

Reuse the original scanner flags when available. Do not weaken severity, ignore, scanner, or exit-code settings.

## Verification expectations

- Python: run frozen/locked install validation, configured static checks, and relevant tests.
- Node.js: run frozen/immutable lockfile install, configured lint/typecheck/build, and relevant tests.
- Container: execute health checks or smoke tests already defined by the repository.
- Always record commands and exit codes.
- After any review-driven change, rerun affected tests, build, rescan, diff guard, and all stale review gates.

## Pre-push checks

Run only after the final code change:

```bash
git diff --check
git status --short
```

Never run `git push` unless all review gates pass and the user explicitly requested it. Never use `--no-verify`, `--force`, or `--force-with-lease` to bypass a failed gate.
