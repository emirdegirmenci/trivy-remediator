# Report and Output Contract

## Accepted inputs

Accept any readable Trivy output supplied by the user or repository:

- Pasted chat text
- Markdown table
- Terminal table or log
- Screenshot or rendered table
- JSON
- CSV/TSV/pipe-delimited text
- SARIF
- A fresh `trivy image`, `trivy fs`, `trivy repo`, or equivalent repository scan

Do not require the user to convert a table or chat excerpt into JSON/CSV. Prefer a fresh machine-readable scan for final verification, not as a prerequisite for initial analysis.

## Unstructured input rules

For pasted tables, logs, and screenshots:

1. Preserve only visible values.
2. Map alternate headers such as `Library`, `Package`, or `PkgName` to package name only when the meaning is clear.
3. Keep missing values as `UNKNOWN`.
4. Do not infer a fixed version from a CVE description or internet memory.
5. Do not infer the ecosystem solely from the package name.
6. State when the input appears truncated, filtered, deduplicated, or visually ambiguous.
7. Require repository evidence or a fresh scan before making changes from incomplete rows.

Normalize at least these fields when present:

| Field | Required for analysis | Required for automatic remediation |
|---|---|---|
| Package name | Yes | Yes |
| Vulnerability ID | Preferred | Yes, or an equivalent unique finding identifier |
| Severity | Preferred | Required for threshold gating |
| Installed version | Preferred | Yes |
| Fixed version | No | Yes; otherwise `NO_FIX_AVAILABLE` or `REPORT_ONLY` |
| Ecosystem/class/type | No | Yes, proven from report or repository |
| Target/artifact | No | Required for reproducible image remediation |
| Layer/source path | No | Required when package origin is otherwise ambiguous |

## Structured input rules

### Trivy JSON

Support schema version 2 reports containing top-level metadata and `Results[].Vulnerabilities[]`. Preserve at least:

- Artifact name, type, ID, OS family, and OS version
- Result target, class, and type
- Package name and installed version
- Vulnerability ID, severity, status, and fixed version
- Layer DiffID, fingerprint, title, and primary URL when present

Warn instead of guessing when the schema version differs or required context is absent.

### CSV and delimited tables

Accept comma-, semicolon-, tab-, or pipe-delimited reports. Recognize these common columns case-insensitively:

- `Package`, `Library`, or `PkgName`
- `CVE` or `VulnerabilityID`
- `Severity`
- `InstalledVersion`
- `FixedVersion`

Optional fields include `Title`, `Image`, `Tag`, `Class`, `Type`, `Status`, `PrimaryURL`, `Layer`, and `Fingerprint`.

Delimited exports that omit `Class` and `Type` cannot prove whether a package is OS, Python, Node, or another ecosystem. Parse them, but require repository evidence before selecting a remediation command.

### SARIF

Map each result to its rule/finding identifier, severity level, package or component when present, installed/fixed versions when present, and source location. Preserve uncertainty rather than forcing SARIF into a Trivy JSON shape.

## Required remediation plan

Before changing files, output one row per normalized package group:

| Package | Ecosystem | Installed | Required minimum | CVEs | Decision | Repository source | Verification |
|---|---|---:|---:|---:|---|---|---|

The `Required minimum` must satisfy every CVE in that group. Use `UNKNOWN` when no valid comparator exists.

Also include:

- Input form and completeness warning
- Primary-agent conclusion
- Codex plan-gate verdict
- Any disagreement and its evidence-based resolution

## Required final report

Use this exact remediation status vocabulary:

- `FIXED`: rebuilt and rescanned; comparison gate passed
- `PARTIALLY_FIXED`: some findings resolved, but at least one target finding remains
- `BLOCKED`: safe remediation requires approval, required tools/reviews are unavailable, or external fixes are missing
- `NOT_VERIFIED`: files changed, but build, tests, rebuild, rescan, or required reviews did not complete
- `NO_CHANGE`: analysis completed without modifying files

Report one push-gate state:

- `PASSED`: every required post-change review and verification gate passed
- `BLOCKED`: at least one gate is missing, stale, failed, or unresolved
- `NOT_REQUESTED`: no push was requested; state whether the current diff is review-ready

Include:

1. Scope, report input form, and metadata
2. Input completeness and transcription warnings
3. Files changed
4. Package-by-package before/after versions
5. Commands actually executed and exit status
6. Test, build, and smoke results
7. Trivy before/after counts by severity
8. Remaining and newly introduced findings
9. `/ask-codex` plan, patch, and final verdicts
10. `/code-review` and `/security-review` results
11. Disagreements, changes made in response, and unresolved risks
12. Approval-required items
13. Remediation status and push-gate state

Do not say "all clear", "resolved", "ready to push", or "fixed" when the corresponding gate failed, is stale, or was not run.
