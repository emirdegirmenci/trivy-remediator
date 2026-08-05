# Dual-Agent Protocol

## Roles

Use a single-writer model:

- **Primary agent:** inspect the repository, construct the plan, apply approved edits, and execute verification.
- **Codex through `/ask-codex`:** independently challenge evidence, plan, diff, test coverage, and final readiness.

Do not let both agents edit the same working tree concurrently. Treat Codex output as review input, not authority. Verify every material claim against repository evidence.

## Consensus rule

Require evidence-backed agreement on:

1. The report row or CVE group being addressed
2. The package ecosystem and origin
3. The repository file controlling the installed version
4. The minimum version satisfying all grouped findings
5. Whether the change is non-breaking and narrow enough for `SAFE_AUTO`
6. The exact build, test, rescan, and comparison steps

Silence is not agreement. A generic answer such as "looks good" without addressing the supplied evidence is not a passing review. If a factual disagreement cannot be resolved, do not average the answers; classify the item conservatively and stop editing it.

## PLAN_GATE template

Invoke `/ask-codex` with a prompt containing:

```text
PLAN_GATE — independent Trivy remediation review

Act as a skeptical security reviewer. Do not edit files. Review the supplied report normalization and remediation plan against repository evidence.

Report input form: <pasted table/log/screenshot/JSON/CSV/SARIF/fresh scan>
Target artifact: <value or UNKNOWN>
Scanner policy/threshold: <value or UNKNOWN>
Repository state: <git status summary>

Normalized findings:
<package/CVE/installed/fixed/severity/source table>

Proposed decisions and changes:
<plan table with SAFE_AUTO/NEEDS_APPROVAL/NO_FIX_AVAILABLE/REPORT_ONLY>

Verification plan:
<commands and expected evidence>

Return:
1. BLOCKERS — factual or safety issues that must stop editing
2. CHALLENGES — assumptions requiring evidence
3. MINIMUM_SAFE_TARGETS — corrected package targets, if any
4. MISSING_TESTS — verification gaps
5. VERDICT — PASS or FAIL

PASS only when every SAFE_AUTO item is narrow, evidence-backed, and verifiable. Do not recommend suppressions, force upgrades, broad updates, or weakened scan policy.
```

## PATCH_GATE template

Invoke `/ask-codex` with:

```text
PATCH_GATE — independent Trivy patch review

Act as a skeptical reviewer. Do not edit files. Determine whether this exact diff safely implements the previously agreed Trivy remediation.

Addressed findings:
<package/CVE/installed/target table>

Exact diff:
<git diff -- relevant files>

Diff-guard output:
<blockers and warnings>

Checks already run:
<command, exit code, relevant result>

Return:
1. BLOCKERS — incorrect, unsafe, unrelated, or incomplete changes
2. LOCKFILE_OR_IMAGE_BLAST_RADIUS — unexpected transitive changes
3. SECURITY_REGRESSIONS — auth/TLS/CORS/network/secrets/runtime concerns
4. REQUIRED_CHECKS — missing tests/build/scan evidence
5. VERDICT — PASS or FAIL

FAIL if the patch hides findings, relies on an unapproved major change, contains unrelated edits, or lacks adequate verification.
```

## FINAL_GATE template

Invoke `/ask-codex` after the final code change and after `/code-review` plus `/security-review` pass:

```text
FINAL_GATE — independent pre-push Trivy review

Act as the last adversarial reviewer. Do not edit files. Verify that the final diff is ready to push.

Original normalized findings:
<table>
Final package/image versions:
<table>
Final diff:
<git diff>
Tests/build/smoke results:
<commands and exit codes>
Before/after Trivy comparison:
<resolved, remaining, new findings>
/code-review result:
<result and unresolved items>
/security-review result:
<result and unresolved items>
Working-tree status:
<git status --short>

Return:
1. BLOCKERS
2. UNRESOLVED_SECURITY_RISK
3. VERIFICATION_GAPS
4. PUSH_VERDICT — PASS or FAIL

PASS only if the final diff is scoped, all target findings are demonstrably resolved or explicitly approval-blocked, no new threshold findings exist, all required checks are current, and both review commands passed after the last change.
```

## Review loop rules

- Preserve the full Codex response in the work log or final report summary.
- Distinguish valid findings from unsupported suggestions and state the evidence used to resolve them.
- Rerun the relevant Codex gate after every material code or lockfile change.
- Never mark a gate passed using a review of an older diff.
- Never convert a Codex failure into approval by rewording the prompt or omitting context.
- If the slash command cannot consume the full context, provide a compact summary plus exact file paths and diff ranges; do not omit known risks.
