#!/usr/bin/env python3
"""Compare before/after Trivy reports and enforce a fail-closed remediation gate."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from parse_trivy_report import Finding, parse_report

SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def finding_key(finding: Finding, ignore_target: bool) -> tuple[str, ...]:
    base = (
        finding.result_class,
        finding.result_type,
        finding.package,
        finding.vulnerability_id,
    )
    return base if ignore_target else (finding.target, *base)


def as_record(finding: Finding) -> dict[str, str]:
    return {
        "target": finding.target,
        "class": finding.result_class,
        "type": finding.result_type,
        "package": finding.package,
        "vulnerability_id": finding.vulnerability_id,
        "severity": finding.severity,
        "status": finding.status,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "title": finding.title,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument(
        "--minimum-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Severity threshold that must be fully remediated (default: HIGH)",
    )
    parser.add_argument("--output", "-o", type=Path)
    args = parser.parse_args()

    try:
        before, before_meta, before_warnings, _ = parse_report(args.before)
        after, after_meta, after_warnings, _ = parse_report(args.after)
    except Exception as exc:  # Keep CLI errors concise and fail closed.
        print(f"error: {exc}", file=sys.stderr)
        return 2

    ignore_target = (
        before_meta.get("artifact_type") == "container_image"
        and after_meta.get("artifact_type") == "container_image"
    )
    before_map = {finding_key(item, ignore_target): item for item in before}
    after_map = {finding_key(item, ignore_target): item for item in after}
    before_keys = set(before_map)
    after_keys = set(after_map)

    resolved = [before_map[key] for key in sorted(before_keys - after_keys)]
    remaining = [after_map[key] for key in sorted(before_keys & after_keys)]
    new = [after_map[key] for key in sorted(after_keys - before_keys)]

    threshold = SEVERITY_RANK[args.minimum_severity]
    unresolved_gate = [
        item for item in remaining if SEVERITY_RANK.get(before_map[finding_key(item, ignore_target)].severity, 0) >= threshold
    ]
    new_gate = [item for item in new if SEVERITY_RANK.get(item.severity, 0) >= threshold]
    passed = not unresolved_gate and not new_gate

    report = {
        "passed": passed,
        "minimum_severity": args.minimum_severity,
        "before": {
            "path": str(args.before),
            "artifact_name": before_meta.get("artifact_name", ""),
            "finding_count": len(before),
            "severity_counts": dict(Counter(item.severity for item in before)),
            "warnings": before_warnings,
        },
        "after": {
            "path": str(args.after),
            "artifact_name": after_meta.get("artifact_name", ""),
            "finding_count": len(after),
            "severity_counts": dict(Counter(item.severity for item in after)),
            "warnings": after_warnings,
        },
        "counts": {
            "resolved": len(resolved),
            "remaining": len(remaining),
            "new": len(new),
            "unresolved_at_or_above_threshold": len(unresolved_gate),
            "new_at_or_above_threshold": len(new_gate),
        },
        "resolved": [as_record(item) for item in resolved],
        "remaining": [as_record(item) for item in remaining],
        "new": [as_record(item) for item in new],
        "gate_failures": {
            "unresolved": [as_record(item) for item in unresolved_gate],
            "new": [as_record(item) for item in new_gate],
        },
    }

    payload = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
