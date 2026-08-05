#!/usr/bin/env python3
"""Normalize Trivy JSON or CSV reports into a deterministic remediation model.

The script is deliberately conservative. When it cannot compare versions using
an ecosystem-appropriate comparator, it records that fact instead of guessing.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(frozen=True)
class Finding:
    target: str
    result_class: str
    result_type: str
    package: str
    vulnerability_id: str
    severity: str
    status: str
    installed_version: str
    fixed_version: str
    title: str
    primary_url: str
    layer_diff_id: str
    fingerprint: str

    def identity(self) -> tuple[str, str, str, str, str]:
        return (
            self.target,
            self.result_class,
            self.result_type,
            self.package,
            self.vulnerability_id,
        )


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _normalize_severity(value: Any) -> str:
    severity = _text(value).upper() or "UNKNOWN"
    return severity if severity in SEVERITY_RANK else "UNKNOWN"


def parse_json(path: Path) -> tuple[list[Finding], dict[str, Any], list[str]]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)

    warnings: list[str] = []
    if not isinstance(data, dict):
        raise ValueError("Trivy JSON root must be an object")
    if data.get("SchemaVersion") != 2:
        warnings.append(
            f"Unverified Trivy SchemaVersion: {data.get('SchemaVersion')!r}; expected 2"
        )

    findings: list[Finding] = []
    for result in data.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = _text(result.get("Target"))
        result_class = _text(result.get("Class")) or "unknown"
        result_type = _text(result.get("Type")) or "unknown"
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            layer = vuln.get("Layer") if isinstance(vuln.get("Layer"), dict) else {}
            findings.append(
                Finding(
                    target=target,
                    result_class=result_class,
                    result_type=result_type,
                    package=_text(vuln.get("PkgName")),
                    vulnerability_id=_text(vuln.get("VulnerabilityID")),
                    severity=_normalize_severity(vuln.get("Severity")),
                    status=_text(vuln.get("Status")) or "unknown",
                    installed_version=_text(vuln.get("InstalledVersion")),
                    fixed_version=_text(vuln.get("FixedVersion")),
                    title=_text(vuln.get("Title")),
                    primary_url=_text(vuln.get("PrimaryURL")),
                    layer_diff_id=_text(layer.get("DiffID")),
                    fingerprint=_text(vuln.get("Fingerprint")),
                )
            )

    metadata = {
        "schema_version": data.get("SchemaVersion"),
        "trivy_version": _text((data.get("Trivy") or {}).get("Version")),
        "report_id": _text(data.get("ReportID")),
        "created_at": _text(data.get("CreatedAt")),
        "artifact_id": _text(data.get("ArtifactID")),
        "artifact_name": _text(data.get("ArtifactName")),
        "artifact_type": _text(data.get("ArtifactType")),
        "os_family": _text(((data.get("Metadata") or {}).get("OS") or {}).get("Family")),
        "os_name": _text(((data.get("Metadata") or {}).get("OS") or {}).get("Name")),
    }
    return findings, metadata, warnings


def _sniff_delimiter(sample: str) -> str:
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        return dialect.delimiter
    except csv.Error:
        first = sample.splitlines()[0] if sample.splitlines() else ""
        return ";" if first.count(";") > first.count(",") else ","


def _get(row: dict[str, Any], *names: str) -> str:
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    for name in names:
        if name.lower() in lowered:
            return _text(lowered[name.lower()])
    return ""


def parse_csv(path: Path) -> tuple[list[Finding], dict[str, Any], list[str]]:
    sample = path.read_text(encoding="utf-8-sig", errors="strict")[:8192]
    delimiter = _sniff_delimiter(sample)
    findings: list[Finding] = []
    warnings: list[str] = []

    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        if not reader.fieldnames:
            raise ValueError("CSV report has no header")
        header = {name.strip().lower() for name in reader.fieldnames if name}
        required = {"package", "cve", "severity", "installedversion", "fixedversion"}
        missing = sorted(required - header)
        if missing:
            raise ValueError(f"CSV report is missing required columns: {', '.join(missing)}")

        for row_number, row in enumerate(reader, start=2):
            package = _get(row, "Package", "PkgName")
            cve = _get(row, "CVE", "VulnerabilityID")
            if not package or not cve:
                warnings.append(f"Skipped CSV row {row_number}: package or CVE is empty")
                continue
            image = _get(row, "Image")
            tag = _get(row, "Tag")
            target = f"{image}:{tag}" if image and tag else image
            findings.append(
                Finding(
                    target=target,
                    result_class=_get(row, "Class") or "unknown",
                    result_type=_get(row, "Type") or "unknown",
                    package=package,
                    vulnerability_id=cve,
                    severity=_normalize_severity(_get(row, "Severity")),
                    status=_get(row, "Status") or ("fixed" if _get(row, "FixedVersion") else "unknown"),
                    installed_version=_get(row, "InstalledVersion"),
                    fixed_version=_get(row, "FixedVersion"),
                    title=_get(row, "Title"),
                    primary_url=_get(row, "PrimaryURL", "URL"),
                    layer_diff_id=_get(row, "Layer", "LayerDiffID"),
                    fingerprint=_get(row, "Fingerprint"),
                )
            )

    metadata = {
        "delimiter": delimiter,
        "artifact_name": next((f.target for f in findings if f.target), ""),
        "artifact_type": "unknown",
    }
    if not any(f.result_class != "unknown" for f in findings):
        warnings.append("CSV has no Trivy result Class/Type; repository mapping must be verified manually")
    return findings, metadata, warnings


def parse_report(path: Path) -> tuple[list[Finding], dict[str, Any], list[str], str]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        findings, metadata, warnings = parse_json(path)
        return findings, metadata, warnings, "json"
    if suffix in {".csv", ".tsv"}:
        findings, metadata, warnings = parse_csv(path)
        return findings, metadata, warnings, "csv"

    with path.open("rb") as handle:
        prefix = handle.read(64).lstrip()
    if prefix.startswith((b"{", b"[")):
        findings, metadata, warnings = parse_json(path)
        return findings, metadata, warnings, "json"
    findings, metadata, warnings = parse_csv(path)
    return findings, metadata, warnings, "csv"


def _dpkg_greater(left: str, right: str) -> bool | None:
    if not shutil.which("dpkg"):
        return None
    completed = subprocess.run(
        ["dpkg", "--compare-versions", left, "gt", right],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode == 0:
        return True
    equal = subprocess.run(
        ["dpkg", "--compare-versions", left, "eq", right],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if equal.returncode == 0:
        return False
    lower = subprocess.run(
        ["dpkg", "--compare-versions", left, "lt", right],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return False if lower.returncode == 0 else None


def _pep440_greater(left: str, right: str) -> bool | None:
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return None
    try:
        return Version(left) > Version(right)
    except InvalidVersion:
        return None


def _choose_highest(versions: Iterable[str], result_type: str) -> tuple[str, str]:
    unique = sorted({v for v in versions if v})
    if not unique:
        return "", "no-fixed-version"
    if len(unique) == 1:
        return unique[0], "single-value"

    if result_type in {"debian", "ubuntu"}:
        comparator = _dpkg_greater
    elif result_type == "python-pkg":
        comparator = _pep440_greater
    else:
        return "", "manual-comparator-required"

    current = unique[0]
    for candidate in unique[1:]:
        greater = comparator(candidate, current)
        if greater is None:
            return "", "manual-comparator-required"
        if greater:
            current = candidate
    method = "dpkg" if comparator is _dpkg_greater else "pep440"
    return current, method


def _major(version: str) -> int | None:
    try:
        from packaging.version import InvalidVersion, Version
    except ImportError:
        return None
    try:
        release = Version(version).release
        return release[0] if release else None
    except InvalidVersion:
        return None


def build_model(
    findings: list[Finding], metadata: dict[str, Any], warnings: list[str], source_format: str, path: Path
) -> dict[str, Any]:
    groups: dict[tuple[str, str, str, str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[
            (
                finding.target,
                finding.result_class,
                finding.result_type,
                finding.package,
                finding.installed_version,
            )
        ].append(finding)

    normalized_groups: list[dict[str, Any]] = []
    for key, group_findings in groups.items():
        target, result_class, result_type, package, installed = key
        required_fixed, comparison = _choose_highest(
            (f.fixed_version for f in group_findings), result_type
        )
        installed_major = _major(installed)
        fixed_major = _major(required_fixed)
        crosses_major = (
            installed_major is not None
            and fixed_major is not None
            and fixed_major > installed_major
            and result_class == "lang-pkgs"
        )

        if not required_fixed:
            decision_hint = (
                "manual-review" if comparison == "manual-comparator-required" else "no-fix-available"
            )
        elif crosses_major:
            decision_hint = "approval-required-major-upgrade"
        elif result_class == "os-pkgs":
            decision_hint = "rebuild-or-base-image-update"
        elif result_class == "lang-pkgs":
            decision_hint = "targeted-dependency-update"
        else:
            decision_hint = "manual-ecosystem-mapping"

        normalized_groups.append(
            {
                "target": target,
                "class": result_class,
                "type": result_type,
                "package": package,
                "installed_version": installed,
                "required_fixed_version": required_fixed,
                "fixed_version_candidates": sorted({f.fixed_version for f in group_findings if f.fixed_version}),
                "version_comparison": comparison,
                "crosses_major_version": crosses_major,
                "decision_hint": decision_hint,
                "highest_severity": max(
                    (f.severity for f in group_findings), key=lambda s: SEVERITY_RANK.get(s, 0)
                ),
                "vulnerability_count": len(group_findings),
                "findings": [asdict(f) for f in sorted(group_findings, key=lambda item: item.vulnerability_id)],
            }
        )

    normalized_groups.sort(
        key=lambda item: (
            -SEVERITY_RANK.get(item["highest_severity"], 0),
            item["class"],
            item["type"],
            item["package"],
        )
    )

    severity_counts = Counter(f.severity for f in findings)
    status_counts = Counter(f.status for f in findings)
    fixable_count = sum(bool(f.fixed_version) for f in findings)
    return {
        "source": {
            "path": str(path),
            "format": source_format,
            **metadata,
        },
        "summary": {
            "finding_count": len(findings),
            "group_count": len(normalized_groups),
            "severity_counts": dict(sorted(severity_counts.items())),
            "status_counts": dict(sorted(status_counts.items())),
            "fixable_finding_count": fixable_count,
            "unfixed_finding_count": len(findings) - fixable_count,
        },
        "warnings": warnings,
        "groups": normalized_groups,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Trivy JSON or CSV report")
    parser.add_argument("--output", "-o", type=Path, help="Write normalized JSON to this path")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON")
    args = parser.parse_args()

    if not args.report.is_file():
        parser.error(f"Report does not exist or is not a file: {args.report}")

    try:
        findings, metadata, warnings, source_format = parse_report(args.report)
        model = build_model(findings, metadata, warnings, source_format, args.report)
    except (OSError, UnicodeError, csv.Error, json.JSONDecodeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    indent = None if args.compact else 2
    payload = json.dumps(model, indent=indent, ensure_ascii=False, sort_keys=False) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
