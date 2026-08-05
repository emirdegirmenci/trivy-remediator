#!/usr/bin/env python3
"""Detect high-risk remediation shortcuts in a unified git diff.

This is a guardrail, not a proof of correctness. A clean result does not replace
review, tests, rebuild, and a fresh Trivy scan.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable

BLOCK_PATTERNS = [
    (re.compile(r"npm\s+audit\s+fix\s+.*--force", re.I), "npm audit fix --force is forbidden"),
    (re.compile(r"\b(?:pip|pip3)\s+install\s+(?:-U|--upgrade)\s*(?:$|&&|;)", re.I), "broad pip upgrade is forbidden"),
    (re.compile(r"\bpoetry\s+update\s*(?:$|&&|;)", re.I), "unscoped poetry update is forbidden"),
    (re.compile(r"\b(?:npm|pnpm|yarn)\s+update\s*(?:$|&&|;)", re.I), "unscoped JavaScript dependency update is forbidden"),
    (re.compile(r"apt-get\s+(?:dist-upgrade|full-upgrade)", re.I), "broad OS dist/full upgrade is forbidden"),
    (re.compile(r"^\s*FROM\s+\S+:latest(?:\s|$)", re.I), "floating latest base image is forbidden"),
    (re.compile(r"--no-verify\b", re.I), "bypassing verification hooks is forbidden"),
    (re.compile(r"(?:--skip-tests|--no-tests|SKIP_TESTS\s*=\s*(?:1|true))", re.I), "disabling tests is forbidden"),
]

WARN_PATTERNS = [
    (re.compile(r"apt-get\s+upgrade\b", re.I), "broad apt upgrade requires explicit justification"),
    (re.compile(r"(?:pip|pip3)\s+install\s+.*--pre\b", re.I), "pre-release package selected"),
    (re.compile(r"(?:npm|pnpm|yarn).*(?:--legacy-peer-deps|--force)\b", re.I), "dependency resolver override used"),
    (re.compile(r"^\s*FROM\s+\S+:[^@\s]+\s*$", re.I), "base image tag is not digest-pinned"),
]


def load_diff(path: Path | None) -> str:
    if path:
        return path.read_text(encoding="utf-8")
    completed = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--unified=0"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "git diff failed")
    return completed.stdout


def inspect(diff_text: str) -> list[dict[str, object]]:
    issues: list[dict[str, object]] = []
    current_file = ""
    for line_number, line in enumerate(diff_text.splitlines(), start=1):
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if not line.startswith("+") or line.startswith("+++"):
            continue
        added = line[1:]
        normalized_file = current_file.lower()
        if normalized_file.endswith((".trivyignore", "trivyignore.yaml", "trivyignore.yml")):
            issues.append(
                {
                    "level": "BLOCK",
                    "file": current_file,
                    "diff_line": line_number,
                    "message": "automatic Trivy suppression changes are forbidden",
                    "content": added,
                }
            )
        for pattern, message in BLOCK_PATTERNS:
            if pattern.search(added):
                issues.append(
                    {"level": "BLOCK", "file": current_file, "diff_line": line_number, "message": message, "content": added}
                )
        for pattern, message in WARN_PATTERNS:
            if pattern.search(added):
                issues.append(
                    {"level": "WARN", "file": current_file, "diff_line": line_number, "message": message, "content": added}
                )
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diff", nargs="?", type=Path, help="Unified diff file; defaults to git diff")
    parser.add_argument("--output", "-o", type=Path)
    args = parser.parse_args()

    try:
        text = load_diff(args.diff)
        issues = inspect(text)
    except (OSError, RuntimeError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    blockers = [issue for issue in issues if issue["level"] == "BLOCK"]
    result = {
        "passed": not blockers,
        "blocker_count": len(blockers),
        "warning_count": sum(issue["level"] == "WARN" for issue in issues),
        "issues": issues,
        "note": "A passing guard only means no known shortcut pattern was detected; tests and a fresh scan are still mandatory.",
    }
    payload = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
