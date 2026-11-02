"""
palisade.identity.secret_scan
=============================

Fail CI if any prompt, skill manifest, tool config, or RoE file contains a
secret-shaped string. A secret in a prompt is a secret in your ledger, in
your trace pipeline, and in your model provider's request logs.

Usage:  python -m palisade.identity.secret_scan prompts/ skills/ tools/ roe/
Exit 0: clean. Exit 1: findings. Exit 2: bad invocation.

This is deliberately narrow: it scans the directories where prompts live.
Run gitleaks or trufflehog across the whole repository as well; this tool
exists so the prompt tree gets a check that understands prompt files and
so the failure message says what a prompt author needs to hear.
"""

from __future__ import annotations

import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

SCAN_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".jinja", ".j2", ".py"}

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_header", re.compile(r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("basic_auth_url", re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")),
    ("generic_assignment", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|client[_-]?secret|token)\b\s*[:=]\s*['\"]?(?P<val>[A-Za-z0-9/+_=.-]{12,})")),
]

# Placeholder conventions that are allowed in prompts and configs.
ALLOW_VALUE = re.compile(r"^(\$\{[A-Z0-9_]+\}|\{\{\s*[a-z0-9_.]+\s*\}\}|<[A-Z_]+>|\*{3,}|REDACTED.*|tok_[a-z0-9_]+|example|changeme|placeholder)$", re.I)
ALLOW_LINE = re.compile(r"palisade:\s*allow-secret-shape")  # explicit, reviewed opt-out


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


@dataclass
class Finding:
    path: Path
    line_no: int
    rule: str
    excerpt: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line_no}: {self.rule}: {self.excerpt}"


def iter_files(roots: Iterable[Path]) -> Iterator[Path]:
    for root in roots:
        if root.is_file():
            yield root
            continue
        for p in sorted(root.rglob("*")):
            if p.is_file() and p.suffix.lower() in SCAN_SUFFIXES and ".git" not in p.parts:
                yield p


def scan_text(path: Path, text: str) -> list[Finding]:
    out: list[Finding] = []
    for no, line in enumerate(text.splitlines(), start=1):
        if ALLOW_LINE.search(line):
            continue
        for rule, pat in PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            value = m.groupdict().get("val") or m.group(0)
            if ALLOW_VALUE.match(value.strip("'\"")):
                continue
            if rule == "generic_assignment" and (
                shannon_entropy(value) < 3.0 or re.fullmatch(r"[a-z][a-z_-]*", value)
            ):
                continue  # 'password: your-password-here' is prose, not a secret
            shown = value[:6] + "..." + value[-3:] if len(value) > 12 else "[...]"
            out.append(Finding(path, no, rule, shown))
            break
    return out


def scan_paths(roots: Iterable[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for p in iter_files(roots):
        try:
            findings.extend(scan_text(p, p.read_text(encoding="utf-8", errors="replace")))
        except OSError as exc:
            print(f"warn: cannot read {p}: {exc}", file=sys.stderr)
    return findings


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: secret_scan <path> [<path> ...]", file=sys.stderr)
        return 2
    findings = scan_paths(Path(a) for a in argv)
    for f in findings:
        print(f)
    if findings:
        print(f"\n{len(findings)} secret-shaped string(s) found. Prompts and tool configs must reference "
              f"secrets by broker handle, never by value. See Chapter 12, Section 12.8.", file=sys.stderr)
        return 1
    print("secret_scan: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
