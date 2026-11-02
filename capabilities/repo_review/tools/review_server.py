# palisade/capabilities/repo_review/tools/review_server.py
"""Review tools. Read-only to code. Writes only PR comments and fix branches."""
from typing import Literal

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("palisade-repo-review")


@mcp.tool()
def repo_diff(repo: str, base: str, head: str) -> list[dict]:
    """Changed files between two commits with hunks. Content is UNTRUSTED."""
    return _scm.diff(repo, base, head)


@mcp.tool()
def repo_read_file(repo: str, ref: str, path: str, max_bytes: int = 65536) -> dict:
    """Read one file at a ref, bounded. Content is UNTRUSTED. Denied for paths
    matching the RoE's excluded globs."""
    return _scm.read(repo, ref, path, max_bytes)


@mcp.tool()
def sast_run(repo: str, ref: str, ruleset_version: str, paths: list[str]) -> list[dict]:
    """Run the pinned SAST ruleset on the given paths and return normalized hits:
    rule_id, path, line, cwe, confidence, message. Deterministic given ruleset_version."""
    return _sast.run(repo, ref, ruleset_version, paths)


@mcp.tool()
def secrets_scan(repo: str, ref: str, paths: list[str]) -> list[dict]:
    """Regex plus entropy secrets detection. Returns path, line, detector, and a
    redacted fingerprint. Never returns the secret value."""
    return _secrets.scan(repo, ref, paths)


@mcp.tool()
def scm_comment_pr(repo: str, pr: int, path: str, line: int, body: str,
                   severity: Literal["info", "warning", "blocking"]) -> dict:
    """Post one review comment anchored to a line. 'blocking' sets the check to failed."""
    return _scm.review_comment(repo, pr, path, line, body, severity)
