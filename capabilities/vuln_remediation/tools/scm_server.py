# palisade/capabilities/vuln_remediation/tools/scm_server.py (two of four tools shown)
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("palisade-scm")
BRANCH_PREFIX = "palisade/fix/"   # scm_create_branch names branches; callers cannot


def _require_fix_branch(branch: str) -> None:
    if not branch.startswith(BRANCH_PREFIX):
        raise PermissionError("remediation agent may only act on palisade/fix/* branches")


@mcp.tool()
def scm_commit_patch(repo: str, branch: str, unified_diff: str, message: str) -> dict:
    """Apply a unified diff to a fix branch and commit. Refuses diffs touching
    paths outside the capability allowlist (CI configuration is excluded)."""
    _require_fix_branch(branch)
    _scm.apply_and_commit(repo, branch, unified_diff, message, path_allowlist=_ALLOW)
    return {"repo": repo, "branch": branch, "commit": _scm.head(repo, branch)}


@mcp.tool()
def scm_open_pr(repo: str, branch: str, title: str, body: str, reviewers: list[str]) -> dict:
    """Open a pull request from a fix branch to the default branch. Never merges."""
    _require_fix_branch(branch)
    return _scm.open_pr(repo, branch, title, body, reviewers)
