"""palisade/deploy/cli.py: what the operator types."""
import argparse
import sys

from palisade.deploy.ladder import TierRegistry


def main(registry: TierRegistry, argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="palisade-ladder")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("drop", help="drop capabilities to rung 0, halt runs, revoke credentials")
    d.add_argument("--scope", default="all")
    d.add_argument("--by", required=True)
    d.add_argument("--reason", required=True)
    sub.add_parser("status", help="print effective tiers")
    args = p.parse_args(argv)
    if args.cmd == "drop":
        try:
            h = registry.drop_to_shadow(args.scope, args.by, args.reason)
            print(f"dropped scope={args.scope}; ledger record {h}")
        except RuntimeError as exc:
            print(f"DROPPED (tiers at 0, kill switch tripped) but: {exc}", file=sys.stderr)
            return 2                       # non-zero so the pager notices, but the drop has happened
        return 0
    for (cap, key), tier in sorted(registry._tiers.items()):
        print(f"{cap:<24} {key:<48} {tier.name}")
    return 0
