# lab/synth_siem.py
"""Deterministic synthetic SIEM events for the Palisade labs.

Generates alerts and authentication events for the fictional enterprise
palisade.example. Nothing here is real telemetry. The --note option places
a caller-supplied string into the alert description field so that Chapter 3
and Chapter 14 labs can measure how the loop treats untrusted content.
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

HOSTS = [f"host-{n}" for n in (4471, 4472, 4480, 5101, 5102, 6210)]
USERS = ["u.ramirez", "u.chen", "u.okafor", "u.novak", "svc-backup", "svc-ci"]
RULES = [
    ("Suspicious PowerShell encoded command", "high"),
    ("Impossible travel sign-in", "medium"),
    ("New OAuth consent grant", "medium"),
    ("Multiple failed logons followed by success", "high"),
    ("Rare parent-child process", "low"),
    ("Outbound connection to newly registered domain", "medium"),
]
TENANT = "tenant-acme"


def gen_alert(rng: random.Random, idx: int, start: datetime, note: str | None) -> dict:
    rule, sev = rng.choice(RULES)
    host = rng.choice(HOSTS)
    user = rng.choice(USERS)
    detected = start + timedelta(minutes=rng.randint(0, 7 * 24 * 60))
    desc = f"{rule} observed on {host} for {user}."
    if note:
        desc = f"{desc} {note}"
    return {
        "alert_id": f"alt_{idx:04d}",
        "tenant": TENANT,
        "detected_at": detected.isoformat(),
        "rule_name": rule,
        "severity": sev,
        "host": host,
        "user": user,
        "src_ip": f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
        "description": desc,          # treated as UNTRUSTED by the harness
        "source": "synthetic",
    }


def gen_auth_event(rng: random.Random, start: datetime) -> dict:
    return {
        "event_type": "auth",
        "tenant": TENANT,
        "at": (start + timedelta(minutes=rng.randint(0, 7 * 24 * 60))).isoformat(),
        "user": rng.choice(USERS),
        "host": rng.choice(HOSTS),
        "result": rng.choices(["success", "failure"], weights=[9, 1])[0],
        "method": rng.choice(["password", "mfa", "token"]),
        "source": "synthetic",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261004)
    ap.add_argument("--alerts", type=int, default=200)
    ap.add_argument("--auth-events", type=int, default=2000)
    ap.add_argument("--note", default=None,
                    help="string appended to every alert description (lab-supplied)")
    ap.add_argument("--out", default="lab/data/siem.jsonl")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    start = datetime(2026, 10, 1, tzinfo=timezone.utc)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        for i in range(args.alerts):
            fh.write(json.dumps(gen_alert(rng, i + 1, start, args.note)) + "\n")
        for _ in range(args.auth_events):
            fh.write(json.dumps(gen_auth_event(rng, start)) + "\n")
    print(f"wrote {args.alerts} alerts and {args.auth_events} auth events to {args.out}")


if __name__ == "__main__":
    main()
