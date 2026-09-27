"""Command line for the egress reference."""

from __future__ import annotations

import argparse
import json
import sys
import getpass
import os
from pathlib import Path

from headgate_egress.gate import Channel, Gate, Segment, judge, resting


def _home(value: str | None) -> Path:
    if value:
        return Path(value)
    env = (os.environ.get("EGRESS_HOME", "") or "").strip()
    if env:
        return Path(env)
    return Path.cwd() / ".egress"


def _emit(body: dict, code: int) -> int:
    json.dump(body, sys.stdout, sort_keys=True, indent=2)
    sys.stdout.write("\n")
    return code


def _line(prompt: str = "Seal: ") -> str:
    """Read one seal. On a terminal the seal is not echoed."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().strip()


def _channels(text: str) -> list[Channel]:
    """Parse the witness input without coercing it. A string "false", a float, a negative or an
    infinite count stays what it is, and the strict witness reads it as unknown, never sealed."""
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("channels must be a list")
    out: list[Channel] = []
    for row in data:
        if not isinstance(row, dict):
            raise ValueError("channel must be an object")
        out.append(Channel(name=row.get("name"), up=row.get("up"), blocked=row.get("blocked"),
                           bytes_in=row.get("bytes_in", 0), bytes_out=row.get("bytes_out", 0)))
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Egress Headgate. Resting state passes nothing.")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--home", default=None)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("resting", parents=[common])
    sub.add_parser("discover", parents=[common])
    admit = sub.add_parser("admit", parents=[common])
    admit.add_argument("--length", type=int, required=True)
    sub.add_parser("init-seal", parents=[common])
    open_parser = sub.add_parser("open", parents=[common])
    open_parser.add_argument("--ttl", type=int, default=3600)
    sub.add_parser("rotate", parents=[common])
    check_parser = sub.add_parser("check", parents=[common])
    check_parser.add_argument("--action", required=True)
    sub.add_parser("close", parents=[common])
    sub.add_parser("witness", parents=[common])
    args = parser.parse_args(argv)
    if args.cmd == "resting":
        return _emit(resting(), 0)
    if args.cmd == "witness":
        try:
            body = judge(_channels(sys.stdin.read()))
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            return _emit({"ok": False, "decision": "DENY", "code": "egress_error", "detail": type(exc).__name__}, 1)
        body["ok"] = body["state"] == "sealed"
        return _emit(body, 0 if body["ok"] else 1)
    gate = Gate(_home(args.home))
    if args.cmd == "discover":
        decision = gate.discover()
    elif args.cmd == "admit":
        decision = gate.admit(Segment(args.length))
    elif args.cmd == "init-seal":
        decision = gate.init_seal(_line())
    elif args.cmd == "open":
        decision = gate.open(_line(), ttl_seconds=args.ttl)
    elif args.cmd == "rotate":
        current = _line("Current seal: ")
        new = _line("New seal: ")
        decision = gate.rotate(current, new)
    elif args.cmd == "check":
        decision = gate.check(args.action)
    else:
        decision = gate.close()
    if decision.decision == "ABSTAIN":
        code = 3
    elif decision.decision == "DENY":
        code = 1
    else:
        code = 0
    return _emit(decision.as_dict(), code)


if __name__ == "__main__":
    raise SystemExit(main())