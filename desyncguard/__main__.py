"""CLI. inspect already works; analyze is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from desyncguard.parse import parse_edge, parse_origin


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="desyncguard")
    sub = p.add_subparsers(dest="cmd", required=True)

    ins = sub.add_parser("inspect", help="show edge and origin parses of a raw request")
    ins.add_argument("--raw", required=True)

    ana = sub.add_parser("analyze", help="decide whether the bytes are safe to forward")
    ana.add_argument("--raw", required=True)
    ana.add_argument("--report", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.raw)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"failed to read raw request: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "inspect":
        edge = parse_edge(raw)
        origin = parse_origin(raw)
        print(json.dumps({"edge": edge.as_dict(), "origin": origin.as_dict()}, ensure_ascii=False, indent=2))
        return 0 if edge.ok or origin.ok else 1

    if args.cmd == "analyze":
        from desyncguard.engine import analyze

        try:
            report = analyze(raw)
        except Exception as exc:
            print(f"analyze failed: {exc}", file=sys.stderr)
            return 2
        try:
            Path(args.report).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report).write_text(
                json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"failed to write report: {exc}", file=sys.stderr)
            return 2
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
