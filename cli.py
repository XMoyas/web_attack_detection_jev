from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent


def samples_path() -> Path:
    return ROOT / "data" / "samples.json"


def load_samples() -> list[dict]:
    return json.loads(samples_path().read_text(encoding="utf-8"))


def cmd_detect(args: argparse.Namespace) -> int:
    from detector import WebAttackDetector

    payload = args.payload
    if args.file:
        payload = Path(args.file).read_text(encoding="utf-8")
    if payload is None:
        print("Provide a payload or --file", file=sys.stderr)
        return 2

    result = WebAttackDetector().detect(
        payload,
        content_type=args.content_type,
        path=args.path,
    )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0 if result.action != "block" else 1


def cmd_demo(_args: argparse.Namespace) -> int:
    from detector import WebAttackDetector

    detector = WebAttackDetector()
    rows = []
    for sample in load_samples():
        result = detector.detect(sample["payload"])
        rows.append(
            {
                "name": sample["name"],
                "action": result.action,
                "attack_type": result.attack_type,
                "is_attack": result.is_attack,
                "attack_probability": result.attack_probability,
                "severity": result.severity,
            }
        )
        print(
            f"{sample['name']:20} action={result.action:6} type={result.attack_type:18} "
            f"p={result.attack_probability:.2f} severity={result.severity:.2f}"
        )
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Web attack detector powered by JEV")
    sub = parser.add_subparsers(dest="command", required=True)

    detect = sub.add_parser("detect", help="Detect a single payload")
    detect.add_argument("payload", nargs="?", help="Raw payload string")
    detect.add_argument("--file", help="Read payload from a file")
    detect.add_argument("--content-type", dest="content_type")
    detect.add_argument("--path")
    detect.set_defaults(func=cmd_detect)

    demo = sub.add_parser("demo", help="Run built-in sample payloads against JEV")
    demo.set_defaults(func=cmd_demo)

    serve = sub.add_parser("serve", help="Start the HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--reload", action="store_true")
    serve.set_defaults(func=cmd_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
