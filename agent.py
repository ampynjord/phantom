from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from phantom.config import PhantomConfig
from phantom.engine.runner import PhantomRunner
from phantom.plugins import build_default_plugins


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="Run Phantom as a bounded autonomous agent from a JSON configuration file.",
    )
    parser.add_argument("--config", required=True, help="Path to the engagement JSON configuration file.")
    parser.add_argument(
        "--full-report",
        action="store_true",
        help="Print the full JSON report instead of a short execution summary.",
    )
    return parser


def load_config(config_path: Path) -> PhantomConfig:
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    return PhantomConfig.from_dict(payload)


def main(argv: list[str] | None = None) -> int:
    load_dotenv(Path(".env"), override=False)
    parser = build_parser()
    args = parser.parse_args(argv)
    config_path = Path(args.config)

    if not config_path.exists():
        print(f"Configuration file not found: {config_path}", file=sys.stderr)
        return 1

    try:
        config = load_config(config_path)
        runner = PhantomRunner(config=config, plugins=build_default_plugins())
        report = runner.run()
    except json.JSONDecodeError as error:
        print(f"Invalid JSON configuration: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        print(f"Phantom execution failed: {error}", file=sys.stderr)
        return 1

    if args.full_report:
        print(json.dumps(report, indent=2))
    else:
        summary = {
            "run_id": report["run_id"],
            "engagement_name": report["engagement_name"],
            "targets_in_scope": report["targets"],
            "summary": report["summary"],
            "files": report["files"],
        }
        print(json.dumps(summary, indent=2))

    return 0 if report["targets"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
