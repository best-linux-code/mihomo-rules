from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable, Final

from geoip_gen.builder import generate, inspect
from geoip_gen.models import BuildResult, Paths, build_paths


CommandRunner = Callable[[Paths], BuildResult]
DEFAULT_ROOT: Final = Path(__file__).resolve().parent
COMMAND_RUNNERS: Final[dict[str, CommandRunner]] = {
    "generate": generate,
    "inspect": inspect,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate or inspect the Mihomo/FlClash geoip.dat artifact.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_ROOT,
        help="Repository root containing china_ip_list.txt.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("generate", help="Generate geoip.dat and metadata files.")
    subparsers.add_parser("inspect", help="Inspect the generated geoip.dat.")
    return parser


def payload(paths: Paths, result: BuildResult) -> dict[str, str | dict[str, int]]:
    return {
        "output": paths.output.name,
        "checksum": paths.checksum.name,
        "provenance": paths.provenance.name,
        "input_sha256": result.input_sha256,
        "output_sha256": result.output_sha256,
        "counts": {
            "CN": result.cn_count,
            "PRIVATE": result.private_count,
        },
    }


def run(command: str, root: Path) -> dict[str, str | dict[str, int]]:
    paths = build_paths(root)
    result = COMMAND_RUNNERS[command](paths)
    return payload(paths, result)


def main() -> int:
    namespace = build_parser().parse_args()
    result = run(namespace.command, namespace.root.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
