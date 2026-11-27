import argparse
import asyncio
import os
import sys
from pathlib import Path

from . import cli
from .errors import ScanError
from .models import LookupStatus, ManifestFormat
from .osv import OSVConfig
from .parsers import ParseLimits
from .serialization import to_json


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if not args or args[0] in {"scan", "history", "report", "compare", "--version", "--help", "-h"}:
        return cli.main(args)

    parser = argparse.ArgumentParser(description="Legacy DepScope scanner")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--format", choices=list(ManifestFormat))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true")
    mode.add_argument("--live", action="store_true")
    parser.add_argument("--json", type=Path, metavar="FILE")
    options = parser.parse_args(args)
    try:
        format = cli.input_format(options.manifest, options.format)
        try:
            value = int(os.environ.get("DEPSCOPE_MAX_FILE_BYTES", "1000000"))
            if not 1 <= value < sys.maxsize:
                raise ValueError
            limits = ParseLimits(max_file_bytes=value)
        except ValueError:
            raise ScanError(
                "invalid_file_limit", "DEPSCOPE_MAX_FILE_BYTES must be a positive byte count."
            ) from None
        content = cli.manifest_bytes(options.manifest, limits.max_file_bytes)
        result = asyncio.run(cli.run_scan(content, format, options.live, limits, OSVConfig()))
        if options.json:
            cli.write_export(options.json, to_json(result))
        sys.stdout.write(cli.summary(result))
    except ScanError as exc:
        print(f"{exc.code}: {exc}", file=sys.stderr)
        return 2
    return 0 if result.status is LookupStatus.COMPLETE else 1


if __name__ == "__main__":
    raise SystemExit(main())
