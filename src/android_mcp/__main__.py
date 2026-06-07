"""android-mcp entry point.

Two modes:

  python -m android_mcp                       # stdio MCP transport (default)
  python -m android_mcp --mode http \
                       --port 18823           # HTTP transport on 127.0.0.1
"""

from __future__ import annotations

import argparse
import logging
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="android-mcp server")
    parser.add_argument(
        "--mode",
        choices=("stdio", "http"),
        default="stdio",
        help="transport (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="HTTP bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18823,
        help="HTTP bind port (default: 18823; sibling to audit-mcp's 18822 and ida-headless-mcp's 18821)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="logging level (default: INFO)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.mode == "stdio":
        from .server import mcp

        mcp.run()
        return 0

    if args.mode == "http":
        import uvicorn

        from .http_api import build_app

        app = build_app()
        uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level.lower())
        return 0

    parser.error(f"unknown mode: {args.mode}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
