"""CLI entry: load ``.env`` and run Uvicorn."""

from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

import uvicorn


def main() -> None:
    load_dotenv()
    host = os.environ.get("SERVER_HOST", "").strip()
    port_raw = os.environ.get("SERVER_PORT", "").strip()
    if not host:
        print("SERVER_HOST not set, please check your env file!", file=sys.stderr)
        sys.exit(1)
    if not port_raw:
        print("SERVER_PORT not set, please check your env file!", file=sys.stderr)
        sys.exit(1)
    try:
        port = int(port_raw)
    except ValueError:
        print("SERVER_PORT must be an integer", file=sys.stderr)
        sys.exit(1)

    uvicorn.run(
        "gophertls_api.app:app",
        host=host,
        port=port,
        factory=False,
    )


if __name__ == "__main__":
    main()
