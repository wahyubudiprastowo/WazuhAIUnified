#!/usr/bin/env python3
"""Dedicated bounded Wazuh rollup worker.

This process intentionally has no HTTP listener. It owns the incremental
pipeline checkpoint and writes only SQLite materializations shared with the
dashboard. Keep one replica unless checkpoint ownership is made distributed.
"""
from __future__ import annotations

import os
import signal
import threading
import time

# Importing server builds the identical authenticated Indexer client and reads
# the same dashboard.env, but starting this module never starts its web server.
import server


def main() -> None:
    if os.environ.get("SOC_PIPELINE_WORKER_ENABLED", "true").lower() != "true":
        raise SystemExit("SOC_PIPELINE_WORKER_ENABLED must be true for mcp-materializer")
    stopping = threading.Event()

    def stop(*_args: object) -> None:
        stopping.set()
        server.pipeline.stop.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server.pipeline.start()
    print("SOC materializer started")
    while not stopping.wait(5):
        pass
    print("SOC materializer stopped")


if __name__ == "__main__":
    main()
