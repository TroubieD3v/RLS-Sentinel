#!/usr/bin/env python3
"""Run the fixture benchmark against several PostgreSQL major versions using throwaway Docker containers.

Each container is bound to 127.0.0.1 on a random port, holds no volume, and is removed afterwards. The harness
connects to it as the disposable-server superuser (SENTINEL_FIXTURE_BACKEND=external, SENTINEL_FIXTURE_DISPOSABLE=true).

Usage:  python scripts/pg_matrix.py [--versions 15 16 17 18] [--bin rls-sentinel] [--repeat 1]
Exit status is non-zero if any version disagrees with the documented expectations.
"""
from __future__ import annotations

import argparse
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_ready(name: str, timeout: float = 60) -> None:
    end = time.time() + timeout
    while time.time() < end:
        r = subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True, check=False)
        if r.returncode == 0:
            time.sleep(1.5)  # the entrypoint restarts the server once after init
            r = subprocess.run(["docker", "exec", name, "pg_isready", "-U", "postgres"], capture_output=True, check=False)
            if r.returncode == 0:
                return
        time.sleep(1)
    raise SystemExit(f"{name} did not become ready")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--versions", nargs="+", default=["15", "16", "17", "18"])
    ap.add_argument("--bin", default="rls-sentinel")
    ap.add_argument("--repeat", default="1")
    a = ap.parse_args()

    failed: list[str] = []
    for ver in a.versions:
        name = f"rls-sentinel-matrix-{ver}-{secrets.token_hex(3)}"
        pw = secrets.token_urlsafe(18)
        port = free_port()
        print(f"\n=== PostgreSQL {ver} ===", flush=True)
        subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-e", f"POSTGRES_PASSWORD={pw}",
                        "-p", f"127.0.0.1:{port}:5432", f"postgres:{ver}-alpine"], check=True, capture_output=True)
        try:
            wait_ready(name)
            env = {**os.environ, "SENTINEL_FIXTURE_BACKEND": "external", "SENTINEL_FIXTURE_DISPOSABLE": "true",
                   "SENTINEL_FIXTURE_ADMIN_URL": f"postgresql://postgres:{pw}@127.0.0.1:{port}/postgres",
                   "SENTINEL_ALLOWED_TARGETS": "127.0.0.1", "PYTHONUTF8": "1"}
            r = subprocess.run([sys.executable, str(ROOT / "scripts" / "benchmark.py"), "--bin", a.bin, "--repeat", a.repeat],
                               env=env, cwd=ROOT, check=False)
            if r.returncode != 0:
                failed.append(ver)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    print("\nversions with disagreements:", failed or "none")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
