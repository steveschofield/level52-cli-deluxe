#!/usr/bin/env python3
"""
Install ProjectDiscovery nuclei into tools/.bin/nuclei.

Keeps the repo runnable without requiring system-wide Go installs.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path


REPO = "projectdiscovery/nuclei"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"


def _arch_suffix() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "linux_amd64"
    if machine in {"aarch64", "arm64"}:
        return "linux_arm64"
    raise SystemExit(f"Unsupported architecture for auto-install: {platform.machine()}")


def _download(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "guardian-cli-deluxe"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def _verify_sha256(data: bytes, expected: str, label: str) -> None:
    expected = (expected or "").strip().lower()
    if expected.startswith("sha256:"):
        expected = expected.split("sha256:", 1)[-1].strip()
    if not expected:
        return
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise SystemExit(f"SHA256 mismatch for {label}: expected {expected}, got {actual}")


def _pick_asset(release: dict, suffix: str) -> tuple[str, str]:
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        url = asset.get("browser_download_url", "")
        if name.endswith(".zip") and suffix in name and "nuclei" in name.lower():
            return name, url
    raise SystemExit(f"Could not find a {suffix} .zip asset in latest {REPO} release")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    out_dir = repo_root / "tools" / ".bin"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "nuclei"

    suffix = _arch_suffix()
    release = json.loads(_download(API_LATEST).decode("utf-8", errors="replace"))
    name, url = _pick_asset(release, suffix)

    print(f"Downloading {name} ...", file=sys.stderr)
    data = _download(url)

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = [m for m in zf.namelist() if m.endswith("/nuclei") or m == "nuclei"]
        if not members:
            raise SystemExit("Downloaded archive does not contain a 'nuclei' binary")
        member = members[0]
        extracted = zf.read(member)

    expected_sha = os.getenv("GUARDIAN_NUCLEI_SHA256", "")
    _verify_sha256(extracted, expected_sha, "nuclei")

    out_path.write_bytes(extracted)
    out_path.chmod(out_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Installed ProjectDiscovery nuclei to {out_path}", file=sys.stderr)
    print("Optional: set GUARDIAN_NUCLEI_BIN to override.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
