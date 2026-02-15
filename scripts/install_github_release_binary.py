#!/usr/bin/env python3
"""
Install a GitHub Release binary (zip/tar.gz/tgz) into tools/.bin/<binary>.

This is used as a fallback when `go install` is not viable (e.g., DNS/proxy issues).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path


def _arch_tokens() -> list[str]:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return ["linux_amd64", "linux-amd64", "linuxamd64", "linux_x86_64", "linux-x86_64", "x86_64"]
    if machine in {"aarch64", "arm64"}:
        return ["linux_arm64", "linux-arm64", "linuxarm64", "linux_aarch64", "linux-aarch64", "arm64", "aarch64"]
    raise SystemExit(f"Unsupported architecture for auto-install: {platform.machine()}")


def _download(url: str, accept_json: bool = False) -> bytes:
    headers = {"User-Agent": "guardian-cli-deluxe"}
    if accept_json:
        headers["Accept"] = "application/vnd.github+json"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
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


def _pick_asset(release: dict, binary: str) -> tuple[str, str]:
    tokens = [t.lower() for t in _arch_tokens()]
    binary_l = binary.lower()

    candidates: list[tuple[str, str]] = []
    for asset in release.get("assets", []):
        name = asset.get("name", "") or ""
        url = asset.get("browser_download_url", "") or ""
        name_l = name.lower()

        if not url:
            continue
        if not (name_l.endswith(".zip") or name_l.endswith(".tar.gz") or name_l.endswith(".tgz")):
            continue
        if binary_l not in name_l:
            continue
        if not any(tok in name_l for tok in tokens):
            continue

        candidates.append((name, url))

    if not candidates:
        raise SystemExit("Could not find a matching release asset for this OS/arch")
    return candidates[0]


def _extract_from_zip(data: bytes, binary: str) -> bytes:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = [m for m in zf.namelist() if m.endswith(f"/{binary}") or m == binary]
        if not members:
            raise SystemExit(f"Downloaded zip does not contain '{binary}'")
        return zf.read(members[0])


def _extract_from_tar(data: bytes, binary: str) -> bytes:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        members = [m for m in tf.getmembers() if m.name.endswith(f"/{binary}") or m.name == binary]
        if not members:
            raise SystemExit(f"Downloaded tar does not contain '{binary}'")
        member = members[0]
        extracted = tf.extractfile(member)
        if extracted is None:
            raise SystemExit(f"Failed to extract '{binary}' from tar")
        return extracted.read()


def main(argv: list[str]) -> int:
    if len(argv) not in {3, 4}:
        print("Usage: install_github_release_binary.py <org/repo> <binary> [sha256]", file=sys.stderr)
        return 2

    repo = argv[1].strip()
    binary = argv[2].strip()
    sha_arg = argv[3].strip() if len(argv) == 4 else ""

    api_latest = f"https://api.github.com/repos/{repo}/releases/latest"
    release = json.loads(_download(api_latest, accept_json=True).decode("utf-8", errors="replace"))
    asset_name, asset_url = _pick_asset(release, binary)

    print(f"Downloading {repo} asset {asset_name} ...", file=sys.stderr)
    data = _download(asset_url)

    env_key = f"GUARDIAN_{binary.upper()}_SHA256"
    expected_sha = sha_arg or os.getenv(env_key) or os.getenv("GUARDIAN_SHA256") or ""
    _verify_sha256(data, expected_sha, asset_name)

    out_dir = Path(__file__).resolve().parent.parent / "tools" / ".bin"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / binary

    asset_l = asset_name.lower()
    if asset_l.endswith(".zip"):
        extracted = _extract_from_zip(data, binary)
    else:
        extracted = _extract_from_tar(data, binary)

    out_path.write_bytes(extracted)
    out_path.chmod(out_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Installed {binary} to {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
