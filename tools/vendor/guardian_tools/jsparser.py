#!/usr/bin/env python3
"""
Lightweight JS endpoint extractor (fallback for JSParser).
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import urllib.parse
import urllib.request
from html.parser import HTMLParser


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(/api/[A-Za-z0-9_./-]+)", re.IGNORECASE)


class ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        attrs = dict((k.lower(), v) for k, v in attrs)
        src = attrs.get("src")
        if src:
            self.scripts.append(src)


def fetch_text(url: str, *, timeout: int, insecure: bool) -> str:
    ctx = None
    if insecure and url.lower().startswith("https://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Guardian-JSParser/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def extract_endpoints(text: str) -> dict[str, list[str]]:
    urls = URL_RE.findall(text or "")
    paths = PATH_RE.findall(text or "")
    return {
        "urls": list(dict.fromkeys(urls)),
        "paths": list(dict.fromkeys(paths)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Lightweight JS endpoint extractor")
    parser.add_argument("--url", "-u", required=True, help="Target URL (HTML or JS)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--max-scripts", type=int, default=10, help="Max linked scripts to inspect")
    args = parser.parse_args()

    target_url = args.url
    content = fetch_text(target_url, timeout=args.timeout, insecure=args.insecure)

    scripts = []
    if target_url.lower().endswith(".js"):
        scripts = [target_url]
    else:
        parser_obj = ScriptParser()
        parser_obj.feed(content)
        scripts = [urllib.parse.urljoin(target_url, s) for s in parser_obj.scripts[: args.max_scripts]]

    urls = []
    paths = []

    primary = extract_endpoints(content)
    urls.extend(primary["urls"])
    paths.extend(primary["paths"])

    for script_url in scripts:
        try:
            script_text = fetch_text(script_url, timeout=args.timeout, insecure=args.insecure)
        except Exception:
            continue
        extracted = extract_endpoints(script_text)
        urls.extend(extracted["urls"])
        paths.extend(extracted["paths"])

    payload = {
        "url": target_url,
        "scripts_checked": scripts,
        "urls": list(dict.fromkeys(urls)),
        "paths": list(dict.fromkeys(paths)),
    }

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
