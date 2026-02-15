#!/usr/bin/env python3
"""
Minimal CSRF form inspection (token presence heuristic).
"""

from __future__ import annotations

import argparse
import json
import ssl
import urllib.parse
import urllib.request
from html.parser import HTMLParser


TOKEN_KEYS = ("csrf", "xsrf", "token", "authenticity", "nonce")


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = []
        self._form_stack = []

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs = dict((k.lower(), v) for k, v in attrs)
        if tag.lower() == "form":
            form = {
                "action": attrs.get("action", "").strip(),
                "method": (attrs.get("method") or "GET").upper(),
                "tokens": [],
            }
            self._form_stack.append(form)
            return

        if tag.lower() == "input" and self._form_stack:
            name = (attrs.get("name") or attrs.get("id") or "").lower()
            if any(key in name for key in TOKEN_KEYS):
                self._form_stack[-1]["tokens"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form_stack:
            self.forms.append(self._form_stack.pop())


def fetch_html(url: str, *, timeout: int, insecure: bool) -> str:
    ctx = None
    if insecure and url.lower().startswith("https://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Guardian-CSRF-Tester/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal CSRF token heuristic")
    parser.add_argument("--url", "-u", required=True, help="Target URL to inspect")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    target_url = args.url
    html = fetch_html(target_url, timeout=args.timeout, insecure=args.insecure)

    parser_obj = FormParser()
    parser_obj.feed(html)

    with_tokens = []
    without_tokens = []
    for form in parser_obj.forms:
        if form.get("action"):
            form["action"] = urllib.parse.urljoin(target_url, form["action"])
        if form["tokens"]:
            with_tokens.append(form)
        else:
            without_tokens.append(form)

    payload = {
        "url": target_url,
        "forms_total": len(parser_obj.forms),
        "forms_with_tokens": with_tokens,
        "forms_missing_tokens": without_tokens,
    }

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
