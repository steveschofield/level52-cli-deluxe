#!/usr/bin/env python3
"""
Minimal upload-scanner fallback (HTML form inspection).
"""

from __future__ import annotations

import argparse
import json
import ssl
import urllib.parse
import urllib.request
from html.parser import HTMLParser


class UploadFormParser(HTMLParser):
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
                "enctype": attrs.get("enctype", "").strip(),
                "file_inputs": [],
            }
            self._form_stack.append(form)
            return

        if tag.lower() == "input":
            input_type = (attrs.get("type") or "").lower()
            if input_type == "file":
                entry = {
                    "name": attrs.get("name", "") or attrs.get("id", ""),
                    "accept": attrs.get("accept", ""),
                }
                if self._form_stack:
                    self._form_stack[-1]["file_inputs"].append(entry)
                else:
                    self.forms.append(
                        {
                            "action": "",
                            "method": "GET",
                            "enctype": "",
                            "file_inputs": [entry],
                        }
                    )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form_stack:
            self.forms.append(self._form_stack.pop())


def fetch_html(url: str, *, timeout: int, insecure: bool) -> str:
    ctx = None
    if insecure and url.lower().startswith("https://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Guardian-Upload-Scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal upload form inspector")
    parser.add_argument("--url", "-u", required=True, help="Target URL to inspect")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    args = parser.parse_args()

    target_url = args.url
    html = fetch_html(target_url, timeout=args.timeout, insecure=args.insecure)

    parser_obj = UploadFormParser()
    parser_obj.feed(html)

    forms_with_files = [f for f in parser_obj.forms if f.get("file_inputs")]

    for form in forms_with_files:
        if form.get("action"):
            form["action"] = urllib.parse.urljoin(target_url, form["action"])

    payload = {
        "url": target_url,
        "forms_total": len(parser_obj.forms),
        "forms_with_file_inputs": forms_with_files,
        "file_inputs_total": sum(len(f.get("file_inputs", [])) for f in forms_with_files),
    }

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
