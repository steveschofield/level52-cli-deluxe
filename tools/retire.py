"""
Retire.js wrapper for JavaScript library vulnerability scanning
"""

import hashlib
import os
import ssl
import tempfile
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Dict, Any, List, Optional

from tools.base_tool import BaseTool


class _ScriptTagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "script":
            return
        attrs = dict((k.lower(), v) for k, v in attrs)
        src = attrs.get("src")
        if src:
            self.scripts.append(src)


class RetireTool(BaseTool):
    """Retire.js wrapper"""

    def is_success_exit_code(self, exit_code: int) -> bool:
        """
        Retire.js exit codes:
        0 = No vulnerabilities found
        13 = Vulnerabilities found (this is still success!)
        Other non-zero = Actual failure
        """
        return exit_code in (0, 13)

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("retire", {}) or {}
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        scan_path = kwargs.get("scan_path") or target

        command = ["retire", "--outputformat", "json"]

        if args:
            args = str(args)
            if "{target}" in args:
                args = args.replace("{target}", str(scan_path))
            elif str(scan_path) not in args:
                args = f"{args} {scan_path}"
            if "--url" in args:
                args = args.replace("--url", "--path")
            command.extend(args.split())
            return command

        command.extend(["--path", str(scan_path)])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        script_urls = kwargs.pop("script_urls", None)
        scan_path = kwargs.pop("scan_path", None)
        cfg = (self.config or {}).get("tools", {}).get("retire", {}) or {}

        tmp_dir: Optional[tempfile.TemporaryDirectory] = None
        if scan_path is None:
            candidate_url = None
            if self._is_url(target):
                candidate_url = target
            elif os.path.exists(target):
                scan_path = target
            else:
                scheme = cfg.get("scheme") or "http"
                candidate_url = f"{scheme}://{target}"

            if candidate_url:
                timeout = kwargs.get("timeout") or cfg.get("timeout", 10)
                insecure = kwargs.get("insecure") or cfg.get("insecure", False)
                max_scripts = kwargs.get("max_scripts") or cfg.get("max_scripts", 20)
                try:
                    timeout = int(timeout)
                except Exception:
                    timeout = 10
                try:
                    max_scripts = int(max_scripts)
                except Exception:
                    max_scripts = 20

                tmp_dir = tempfile.TemporaryDirectory(prefix="guardian-retire-")
                scan_path = self._populate_scan_dir(
                    target_url=candidate_url,
                    out_dir=tmp_dir.name,
                    script_urls=script_urls,
                    timeout=timeout,
                    insecure=bool(insecure),
                    max_scripts=max_scripts,
                )
                if not scan_path:
                    if tmp_dir:
                        tmp_dir.cleanup()
                    raise ValueError("retire: no JavaScript assets discovered to scan")

        try:
            return await super().execute(target, scan_path=scan_path, **kwargs)
        finally:
            if tmp_dir:
                tmp_dir.cleanup()

    def _is_url(self, target: str) -> bool:
        return target.startswith("http://") or target.startswith("https://")

    def _fetch_text(self, url: str, timeout: int, insecure: bool) -> str:
        ctx = None
        if insecure and url.lower().startswith("https://"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Guardian-Retire/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            return resp.read().decode(charset, errors="replace")

    def _populate_scan_dir(
        self,
        target_url: str,
        out_dir: str,
        script_urls: Optional[List[str]],
        timeout: int,
        insecure: bool,
        max_scripts: int,
    ) -> Optional[str]:
        urls: List[str] = []
        if script_urls and isinstance(script_urls, list):
            urls = [u for u in script_urls if isinstance(u, str)]

        if not urls:
            if target_url.lower().endswith(".js"):
                urls = [target_url]
            else:
                try:
                    html = self._fetch_text(target_url, timeout=timeout, insecure=insecure)
                except Exception:
                    html = ""
                parser = _ScriptTagParser()
                parser.feed(html or "")
                urls = [
                    urllib.parse.urljoin(target_url, src)
                    for src in parser.scripts
                    if src
                ]

        if max_scripts > 0:
            urls = urls[:max_scripts]

        written = 0
        for idx, url in enumerate(dict.fromkeys(urls)):
            try:
                content = self._fetch_text(url, timeout=timeout, insecure=insecure)
            except Exception:
                continue
            filename = self._safe_script_name(url, idx)
            filepath = os.path.join(out_dir, filename)
            try:
                with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                    f.write(content)
                written += 1
            except Exception:
                continue

        if written == 0:
            return None
        return out_dir

    def _safe_script_name(self, url: str, idx: int) -> str:
        parsed = urllib.parse.urlparse(url)
        base = os.path.basename(parsed.path) or f"script_{idx}.js"
        if not base.lower().endswith(".js"):
            base = f"{base}.js"
        safe_base = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in base)
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
        return f"{digest}_{safe_base}"
