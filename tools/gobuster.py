"""
gobuster tool wrapper for directory/path discovery
"""

import re
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class GobusterTool(BaseTool):
    """gobuster directory scanner wrapper (dir mode)"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "gobuster"

    def is_success_exit_code(self, exit_code: int) -> bool:
        # 0 = found results, 1 = no results / completed cleanly
        return exit_code in (0, 1)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build gobuster dir command"""
        cfg = (self.config or {}).get("tools", {}).get("gobuster", {})

        wordlist = (
            kwargs.get("wordlist")
            or cfg.get("wordlist")
            or "/usr/share/wordlists/dirb/common.txt"
        )

        # Thread count — keep low by default to avoid hammering targets
        threads = int(kwargs.get("threads") or cfg.get("threads") or 10)

        # Per-request delay in milliseconds (--delay) — adds courtesy pause
        delay_ms = int(kwargs.get("delay_ms") or cfg.get("delay_ms") or 0)

        # Timeout per request in seconds
        timeout = int(kwargs.get("request_timeout") or cfg.get("request_timeout") or 10)

        command = [
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-t", str(threads),
            "--timeout", f"{timeout}s",
            "-q",           # suppress banner
            "--no-progress",  # suppress progress bar
            "--no-error",   # suppress connection errors to keep output clean
            "--no-color",   # no ANSI codes in output
        ]

        if delay_ms > 0:
            command.extend(["--delay", f"{delay_ms}ms"])

        extensions = kwargs.get("extensions") or cfg.get("extensions")
        if extensions:
            command.extend(["-x", str(extensions)])

        # Follow redirects
        if kwargs.get("follow_redirects") or cfg.get("follow_redirects"):
            command.append("-r")

        # Skip TLS verification
        if kwargs.get("insecure") or cfg.get("insecure"):
            command.append("-k")

        # Custom status codes to include (overrides gobuster defaults)
        status_codes = kwargs.get("status_codes") or cfg.get("status_codes")
        if status_codes:
            command.extend(["-s", str(status_codes)])

        # Status codes to exclude
        exclude_codes = kwargs.get("exclude_codes") or cfg.get("exclude_codes")
        if exclude_codes:
            command.extend(["-b", str(exclude_codes)])

        # Also discover backup files
        if kwargs.get("discover_backup") or cfg.get("discover_backup"):
            command.append("--discover-backup")

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """
        Parse gobuster dir plain-text output.

        Example lines:
          /admin                (Status: 200) [Size: 12345]
          /login                (Status: 301) [Size: 234] [--> /login/]
        """
        endpoints = []
        api_endpoints = []
        urls = []

        pattern = re.compile(
            r"^(\/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\](?:\s+\[--> ([^\]]+)\])?"
        )

        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            m = pattern.match(line)
            if not m:
                continue
            path, status, size, redirect = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
            endpoints.append({
                "path": path,
                "status": status,
                "size": size,
                "redirect": redirect,
            })
            # Build full URL if we know the base — path is relative so we
            # return both so callers can decide.
            if any(api_kw in path.lower() for api_kw in ["/api/", "/v1/", "/v2/", "/rest/", "/graphql"]):
                api_endpoints.append(path)
            urls.append(path)

        return {
            "endpoints": endpoints,
            "api_endpoints": api_endpoints,
            "urls": urls,
            "total_found": len(endpoints),
            "api_count": len(api_endpoints),
        }
