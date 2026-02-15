"""
enum4linux-ng tool wrapper for SMB enumeration
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class Enum4linuxNgTool(BaseTool):
    """enum4linux-ng SMB enumeration wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "enum4linux-ng"

    def _check_installation(self) -> bool:
        # Check for enum4linux-ng (preferred) or enum4linux-ng.py (some distros)
        return bool(shutil.which("enum4linux-ng") or shutil.which("enum4linux-ng.py"))

    def get_command(self, target: str, **kwargs) -> List[str]:
        tools_cfg = (self.config or {}).get("tools", {}) or {}
        cfg = (
            tools_cfg.get("enum4linux-ng")
            or tools_cfg.get("enum4linux_ng")
            or tools_cfg.get("enum4linux")
            or {}
        )

        binary = cfg.get("command") or cfg.get("binary") or shutil.which("enum4linux-ng") or shutil.which("enum4linux-ng.py") or "enum4linux-ng"
        args = kwargs.get("args")
        if args is None:
            args = kwargs.get("scan_type")
        if args is None:
            args = cfg.get("args")
        if args is None:
            args = cfg.get("default_args", "-A")

        username = kwargs.get("username") if "username" in kwargs else cfg.get("username")
        password = kwargs.get("password") if "password" in kwargs else cfg.get("password")
        output_format = kwargs.get("output_format")

        command = [str(binary)]
        if args:
            command.extend(str(args).replace("{target}", target).split())
        if output_format:
            command.extend(str(output_format).replace("{target}", target).split())
        if username is not None:
            command.extend(["-u", str(username)])
        if password is not None:
            command.extend(["-p", str(password)])
        if "{target}" not in str(args):
            command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "shares": [],
            "users": [],
            "null_session_allowed": False,
        }
        text = output or ""

        if re.search(r"null session|anonymous|guest", text, re.IGNORECASE):
            results["null_session_allowed"] = True

        # Fallback parsing for plaintext mode.
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.lower().startswith("share:"):
                share = stripped.split(":", 1)[1].strip()
                if share and share not in results["shares"]:
                    results["shares"].append(share)
            if stripped.lower().startswith("user:"):
                user = stripped.split(":", 1)[1].strip()
                if user and user not in results["users"]:
                    results["users"].append(user)

        return results
