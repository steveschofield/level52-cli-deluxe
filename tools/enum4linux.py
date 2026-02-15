"""
enum4linux tool wrapper for SMB enumeration
"""

import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class Enum4linuxTool(BaseTool):
    """enum4linux SMB enumeration wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "enum4linux"

    def _check_installation(self) -> bool:
        return shutil.which("enum4linux") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("enum4linux", {}) or {}
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args") or "-a"
        username = kwargs.get("username") if "username" in kwargs else cfg.get("username")
        password = kwargs.get("password") if "password" in kwargs else cfg.get("password")
        command = ["enum4linux"]
        if args:
            command.extend(str(args).split())
        if username is not None:
            command.extend(["-u", str(username)])
        if password is not None:
            command.extend(["-p", str(password)])
        command.append(target)
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"shares": [], "users": []}
        text = (output or "").splitlines()
        capture_shares = False
        for line in text:
            if line.strip().lower().startswith("sharename"):
                capture_shares = True
                continue
            if capture_shares:
                if not line.strip() or line.strip().startswith("----"):
                    continue
                parts = line.split()
                if parts:
                    share = parts[0].strip()
                    if share and share not in results["shares"]:
                        results["shares"].append(share)
        return results
