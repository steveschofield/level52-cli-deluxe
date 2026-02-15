"""
smbclient tool wrapper for SMB share enumeration
"""

import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class SmbclientTool(BaseTool):
    """smbclient wrapper for listing shares"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "smbclient"

    def _check_installation(self) -> bool:
        return shutil.which("smbclient") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("smbclient", {}) or {}
        username = kwargs.get("username") or cfg.get("username")
        password = kwargs.get("password") or cfg.get("password")

        command = ["smbclient", "-L", f"//{target}"]
        if username:
            if password:
                command.extend(["-U", f"{username}%{password}"])
            else:
                command.extend(["-U", username])
        else:
            command.append("-N")
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"shares": []}
        lines = (output or "").splitlines()
        capture = False
        for line in lines:
            if line.strip().lower().startswith("sharename"):
                capture = True
                continue
            if capture:
                if not line.strip():
                    continue
                if line.strip().startswith("----"):
                    continue
                parts = line.split()
                if parts:
                    share = parts[0].strip()
                    if share and share not in results["shares"]:
                        results["shares"].append(share)
        return results
