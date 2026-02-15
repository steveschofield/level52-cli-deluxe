"""
amass tool wrapper for passive OSINT enumeration
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class AmassTool(BaseTool):
    """amass enumeration wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "amass"

    def _check_installation(self) -> bool:
        return shutil.which("amass") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("amass", {}) or {}
        args = kwargs.get("args") or cfg.get("args") or "-passive"
        command = ["amass", "enum"]
        if args:
            command.extend(str(args).split())
        command.extend(["-d", target])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"domains": []}
        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if re.search(r"[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", line):
                results["domains"].append(line)
        return results
