"""
showmount tool wrapper for NFS enumeration
"""

import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class ShowmountTool(BaseTool):
    """showmount NFS exports wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "showmount"

    def _check_installation(self) -> bool:
        return shutil.which("showmount") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        return ["showmount", "-e", target]

    def parse_output(self, output: str) -> Dict[str, Any]:
        exports: List[str] = []
        lines = (output or "").splitlines()
        capture = False
        for line in lines:
            if line.lower().startswith("export list for"):
                capture = True
                continue
            if capture:
                if not line.strip():
                    continue
                exports.append(line.strip())
        return {"exports": exports}
