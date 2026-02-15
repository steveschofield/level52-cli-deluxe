"""
snmpwalk tool wrapper for SNMP enumeration
"""

import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class SnmpwalkTool(BaseTool):
    """snmpwalk enumeration wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "snmpwalk"

    def _check_installation(self) -> bool:
        return shutil.which("snmpwalk") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("snmpwalk", {}) or {}
        version = kwargs.get("version") or cfg.get("version") or "2c"
        community = kwargs.get("community") or cfg.get("community") or "public"
        oid = kwargs.get("oid") or cfg.get("oid") or ""

        command = ["snmpwalk", "-v", str(version), "-c", str(community), target]
        if oid:
            command.append(str(oid))
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        items = [line.strip() for line in (output or "").splitlines() if line.strip()]
        return {"items": items, "count": len(items)}
