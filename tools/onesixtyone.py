"""
onesixtyone tool wrapper for SNMP community discovery
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class OnesixtyoneTool(BaseTool):
    """onesixtyone SNMP brute force wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "onesixtyone"

    def _check_installation(self) -> bool:
        return shutil.which("onesixtyone") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("onesixtyone", {}) or {}
        wordlist = kwargs.get("wordlist") or cfg.get("wordlist")
        community = kwargs.get("community") or cfg.get("community") or "public"

        command = ["onesixtyone", "-q"]
        if wordlist:
            command.extend(["-c", str(wordlist)])
            command.append(target)
        else:
            command.extend([target, str(community)])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"matches": [], "communities": {}}
        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # Typical format: "192.168.1.10 [public]"
            m = re.match(r"^(\\S+)\\s+\\[(.+)\\]$", line)
            if m:
                host = m.group(1)
                community = m.group(2).strip()
                results["matches"].append({"host": host, "community": community})
                results["communities"].setdefault(host, []).append(community)
        return results
