"""
asnmap tool wrapper for ASN lookups and CIDR discovery
"""

import json
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class AsnmapTool(BaseTool):
    """asnmap asset mapping wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "asnmap"

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build asnmap command"""
        config = self.config.get("tools", {}).get("asnmap", {})

        command = ["asnmap", "-json"]

        # Include organization info if requested
        if config.get("include_org", True):
            command.append("-org")

        # Input target(s)
        if kwargs.get("from_file"):
            command.extend(["-ilist", kwargs["from_file"]])
        else:
            command.extend(["-i", target])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse asnmap JSONL output"""
        results = {
            "asn_info": [],
            "prefixes": {}
        }

        for line in output.strip().splitlines():
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            asn = data.get("asn") or data.get("autonomous_system_number")
            org = data.get("organization") or data.get("org")
            country = data.get("country")
            prefixes = data.get("prefixes") or []

            entry = {
                "asn": asn,
                "organization": org,
                "country": country,
                "prefix_count": len(prefixes)
            }
            results["asn_info"].append(entry)

            for cidr in prefixes:
                results["prefixes"][cidr] = {
                    "asn": asn,
                    "organization": org,
                    "country": country
                }

        return results
