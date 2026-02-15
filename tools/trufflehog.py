"""
TruffleHog wrapper for secret scanning
"""

import json
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class TrufflehogTool(BaseTool):
    """trufflehog wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        mode = "url" if target.startswith(("http://", "https://")) else "filesystem"
        command = ["trufflehog", mode, target, "--json"]
        if kwargs.get("only_verified"):
            command.append("--only-verified")
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(data)
            except json.JSONDecodeError:
                continue
        return {"findings": findings, "count": len(findings)}
