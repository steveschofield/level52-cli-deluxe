"""
Dalfox tool wrapper for XSS vulnerability scanning
"""

import json
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class DalfoxTool(BaseTool):
    """Dalfox XSS scanner wrapper"""
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["dalfox"]

        if kwargs.get("from_file"):
            from_file = kwargs["from_file"]
            command.extend(["file", from_file])
        else:
            command.extend(["url", target])

        command.extend(["--format", "json"])
        
        if kwargs.get("deep"):
            command.append("--deep-domxss")
        
        if kwargs.get("blind"):
            command.extend(["--blind", kwargs["blind"]])
            
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Dalfox JSON output"""
        vulnerabilities = []
        
        for line in output.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get("type") == "VULN":
                    vuln = {
                        "name": "Cross-Site Scripting (XSS)",
                        "severity": "medium",
                        "url": data.get("data", ""),
                        "parameter": data.get("param", ""),
                        "payload": data.get("payload", ""),
                        "evidence": data.get("evidence", "")
                    }
                    vulnerabilities.append(vuln)
            except json.JSONDecodeError:
                continue
        
        return {
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities)
        }
