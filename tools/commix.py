"""
Commix tool wrapper for command injection testing
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class CommixTool(BaseTool):
    """Commix command injection scanner wrapper"""
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        command = ["commix", "--url", target, "--batch"]
        
        if kwargs.get("data"):
            command.extend(["--data", kwargs["data"]])
        
        if kwargs.get("cookie"):
            command.extend(["--cookie", kwargs["cookie"]])
            
        if kwargs.get("level"):
            command.extend(["--level", str(kwargs["level"])])
            
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Commix output"""
        vulnerabilities = []
        
        if "is vulnerable" in output.lower():
            lines = output.split('\n')
            for line in lines:
                if "vulnerable" in line.lower() and "parameter" in line.lower():
                    vuln = {
                        "name": "Command Injection",
                        "severity": "high",
                        "description": line.strip(),
                        "type": "command_injection"
                    }
                    vulnerabilities.append(vuln)
        
        return {
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities)
        }