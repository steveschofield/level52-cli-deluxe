"""
whois tool wrapper for WHOIS lookup
"""

import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class WhoisTool(BaseTool):
    """whois lookup wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "whois"

    def _check_installation(self) -> bool:
        return shutil.which("whois") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        return ["whois", target]

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
