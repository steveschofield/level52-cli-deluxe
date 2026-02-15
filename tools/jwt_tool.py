"""
jwt_tool wrapper for JWT analysis
"""

import os
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class JwtTool(BaseTool):
    """jwt_tool wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "jwt_tool"

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("jwt_tool", {}) or {}
        binary = cfg.get("binary")
        return bool((binary and os.path.isfile(str(binary))) or shutil.which("jwt_tool"))

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("jwt_tool", {}) or {}
        binary = cfg.get("binary") or "jwt_tool"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        token = kwargs.get("token") if "token" in kwargs else cfg.get("token")

        if args:
            args = str(args).replace("{target}", target)
            if "{token}" in args:
                if not token:
                    raise ValueError("jwt_tool requires token when args include {token}")
                args = args.replace("{token}", str(token))
            elif token and str(token) not in args:
                args = f"{args} {token}"
            return [binary] + args.split()

        if not token:
            raise ValueError("jwt_tool requires token or args")

        command = [binary, str(token)]
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
