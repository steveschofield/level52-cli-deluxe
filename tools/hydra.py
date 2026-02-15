"""
hydra tool wrapper for authentication testing
"""

import os
import shutil
from urllib.parse import urlparse
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class HydraTool(BaseTool):
    """Hydra authentication testing wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "hydra"

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("hydra", {}) or {}
        binary = cfg.get("binary")
        return bool((binary and os.path.isfile(str(binary))) or shutil.which("hydra"))

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("hydra", {}) or {}
        binary = cfg.get("binary") or "hydra"
        normalized_target = target
        if "://" in target:
            parsed = urlparse(target)
            if parsed.hostname:
                normalized_target = parsed.hostname

        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        if args:
            args_str = str(args)
            if "{target}" in args_str:
                args_str = args_str.replace("{target}", normalized_target)
            command = [binary] + args_str.split()
            if "{target}" not in str(args) and normalized_target not in command:
                command.append(normalized_target)
            return command

        userlist = kwargs.get("userlist") or cfg.get("userlist")
        passlist = kwargs.get("passlist") or cfg.get("passlist")
        service = kwargs.get("service") or cfg.get("service")
        module_args = kwargs.get("module_args") or cfg.get("module_args")

        if not userlist or not passlist or not service:
            raise ValueError("hydra requires args or userlist/passlist/service")

        userlist = os.path.expandvars(os.path.expanduser(str(userlist)))
        passlist = os.path.expandvars(os.path.expanduser(str(passlist)))

        command = [binary, "-L", userlist, "-P", passlist, normalized_target, str(service)]
        if module_args:
            command.extend(str(module_args).split())
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
