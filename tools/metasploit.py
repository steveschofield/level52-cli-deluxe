"""
Metasploit wrapper for scripted module execution
"""

import os
import shutil
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class MetasploitTool(BaseTool):
    """metasploit wrapper (msfconsole scripted run)"""

    def __init__(self, config):
        self._binary: str | None = None
        super().__init__(config)
        self.tool_name = "msfconsole"

    def _check_installation(self) -> bool:
        resolved = self._resolve_tool_path()
        if resolved:
            self._binary = resolved
            return True

        cfg = (self.config or {}).get("tools", {}).get("metasploit", {}) or {}
        binary = cfg.get("binary")
        if binary and os.path.isfile(str(binary)):
            self._binary = str(binary)
            return True

        found = shutil.which("msfconsole")
        if found:
            self._binary = found
            return True

        return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("metasploit", {}) or {}

        if kwargs.get("msf_commands") or cfg.get("msf_commands"):
            command_string = kwargs.get("msf_commands") or cfg.get("msf_commands")
        elif kwargs.get("module") or cfg.get("module"):
            module = kwargs.get("module") or cfg.get("module")
            rhosts = kwargs.get("rhosts") or cfg.get("rhosts") or target
            extra = kwargs.get("extra_commands") or cfg.get("extra_commands", "")
            command_string = f"use {module}; set RHOSTS {rhosts}; {extra}; run; exit"
        else:
            # Fast sanity check
            command_string = "version; exit"

        return [self._binary or "msfconsole", "-q", "-x", command_string]

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw_output": output}
