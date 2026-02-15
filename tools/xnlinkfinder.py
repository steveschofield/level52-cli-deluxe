"""
xnLinkFinder wrapper for advanced JS endpoint extraction
"""

import os
import re
import shutil
from typing import Dict, Any, List
from tools.base_tool import BaseTool


class XnlinkfinderTool(BaseTool):
    """xnlinkfinder wrapper"""

    def __init__(self, config):
        self._binary: str | None = None
        super().__init__(config)
        # Config keys use xnlinkfinder; binary installs as xnLinkFinder.
        self.tool_name = "xnlinkfinder"

    def _check_installation(self) -> bool:
        resolved = self._resolve_tool_path()
        if resolved:
            self._binary = resolved
            return True

        cfg = (self.config or {}).get("tools", {}).get("xnlinkfinder", {}) or {}
        binary = cfg.get("binary")
        if binary and os.path.isfile(str(binary)):
            self._binary = str(binary)
            return True

        for candidate in ("xnLinkFinder", "xnlinkfinder"):
            found = shutil.which(candidate)
            if found:
                self._binary = found
                return True

        return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        binary = self._binary or "xnLinkFinder"
        input_target = kwargs.get("from_file") or target
        command = [binary, "-i", input_target]
        if kwargs.get("domain"):
            command.extend(["-d", kwargs["domain"]])
        if kwargs.get("output"):
            command.extend(["-o", kwargs["output"]])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = []
        for line in output.splitlines():
            for match in re.findall(r"https?://[^\s\"'<>]+", line):
                urls.append(match)
        return {"urls": urls}
