"""
LinkFinder wrapper for extracting endpoints from JS
"""

import os
import re
import shutil
import sys
from typing import Dict, Any, List
from importlib.util import find_spec
from tools.base_tool import BaseTool
from utils.logger import get_logger


class LinkfinderTool(BaseTool):
    """linkfinder wrapper"""

    def __init__(self, config):
        self._script_path = None
        super().__init__(config)
        self.tool_name = "linkfinder"

    def _check_installation(self) -> bool:
        # Check for linkfinder script in PATH first (Docker container)
        if shutil.which("linkfinder"):
            return True
        if shutil.which("linkfinder.py"):
            return True
        # Check vendored location
        vendor_script = os.path.join(
            os.path.dirname(__file__), "..", "tools", "vendor", "LinkFinder", "linkfinder.py"
        )
        if os.path.isfile(vendor_script):
            self._script_path = vendor_script
            return True
        # Check /opt/tools location (Docker)
        opt_script = "/opt/tools/LinkFinder/linkfinder.py"
        if os.path.isfile(opt_script):
            self._script_path = opt_script
            return True
        # Check for Python module
        if find_spec("linkfinder") is not None:
            return True
        self.logger.warning("Tool linkfinder is not installed or importable (pip install linkfinder-py)")
        return False

    def get_command(self, target: str, **kwargs) -> List[str]:
        if not self.is_available:
            raise RuntimeError("linkfinder not installed. Install with: pip install linkfinder-py or use Docker image")

        if self._script_path:
            command = [sys.executable, self._script_path, "-i", target, "-o", "cli"]
        elif shutil.which("linkfinder"):
            command = ["linkfinder", "-i", target, "-o", "cli"]
        elif shutil.which("linkfinder.py"):
            command = ["linkfinder.py", "-i", target, "-o", "cli"]
        else:
            command = [sys.executable, "-m", "linkfinder", "-i", target, "-o", "cli"]

        if kwargs.get("custom_regex"):
            command.extend(["-r", kwargs["custom_regex"]])
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        urls = []
        for line in output.splitlines():
            for match in re.findall(r"https?://[^\s\"'<>]+", line):
                urls.append(match)
        return {"urls": urls}
