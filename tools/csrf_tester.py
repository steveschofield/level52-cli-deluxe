"""
csrf tester tool wrapper
"""

import os
import shutil
import sys
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class CsrfTesterTool(BaseTool):
    """CSRF tester wrapper"""

    def __init__(self, config):
        self._binary = None
        self._script_path = None
        super().__init__(config)
        self.tool_name = "csrf-tester"

    def _resolve_binary(self) -> str | None:
        cfg = (self.config or {}).get("tools", {}).get("csrf_tester", {}) or {}
        binary = cfg.get("binary")
        if binary and os.path.isfile(str(binary)):
            return str(binary)
        for name in ("csrf-tester", "csrftester"):
            found = shutil.which(name)
            if found:
                return found
        return None

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("csrf_tester", {}) or {}
        script = cfg.get("script")
        if script and os.path.isfile(str(script)):
            self._script_path = str(script)
            return True
        local_script = self._local_script()
        if local_script:
            self._script_path = local_script
            return True
        self._binary = self._resolve_binary()
        return self._binary is not None

    def _local_script(self) -> str | None:
        here = os.path.abspath(os.path.dirname(__file__))
        repo_root = os.path.abspath(os.path.join(here, os.pardir))
        candidate = os.path.join(repo_root, "tools", "vendor", "guardian_tools", "csrf_tester.py")
        return candidate if os.path.isfile(candidate) else None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("csrf_tester", {}) or {}
        binary = self._binary or cfg.get("binary") or "csrf-tester"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        script = kwargs.get("script") or cfg.get("script") or self._script_path
        insecure = kwargs.get("insecure") if "insecure" in kwargs else cfg.get("insecure")

        if args:
            args = str(args).replace("{target}", target)
            if insecure and "--insecure" not in args:
                args = f"{args} --insecure"
            if script:
                script = os.path.expandvars(os.path.expanduser(str(script)))
                return [sys.executable, script] + args.split()
            return [binary] + args.split()

        raise ValueError("csrf tester requires args in config")

    def parse_output(self, output: str) -> Dict[str, Any]:
        return {"raw": output}
