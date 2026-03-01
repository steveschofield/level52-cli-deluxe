import os
import json
import tempfile
import uuid
from typing import List, Dict, Any
from tools.base_tool import BaseTool

class ArjunTool(BaseTool):
    """Wrapper for Arjun - HTTP Parameter Discovery Tool"""

    def is_success_exit_code(self, exit_code: int) -> bool:
        """
        arjun exit codes:
        0 = Success
        2 = No parameters found or target unreachable (not a failure)
        """
        return exit_code in (0, 2)

    def get_command(self, target: str, **kwargs) -> List[str]:
        cmd = ["arjun", "-u", target, "--json"]

        if kwargs.get("method"):
            cmd.extend(["-m", kwargs["method"]])

        if kwargs.get("threads"):
            cmd.extend(["-t", str(kwargs["threads"])])

        if kwargs.get("delay"):
            cmd.extend(["--delay", str(kwargs["delay"])])

        self.output_file = os.path.join(
            tempfile.gettempdir(), f"guardian-arjun-{uuid.uuid4().hex}.json"
        )
        cmd.extend(["-oJ", self.output_file])

        return cmd

    def parse_output(self, output: str) -> Dict[str, Any]:
        result = {
            "params": [],
            "method": "GET",
            "raw_output": output
        }

        if not hasattr(self, "output_file"):
            return result

        if os.path.exists(self.output_file):
            try:
                with open(self.output_file, 'r') as f:
                    data = json.load(f)

                if isinstance(data, dict):
                    if "params" in data:
                        result["params"] = data["params"]
                        result["method"] = data.get("method", "GET")
                    else:
                        for url, info in data.items():
                            if isinstance(info, dict) and "params" in info:
                                result["params"].extend(info["params"])
                                result["method"] = info.get("method", "GET")
            except Exception as e:
                self.logger.error(f"Error parsing Arjun JSON: {e}")
            finally:
                try:
                    os.remove(self.output_file)
                except OSError:
                    pass

        return result
