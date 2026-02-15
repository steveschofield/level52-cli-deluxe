"""
ParamSpider wrapper for parameter discovery
"""

import asyncio
import os
import re
import tempfile
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from tools.base_tool import BaseTool


class ParamspiderTool(BaseTool):
    """paramspider wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        parsed = urlparse(target)
        domain = parsed.netloc or target

        command = ["paramspider", "-d", domain]

        if kwargs.get("exclude"):
            command.extend(["-e", kwargs["exclude"]])
        if kwargs.get("threads"):
            command.extend(["-t", str(kwargs["threads"])])
        if kwargs.get("level"):
            command.extend(["-l", str(kwargs["level"])])

        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Override execute to run paramspider from a temp directory so that
        its 'results/' folder is not created at the project root.
        """
        if not self.is_available:
            raise RuntimeError(f"Tool {self.tool_name} is not available")

        command = self.get_command(target, **kwargs)
        command = self._apply_resolved_binary(command)
        self._validate_safe_mode(command)

        self.logger.info(f"Executing: {' '.join(command)}")

        timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        start_time = datetime.now()

        with tempfile.TemporaryDirectory(prefix="guardian-paramspider-") as tmpdir:
            process: asyncio.subprocess.Process | None = None
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=tmpdir,  # Run from temp dir so results/ is created there
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.CancelledError:
                try:
                    if process and process.returncode is None:
                        process.kill()
                        await process.communicate()
                except Exception:
                    pass
                raise
            except asyncio.TimeoutError:
                try:
                    if process:
                        process.kill()
                        await process.communicate()
                except Exception:
                    pass
                raise

            duration = (datetime.now() - start_time).total_seconds()
            output = (stdout or b"").decode("utf-8", errors="replace")
            error = (stderr or b"").decode("utf-8", errors="replace")

            # Also read any results files paramspider created
            results_dir = os.path.join(tmpdir, "results")
            if os.path.isdir(results_dir):
                for fname in os.listdir(results_dir):
                    fpath = os.path.join(results_dir, fname)
                    if os.path.isfile(fpath):
                        try:
                            with open(fpath, "r", errors="replace") as f:
                                output += "\n" + f.read()
                        except Exception:
                            pass

            parsed = self.parse_output(output)

            combined_output = output
            if error and (not output.strip() or process.returncode != 0):
                combined_output = (output + "\n" + error).strip()

            return {
                "tool": self.tool_name,
                "target": target,
                "command": " ".join(command),
                "timestamp": start_time.isoformat(),
                "exit_code": process.returncode,
                "duration": duration,
                "raw_output": combined_output,
                "error": error if error else None,
                "parsed": parsed,
            }

    def parse_output(self, output: str) -> Dict[str, Any]:
        params = []
        for line in output.splitlines():
            for match in re.findall(r"https?://[^\s\"'<>]+", line):
                params.append(match)
        return {"urls": params}
