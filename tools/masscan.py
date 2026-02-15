"""
masscan tool wrapper for fast port discovery
"""

import asyncio
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class MasscanTool(BaseTool):
    """masscan port scanner wrapper"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "masscan"

    def _check_installation(self) -> bool:
        return shutil.which("masscan") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build masscan command"""
        config = self.config.get("tools", {}).get("masscan", {})

        ports = kwargs.get("ports") or config.get("ports") or "80,443"
        rate = kwargs.get("rate") or config.get("rate") or 10000

        output_file = kwargs.get("output_file")
        command = ["masscan", "-p", str(ports), "--rate", str(rate), "-oJ", str(output_file) if output_file else "-"]

        if kwargs.get("exclude"):
            command.extend(["--exclude", str(kwargs["exclude"])])

        # Input target(s)
        if kwargs.get("from_file"):
            command.extend(["-iL", kwargs["from_file"]])
        else:
            command.append(target)

        return command

    def _default_output_path(self) -> Path:
        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return out_dir / f"masscan_{stamp}.json"

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        if not self.is_available:
            raise RuntimeError(f"Tool {self.tool_name} is not available")

        output_path = kwargs.pop("output_file", None)
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            output_path = self._default_output_path()

        command = self.get_command(target, output_file=str(output_path), **kwargs)
        command = self._apply_resolved_binary(command)
        self._validate_safe_mode(command)

        self.logger.info(f"Executing: {' '.join(command)}")

        timeout_override = kwargs.get("tool_timeout")
        timeout = (
            (self.config.get("tools", {}).get(self.tool_name, {}) or {}).get("tool_timeout")
            if isinstance(self.config, dict)
            else None
        )
        if timeout_override is not None:
            timeout = timeout_override
        if timeout is None:
            timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        try:
            timeout = int(timeout)
        except Exception:
            timeout = 300

        start_time = datetime.now()
        status = "unknown"
        exit_code = None
        stdout_len = 0
        stderr_len = 0
        process: asyncio.subprocess.Process | None = None
        env = self.get_env(target, **kwargs)

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)

            duration = (datetime.now() - start_time).total_seconds()
            exit_code = process.returncode

            stdout_len = len(stdout or b"")
            stderr_len = len(stderr or b"")
            out_text = (stdout or b"").decode("utf-8", errors="replace")
            err_text = (stderr or b"").decode("utf-8", errors="replace")

            file_text = ""
            try:
                if output_path.exists():
                    file_text = output_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                file_text = ""

            raw = (file_text.strip() or out_text).strip()
            if err_text and (not raw or process.returncode != 0):
                raw = (raw + "\n" + err_text).strip()

            parsed = self.parse_output(file_text.strip() or out_text)

            result = {
                "tool": self.tool_name,
                "target": target,
                "command": " ".join(command),
                "timestamp": start_time.isoformat(),
                "exit_code": process.returncode,
                "duration": duration,
                "raw_output": raw,
                "error": err_text if err_text else None,
                "parsed": parsed,
            }

            status = "completed" if self.is_success_exit_code(process.returncode) else "failed"
            return result

        except asyncio.CancelledError:
            status = "cancelled"
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.communicate()
            except Exception:
                pass
            raise
        except asyncio.TimeoutError:
            status = "timed_out"
            self.logger.error(f"Tool {self.tool_name} timed out after {timeout}s")
            try:
                if process and process.returncode is None:
                    process.kill()
                    await process.communicate()
            except Exception:
                pass
            raise
        except Exception as e:
            status = "exception"
            self.logger.error(f"Tool {self.tool_name} failed: {e}")
            raise
        finally:
            duration = (datetime.now() - start_time).total_seconds()
            exit_str = f"{exit_code}" if exit_code is not None else "n/a"
            self.logger.info(
                f"Tool {self.tool_name} finished in {duration:.2f}s (status={status}, exit={exit_str}, stdout={stdout_len}B, stderr={stderr_len}B)"
            )

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse masscan JSON output"""
        results = {"hosts": {}, "open_ports": []}
        text = (output or "").strip()
        if not text:
            return results

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = []
            for line in text.splitlines():
                line = line.strip().rstrip(",")
                if not line or not line.startswith("{"):
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if isinstance(data, dict):
            data = [data]

        for entry in data:
            if not isinstance(entry, dict):
                continue
            ip = entry.get("ip")
            ports = entry.get("ports") or []
            if not ip or not isinstance(ports, list):
                continue
            for p in ports:
                port = p.get("port") if isinstance(p, dict) else None
                proto = p.get("proto") if isinstance(p, dict) else None
                if port is None:
                    continue
                results["open_ports"].append({"host": ip, "port": port, "protocol": proto})
                host_ports = results["hosts"].setdefault(ip, [])
                host_ports.append(port)

        return results
