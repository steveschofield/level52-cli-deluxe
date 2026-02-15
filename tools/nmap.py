"""
Nmap tool wrapper for port scanning and service detection
"""

import asyncio
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from urllib.parse import urlparse

from tools.base_tool import BaseTool


class NmapTool(BaseTool):
    """Nmap port scanner wrapper"""
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build nmap command"""
        config = self.config.get("tools", {}).get("nmap", {})

        # Normalize target: strip scheme, capture port if present
        parsed = urlparse(target)
        target_host = target
        target_port = None
        if parsed.scheme and parsed.hostname:
            target_host = parsed.hostname
            target_port = parsed.port
        elif parsed.scheme and not parsed.hostname:
            raise ValueError(f"Invalid target for nmap: {target}")
        
        # Base command
        command = ["nmap"]
        
        # Arguments profile (recon vs vuln scripts)
        profile = (kwargs.get("profile") or "recon").strip().lower()
        recon_args = config.get("default_args", "-sV -sC")
        vuln_args = config.get("vuln_args", "-sV --script vuln")
        scan_type = kwargs.get("scan_type") or ""
        skip_default_args = bool(kwargs.get("skip_default_args"))
        if isinstance(scan_type, str) and "-sn" in scan_type.split():
            skip_default_args = True
        if skip_default_args:
            args = ""
        else:
            args = vuln_args if profile in {"vuln", "vulnerability"} else recon_args
        override_args = kwargs.get("override_args")
        if "args" in kwargs:
            override_args = kwargs.get("args")
        if override_args is not None:
            args = override_args
        if args:
            command.extend(str(args).split())
        
        # Timing template
        timing = kwargs.get("timing") or config.get("timing", "T4")
        command.append(f"-{timing}")

        # Treat hosts as online to handle environments where ICMP is blocked.
        if "-Pn" not in command:
            command.append("-Pn")
        
        # XML output for parsing
        output_file = kwargs.get("output_file")
        command.extend(["-oX", str(output_file) if output_file else "-"])
        
        # Custom args from kwargs
        if "ports" in kwargs and kwargs["ports"]:
            command.extend(["-p", kwargs["ports"]])
        elif target_port:
            command.extend(["-p", str(target_port)])

        if "scan_type" in kwargs:
            scan_type = kwargs["scan_type"]
            if isinstance(scan_type, list):
                command.extend([str(arg) for arg in scan_type if str(arg).strip()])
            elif isinstance(scan_type, str):
                command.extend(scan_type.split())
            else:
                command.append(str(scan_type))

        extra_args = kwargs.get("extra_args")
        if extra_args:
            if isinstance(extra_args, list):
                command.extend([str(a) for a in extra_args if str(a).strip()])
            else:
                command.extend(str(extra_args).split())
        
        # Target
        command.append(target_host)
        
        return command

    def _default_output_path(self) -> Path:
        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return out_dir / f"nmap_{stamp}.xml"

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
        """Parse nmap XML output"""
        results = {
            "open_ports": [],
            "services": [],
            "os_detection": None,
            "vulnerabilities": [],
            "hosts_up": []
        }
        
        # Simple regex parsing (in production, use proper XML parser)
        # Extract open ports
        port_pattern = r'portid="(\d+)".*?service name="([^"]*)".*?product="([^"]*)"'
        for match in re.finditer(port_pattern, output, re.DOTALL):
            port = match.group(1)
            service = match.group(2)
            product = match.group(3) if match.group(3) else "unknown"
            
            results["open_ports"].append(int(port))
            results["services"].append({
                "port": int(port),
                "service": service,
                "product": product
            })
        
        # Extract OS if available
        os_match = re.search(r'osclass type="([^"]*)".*?osfamily="([^"]*)"', output)
        if os_match:
            results["os_detection"] = {
                "type": os_match.group(1),
                "family": os_match.group(2)
            }

        # Extract hosts up (ping scan or host discovery)
        for host_block in re.findall(r"<host[^>]*>.*?</host>", output, re.DOTALL):
            if 'state="up"' not in host_block:
                continue
            addr_match = re.search(r'address addr="([^"]+)"', host_block)
            if addr_match:
                addr = addr_match.group(1)
                if addr and addr not in results["hosts_up"]:
                    results["hosts_up"].append(addr)
        
        return results
