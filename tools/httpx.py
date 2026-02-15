"""
httpx tool wrapper for HTTP probing
"""

import os
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class HttpxTool(BaseTool):
    """httpx HTTP probing wrapper"""
    
    def __init__(self, config):
        self._executable: str | None = None
        super().__init__(config)

    def _repo_bin_candidates(self) -> List[str]:
        repo_root = Path(__file__).resolve().parent.parent
        return [
            str(repo_root / "tools" / ".bin" / "httpx"),
            str(repo_root / "tools" / ".bin" / "httpx_pd"),
            str(repo_root / "tools" / ".bin" / "httpx-projectdiscovery"),
        ]

    def _is_projectdiscovery_httpx(self, executable: str) -> bool:
        try:
            proc = subprocess.run(
                [executable, "-h"],
                capture_output=True,
                text=True,
                timeout=3,
            )
        except Exception:
            return False

        help_text = (proc.stdout or "") + "\n" + (proc.stderr or "")
        help_text = help_text.lower()

        # ProjectDiscovery httpx has scanner/probing flags. Python httpx (HTTP client) does not.
        required_markers = ["-tech-detect", "-status-code", "-title", "-json", "-threads", "-timeout"]
        return all(m in help_text for m in required_markers)

    def _find_projectdiscovery_httpx(self) -> str | None:
        cfg = (self.config or {}).get("tools", {}).get("httpx", {})
        override = (
            cfg.get("binary")
            or os.environ.get("GUARDIAN_HTTPX_BIN")
            or os.environ.get("GUARDIAN_PD_HTTPX_BIN")
        )
        candidates: List[str] = []
        if override:
            candidates.append(str(override))

        # Prefer repo-local binaries if present.
        candidates.extend(self._repo_bin_candidates())

        # Look for httpx variants in PATH.
        for name in ("httpx", "httpx_pd", "httpx-projectdiscovery", "pdhttpx"):
            found = shutil.which(name)
            if found:
                candidates.append(found)

        # Also search all PATH hits for "httpx" (venv can shadow with the Python HTTP client).
        try:
            which_all = subprocess.run(
                ["which", "-a", "httpx"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if which_all.returncode == 0:
                for line in which_all.stdout.splitlines():
                    line = line.strip()
                    if line:
                        candidates.append(line)
        except Exception:
            pass

        seen = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and self._is_projectdiscovery_httpx(candidate):
                return candidate

        return None

    def _check_installation(self) -> bool:
        self.tool_name = "httpx"
        self._executable = self._find_projectdiscovery_httpx()
        if not self._executable:
            # Check for curl fallback
            if shutil.which("curl"):
                self.logger.info("httpx not found, will use curl fallback")
                self._executable = "curl"
                self._use_fallback = True
                return True
            self.logger.warning(
                "ProjectDiscovery httpx not found (the installed Python 'httpx' CLI is incompatible); "
                "install ProjectDiscovery httpx or run `python scripts/install_projectdiscovery_httpx.py`."
            )
            return False
        self._use_fallback = False
        return True
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build httpx command or curl fallback"""
        if not self._executable:
            raise RuntimeError("httpx executable not resolved")

        if getattr(self, '_use_fallback', False):
            return self._get_curl_command(target, **kwargs)
        
        return self._get_httpx_command(target, **kwargs)
    
    def _get_httpx_command(self, target: str, **kwargs) -> List[str]:
        """Build ProjectDiscovery httpx command"""
        config = self.config.get("tools", {}).get("httpx", {})
        
        command = [self._executable]
        
        # JSON output for easy parsing
        command.extend(["-json"])

        # Suppress banner/progress noise so stdout is parseable
        command.append("-silent")
        
        # Threads
        threads = config.get("threads", 50)
        command.extend(["-threads", str(threads)])
        
        # Timeout
        timeout = config.get("timeout", 10)
        command.extend(["-timeout", str(timeout)])
        
        # Tech detection
        command.append("-tech-detect")
        
        # Status code
        command.append("-status-code")
        
        # Title
        command.append("-title")
        
        # Target (from stdin or direct)
        if kwargs.get("from_file"):
            from_file = os.path.expandvars(os.path.expanduser(kwargs["from_file"]))
            command.extend(["-l", from_file])
        else:
            command.extend(["-u", target])
        
        return command
    
    def _get_curl_command(self, target: str, **kwargs) -> List[str]:
        """Build curl fallback command"""
        config = self.config.get("tools", {}).get("httpx", {})
        timeout = config.get("timeout", 10)
        
        command = [
            "curl", "-s", "-I", "-L", 
            "--max-time", str(timeout),
            "--user-agent", "Guardian-Scanner/1.0",
            target
        ]
        
        return command
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse httpx JSON output or curl fallback"""
        if getattr(self, '_use_fallback', False):
            return self._parse_curl_output(output)
        
        return self._parse_httpx_output(output)
    
    def _parse_httpx_output(self, output: str) -> Dict[str, Any]:
        """Parse ProjectDiscovery httpx JSON output"""
        results = {
            "urls": [],
            "technologies": [],
            "status_codes": {},
            "titles": {}
        }
        
        # Parse JSON lines
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                url = data.get("url", "")
                
                if url:
                    results["urls"].append(url)
                    results["status_codes"][url] = data.get("status_code")
                    results["titles"][url] = data.get("title", "")
                    
                    # Extract technologies
                    if "tech" in data:
                        for tech in data["tech"]:
                            if tech not in results["technologies"]:
                                results["technologies"].append(tech)
                
            except json.JSONDecodeError:
                continue
        
        return results
    
    def _parse_curl_output(self, output: str) -> Dict[str, Any]:
        """Parse curl fallback output"""
        results = {
            "urls": [],
            "technologies": [],
            "status_codes": {},
            "titles": {}
        }
        
        # Extract status code from curl headers
        lines = output.split('\n')
        status_code = 0
        server = ""
        
        for line in lines:
            if line.startswith('HTTP/'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        status_code = int(parts[1])
                    except ValueError:
                        pass
            elif line.lower().startswith('server:'):
                server = line.split(':', 1)[1].strip()
        
        # For curl fallback, we only get basic info
        if status_code > 0:
            # Reconstruct URL from command (basic approach)
            url = "http://target"  # Placeholder
            results["urls"].append(url)
            results["status_codes"][url] = status_code
            if server:
                results["technologies"].append(server)
        
        return results
