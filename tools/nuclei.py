"""
Nuclei tool wrapper for vulnerability scanning
"""

import os
import json
import shutil
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class NucleiTool(BaseTool):
    """Nuclei vulnerability scanner wrapper"""
    
    def __init__(self, config):
        self._executable: str | None = None
        self._last_output_file: str | None = None
        self._last_targets_file: str | None = None
        super().__init__(config)
        self.tool_name = "nuclei"

    def _repo_bin_candidates(self) -> List[str]:
        repo_root = Path(__file__).resolve().parent.parent
        return [
            str(repo_root / "tools" / ".bin" / "nuclei"),
            str(repo_root / "tools" / ".bin" / "nuclei_pd"),
            str(repo_root / "tools" / ".bin" / "nuclei-projectdiscovery"),
        ]

    def _is_projectdiscovery_nuclei(self, executable: str) -> bool:
        # Nuclei supports -version across versions; fall back to -h.
        for args in ([executable, "-version"], [executable, "-h"]):
            try:
                proc = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
            except Exception:
                continue

            out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).lower()
            if "nuclei" in out and ("projectdiscovery" in out or "templates" in out or "-jsonl" in out):
                return True
        return False

    def _find_projectdiscovery_nuclei(self) -> str | None:
        cfg = (self.config or {}).get("tools", {}).get("nuclei", {})
        override = cfg.get("binary") or os.environ.get("GUARDIAN_NUCLEI_BIN")

        candidates: List[str] = []
        if override:
            candidates.append(str(override))

        candidates.extend(self._repo_bin_candidates())

        found = shutil.which("nuclei")
        if found:
            candidates.append(found)

        try:
            which_all = subprocess.run(
                ["which", "-a", "nuclei"],
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
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and self._is_projectdiscovery_nuclei(candidate):
                return candidate

        return None

    def _check_installation(self) -> bool:
        self.tool_name = "nuclei"
        self._executable = self._find_projectdiscovery_nuclei()
        if not self._executable:
            self.logger.warning(
                "ProjectDiscovery nuclei not found; install it or run `python scripts/install_projectdiscovery_nuclei.py`."
            )
            return False
        return True

    def get_env(self, target: str, **kwargs) -> Dict[str, str] | None:
        env = os.environ.copy()

        # Nuclei will error if GOOGLE_API_KEY exists but GOOGLE_API_CX does not.
        # Those vars are unrelated to running most scans, so sanitize for this subprocess.
        if env.get("GOOGLE_API_KEY") and not env.get("GOOGLE_API_CX"):
            env.pop("GOOGLE_API_KEY", None)

        return env
    
    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build nuclei command"""
        if not self._executable:
            raise RuntimeError("ProjectDiscovery nuclei executable not resolved")

        config = self.config.get("tools", {}).get("nuclei", {})
        
        command = [self._executable]

        safe_mode = (self.config or {}).get("pentest", {}).get("safe_mode", True)
        http_only = config.get("http_only")
        
        # Target
        if kwargs.get("from_file"):
            from_file = os.path.expandvars(os.path.expanduser(kwargs["from_file"]))
            command.extend(["-l", from_file])
            self._last_targets_file = from_file
            if http_only is None:
                http_only = True
        else:
            # Nuclei is URL-first; if we get a bare host/IP, try both http and https.
            target_str = (target or "").strip()
            if re.match(r"^https?://", target_str, re.IGNORECASE):
                command.extend(["-u", target_str])
                if http_only is None:
                    http_only = True
            else:
                out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
                out_dir.mkdir(parents=True, exist_ok=True)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                targets_file = out_dir / f"nuclei_targets_{ts}.txt"
                with open(targets_file, "w", encoding="utf-8") as f:
                    f.write(f"http://{target_str}\nhttps://{target_str}\n")
                command.extend(["-l", str(targets_file)])
                self._last_targets_file = str(targets_file)
                if http_only is None:
                    http_only = False
        
        # JSONL output (parseable line by line)
        command.extend(["-jsonl"])
        # Persist JSONL to reports for evidence.
        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = out_dir / f"nuclei_{ts}.jsonl"
        command.extend(["-o", str(output_file)])
        self._last_output_file = str(output_file)

        # Concurrency (reduce memory/pressure in constrained environments)
        concurrency = kwargs.get("concurrency") if "concurrency" in kwargs else config.get("concurrency")
        if concurrency is None and safe_mode:
            concurrency = 10
        if concurrency is not None:
            command.extend(["-c", str(concurrency)])

        # Severity filtering
        severities = kwargs.get("severity", config.get("severity", ["critical", "high", "medium"]))
        if isinstance(severities, str):
            severities = [s.strip() for s in severities.split(",") if s.strip()]
        if severities:
            command.extend(["-severity", ",".join(severities)])

        # Tags
        tags = kwargs.get("tags", config.get("tags"))
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        if tags:
            command.extend(["-tags", ",".join(tags)])

        # Templates path(s)
        templates_paths = (
            kwargs.get("templates_paths")
            or kwargs.get("templates_path")
            or config.get("templates_paths")
            or config.get("templates_path")
        )
        if templates_paths:
            if isinstance(templates_paths, str):
                templates_paths = [templates_paths]

            expanded: list[str] = []
            for path in templates_paths:
                p = os.path.expandvars(os.path.expanduser(path))
                expanded.append(p)

            # OOM mitigation: limit template directories by default in safe mode.
            max_paths = config.get("max_templates_paths")
            if max_paths is None and safe_mode:
                max_paths = 1
            if isinstance(max_paths, int) and max_paths > 0 and len(expanded) > max_paths:
                self.logger.warning(
                    f"Reducing nuclei templates_paths from {len(expanded)} to {max_paths} (configure tools.nuclei.max_templates_paths to override)"
                )
                expanded = expanded[:max_paths]

            # Further OOM mitigation: for URL inputs, default to http-only templates when available.
            if http_only:
                scoped: list[str] = []
                for p in expanded:
                    http_dir = os.path.join(p, "http")
                    if os.path.isdir(http_dir):
                        scoped.append(http_dir)
                    else:
                        scoped.append(p)
                expanded = scoped

            for p in expanded:
                command.extend(["-t", p])
        
        # Silent mode
        command.append("-silent")
        
        # Rate limit
        default_rate = 50 if safe_mode else 150
        rate = kwargs.get("rate_limit") if "rate_limit" in kwargs else config.get("rate_limit", default_rate)
        command.extend(["-rate-limit", str(rate)])
        
        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        result = await super().execute(target, **kwargs)
        try:
            self._append_consolidated_log(result)
        except Exception as exc:
            self.logger.warning(f"Failed to write nuclei consolidated log: {exc}")
        return result

    def _resolve_log_path(self) -> Path:
        cfg = (self.config or {}).get("tools", {}).get("nuclei", {}) or {}
        log_path = cfg.get("log_file")
        if log_path:
            log_path = os.path.expandvars(os.path.expanduser(str(log_path)))
            return Path(log_path)
        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        return out_dir / "nuclei.log"

    def _append_consolidated_log(self, result: Dict[str, Any]) -> None:
        log_path = self._resolve_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        parsed = result.get("parsed") if isinstance(result.get("parsed"), dict) else {}
        count = parsed.get("count")
        target = result.get("target") or ""
        timestamp = result.get("timestamp") or datetime.utcnow().isoformat()
        exit_code = result.get("exit_code")
        duration = result.get("duration")
        command = result.get("command") or ""
        output = result.get("raw_output") or ""

        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] target={target} exit={exit_code} duration={duration}s findings={count}\n")
            if command:
                handle.write(f"command: {command}\n")
            if self._last_targets_file:
                handle.write(f"targets: {self._last_targets_file}\n")
            if self._last_output_file:
                handle.write(f"jsonl: {self._last_output_file}\n")
            if output.strip():
                handle.write("output:\n")
                handle.write(output.rstrip() + "\n")
            else:
                handle.write("output: <empty>\n")
            handle.write("\n")
    
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nuclei JSON output"""
        results = {
            "vulnerabilities": [],
            "count": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        # Parse JSON lines
        for line in output.strip().split('\n'):
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                vuln = {
                    "template": data.get("template-id", "unknown"),
                    "name": data.get("info", {}).get("name", "Unknown"),
                    "severity": data.get("info", {}).get("severity", "info").lower(),
                    "matched_at": data.get("matched-at", ""),
                    "type": data.get("type", ""),
                    "description": data.get("info", {}).get("description", ""),
                    "reference": data.get("info", {}).get("reference", [])
                }
                
                results["vulnerabilities"].append(vuln)
                results["count"] += 1
                
                # Count by severity
                severity = vuln["severity"]
                if severity in results["by_severity"]:
                    results["by_severity"][severity] += 1
                
            except json.JSONDecodeError:
                continue
        
        return results
