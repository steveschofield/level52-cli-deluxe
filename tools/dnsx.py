"""
dnsx tool wrapper for DNS resolution/enumeration
"""

import os
import shutil
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class DnsxTool(BaseTool):
    """dnsx wrapper"""

    def __init__(self, config):
        self._executable: str | None = None
        super().__init__(config)
        self.tool_name = "dnsx"

    def _repo_bin_candidates(self) -> List[str]:
        repo_root = Path(__file__).resolve().parent.parent
        return [
            str(repo_root / "tools" / ".bin" / "dnsx"),
            str(repo_root / "tools" / ".bin" / "dnsx_pd"),
            str(repo_root / "tools" / ".bin" / "dnsx-projectdiscovery"),
        ]

    def _is_projectdiscovery_dnsx(self, executable: str) -> bool:
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
            if "dnsx" in out and ("projectdiscovery" in out or "projectdiscovery.io" in out or "-recon" in out):
                return True
        return False

    def _find_projectdiscovery_dnsx(self) -> str | None:
        cfg = (self.config or {}).get("tools", {}).get("dnsx", {})
        override = cfg.get("binary") or os.environ.get("GUARDIAN_DNSX_BIN")

        candidates: List[str] = []
        if override:
            candidates.append(str(override))

        candidates.extend(self._repo_bin_candidates())

        found = shutil.which("dnsx")
        if found:
            candidates.append(found)

        try:
            which_all = subprocess.run(
                ["which", "-a", "dnsx"],
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
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK) and self._is_projectdiscovery_dnsx(candidate):
                return candidate

        return None

    def _check_installation(self) -> bool:
        self.tool_name = "dnsx"
        self._executable = self._find_projectdiscovery_dnsx()
        return bool(self._executable)

    def _write_targets_file(self, targets: List[str]) -> str:
        out_dir = Path((self.config or {}).get("output", {}).get("save_path", "./reports"))
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = out_dir / f"dnsx_targets_{ts}.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(t.strip() for t in targets if isinstance(t, str) and t.strip()) + "\n")
        return str(path)

    def get_command(self, target: str, **kwargs) -> List[str]:
        if not self._executable:
            raise RuntimeError("ProjectDiscovery dnsx executable not resolved")

        config = (self.config or {}).get("tools", {}).get("dnsx", {}) or {}
        safe_mode = bool((self.config or {}).get("pentest", {}).get("safe_mode", True))

        command = [self._executable]

        # Prefer list input (-l) to avoid requiring a bruteforce wordlist (-w).
        targets_file = None
        if kwargs.get("from_file"):
            targets_file = os.path.expandvars(os.path.expanduser(kwargs["from_file"]))
        else:
            targets_file = self._write_targets_file([target])
        command.extend(["-l", targets_file])

        # Query behavior: by default, do recon across record types, but avoid AXFR in safe_mode.
        if config.get("recon", True):
            command.append("-recon")
            if safe_mode:
                command.extend(["-e", "axfr"])

        # Threads / rate limiting
        threads = kwargs.get("threads", config.get("threads"))
        if threads:
            command.extend(["-t", str(threads)])

        rate_limit = kwargs.get("rate_limit", config.get("rate_limit"))
        if rate_limit:
            command.extend(["-rl", str(rate_limit)])

        # Output as JSONL for parsing (dnsx: -j means json lines)
        command.append("-j")
        command.append("-silent")

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        results: Dict[str, Any] = {"resolved": [], "records": []}

        for line in (output or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # dnsx -j emits JSONL; fall back to plain lines if parsing fails.
            try:
                obj = __import__("json").loads(line)
                if isinstance(obj, dict):
                    if isinstance(obj.get("host"), str):
                        results["resolved"].append(obj["host"])
                    results["records"].append(obj)
                    continue
            except Exception:
                pass
            results["resolved"].append(line)

        # De-dupe
        seen = set()
        deduped = []
        for h in results["resolved"]:
            if h in seen:
                continue
            seen.add(h)
            deduped.append(h)
        results["resolved"] = deduped

        return results
