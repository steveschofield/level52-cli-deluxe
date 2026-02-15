"""
Helpers for locating per-session report and log paths.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def generate_session_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def get_base_reports_dir(config: Optional[Dict[str, Any]] = None) -> Path:
    cfg = config or {}
    output_cfg = cfg.get("output", {}) if isinstance(cfg, dict) else {}
    base_dir = output_cfg.get("save_path", "./reports")
    return Path(base_dir)


def ensure_session_dir(base_dir: Path, session_id: str) -> Path:
    session_dir = base_dir / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


def apply_session_paths(config: Optional[Dict[str, Any]], session_id: str) -> Path:
    cfg = config if isinstance(config, dict) else {}
    base_dir = get_base_reports_dir(cfg)
    session_dir = ensure_session_dir(base_dir, session_id)

    output_cfg = dict((cfg.get("output") or {})) if isinstance(cfg, dict) else {}
    output_cfg["save_path"] = str(session_dir)
    cfg["output"] = output_cfg

    logging_cfg = dict((cfg.get("logging") or {})) if isinstance(cfg, dict) else {}
    logging_cfg["path"] = str(session_dir / "guardian.log")
    logging_cfg["console_log_path"] = str(session_dir / f"console_{session_id}.log")
    cfg["logging"] = logging_cfg

    # Keep nuclei's consolidated log in the session folder when the default path is used.
    tools_cfg = dict((cfg.get("tools") or {})) if isinstance(cfg, dict) else {}
    nuclei_cfg = dict((tools_cfg.get("nuclei") or {})) if isinstance(tools_cfg, dict) else {}
    log_file = nuclei_cfg.get("log_file")
    if log_file:
        expanded = Path(os.path.expandvars(os.path.expanduser(str(log_file))))
        if expanded == base_dir / "nuclei.log":
            nuclei_cfg["log_file"] = str(session_dir / "nuclei.log")
    else:
        nuclei_cfg["log_file"] = str(session_dir / "nuclei.log")
    tools_cfg["nuclei"] = nuclei_cfg
    cfg["tools"] = tools_cfg

    return session_dir


def resolve_session_file(config: Optional[Dict[str, Any]], session_id: str) -> Path:
    base_dir = get_base_reports_dir(config)
    candidate = base_dir / session_id / f"session_{session_id}.json"
    if candidate.exists():
        return candidate
    legacy = base_dir / f"session_{session_id}.json"
    return legacy if legacy.exists() else candidate


def find_latest_session_file(config: Optional[Dict[str, Any]]) -> Optional[Path]:
    base_dir = get_base_reports_dir(config)
    if not base_dir.exists():
        return None
    session_files = list(base_dir.rglob("session_*.json"))
    if not session_files:
        return None
    return max(session_files, key=lambda p: p.stat().st_mtime)
