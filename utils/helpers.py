"""
Common utility functions for Guardian
"""

import re
import json
import yaml
import os
from pathlib import Path
from typing import Any, Dict, Optional, List
from datetime import datetime
import socket
import ssl
from dotenv import load_dotenv


def load_config(config_path: str = "config/guardian.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file with environment variable expansion"""
    try:
        # Load environment variables from:
        # - current working directory `.env` (default python-dotenv behavior)
        # - config-adjacent `.env` (e.g. `~/.guardian/.env` when using `guardian init`)
        # without overriding already-set environment variables.
        load_dotenv()

        def _resolve_config_path(path: str) -> str:
            p = Path(path).expanduser()
            if p.exists():
                return str(p)

            # If the CLI is invoked outside the repo, `config/guardian.yaml` often won't exist.
            # Prefer the user config created by `guardian init` if present.
            if path == "config/guardian.yaml":
                home_cfg = Path.home() / ".guardian" / "guardian.yaml"
                if home_cfg.exists():
                    return str(home_cfg)

                # As a last-resort, if a repo-root `guardian.yaml` exists, treat it as the config.
                if Path("guardian.yaml").exists():
                    return "guardian.yaml"

            return str(p)

        resolved_config_path = _resolve_config_path(config_path)

        # Load `.env` adjacent to the resolved config path (if any).
        try:
            env_candidate = Path(resolved_config_path).expanduser().parent / ".env"
            if env_candidate.exists():
                load_dotenv(env_candidate)
        except Exception:
            pass

        def _expand_env_vars(value: Any) -> Any:
            """Recursively expand environment variables in config values"""
            if isinstance(value, str):
                # Match ${VAR_NAME:-default_value} or ${VAR_NAME}
                pattern = r'\$\{([^:}]+)(?::-(.*?))?\}'

                def replacer(match):
                    var_name = match.group(1)
                    default_value = match.group(2) if match.group(2) is not None else ""
                    return os.getenv(var_name, default_value)

                return re.sub(pattern, replacer, value)
            elif isinstance(value, dict):
                return {k: _expand_env_vars(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [_expand_env_vars(item) for item in value]
            else:
                return value

        def _load(path: str) -> Dict[str, Any]:
            with open(path, "r") as f:
                config = yaml.safe_load(f) or {}
                # Expand environment variables in the loaded config
                return _expand_env_vars(config)

        def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
            merged = dict(base)
            for key, value in override.items():
                if isinstance(value, dict) and isinstance(merged.get(key), dict):
                    merged[key] = _deep_merge(merged[key], value)
                else:
                    merged[key] = value
            return merged

        cfg = _load(resolved_config_path)

        # Compatibility: many users edit repo-root `guardian.yaml` but CLI defaults to `config/guardian.yaml`.
        # When using the default path, treat `guardian.yaml` (if present) as an override layer.
        if resolved_config_path == "config/guardian.yaml" and Path("guardian.yaml").exists():
            override = _load("guardian.yaml")
            cfg = _deep_merge(cfg, override)

        return cfg
    except Exception as e:
        print(f"Warning: Could not load config from {config_path}: {e}")
        return {}


def save_json(data: Any, filepath: Path):
    """Save data as JSON"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def load_json(filepath: Path) -> Any:
    """Load JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)


def is_valid_domain(domain: str) -> bool:
    """Validate domain name format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_ip(ip: str) -> bool:
    """Validate IP address format"""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))


def is_valid_url(url: str) -> bool:
    """Validate URL format"""
    pattern = r'^https?://(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::[0-9]{1,5})?(?:/.*)?$'
    return bool(re.match(pattern, url))


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.hostname or parsed.netloc
    except:
        return None


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp for reports"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to be filesystem-safe"""
    # Remove/replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')
    # Limit length
    return filename[:200]


def parse_severity(severity: str) -> int:
    """Convert severity string to numeric value for sorting"""
    severity_map = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'info': 0
    }
    return severity_map.get(severity.lower(), 0)


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to maximum length"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix


def ensure_dir(path: Path):
    """Ensure directory exists"""
    path.mkdir(parents=True, exist_ok=True)


def color_severity(severity: str) -> str:
    """Return rich markup color for severity"""
    colors = {
        'critical': 'bold red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'blue',
        'info': 'cyan'
    }
    return colors.get(severity.lower(), 'white')


def reverse_lookup_ip(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup for an IP; return hostname or None."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


def fetch_tls_names(ip: str, port: int = 443, timeout: float = 5.0) -> List[str]:
    """
    Attempt to retrieve TLS certificate SAN/CN names from an IP:port.
    Returns a list of hostnames; empty on failure/non-TLS.
    """
    names: List[str] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                # subjectAltName entries
                for tup in cert.get("subjectAltName", []):
                    if tup[0].lower() == "dns":
                        names.append(tup[1])
                # fallback to commonName
                for attr in cert.get("subject", []):
                    for k, v in attr:
                        if k.lower() == "commonname":
                            names.append(v)
    except Exception:
        return []

    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for n in names:
        if n not in seen:
            uniq.append(n)
            seen.add(n)
    return uniq
