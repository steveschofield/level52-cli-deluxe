#!/usr/bin/env python3
"""
Run an OWASP ZAP scan using an already-running ZAP daemon (local or remote) via the ZAP API.

This is intentionally conservative by default:
- Spider (optional) + passive scan (baseline-ish)
- Optional active scan only when explicitly requested (and Guardian safe_mode allows it)

Outputs a JSON document to stdout containing alerts.

Enhanced with comprehensive structured logging for visibility into scan progress and performance.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


# ============================================================================
# LOGGING SETUP
# ============================================================================


def setup_logging(verbose: bool = False, log_file: str = "") -> logging.Logger:
    """Configure structured logging with optional file output.

    By default, INFO-level logs are shown (progress updates, phase timing, etc.).
    Use --verbose for DEBUG-level logs (API calls, detailed responses, etc.).
    """
    logger = logging.getLogger("zap_daemon_scan")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()  # Remove any existing handlers

    # Console handler (stderr so stdout remains clean for JSON)
    # Always show INFO+ logs (progress, timing, etc.) - verbose adds DEBUG logs
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler (if specified)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] [%(funcName)s:%(lineno)d] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            logger.info(f"Logging to file: {log_path}")
        except Exception as e:
            logger.warning(f"Failed to setup file logging: {e}")

    return logger


# Global logger (will be initialized in main)
logger = logging.getLogger("zap_daemon_scan")


# ============================================================================
# PHASE TIMING TRACKER
# ============================================================================


class PhaseTimer:
    """Track timing for each scan phase."""

    def __init__(self):
        self.phases: Dict[str, Dict[str, Any]] = {}
        self.current_phase: Optional[str] = None
        self.phase_start: Optional[float] = None

    def start(self, phase_name: str) -> None:
        """Start timing a new phase."""
        if self.current_phase:
            self.end()
        self.current_phase = phase_name
        self.phase_start = time.time()
        logger.info(f"=== PHASE START: {phase_name} ===")

    def end(self) -> None:
        """End the current phase."""
        if self.current_phase and self.phase_start:
            elapsed = time.time() - self.phase_start
            self.phases[self.current_phase] = {
                "elapsed_seconds": round(elapsed, 2),
                "elapsed_formatted": self._format_duration(elapsed),
            }
            logger.info(
                f"=== PHASE COMPLETE: {self.current_phase} "
                f"({self._format_duration(elapsed)}) ==="
            )
            self.current_phase = None
            self.phase_start = None

    def get_summary(self) -> Dict[str, Any]:
        """Get timing summary for all phases."""
        if self.current_phase:  # End current phase if still running
            self.end()
        total = sum(p["elapsed_seconds"] for p in self.phases.values())
        return {
            "phases": self.phases,
            "total_seconds": round(total, 2),
            "total_formatted": self._format_duration(total),
        }

    @staticmethod
    def _format_duration(seconds: float) -> str:
        """Format duration in human-readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"


# ============================================================================
# API HELPERS
# ============================================================================


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def _get_json(url: str, timeout: float = 30.0) -> Dict[str, Any]:
    logger.debug(f"API GET: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-zap-daemon-scan/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        result = json.loads(data.decode("utf-8", errors="replace") or "{}")
        logger.debug(f"API Response: {json.dumps(result, indent=2)[:200]}...")
        return result
    except Exception as e:
        logger.error(f"API request failed for {url}: {e}")
        raise RuntimeError(f"Failed to parse JSON from {url}: {e}")


def _api_url(api_base: str, component: str, kind: str, method: str, params: Dict[str, Any]) -> str:
    # ZAP API paths look like: /JSON/<component>/<view|action>/<method>/
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    return _join(api_base, f"JSON/{component}/{kind}/{method}/") + (f"?{query}" if query else "")


def _api_other_url(api_base: str, component: str, method: str, params: Dict[str, Any]) -> str:
    query = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    return _join(api_base, f"OTHER/{component}/other/{method}/") + (f"?{query}" if query else "")


def _get_raw(url: str, timeout: float = 30.0) -> bytes:
    logger.debug(f"API GET (raw): {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "guardian-zap-daemon-scan/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _sleep_poll(deadline: float, interval: float = 2.0, last_status: str = "") -> None:
    if time.time() >= deadline:
        msg = "Timed out waiting for ZAP scan to finish"
        if last_status:
            msg += f" (last known status: {last_status})"
        logger.error(msg)
        raise TimeoutError(msg)
    time.sleep(interval)


def _parse_seed_urls(seed_urls: str, seed_file: str) -> list[str]:
    urls: list[str] = []
    if seed_urls:
        parts = [p.strip() for p in seed_urls.replace("\n", ",").split(",")]
        urls.extend([p for p in parts if p])
    if seed_file:
        try:
            with open(seed_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.append(line)
            logger.info(f"Loaded {len(urls)} seed URLs from {seed_file}")
        except Exception as e:
            logger.warning(f"Failed to load seed file {seed_file}: {e}")
    return urls


# ============================================================================
# REPORT GENERATORS
# ============================================================================


def _generate_html_report(data: Dict[str, Any]) -> str:
    """Generate a simple HTML report from ZAP scan data."""
    alerts = data.get("alerts", [])
    target = data.get("target", "")
    zap_info = data.get("zap", {})
    warnings = data.get("warnings", [])
    timing = data.get("timing", {})

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>ZAP Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; margin-top: 30px; }}
        .alert {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .alert-high {{ border-left: 5px solid #d9534f; }}
        .alert-medium {{ border-left: 5px solid #f0ad4e; }}
        .alert-low {{ border-left: 5px solid #5bc0de; }}
        .alert-info {{ border-left: 5px solid #5cb85c; }}
        .meta {{ color: #777; font-size: 0.9em; }}
        .warning {{ background: #fff3cd; padding: 10px; border-left: 3px solid #ffc107; margin: 10px 0; }}
        .timing {{ background: #f0f0f0; padding: 10px; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>OWASP ZAP Scan Report</h1>
    <div class="meta">
        <p><strong>Target:</strong> {target}</p>
        <p><strong>ZAP Version:</strong> {zap_info.get('version', 'unknown')}</p>
        <p><strong>Mode:</strong> {data.get('mode', 'daemon')}</p>
        <p><strong>Spider:</strong> {data.get('spider', False)}</p>
        <p><strong>AJAX Spider:</strong> {data.get('ajax_spider', False)}</p>
        <p><strong>Active Scan:</strong> {data.get('active', False)}</p>
        <p><strong>Total Alerts:</strong> {len(alerts)}</p>
    </div>
"""

    if timing:
        html += '    <div class="timing">\n'
        html += "        <h2>Scan Timing</h2>\n"
        html += f"        <p><strong>Total Duration:</strong> {timing.get('total_formatted', 'unknown')}</p>\n"
        phases = timing.get("phases", {})
        if phases:
            html += "        <ul>\n"
            for phase_name, phase_info in phases.items():
                html += f'            <li><strong>{phase_name}:</strong> {phase_info.get("elapsed_formatted", "unknown")}</li>\n'
            html += "        </ul>\n"
        html += "    </div>\n"

    if warnings:
        html += "    <h2>Warnings</h2>\n"
        for warning in warnings:
            html += f'    <div class="warning">{warning}</div>\n'

    html += "    <h2>Alerts</h2>\n"

    if not alerts:
        html += "    <p>No alerts found.</p>\n"
    else:
        for alert in alerts:
            risk = str(alert.get("risk") or alert.get("riskdesc", "")).lower()
            alert_class = f"alert-{risk}" if risk in ["high", "medium", "low", "info"] else "alert"
            name = alert.get("name") or alert.get("alert", "Unknown")
            desc = alert.get("desc") or alert.get("description", "")
            solution = alert.get("solution", "")
            confidence = alert.get("confidence", "")
            url = alert.get("url", "")
            evidence = alert.get("evidence", "")

            html += f'    <div class="alert {alert_class}">\n'
            html += f'        <h3>{name}</h3>\n'
            html += f'        <p><strong>Risk:</strong> {risk.upper()} | <strong>Confidence:</strong> {confidence}</p>\n'
            if url:
                html += f'        <p><strong>URL:</strong> {url}</p>\n'
            if evidence:
                html += f'        <p><strong>Evidence:</strong> <code>{evidence}</code></p>\n'
            if desc:
                html += f'        <p><strong>Description:</strong> {desc}</p>\n'
            if solution:
                html += f'        <p><strong>Solution:</strong> {solution}</p>\n'
            html += '    </div>\n'

    html += """</body>
</html>
"""
    return html


def _generate_md_report(data: Dict[str, Any]) -> str:
    """Generate a Markdown report from ZAP scan data."""
    alerts = data.get("alerts", [])
    target = data.get("target", "")
    zap_info = data.get("zap", {})
    warnings = data.get("warnings", [])
    timing = data.get("timing", {})

    md = f"""# OWASP ZAP Scan Report

## Target Information
- **Target**: {target}
- **ZAP Version**: {zap_info.get('version', 'unknown')}
- **Mode**: {data.get('mode', 'daemon')}
- **Spider**: {data.get('spider', False)}
- **AJAX Spider**: {data.get('ajax_spider', False)}
- **Active Scan**: {data.get('active', False)}
- **Total Alerts**: {len(alerts)}

"""

    if timing:
        md += "## Scan Timing\n\n"
        md += f"**Total Duration**: {timing.get('total_formatted', 'unknown')}\n\n"
        phases = timing.get("phases", {})
        if phases:
            md += "### Phase Breakdown\n\n"
            for phase_name, phase_info in phases.items():
                md += f"- **{phase_name}**: {phase_info.get('elapsed_formatted', 'unknown')}\n"
            md += "\n"

    if warnings:
        md += "## Warnings\n\n"
        for warning in warnings:
            md += f"- {warning}\n"
        md += "\n"

    md += "## Alerts\n\n"

    if not alerts:
        md += "No alerts found.\n"
    else:
        for i, alert in enumerate(alerts, 1):
            risk = str(alert.get("risk") or alert.get("riskdesc", "")).upper()
            name = alert.get("name") or alert.get("alert", "Unknown")
            desc = alert.get("desc") or alert.get("description", "")
            solution = alert.get("solution", "")
            confidence = alert.get("confidence", "")
            url = alert.get("url", "")
            evidence = alert.get("evidence", "")

            md += f"### {i}. {name}\n\n"
            md += f"**Risk**: {risk} | **Confidence**: {confidence}\n\n"
            if url:
                md += f"**URL**: `{url}`\n\n"
            if evidence:
                md += f"**Evidence**: `{evidence}`\n\n"
            if desc:
                md += f"**Description**: {desc}\n\n"
            if solution:
                md += f"**Solution**: {solution}\n\n"
            md += "---\n\n"

    return md


# ============================================================================
# MAIN SCAN LOGIC
# ============================================================================


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-url", default="http://127.0.0.1:8080", help="ZAP daemon base URL")
    ap.add_argument("--api-key", default="", help="ZAP API key (optional; empty when api.disablekey=true)")
    ap.add_argument("--target", required=True, help="Target base URL (e.g., https://example.com)")
    ap.add_argument("--spider", action="store_true", help="Run spider scan before passive/active scan")
    ap.add_argument("--ajax-spider", action="store_true", help="Run AJAX spider (useful for SPA apps)")
    ap.add_argument("--active", action="store_true", help="Run active scan (more intrusive)")
    ap.add_argument("--max-minutes", type=int, default=10, help="Max time budget for scan (minutes)")
    ap.add_argument("--max-alerts", type=int, default=5000, help="Max number of alerts to fetch")
    ap.add_argument("--har-out", default="", help="Write HAR output to this path (optional)")
    ap.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt for spider")
    ap.add_argument("--seed-urls", default="", help="Comma-separated seed URLs")
    ap.add_argument("--seed-file", default="", help="File containing seed URLs (one per line)")
    ap.add_argument("--context-name", default="", help="ZAP context name (optional)")
    ap.add_argument("--include-regex", default="", help="Regex to include in context scope")
    ap.add_argument("--login-url", default="", help="Login URL for form-based auth")
    ap.add_argument("--login-request-data", default="", help="POST data template (use {username}/{password})")
    ap.add_argument("--username", default="", help="Username for auth")
    ap.add_argument("--password", default="", help="Password for auth")
    ap.add_argument("--username-field", default="username", help="Username field name for login form")
    ap.add_argument("--password-field", default="password", help="Password field name for login form")
    ap.add_argument("--logged-in-regex", default="", help="Regex indicating logged-in state")
    ap.add_argument("--logged-out-regex", default="", help="Regex indicating logged-out state")
    ap.add_argument("--json-out", default="", help="Write JSON report to this path (optional)")
    ap.add_argument("--html-out", default="", help="Write HTML report to this path (optional)")
    ap.add_argument("--md-out", default="", help="Write Markdown report to this path (optional)")

    # Logging options
    ap.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG-level logging (API calls, responses, etc.)")
    ap.add_argument("--log-file", default="", help="Write detailed logs to this file (optional)")

    args = ap.parse_args(argv)

    # Setup logging
    global logger
    logger = setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Log scan configuration
    logger.info("=" * 70)
    logger.info("ZAP DAEMON SCAN STARTING")
    logger.info("=" * 70)
    logger.info(f"Scan Configuration:")
    logger.info(f"  Target: {args.target}")
    logger.info(f"  API URL: {args.api_url}")
    logger.info(f"  Spider: {args.spider}")
    logger.info(f"  AJAX Spider: {args.ajax_spider}")
    logger.info(f"  Active Scan: {args.active}")
    logger.info(f"  Max Time: {args.max_minutes} minutes")
    logger.info(f"  Context: {args.context_name or '(none)'}")
    logger.info(f"  Auth: {'Yes' if args.username else 'No'}")
    logger.info(f"  Verbose: {args.verbose}")
    logger.info(f"  Log File: {args.log_file or '(stderr only)'}")
    logger.info("=" * 70)

    api_base = args.api_url.rstrip("/")
    api_key = args.api_key or ""
    target = args.target.strip()

    deadline = time.time() + max(1, args.max_minutes) * 60
    warnings: list[str] = []
    timer = PhaseTimer()

    try:
        # ====================================================================
        # PHASE: ZAP Connection & Version Check
        # ====================================================================
        timer.start("ZAP Connection & Verification")

        logger.info(f"Connecting to ZAP daemon at {api_base}...")
        ver_url = _api_url(api_base, "core", "view", "version", {"apikey": api_key})
        version = _get_json(ver_url).get("version")
        if not version:
            raise RuntimeError("ZAP API reachable but version not returned; check api-url/api-key")

        logger.info(f"✓ Connected to ZAP version: {version}")

        # Get scan policy info for reproducibility
        scan_policy = "Default Policy"
        try:
            policies_url = _api_url(api_base, "ascan", "view", "scanPolicyNames", {"apikey": api_key})
            policies = _get_json(policies_url).get("scanPolicyNames", [])
            if policies:
                scan_policy = policies[0] if isinstance(policies, list) else str(policies)
        except Exception as e:
            logger.debug(f"Failed to get scan policy: {e}")

        # Make sure passive scanners are enabled.
        logger.info("Enabling passive scanners...")
        _get_json(_api_url(api_base, "pscan", "action", "enableAllScanners", {"apikey": api_key}))
        logger.info("✓ Passive scanners enabled")

        if args.ignore_robots:
            try:
                logger.info("Disabling robots.txt handling...")
                _get_json(_api_url(api_base, "spider", "action", "setOptionHandleRobotsTxt", {"apikey": api_key, "Boolean": "false"}))
                logger.info("✓ Robots.txt handling disabled")
            except Exception as e:
                warnings.append(f"Failed to disable robots.txt handling: {e}")
                logger.warning(f"Failed to disable robots.txt: {e}")

        timer.end()

        # ====================================================================
        # PHASE: Seed URLs
        # ====================================================================
        timer.start("Seed URL Access")

        # Access target once to seed the sites tree.
        logger.info(f"Accessing target URL: {target}")
        _get_json(_api_url(api_base, "core", "action", "accessUrl", {"apikey": api_key, "url": target}))
        logger.info("✓ Target URL accessed")

        # Seed additional URLs if provided.
        seed_urls = _parse_seed_urls(args.seed_urls, args.seed_file)
        if seed_urls:
            logger.info(f"Accessing {len(seed_urls)} seed URLs...")
            for i, url in enumerate(seed_urls, 1):
                try:
                    logger.debug(f"  [{i}/{len(seed_urls)}] {url}")
                    _get_json(_api_url(api_base, "core", "action", "accessUrl", {"apikey": api_key, "url": url}))
                except Exception as e:
                    warnings.append(f"Seed URL failed ({url}): {e}")
                    logger.warning(f"Seed URL failed: {url} - {e}")
            logger.info(f"✓ Seed URLs accessed ({len(seed_urls)} total)")

        timer.end()

        # ====================================================================
        # PHASE: Context & Authentication Setup
        # ====================================================================
        context_id = ""
        user_id = ""
        context_name = ""
        if args.context_name or args.login_url or args.username:
            timer.start("Context & Authentication Setup")

            context_name = args.context_name or "Guardian"
            logger.info(f"Creating context: {context_name}")
            ctx = _get_json(_api_url(api_base, "context", "action", "newContext", {"apikey": api_key, "contextName": context_name}))
            context_id = ctx.get("contextId", "")
            logger.info(f"✓ Context created (ID: {context_id})")

            include_regex = args.include_regex
            if not include_regex:
                parsed = urllib.parse.urlparse(target)
                include_regex = f"{parsed.scheme}://{parsed.netloc}.*"

            logger.info(f"Setting context scope: {include_regex}")
            try:
                _get_json(
                    _api_url(
                        api_base,
                        "context",
                        "action",
                        "includeInContext",
                        {"apikey": api_key, "contextName": context_name, "regex": include_regex},
                    )
                )
                logger.info("✓ Context scope configured")
            except Exception as e:
                warnings.append(f"Failed to include regex in context: {e}")
                logger.warning(f"Failed to set context scope: {e}")

            if args.logged_in_regex:
                logger.info("Setting logged-in indicator...")
                try:
                    _get_json(
                        _api_url(
                            api_base,
                            "authentication",
                            "action",
                            "setLoggedInIndicator",
                            {"apikey": api_key, "contextId": context_id, "loggedInIndicatorRegex": args.logged_in_regex},
                        )
                    )
                    logger.info("✓ Logged-in indicator set")
                except Exception as e:
                    warnings.append(f"Failed to set logged-in indicator: {e}")
                    logger.warning(f"Failed to set logged-in indicator: {e}")

            if args.logged_out_regex:
                logger.info("Setting logged-out indicator...")
                try:
                    _get_json(
                        _api_url(
                            api_base,
                            "authentication",
                            "action",
                            "setLoggedOutIndicator",
                            {"apikey": api_key, "contextId": context_id, "loggedOutIndicatorRegex": args.logged_out_regex},
                        )
                    )
                    logger.info("✓ Logged-out indicator set")
                except Exception as e:
                    warnings.append(f"Failed to set logged-out indicator: {e}")
                    logger.warning(f"Failed to set logged-out indicator: {e}")

            if args.login_url:
                logger.info(f"Configuring authentication: {args.login_url}")
                login_request_data = args.login_request_data
                if not login_request_data and args.username and args.password:
                    login_request_data = f"{args.username_field}={{username}}&{args.password_field}={{password}}"
                if login_request_data:
                    login_request_data = login_request_data.replace("{username}", args.username).replace("{password}", args.password)
                auth_params = {
                    "loginUrl": args.login_url,
                    "loginRequestData": login_request_data or "",
                }
                auth_cfg = urllib.parse.urlencode(auth_params)
                try:
                    _get_json(
                        _api_url(
                            api_base,
                            "authentication",
                            "action",
                            "setAuthenticationMethod",
                            {
                                "apikey": api_key,
                                "contextId": context_id,
                                "authMethodName": "formBasedAuthentication",
                                "authMethodConfigParams": auth_cfg,
                            },
                        )
                    )
                    logger.info("✓ Authentication method configured")
                except Exception as e:
                    warnings.append(f"Failed to set authentication method: {e}")
                    logger.warning(f"Failed to set authentication method: {e}")

            if args.username:
                logger.info(f"Creating user: {args.username}")
                try:
                    usr = _get_json(
                        _api_url(
                            api_base,
                            "users",
                            "action",
                            "newUser",
                            {"apikey": api_key, "contextId": context_id, "name": args.username},
                        )
                    )
                    user_id = usr.get("userId", "")
                    creds = urllib.parse.urlencode({"username": args.username, "password": args.password})
                    _get_json(
                        _api_url(
                            api_base,
                            "users",
                            "action",
                            "setAuthenticationCredentials",
                            {
                                "apikey": api_key,
                                "contextId": context_id,
                                "userId": user_id,
                                "authCredentialsConfigParams": creds,
                            },
                        )
                    )
                    _get_json(
                        _api_url(
                            api_base,
                            "users",
                            "action",
                            "setUserEnabled",
                            {"apikey": api_key, "contextId": context_id, "userId": user_id, "enabled": "true"},
                        )
                    )
                    logger.info(f"✓ User created and enabled (ID: {user_id})")
                except Exception as e:
                    warnings.append(f"Failed to configure user: {e}")
                    logger.warning(f"Failed to configure user: {e}")

            timer.end()

        # ====================================================================
        # PHASE: Spider Scan
        # ====================================================================
        if args.spider:
            timer.start("Spider Scan")

            logger.info("Starting spider scan...")
            if context_id and user_id:
                logger.info(f"  (as authenticated user: {args.username})")
                scan_id = _get_json(
                    _api_url(
                        api_base,
                        "spider",
                        "action",
                        "scanAsUser",
                        {"apikey": api_key, "contextId": context_id, "userId": user_id, "url": target},
                    )
                ).get("scan")
            else:
                scan_id = _get_json(_api_url(api_base, "spider", "action", "scan", {"apikey": api_key, "url": target})).get(
                    "scan"
                )
            if not scan_id:
                raise RuntimeError("Failed to start spider scan (no scan id returned)")

            logger.info(f"✓ Spider scan started (ID: {scan_id})")

            last_pct = -1
            while True:
                status = _get_json(_api_url(api_base, "spider", "view", "status", {"apikey": api_key, "scanId": scan_id}))
                pct = int(status.get("status") or 0)
                if pct != last_pct:
                    logger.info(f"Spider progress: {pct}%")
                    last_pct = pct
                if pct >= 100:
                    break
                _sleep_poll(deadline, last_status=f"spider {pct}%")

            # Get spider results
            results_url = _api_url(api_base, "spider", "view", "results", {"apikey": api_key, "scanId": scan_id})
            results = _get_json(results_url).get("results", [])
            logger.info(f"✓ Spider scan completed - discovered {len(results)} URLs")

            timer.end()

        # ====================================================================
        # PHASE: AJAX Spider Scan
        # ====================================================================
        if args.ajax_spider:
            timer.start("AJAX Spider Scan")

            logger.info("Starting AJAX spider scan...")
            try:
                params = {"apikey": api_key, "url": target}
                if context_name:
                    params["contextName"] = context_name
                    logger.info(f"  (using context: {context_name})")
                _get_json(_api_url(api_base, "spiderAjax", "action", "scan", params))
                logger.info("✓ AJAX spider started")

                while True:
                    status = _get_json(_api_url(api_base, "spiderAjax", "view", "status", {"apikey": api_key})).get(
                        "status"
                    )
                    status_str = str(status or "").lower()
                    logger.info(f"AJAX spider status: {status}")
                    if status_str in {"stopped", "0", "completed"}:
                        break
                    _sleep_poll(deadline, interval=5.0, last_status=f"ajax_spider {status}")

                # Get AJAX spider results
                ajax_results = _get_json(_api_url(api_base, "spiderAjax", "view", "results", {"apikey": api_key})).get("results", [])
                logger.info(f"✓ AJAX spider completed - discovered {len(ajax_results)} URLs")
            except Exception as e:
                warnings.append(f"AJAX spider failed: {e}")
                logger.error(f"AJAX spider failed: {e}")

            timer.end()

        # ====================================================================
        # PHASE: Active Scan
        # ====================================================================
        if args.active:
            timer.start("Active Scan")

            logger.info("Starting active scan...")
            logger.warning("Active scan is intrusive - use with caution!")
            if context_id and user_id:
                logger.info(f"  (as authenticated user: {args.username})")
                scan_id = _get_json(
                    _api_url(
                        api_base,
                        "ascan",
                        "action",
                        "scanAsUser",
                        {"apikey": api_key, "contextId": context_id, "userId": user_id, "url": target},
                    )
                ).get("scan")
            else:
                scan_id = _get_json(_api_url(api_base, "ascan", "action", "scan", {"apikey": api_key, "url": target})).get(
                    "scan"
                )
            if not scan_id:
                raise RuntimeError("Failed to start active scan (no scan id returned)")

            logger.info(f"✓ Active scan started (ID: {scan_id})")

            last_pct = -1
            while True:
                status = _get_json(_api_url(api_base, "ascan", "view", "status", {"apikey": api_key, "scanId": scan_id}))
                pct = int(status.get("status") or 0)
                if pct != last_pct:
                    logger.info(f"Active scan progress: {pct}%")
                    last_pct = pct
                if pct >= 100:
                    break
                _sleep_poll(deadline, interval=5.0, last_status=f"active_scan {pct}%")

            logger.info("✓ Active scan completed")
            timer.end()

        # ====================================================================
        # PHASE: Passive Scan Queue Drain
        # ====================================================================
        timer.start("Passive Scan Queue Drain")

        logger.info("Waiting for passive scan queue to drain...")
        last_remaining = -1
        while True:
            rec = _get_json(_api_url(api_base, "pscan", "view", "recordsToScan", {"apikey": api_key}))
            remaining = int(rec.get("recordsToScan") or 0)
            if remaining != last_remaining:
                logger.info(f"Passive scan queue: {remaining} records remaining")
                last_remaining = remaining
            if remaining <= 0:
                break
            _sleep_poll(deadline, last_status=f"pscan_queue {remaining} records")

        logger.info("✓ Passive scan queue drained")
        timer.end()

        # ====================================================================
        # PHASE: Alert Collection
        # ====================================================================
        timer.start("Alert Collection")

        logger.info(f"Fetching alerts (max: {args.max_alerts})...")
        alerts: list[dict[str, Any]] = []
        start = 0
        page = 500
        max_alerts = max(1, args.max_alerts)
        while start < max_alerts:
            resp = _get_json(
                _api_url(
                    api_base,
                    "core",
                    "view",
                    "alerts",
                    {"apikey": api_key, "baseurl": target, "start": start, "count": page},
                )
            )
            batch = resp.get("alerts") or []
            if not isinstance(batch, list) or not batch:
                break
            alerts.extend(batch)
            logger.debug(f"Fetched {len(batch)} alerts (total: {len(alerts)})")
            start += len(batch)
            if len(batch) < page:
                break

        logger.info(f"✓ Collected {len(alerts)} alerts")

        # Log alert severity breakdown
        risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for alert in alerts:
            risk = str(alert.get("risk", "")).strip() or str(alert.get("riskdesc", "")).strip()
            if risk in risk_counts:
                risk_counts[risk] += 1

        logger.info(f"Alert breakdown:")
        for risk, count in risk_counts.items():
            if count > 0:
                logger.info(f"  {risk}: {count}")

        timer.end()

        # ====================================================================
        # PHASE: HAR Export
        # ====================================================================
        har_path = ""
        har_error = ""
        if args.har_out:
            timer.start("HAR Export")

            logger.info(f"Exporting HAR to: {args.har_out}")
            try:
                har_url = _api_other_url(api_base, "core", "har", {"apikey": api_key, "baseurl": target})
                har_data = _get_raw(har_url)
                out_path = Path(args.har_out)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(har_data)
                har_path = str(out_path)
                logger.info(f"✓ HAR exported ({len(har_data)} bytes)")
            except Exception as e:
                har_error = str(e)
                logger.error(f"HAR export failed: {e}")

            timer.end()

        # ====================================================================
        # Build final output with timing and scan options
        # ====================================================================
        timing_summary = timer.get_summary()

        out = {
            "zap": {
                "api_url": api_base,
                "version": version,
                "scan_policy": scan_policy,
            },
            "target": target,
            "mode": "daemon",
            "scan_options": {
                "spider": bool(args.spider),
                "ajax_spider": bool(args.ajax_spider),
                "active": bool(args.active),
                "ignore_robots": bool(args.ignore_robots),
                "max_minutes": args.max_minutes,
                "context": args.context_name or "",
                "authenticated": bool(args.username),
            },
            "spider": bool(args.spider),
            "ajax_spider": bool(args.ajax_spider),
            "active": bool(args.active),
            "context": args.context_name or "",
            "warnings": warnings,
            "har_path": har_path,
            "har_error": har_error,
            "alerts": alerts,
            "count": len(alerts),
            "timing": timing_summary,
            "timestamp": datetime.now().isoformat(),
        }

        # Write JSON report to file if requested
        if args.json_out:
            try:
                json_path = Path(args.json_out)
                json_path.parent.mkdir(parents=True, exist_ok=True)
                json_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
                logger.info(f"✓ JSON report written to: {json_path}")
            except Exception as e:
                logger.error(f"Failed to write JSON report: {e}")
                sys.stderr.write(f"Warning: Failed to write JSON report: {e}\n")

        # Write HTML report if requested
        if args.html_out:
            try:
                html_path = Path(args.html_out)
                html_path.parent.mkdir(parents=True, exist_ok=True)
                html_content = _generate_html_report(out)
                html_path.write_text(html_content, encoding="utf-8")
                logger.info(f"✓ HTML report written to: {html_path}")
            except Exception as e:
                logger.error(f"Failed to write HTML report: {e}")
                sys.stderr.write(f"Warning: Failed to write HTML report: {e}\n")

        # Write Markdown report if requested
        if args.md_out:
            try:
                md_path = Path(args.md_out)
                md_path.parent.mkdir(parents=True, exist_ok=True)
                md_content = _generate_md_report(out)
                md_path.write_text(md_content, encoding="utf-8")
                logger.info(f"✓ Markdown report written to: {md_path}")
            except Exception as e:
                logger.error(f"Failed to write Markdown report: {e}")
                sys.stderr.write(f"Warning: Failed to write Markdown report: {e}\n")

        # Log final summary
        logger.info("=" * 70)
        logger.info("ZAP SCAN COMPLETED SUCCESSFULLY")
        logger.info(f"Total Duration: {timing_summary['total_formatted']}")
        logger.info(f"Total Alerts: {len(alerts)}")
        logger.info(f"Warnings: {len(warnings)}")
        logger.info("=" * 70)

        # Write JSON to stdout for Guardian workflow integration
        sys.stdout.write(json.dumps(out, ensure_ascii=False))
        return 0

    except TimeoutError as e:
        logger.error(f"SCAN TIMEOUT: {e}")
        timer.end()  # End current phase
        sys.stderr.write(f"ERROR: {e}\n")
        return 1
    except Exception as e:
        logger.error(f"SCAN FAILED: {e}", exc_info=True)
        timer.end()  # End current phase
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        raise
    except Exception as e:
        sys.stderr.write(f"ERROR: {e}\n")
        raise SystemExit(2)
