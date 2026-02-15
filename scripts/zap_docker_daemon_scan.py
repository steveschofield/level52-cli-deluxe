#!/usr/bin/env python3
"""
Launch a ZAP Docker daemon, run the daemon scan helper, then stop the container.

This is used when advanced ZAP options (auth, AJAX spider, seed URLs) are enabled
but the configured mode is docker.

Enhanced with comprehensive logging: captures Docker container logs, monitors startup,
and provides detailed progress visibility.
"""

from __future__ import annotations

import argparse
import logging
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse
import urllib.request


# ============================================================================
# LOGGING SETUP
# ============================================================================


def setup_logging(verbose: bool = False, log_file: str = "") -> logging.Logger:
    """Configure structured logging with optional file output.

    By default, INFO-level logs are shown (progress updates, phase timing, etc.).
    Use --verbose for DEBUG-level logs (API calls, detailed responses, etc.).
    """
    logger = logging.getLogger("zap_docker_daemon_scan")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()

    # Console handler (stderr so stdout remains clean)
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


# Global logger
logger = logging.getLogger("zap_docker_daemon_scan")


# ============================================================================
# DOCKER & ZAP HELPERS
# ============================================================================


def _wait_for_api(api_url: str, timeout_s: int = 180) -> None:
    """Wait for ZAP daemon API to become ready."""
    deadline = time.time() + timeout_s
    attempt = 0
    logger.info(f"Waiting for ZAP API at {api_url} (timeout: {timeout_s}s)...")

    while time.time() < deadline:
        attempt += 1
        try:
            with urllib.request.urlopen(f"{api_url.rstrip('/')}/JSON/core/view/version/", timeout=5) as resp:
                if resp.read():
                    logger.info(f"✓ ZAP API ready after {attempt} attempts ({int(time.time() - (deadline - timeout_s))}s)")
                    return
        except Exception as e:
            logger.debug(f"API check attempt {attempt} failed: {e}")
            time.sleep(2)

    logger.error(f"ZAP API not ready after {timeout_s}s ({attempt} attempts)")
    raise RuntimeError(f"Timed out waiting for ZAP daemon API to become ready (after {attempt} attempts)")


def _capture_docker_logs(container_name: str, log_file: str) -> None:
    """Capture Docker container logs to a file."""
    try:
        logger.info(f"Capturing Docker container logs to: {log_file}")
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["docker", "logs", container_name],
            capture_output=True,
            text=True,
            timeout=10,
        )

        with open(log_path, "w", encoding="utf-8") as f:
            f.write("=== ZAP DOCKER CONTAINER LOGS ===\n\n")
            f.write("=== STDOUT ===\n")
            f.write(result.stdout)
            f.write("\n\n=== STDERR ===\n")
            f.write(result.stderr)

        logger.info(f"✓ Docker logs captured ({len(result.stdout) + len(result.stderr)} bytes)")
    except Exception as e:
        logger.warning(f"Failed to capture Docker logs: {e}")


def _check_docker_available() -> bool:
    """Check if Docker is available and running."""
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_container_info(container_name: str) -> dict:
    """Get Docker container information."""
    try:
        result = subprocess.run(
            ["docker", "inspect", container_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            import json
            info = json.loads(result.stdout)
            if info:
                return info[0]
    except Exception as e:
        logger.debug(f"Failed to get container info: {e}")
    return {}


# ============================================================================
# MAIN
# ============================================================================


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="ghcr.io/zaproxy/zaproxy:stable", help="ZAP Docker image")
    ap.add_argument("--api-url", default="http://127.0.0.1:8080", help="ZAP API URL (host perspective)")
    ap.add_argument("--container-name", default="guardian-zapd", help="Docker container name")
    ap.add_argument("--api-key", default="", help="ZAP API key (optional)")
    ap.add_argument("--target", required=True, help="Target URL to scan")
    ap.add_argument("--max-minutes", type=int, default=10, help="Max scan duration (minutes)")
    ap.add_argument("--startup-timeout", type=int, default=180, help="ZAP startup timeout (seconds)")
    ap.add_argument("--spider", action="store_true", help="Run spider scan")
    ap.add_argument("--ajax-spider", action="store_true", help="Run AJAX spider")
    ap.add_argument("--active", action="store_true", help="Run active scan")
    ap.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt")
    ap.add_argument("--seed-urls", default="", help="Comma-separated seed URLs")
    ap.add_argument("--seed-file", default="", help="File with seed URLs")
    ap.add_argument("--context-name", default="", help="ZAP context name")
    ap.add_argument("--include-regex", default="", help="Context include regex")
    ap.add_argument("--login-url", default="", help="Login URL")
    ap.add_argument("--login-request-data", default="", help="Login POST data")
    ap.add_argument("--username", default="", help="Username")
    ap.add_argument("--password", default="", help="Password")
    ap.add_argument("--username-field", default="username", help="Username field name")
    ap.add_argument("--password-field", default="password", help="Password field name")
    ap.add_argument("--logged-in-regex", default="", help="Logged-in regex")
    ap.add_argument("--logged-out-regex", default="", help="Logged-out regex")
    ap.add_argument("--har-out", default="", help="HAR output path")
    ap.add_argument("--json-out", default="", help="JSON report path")
    ap.add_argument("--html-out", default="", help="HTML report path")
    ap.add_argument("--md-out", default="", help="Markdown report path")

    # Logging options
    ap.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG-level logging (API calls, responses, etc.)")
    ap.add_argument("--log-file", default="", help="Detailed log file path")
    ap.add_argument("--zap-log-dir", default="", help="Directory to mount for ZAP internal logs")
    ap.add_argument("--docker-log", default="", help="Capture Docker container logs to this file")

    args = ap.parse_args(argv)

    # Setup logging
    global logger
    logger = setup_logging(verbose=args.verbose, log_file=args.log_file)

    start_time = time.time()

    # Log configuration
    logger.info("=" * 70)
    logger.info("ZAP DOCKER DAEMON SCAN STARTING")
    logger.info("=" * 70)
    logger.info(f"Configuration:")
    logger.info(f"  Docker Image: {args.image}")
    logger.info(f"  Container Name: {args.container_name}")
    logger.info(f"  Target: {args.target}")
    logger.info(f"  API URL: {args.api_url}")
    logger.info(f"  Spider: {args.spider}")
    logger.info(f"  AJAX Spider: {args.ajax_spider}")
    logger.info(f"  Active Scan: {args.active}")
    logger.info(f"  Max Duration: {args.max_minutes} minutes")
    logger.info(f"  Startup Timeout: {args.startup_timeout} seconds")
    logger.info(f"  Verbose: {args.verbose}")
    logger.info(f"  Log File: {args.log_file or '(stderr only)'}")
    logger.info(f"  Docker Logs: {args.docker_log or '(not captured)'}")
    logger.info(f"  ZAP Log Dir: {args.zap_log_dir or '(not mounted)'}")
    logger.info("=" * 70)

    # Check Docker availability
    logger.info("Checking Docker availability...")
    if not _check_docker_available():
        logger.error("Docker is not available or not running")
        logger.error("Please ensure Docker is installed and the daemon is running")
        return 1
    logger.info("✓ Docker is available")

    api_url = args.api_url.rstrip("/")
    parsed = urlparse(api_url)
    port = parsed.port or 8080

    # Build Docker command
    docker_cmd = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        args.container_name,
        "-p",
        f"{port}:8080",
    ]

    # Mount directory for ZAP internal logs if specified
    if args.zap_log_dir:
        zap_log_path = Path(args.zap_log_dir).resolve()
        zap_log_path.mkdir(parents=True, exist_ok=True)
        docker_cmd.extend(["-v", f"{zap_log_path}:/zap/wrk:rw"])
        logger.info(f"Mounting ZAP log directory: {zap_log_path} -> /zap/wrk")

    docker_cmd.extend([
        args.image,
        "zap.sh",
        "-daemon",
        "-host",
        "0.0.0.0",
        "-port",
        "8080",
        "-config",
        "api.disablekey=true",
        "-config",
        "api.addrs.addr.name=.*",
        "-config",
        "api.addrs.addr.regex=true",
    ])

    # If ZAP log dir is mounted, configure ZAP to write logs there
    if args.zap_log_dir:
        docker_cmd.extend([
            "-config",
            "log.file=/zap/wrk/zap.log",
        ])

    # Build zap_daemon_scan.py command
    zap_daemon_scan = Path(__file__).resolve().parent / "zap_daemon_scan.py"
    if not zap_daemon_scan.exists():
        logger.error(f"zap_daemon_scan.py not found at: {zap_daemon_scan}")
        return 1

    scan_cmd = [
        sys.executable,
        str(zap_daemon_scan),
        "--api-url",
        api_url,
        "--target",
        args.target,
        "--max-minutes",
        str(int(args.max_minutes)),
    ]

    # Pass all options through to zap_daemon_scan.py
    if args.api_key:
        scan_cmd += ["--api-key", args.api_key]
    if args.spider:
        scan_cmd.append("--spider")
    if args.ajax_spider:
        scan_cmd.append("--ajax-spider")
    if args.active:
        scan_cmd.append("--active")
    if args.ignore_robots:
        scan_cmd.append("--ignore-robots")
    if args.seed_urls:
        scan_cmd += ["--seed-urls", args.seed_urls]
    if args.seed_file:
        scan_cmd += ["--seed-file", args.seed_file]
    if args.context_name:
        scan_cmd += ["--context-name", args.context_name]
    if args.include_regex:
        scan_cmd += ["--include-regex", args.include_regex]
    if args.login_url:
        scan_cmd += ["--login-url", args.login_url]
    if args.login_request_data:
        scan_cmd += ["--login-request-data", args.login_request_data]
    if args.username:
        scan_cmd += ["--username", args.username]
    if args.password:
        scan_cmd += ["--password", args.password]
    if args.username_field:
        scan_cmd += ["--username-field", args.username_field]
    if args.password_field:
        scan_cmd += ["--password-field", args.password_field]
    if args.logged_in_regex:
        scan_cmd += ["--logged-in-regex", args.logged_in_regex]
    if args.logged_out_regex:
        scan_cmd += ["--logged-out-regex", args.logged_out_regex]
    if args.har_out:
        scan_cmd += ["--har-out", args.har_out]
    if args.json_out:
        scan_cmd += ["--json-out", args.json_out]
    if args.html_out:
        scan_cmd += ["--html-out", args.html_out]
    if args.md_out:
        scan_cmd += ["--md-out", args.md_out]

    # Pass logging options to zap_daemon_scan.py
    if args.verbose:
        scan_cmd.append("--verbose")
    if args.log_file:
        # Use a separate log file for the nested scan
        nested_log = str(Path(args.log_file).with_suffix("")) + "_scan.log"
        scan_cmd += ["--log-file", nested_log]
        logger.info(f"ZAP daemon scan will log to: {nested_log}")

    container_started = False
    container_id = ""

    try:
        # ====================================================================
        # PHASE 1: Start Docker Container
        # ====================================================================
        logger.info("=" * 70)
        logger.info("PHASE 1: Starting ZAP Docker Container")
        logger.info("=" * 70)
        logger.info(f"Docker command: {' '.join(docker_cmd[:10])}...")  # Log partial command

        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            logger.error("Failed to start Docker container")
            logger.error(f"Docker stdout: {result.stdout}")
            logger.error(f"Docker stderr: {result.stderr}")
            return 1

        container_id = result.stdout.strip()
        container_started = True
        logger.info(f"✓ Docker container started")
        logger.info(f"  Container ID: {container_id[:12]}")
        logger.info(f"  Container Name: {args.container_name}")
        logger.info(f"  Port Mapping: {port}:8080")

        # Get container info
        container_info = _get_container_info(args.container_name)
        if container_info:
            state = container_info.get("State", {})
            logger.debug(f"Container state: {state.get('Status')}")
            logger.debug(f"Container started at: {state.get('StartedAt')}")

        # ====================================================================
        # PHASE 2: Wait for ZAP API
        # ====================================================================
        logger.info("=" * 70)
        logger.info("PHASE 2: Waiting for ZAP API")
        logger.info("=" * 70)

        _wait_for_api(api_url, timeout_s=int(args.startup_timeout))

        logger.info("✓ ZAP API is ready")

        # ====================================================================
        # PHASE 3: Run ZAP Scan
        # ====================================================================
        logger.info("=" * 70)
        logger.info("PHASE 3: Running ZAP Scan")
        logger.info("=" * 70)
        logger.info(f"Executing: {' '.join(scan_cmd[:5])}...")

        # Run the scan (this will produce its own detailed logs)
        proc = subprocess.run(scan_cmd, check=False)

        scan_returncode = int(proc.returncode or 0)
        elapsed = time.time() - start_time

        if scan_returncode == 0:
            logger.info("=" * 70)
            logger.info("ZAP SCAN COMPLETED SUCCESSFULLY")
            logger.info(f"Total Duration: {elapsed:.1f}s")
            logger.info("=" * 70)
        else:
            logger.error("=" * 70)
            logger.error(f"ZAP SCAN FAILED (exit code: {scan_returncode})")
            logger.error(f"Total Duration: {elapsed:.1f}s")
            logger.error("=" * 70)

            # Capture Docker logs on failure
            if args.docker_log:
                logger.info("Capturing Docker logs due to scan failure...")
                _capture_docker_logs(args.container_name, args.docker_log)

        return scan_returncode

    except subprocess.TimeoutExpired as e:
        logger.error(f"Docker container startup timed out: {e}")
        return 1

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)

        # Capture Docker logs on unexpected error
        if container_started and args.docker_log:
            logger.info("Capturing Docker logs due to error...")
            _capture_docker_logs(args.container_name, args.docker_log)

        return 1

    finally:
        # ====================================================================
        # CLEANUP: Stop Docker Container
        # ====================================================================
        if container_started:
            logger.info("=" * 70)
            logger.info("CLEANUP: Stopping Docker Container")
            logger.info("=" * 70)

            # Capture final Docker logs if requested (even on success)
            if args.docker_log:
                _capture_docker_logs(args.container_name, args.docker_log)

            # Check if ZAP log was written
            if args.zap_log_dir:
                zap_log_file = Path(args.zap_log_dir) / "zap.log"
                if zap_log_file.exists():
                    size = zap_log_file.stat().st_size
                    logger.info(f"✓ ZAP internal log written: {zap_log_file} ({size} bytes)")
                else:
                    logger.warning(f"ZAP internal log not found: {zap_log_file}")

            logger.info(f"Stopping container: {args.container_name}")
            stop_result = subprocess.run(
                ["docker", "stop", args.container_name],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if stop_result.returncode == 0:
                logger.info("✓ Container stopped successfully")
            else:
                logger.warning(f"Container stop failed: {stop_result.stderr}")

            logger.info("=" * 70)


if __name__ == "__main__":
    raise SystemExit(main())
