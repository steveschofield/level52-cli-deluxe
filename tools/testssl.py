"""
TestSSL tool wrapper for SSL/TLS testing
"""

import asyncio
import shutil
import re
import tempfile
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse
from pathlib import Path

from tools.base_tool import BaseTool


class TestSSLTool(BaseTool):
    """TestSSL.sh SSL/TLS testing wrapper"""
    
    def __init__(self, config):
        super().__init__(config)

    def _vendor_executable_path(self) -> Path:
        return Path(__file__).resolve().parent / "vendor" / "testssl.sh" / "testssl.sh"

    def _resolve_executable(self) -> str | None:
        # Prefer PATH, fall back to vendored copy if present.
        return (
            shutil.which("testssl.sh")
            or shutil.which("testssl")
            or (str(self._vendor_executable_path()) if self._vendor_executable_path().exists() else None)
        )

    def _check_installation(self) -> bool:
        return self._resolve_executable() is not None

    def _normalize_target(self, target: str) -> str:
        # testssl.sh expects host[:port] (URLs with scheme can confuse it).
        if "://" in target:
            parsed = urlparse(target)
            return parsed.netloc or target
        return target

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build testssl command"""
        executable = self._resolve_executable()
        if not executable:
            raise RuntimeError("testssl executable not found (expected testssl/testssl.sh or vendored copy)")

        command = [executable]

        cfg = (self.config or {}).get("tools", {}).get("testssl", {}) or {}
        
        # Machine-readable output
        jsonfile_path = kwargs.get("jsonfile_path")
        if not jsonfile_path:
            raise ValueError("TestSSLTool requires jsonfile_path")
        command.append(f"--jsonfile={jsonfile_path}")
        
        # Severity level
        severity = kwargs.get("severity", "HIGH")
        command.extend(["--severity", severity])
        
        # Fast mode
        if kwargs.get("fast", False):
            command.append("--fast")

        # Quiet mode
        command.append("--quiet")

        ip_mode = kwargs.get("ip") if "ip" in kwargs else cfg.get("ip")
        if ip_mode:
            command.extend(["--ip", str(ip_mode)])

        nodns = kwargs.get("nodns") if "nodns" in kwargs else cfg.get("nodns")
        if nodns:
            command.extend(["--nodns", str(nodns)])
        
        # Target (host:port or URL)
        command.append(self._normalize_target(target))
        
        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute testssl.sh and parse JSON output from its jsonfile.

        testssl.sh treats `--jsonfile=-` as a literal filename and refuses to overwrite it;
        always use a temp file and read it back.
        """
        if not self.is_available:
            raise RuntimeError("Tool testssl is not available")

        timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        started = datetime.now()

        with tempfile.TemporaryDirectory(prefix="guardian-testssl-") as tmpdir:
            json_path = Path(tmpdir) / "testssl.json"
            command = self.get_command(target, jsonfile_path=str(json_path), **kwargs)

            self.logger.info(f"Executing: {' '.join(command)}")

            process: asyncio.subprocess.Process | None = None
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
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
                duration = (datetime.now() - started).total_seconds()
                self.logger.error(f"Tool {self.tool_name} timed out after {timeout}s (elapsed {duration:.2f}s)")
                raise

            duration = (datetime.now() - started).total_seconds()
            out_text = (stdout or b"").decode("utf-8", errors="replace")
            err_text = (stderr or b"").decode("utf-8", errors="replace")

            file_text = ""
            try:
                if json_path.exists():
                    file_text = json_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                file_text = ""

            raw = (file_text.strip() or out_text).strip()
            if err_text and (not raw or process.returncode != 0):
                raw = (raw + "\n" + err_text).strip()

            parsed = self.parse_output(file_text.strip() or out_text)

            self.logger.info(
                f"Tool {self.tool_name} completed in {duration:.2f}s (exit {process.returncode})"
            )

            return {
                "tool": self.tool_name,
                "target": target,
                "command": " ".join(command),
                "timestamp": started.isoformat(),
                "exit_code": process.returncode,
                "duration": duration,
                "raw_output": raw,
                "error": err_text if err_text else None,
                "parsed": parsed,
            }
    
    # SSL/TLS vulnerability descriptions and remediation
    SSL_VULN_INFO = {
        "heartbleed": {
            "title": "Heartbleed Vulnerability",
            "severity": "critical",
            "description": "The Heartbleed bug (CVE-2014-0160) allows attackers to read memory from the server, potentially exposing private keys, session tokens, and user data.",
            "remediation": "Update OpenSSL to version 1.0.1g or later. Revoke and reissue all SSL certificates. Rotate all server-side secrets and session keys.",
        },
        "ccs": {
            "title": "CCS Injection Vulnerability",
            "severity": "high",
            "description": "CCS injection (CVE-2014-0224) allows man-in-the-middle attackers to decrypt and modify traffic between vulnerable clients and servers.",
            "remediation": "Update OpenSSL to the latest version. Ensure both client and server are patched.",
        },
        "ticketbleed": {
            "title": "Ticketbleed Vulnerability",
            "severity": "high",
            "description": "Ticketbleed (CVE-2016-9244) is a memory disclosure vulnerability in F5 BIG-IP TLS session tickets, leaking up to 31 bytes of server memory per request.",
            "remediation": "Update F5 BIG-IP firmware. Disable session tickets as a workaround.",
        },
        "robot": {
            "title": "ROBOT Attack Vulnerability",
            "severity": "high",
            "description": "ROBOT allows RSA decryption and signing operations using the server's private key via an adaptive chosen-ciphertext attack.",
            "remediation": "Disable RSA key exchange cipher suites. Use ECDHE or DHE key exchange instead.",
        },
        "secure_renego": {
            "title": "Insecure TLS Renegotiation",
            "severity": "high",
            "description": "Server supports insecure TLS renegotiation (CVE-2009-3555), allowing man-in-the-middle attackers to inject plaintext into the TLS session.",
            "remediation": "Enable RFC 5746 secure renegotiation. Disable client-initiated renegotiation if not needed.",
        },
        "crime": {
            "title": "CRIME Attack Vulnerability",
            "severity": "high",
            "description": "CRIME (CVE-2012-4929) exploits TLS compression to recover secret data through a chosen-plaintext attack.",
            "remediation": "Disable TLS-level compression.",
        },
        "breach": {
            "title": "BREACH Attack Vulnerability",
            "severity": "medium",
            "description": "BREACH exploits HTTP compression to recover secrets from HTTPS traffic.",
            "remediation": "Disable HTTP compression for sensitive pages. Use per-request CSRF tokens. Separate secrets from user input in responses.",
        },
        "poodle_ssl": {
            "title": "POODLE Vulnerability (SSLv3)",
            "severity": "high",
            "description": "POODLE (CVE-2014-3566) exploits SSLv3 to decrypt secure connections.",
            "remediation": "Disable SSLv3 entirely. Use TLS 1.2 or TLS 1.3 only.",
        },
        "sweet32": {
            "title": "Sweet32 Birthday Attack",
            "severity": "medium",
            "description": "Sweet32 (CVE-2016-2183) exploits 64-bit block ciphers (3DES, Blowfish) via birthday attack on long-lived connections.",
            "remediation": "Disable 3DES and other 64-bit block cipher suites. Use AES-128 or AES-256.",
        },
        "freak": {
            "title": "FREAK Attack Vulnerability",
            "severity": "high",
            "description": "FREAK (CVE-2015-0204) forces export-grade RSA key exchange, breaking encryption with modest resources.",
            "remediation": "Disable export cipher suites. Ensure no RSA_EXPORT ciphers are offered.",
        },
        "drown": {
            "title": "DROWN Attack Vulnerability",
            "severity": "critical",
            "description": "DROWN (CVE-2016-0800) allows decrypting TLS traffic by exploiting servers supporting SSLv2.",
            "remediation": "Disable SSLv2 on all servers sharing the same RSA private key.",
        },
        "logjam": {
            "title": "Logjam Attack Vulnerability",
            "severity": "high",
            "description": "Logjam (CVE-2015-4000) allows downgrading TLS to export-grade Diffie-Hellman.",
            "remediation": "Disable export cipher suites. Use 2048-bit or larger DH parameters. Prefer ECDHE over DHE.",
        },
        "beast": {
            "title": "BEAST Attack Vulnerability",
            "severity": "medium",
            "description": "BEAST (CVE-2011-3389) exploits TLS 1.0 CBC mode to decrypt portions of HTTPS traffic.",
            "remediation": "Disable TLS 1.0. Use TLS 1.2+ with AEAD ciphers (AES-GCM).",
        },
        "lucky13": {
            "title": "Lucky Thirteen Attack",
            "severity": "medium",
            "description": "Lucky Thirteen is a timing side-channel attack against CBC mode in TLS, potentially allowing plaintext recovery.",
            "remediation": "Use AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) instead of CBC mode ciphers.",
        },
        "rc4": {
            "title": "RC4 Cipher Support",
            "severity": "medium",
            "description": "Server supports the RC4 cipher which has known statistical biases making it vulnerable to plaintext recovery.",
            "remediation": "Disable all RC4 cipher suites. Use AES-GCM or ChaCha20-Poly1305 instead.",
        },
    }

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse testssl JSON output with structured findings"""
        results = {
            "ssl_enabled": False,
            "tls_versions": [],
            "cipher_suites": [],
            "vulnerabilities": [],
            "certificate_info": {},
            "grade": None,
            "issues_count": 0,
            "findings": [],
        }

        try:
            import json

            text = (output or "").strip()
            if not text:
                return results

            items: list[dict] = []
            if text.startswith("[") or text.startswith("{"):
                try:
                    loaded = json.loads(text)
                    if isinstance(loaded, dict):
                        items = [loaded]
                    elif isinstance(loaded, list):
                        items = [i for i in loaded if isinstance(i, dict)]
                except json.JSONDecodeError:
                    items = []

            if not items:
                for line in text.splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict):
                            items.append(data)
                    except json.JSONDecodeError:
                        continue

            for data in items:
                if data.get("id") == "cert_commonName":
                    results["certificate_info"]["common_name"] = data.get("finding")
                elif data.get("id") == "cert_subjectAltName":
                    san_finding = data.get("finding", "")
                    if san_finding:
                        san_list = [s.strip() for s in san_finding.split(",") if s.strip()]
                        results["certificate_info"]["san"] = san_list
                    else:
                        results["certificate_info"]["san"] = []
                elif data.get("id") == "cert_notAfter":
                    results["certificate_info"]["expiry"] = data.get("finding")
                elif "SSLv" in data.get("id", "") or "TLS" in data.get("id", ""):
                    if str(data.get("finding", "")).lower() == "offered":
                        protocol = str(data.get("id", "")).replace("_", " ")
                        results["tls_versions"].append(protocol)
                elif data.get("severity") in ["HIGH", "CRITICAL", "MEDIUM"]:
                    vuln = {
                        "name": data.get("id"),
                        "severity": str(data.get("severity", "")).lower(),
                        "finding": data.get("finding"),
                        "cve": data.get("cve", "")
                    }
                    results["vulnerabilities"].append(vuln)
                    results["issues_count"] += 1

                    # Generate structured finding with description
                    vuln_id = str(data.get("id", "")).lower()
                    vuln_info = self._get_vuln_info(vuln_id)
                    cve = data.get("cve", "")
                    severity = str(data.get("severity", "")).lower()
                    title = vuln_info["title"] if vuln_info else self._format_vuln_title(vuln_id)
                    if cve:
                        title = f"{title} ({cve})"

                    finding = {
                        "title": title,
                        "severity": vuln_info["severity"] if vuln_info else severity,
                        "type": "ssl_tls_vulnerability",
                        "vulnerability": vuln_id,
                        "finding_detail": data.get("finding", ""),
                        "description": vuln_info["description"] if vuln_info else f"SSL/TLS vulnerability detected: {data.get('finding', vuln_id)}",
                        "remediation": vuln_info["remediation"] if vuln_info else "Update SSL/TLS configuration. Disable vulnerable protocols and cipher suites.",
                    }
                    if cve:
                        finding["cve"] = cve
                    results["findings"].append(finding)

            results["ssl_enabled"] = len(results["tls_versions"]) > 0

            # Flag deprecated protocols
            deprecated = {"SSLv2", "SSLv3", "TLS 1.0", "TLSv1", "TLS 1.1", "TLSv1 1"}
            for proto in results["tls_versions"]:
                proto_clean = proto.strip()
                if any(d.lower() in proto_clean.lower() for d in deprecated):
                    results["findings"].append({
                        "title": f"Deprecated Protocol: {proto_clean}",
                        "severity": "high" if "ssl" in proto_clean.lower() else "medium",
                        "type": "ssl_tls_vulnerability",
                        "vulnerability": "deprecated_protocol",
                        "description": f"Server offers deprecated protocol {proto_clean}. Deprecated protocols have known vulnerabilities.",
                        "remediation": f"Disable {proto_clean}. Use TLS 1.2 or TLS 1.3 only.",
                    })

        except Exception as e:
            if "ssl" in output.lower() or "tls" in output.lower():
                results["ssl_enabled"] = True

        return results

    def _get_vuln_info(self, vuln_id: str) -> dict | None:
        """Look up vulnerability info by testssl ID."""
        vuln_id_lower = vuln_id.lower()
        if vuln_id_lower in self.SSL_VULN_INFO:
            return self.SSL_VULN_INFO[vuln_id_lower]
        for key, info in self.SSL_VULN_INFO.items():
            if key in vuln_id_lower or vuln_id_lower in key:
                return info
        return None

    @staticmethod
    def _format_vuln_title(vuln_id: str) -> str:
        """Format a raw vulnerability ID into a readable title."""
        return vuln_id.replace("_", " ").replace("-", " ").title()
