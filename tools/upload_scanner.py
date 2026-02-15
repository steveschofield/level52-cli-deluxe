"""
upload-scanner tool wrapper for file upload testing
"""

import os
import shutil
import sys
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class UploadScannerTool(BaseTool):
    """upload-scanner wrapper"""

    def __init__(self, config):
        self._script_path = None
        super().__init__(config)
        self.tool_name = "upload-scanner"

    def _check_installation(self) -> bool:
        cfg = (self.config or {}).get("tools", {}).get("upload_scanner", {}) or {}
        binary = cfg.get("binary")
        script = cfg.get("script")
        if script and os.path.isfile(str(script)):
            self._script_path = str(script)
            return True
        if binary and os.path.isfile(str(binary)):
            return True
        local_script = self._local_script()
        if local_script:
            self._script_path = local_script
            return True
        return bool(shutil.which("upload-scanner"))

    def _local_script(self) -> str | None:
        here = os.path.abspath(os.path.dirname(__file__))
        repo_root = os.path.abspath(os.path.join(here, os.pardir))
        candidate = os.path.join(repo_root, "tools", "vendor", "guardian_tools", "upload_scanner.py")
        return candidate if os.path.isfile(candidate) else None

    def get_command(self, target: str, **kwargs) -> List[str]:
        cfg = (self.config or {}).get("tools", {}).get("upload_scanner", {}) or {}
        binary = cfg.get("binary") or "upload-scanner"
        args = kwargs.get("args") if "args" in kwargs else cfg.get("args")
        script = kwargs.get("script") or cfg.get("script") or self._script_path
        insecure = kwargs.get("insecure") if "insecure" in kwargs else cfg.get("insecure")

        if args:
            args = str(args).replace("{target}", target)
            if insecure and "--insecure" not in args:
                args = f"{args} --insecure"
            if script:
                script = os.path.expandvars(os.path.expanduser(str(script)))
                return [sys.executable, script] + args.split()
            return [binary] + args.split()

        raise ValueError("upload-scanner requires args in config")

    # Active file upload test payloads
    UPLOAD_PAYLOADS = {
        "php_webshell": {
            "filename": "test.php",
            "content": "<?php echo 'GUARDIAN_UPLOAD_TEST'; ?>",
            "content_type": "application/x-php",
            "severity": "critical",
            "description": "PHP webshell upload accepted. Attackers can execute arbitrary server-side code.",
        },
        "php_double_ext": {
            "filename": "test.php.jpg",
            "content": "<?php echo 'GUARDIAN_UPLOAD_TEST'; ?>",
            "content_type": "image/jpeg",
            "severity": "critical",
            "description": "Double extension bypass accepted. Server may execute PHP despite image extension.",
        },
        "php_null_byte": {
            "filename": "test.php%00.jpg",
            "content": "<?php echo 'GUARDIAN_UPLOAD_TEST'; ?>",
            "content_type": "image/jpeg",
            "severity": "critical",
            "description": "Null byte extension bypass accepted. Legacy systems may truncate at null byte.",
        },
        "asp_webshell": {
            "filename": "test.asp",
            "content": "<%response.write(\"GUARDIAN_UPLOAD_TEST\")%>",
            "content_type": "application/x-asp",
            "severity": "critical",
            "description": "ASP webshell upload accepted. Attackers can execute server-side code on IIS.",
        },
        "jsp_webshell": {
            "filename": "test.jsp",
            "content": "<%= \"GUARDIAN_UPLOAD_TEST\" %>",
            "content_type": "application/x-jsp",
            "severity": "critical",
            "description": "JSP webshell upload accepted. Attackers can execute Java code on the server.",
        },
        "svg_xss": {
            "filename": "test.svg",
            "content": '<svg xmlns="http://www.w3.org/2000/svg"><script>alert("GUARDIAN_XSS")</script></svg>',
            "content_type": "image/svg+xml",
            "severity": "high",
            "description": "SVG with embedded JavaScript accepted. Can lead to stored XSS.",
        },
        "html_xss": {
            "filename": "test.html",
            "content": "<html><body><script>alert('GUARDIAN_XSS')</script></body></html>",
            "content_type": "text/html",
            "severity": "high",
            "description": "HTML file upload accepted. Can lead to stored XSS or phishing.",
        },
        "htaccess": {
            "filename": ".htaccess",
            "content": "AddType application/x-httpd-php .jpg",
            "content_type": "text/plain",
            "severity": "critical",
            "description": ".htaccess upload accepted. Attacker can reconfigure Apache to execute arbitrary file types as PHP.",
        },
    }

    def parse_output(self, output: str) -> Dict[str, Any]:
        results = {
            "upload_forms_found": False,
            "findings": [],
            "raw": output,
        }

        if not output:
            return results

        # Detect file upload forms
        import re
        form_patterns = [
            r'(?i)<form[^>]*enctype=["\']multipart/form-data["\']',
            r'(?i)<input[^>]*type=["\']file["\']',
            r'(?i)dropzone|file-upload|upload-area|drag.*?drop',
        ]

        for pattern in form_patterns:
            if re.search(pattern, output):
                results["upload_forms_found"] = True
                break

        # Check for upload success/failure indicators in response
        success_patterns = [
            (r'(?i)(?:file|upload).*?(?:success|uploaded|complete)', "File upload accepted"),
            (r'(?i)(?:saved|stored).*?(?:file|image|document)', "File saved on server"),
        ]

        rejection_patterns = [
            (r'(?i)(?:file type|extension).*?(?:not allowed|rejected|invalid|blocked)', "File type validation present"),
            (r'(?i)(?:upload|file).*?(?:failed|error|denied|forbidden)', "Upload rejected"),
            (r'(?i)(?:only|accept).*?(?:jpg|jpeg|png|gif|pdf|doc)', "Allowlist-based file type filter"),
        ]

        for pattern, desc in success_patterns:
            if re.search(pattern, output):
                results["findings"].append({
                    "title": "File Upload Endpoint Detected",
                    "severity": "medium",
                    "type": "file_upload",
                    "description": f"{desc}. Further testing with malicious payloads recommended.",
                    "remediation": "Validate file types server-side using magic bytes, not just extensions. "
                                  "Store uploads outside the web root. Rename uploaded files. "
                                  "Set proper Content-Type headers when serving uploaded files.",
                })

        has_protection = False
        for pattern, desc in rejection_patterns:
            if re.search(pattern, output):
                has_protection = True

        if results["upload_forms_found"] and not has_protection:
            results["findings"].append({
                "title": "File Upload Form Without Visible Validation",
                "severity": "high",
                "type": "file_upload",
                "description": "File upload form detected without visible client-side validation. "
                              "Server-side validation may also be missing.",
                "remediation": "Implement server-side file type validation using magic bytes. "
                              "Restrict allowed extensions to a strict allowlist. "
                              "Store uploaded files outside the web root directory. "
                              "Use a CDN or separate domain for serving user-uploaded content.",
            })

        return results
