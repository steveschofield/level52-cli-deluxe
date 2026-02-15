"""
Integration tests for new and enhanced security tools.

Tests tool initialization, output parsing, and structured finding generation
without requiring the actual tools to be installed.
"""

import pytest
from typing import Dict, Any


@pytest.fixture
def tool_config() -> Dict[str, Any]:
    """Config for tool tests."""
    return {
        "tools": {
            "cors_scanner": {"threads": 5, "timeout": 5},
            "cookie_analyzer": {"timeout": 5, "insecure": True},
            "error_detector": {"timeout": 5},
            "ssrf_scanner": {"timeout": 5},
            "xxe_scanner": {"timeout": 5},
            "deserialization_scanner": {"timeout": 5},
            "auth_scanner": {"timeout": 5},
            "idor_scanner": {"timeout": 5},
        },
        "pentest": {
            "tool_timeout": 30,
            "safe_mode": False,
        },
        "logging": {"level": "DEBUG", "log_tool_executions": True},
    }


# ─── Tool Initialization Tests ───

class TestToolInitialization:
    def test_cors_scanner_init(self, tool_config):
        from tools.cors_scanner import CORSScannerTool
        tool = CORSScannerTool(tool_config)
        assert tool.tool_name == "cors-scanner"

    def test_cookie_analyzer_init(self, tool_config):
        from tools.cookie_analyzer import CookieAnalyzerTool
        tool = CookieAnalyzerTool(tool_config)
        assert tool.tool_name == "cookie-analyzer"

    def test_error_detector_init(self, tool_config):
        from tools.error_detector import ErrorDetectorTool
        tool = ErrorDetectorTool(tool_config)
        assert tool.tool_name == "error-detector"
        assert tool.is_available  # passive tool, always available

    def test_ssrf_scanner_init(self, tool_config):
        from tools.ssrf_scanner import SSRFScannerTool
        tool = SSRFScannerTool(tool_config)
        assert tool.tool_name == "ssrf-scanner"

    def test_xxe_scanner_init(self, tool_config):
        from tools.xxe_scanner import XXEScannerTool
        tool = XXEScannerTool(tool_config)
        assert tool.tool_name == "xxe-scanner"

    def test_deserialization_scanner_init(self, tool_config):
        from tools.deserialization_scanner import DeserializationScannerTool
        tool = DeserializationScannerTool(tool_config)
        assert tool.tool_name == "deserialization-scanner"

    def test_auth_scanner_init(self, tool_config):
        from tools.auth_scanner import AuthScannerTool
        tool = AuthScannerTool(tool_config)
        assert tool.tool_name == "auth-scanner"

    def test_idor_scanner_init(self, tool_config):
        from tools.idor_scanner import IDORScannerTool
        tool = IDORScannerTool(tool_config)
        assert tool.tool_name == "idor-scanner"


# ─── CORS Scanner Parser Tests ───

class TestCORSScannerParser:
    def test_parse_json_output(self, tool_config):
        from tools.cors_scanner import CORSScannerTool
        tool = CORSScannerTool(tool_config)
        output = '{"url": "https://example.com", "type": "reflect_origin"}\n{"url": "https://example.com/api", "type": "null_origin"}'
        result = tool.parse_output(output)
        assert result["vulnerable"] is True
        assert len(result["misconfigurations"]) == 2
        assert result["misconfigurations"][0]["severity"] == "critical"
        assert result["misconfigurations"][1]["severity"] == "critical"
        assert len(result["findings"]) == 2
        assert result["findings"][0]["type"] == "cors_misconfiguration"
        assert "remediation" in result["findings"][0]

    def test_parse_no_vulns(self, tool_config):
        from tools.cors_scanner import CORSScannerTool
        tool = CORSScannerTool(tool_config)
        result = tool.parse_output("No vulnerabilities found")
        assert result["vulnerable"] is False
        assert len(result["findings"]) == 0


# ─── Cookie Analyzer Parser Tests ───

class TestCookieAnalyzerParser:
    def test_parse_insecure_cookies(self, tool_config):
        from tools.cookie_analyzer import CookieAnalyzerTool
        tool = CookieAnalyzerTool(tool_config)
        output = (
            "HTTP/1.1 200 OK\r\n"
            "Set-Cookie: sessionid=abc123; Path=/\r\n"
            "Set-Cookie: tracking=xyz; Path=/; HttpOnly; Secure; SameSite=Lax\r\n"
        )
        result = tool.parse_output(output)
        assert len(result["cookies"]) == 2
        # sessionid should have issues (session cookie, no flags)
        session_issues = [i for i in result["issues"] if i["cookie"] == "sessionid"]
        assert len(session_issues) >= 3  # missing httponly, secure, samesite
        # tracking should have no issues
        tracking_issues = [i for i in result["issues"] if i["cookie"] == "tracking"]
        assert len(tracking_issues) == 0
        # Check findings are generated
        assert len(result["findings"]) >= 3
        assert all("remediation" in f for f in result["findings"])

    def test_parse_samesite_none_no_secure(self, tool_config):
        from tools.cookie_analyzer import CookieAnalyzerTool
        tool = CookieAnalyzerTool(tool_config)
        output = "HTTP/1.1 200 OK\r\nSet-Cookie: token=abc; SameSite=None\r\n"
        result = tool.parse_output(output)
        samesite_issues = [i for i in result["issues"] if i["type"] == "samesite_none_no_secure"]
        assert len(samesite_issues) == 1
        assert samesite_issues[0]["severity"] == "high"

    def test_parse_no_cookies(self, tool_config):
        from tools.cookie_analyzer import CookieAnalyzerTool
        tool = CookieAnalyzerTool(tool_config)
        result = tool.parse_output("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
        assert len(result["cookies"]) == 0
        assert len(result["issues"]) == 0


# ─── Error Detector Parser Tests ───

class TestErrorDetectorParser:
    def test_detect_sql_errors(self, tool_config):
        from tools.error_detector import ErrorDetectorTool
        tool = ErrorDetectorTool(tool_config)
        output = "You have an error in your SQL syntax near 'SELECT * FROM users WHERE id=1'"
        result = tool.parse_output(output)
        assert result["errors_found"] is True
        assert "sql_error" in result["error_types"]
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "high"

    def test_detect_php_errors(self, tool_config):
        from tools.error_detector import ErrorDetectorTool
        tool = ErrorDetectorTool(tool_config)
        output = "<b>Fatal error</b>: Call to undefined function test() in /var/www/html/index.php on line 42"
        result = tool.parse_output(output)
        assert result["errors_found"] is True
        assert "php_error" in result["error_types"]

    def test_detect_path_disclosure(self, tool_config):
        from tools.error_detector import ErrorDetectorTool
        tool = ErrorDetectorTool(tool_config)
        output = "Error loading /var/www/html/config/database.php"
        result = tool.parse_output(output)
        assert result["errors_found"] is True
        assert "path_disclosure" in result["error_types"]

    def test_no_errors(self, tool_config):
        from tools.error_detector import ErrorDetectorTool
        tool = ErrorDetectorTool(tool_config)
        result = tool.parse_output("<html><body>Hello World</body></html>")
        assert result["errors_found"] is False
        assert len(result["findings"]) == 0

    def test_analyze_text_method(self, tool_config):
        from tools.error_detector import ErrorDetectorTool
        tool = ErrorDetectorTool(tool_config)
        result = tool.analyze_text("java.lang.NullPointerException at com.example.App.main(App.java:42)")
        assert result["errors_found"] is True
        assert "java_error" in result["error_types"]


# ─── SQLMap Enhanced Parser Tests ───

class TestSQLMapParser:
    def test_parse_vulnerable_output(self, tool_config):
        from tools.sqlmap import SQLMapTool
        tool = SQLMapTool(tool_config)
        output = """
sqlmap identified the following injection point(s) with a total of 52 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind
    Payload: id=1 AND 8234=8234

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=1 AND SLEEP(5)
---
back-end DBMS: MySQL >= 5.0.12
"""
        result = tool.parse_output(output)
        assert result["vulnerable"] is True
        assert result["dbms"] == "MySQL >= 5.0.12"
        assert len(result["injection_types"]) >= 1
        assert len(result["findings"]) >= 1
        finding = result["findings"][0]
        assert finding["severity"] == "critical"
        assert finding["type"] == "sql_injection"
        assert "remediation" in finding
        assert "parameterized queries" in finding["remediation"].lower()
        assert len(finding.get("payloads", [])) > 0

    def test_parse_not_vulnerable(self, tool_config):
        from tools.sqlmap import SQLMapTool
        tool = SQLMapTool(tool_config)
        output = "all tested parameters do not appear to be injectable"
        result = tool.parse_output(output)
        assert result["vulnerable"] is False
        assert len(result["findings"]) == 0


# ─── TestSSL Enhanced Parser Tests ───

class TestTestSSLParser:
    def test_parse_vulnerabilities_with_findings(self, tool_config):
        import json
        from tools.testssl import TestSSLTool
        tool = TestSSLTool(tool_config)
        items = [
            {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE", "cve": "CVE-2014-0160"},
            {"id": "ccs", "severity": "HIGH", "finding": "VULNERABLE", "cve": "CVE-2014-0224"},
            {"id": "TLSv1_2", "finding": "offered"},
            {"id": "cert_commonName", "finding": "example.com"},
        ]
        output = json.dumps(items)
        result = tool.parse_output(output)
        assert result["ssl_enabled"] is True
        assert len(result["vulnerabilities"]) == 2
        assert len(result["findings"]) >= 2
        # Check heartbleed finding has description
        heartbleed = [f for f in result["findings"] if "heartbleed" in f.get("vulnerability", "").lower()]
        assert len(heartbleed) == 1
        assert heartbleed[0]["severity"] == "critical"
        assert "remediation" in heartbleed[0]
        assert "CVE-2014-0160" in heartbleed[0]["title"]

    def test_parse_deprecated_protocol(self, tool_config):
        import json
        from tools.testssl import TestSSLTool
        tool = TestSSLTool(tool_config)
        items = [
            {"id": "SSLv3", "finding": "offered"},
            {"id": "TLSv1_2", "finding": "offered"},
        ]
        output = json.dumps(items)
        result = tool.parse_output(output)
        deprecated_findings = [f for f in result["findings"] if f.get("vulnerability") == "deprecated_protocol"]
        assert len(deprecated_findings) >= 1


# ─── Headers Enhanced Parser Tests ───

class TestHeadersParser:
    def test_parse_missing_headers_with_findings(self, tool_config):
        from tools.headers import HeadersTool
        tool = HeadersTool(tool_config)
        output = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n"
        result = tool.parse_output(output)
        assert len(result["security_headers_missing"]) > 0
        assert len(result["findings"]) > 0
        # Check HSTS is flagged as high severity
        hsts_findings = [f for f in result["findings"] if "strict-transport-security" in f.get("header", "")]
        assert len(hsts_findings) == 1
        assert hsts_findings[0]["severity"] == "high"
        assert "remediation" in hsts_findings[0]

    def test_parse_weak_csp(self, tool_config):
        from tools.headers import HeadersTool
        tool = HeadersTool(tool_config)
        output = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'\r\n\r\n"
        result = tool.parse_output(output)
        weak_csp = [f for f in result["findings"] if f.get("type") == "weak_csp"]
        assert len(weak_csp) == 1
        assert "unsafe-inline" in weak_csp[0]["description"]
        assert "unsafe-eval" in weak_csp[0]["description"]

    def test_parse_all_headers_present(self, tool_config):
        from tools.headers import HeadersTool
        tool = HeadersTool(tool_config)
        output = (
            "HTTP/1.1 200 OK\r\n"
            "Strict-Transport-Security: max-age=31536000\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "X-Frame-Options: DENY\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Referrer-Policy: strict-origin-when-cross-origin\r\n"
            "Permissions-Policy: camera=()\r\n"
            "Cross-Origin-Opener-Policy: same-origin\r\n"
            "Cross-Origin-Embedder-Policy: require-corp\r\n"
            "Cross-Origin-Resource-Policy: same-origin\r\n"
            "\r\n"
        )
        result = tool.parse_output(output)
        assert len(result["security_headers_missing"]) == 0
        missing_findings = [f for f in result["findings"] if f.get("type") == "missing_security_header"]
        assert len(missing_findings) == 0

    def test_parse_deprecated_xss_protection(self, tool_config):
        from tools.headers import HeadersTool
        tool = HeadersTool(tool_config)
        output = "HTTP/1.1 200 OK\r\nX-XSS-Protection: 1; mode=block\r\n\r\n"
        result = tool.parse_output(output)
        deprecated = [f for f in result["findings"] if f.get("type") == "deprecated_header"]
        assert len(deprecated) == 1


# ─── SSRF Scanner Tests ───

class TestSSRFScanner:
    def test_init_and_payloads(self, tool_config):
        from tools.ssrf_scanner import SSRFScannerTool
        tool = SSRFScannerTool(tool_config)
        assert len(tool.SSRF_PAYLOADS) > 5
        assert len(tool.SSRF_PARAMS) > 10

    def test_parse_empty(self, tool_config):
        from tools.ssrf_scanner import SSRFScannerTool
        tool = SSRFScannerTool(tool_config)
        result = tool.parse_output("")
        assert result["vulnerable"] is False


# ─── XXE Scanner Tests ───

class TestXXEScanner:
    def test_detect_xxe_in_response(self, tool_config):
        from tools.xxe_scanner import XXEScannerTool
        tool = XXEScannerTool(tool_config)
        output = "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"
        result = tool.parse_output(output)
        assert result["vulnerable"] is True
        assert len(result["findings"]) >= 1
        assert result["findings"][0]["severity"] == "critical"

    def test_no_xxe(self, tool_config):
        from tools.xxe_scanner import XXEScannerTool
        tool = XXEScannerTool(tool_config)
        result = tool.parse_output("<response>OK</response>")
        assert result["vulnerable"] is False


# ─── Deserialization Scanner Tests ───

class TestDeserializationScanner:
    def test_detect_java_serialization(self, tool_config):
        from tools.deserialization_scanner import DeserializationScannerTool
        tool = DeserializationScannerTool(tool_config)
        output = "Content-Type: application/x-java-serialized-object\nrO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0"
        result = tool.parse_output(output)
        assert result["vulnerable"] is True
        assert "java_serialized" in result["deserialization_types"]

    def test_detect_viewstate(self, tool_config):
        from tools.deserialization_scanner import DeserializationScannerTool
        tool = DeserializationScannerTool(tool_config)
        output = '<input type="hidden" name="__VIEWSTATE" value="AAEAAAD/////" />'
        result = tool.parse_output(output)
        assert result["vulnerable"] is True

    def test_detect_php_serialization(self, tool_config):
        from tools.deserialization_scanner import DeserializationScannerTool
        tool = DeserializationScannerTool(tool_config)
        output = 'O:4:"User":{s:4:"name";s:5:"admin";}'
        result = tool.parse_output(output)
        assert result["vulnerable"] is True
        assert "php_serialized" in result["deserialization_types"]


# ─── Auth Scanner Tests ───

class TestAuthScanner:
    def test_detect_token_exposure(self, tool_config):
        from tools.auth_scanner import AuthScannerTool
        tool = AuthScannerTool(tool_config)
        output = '{"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"}'
        result = tool.parse_output(output)
        token_findings = [f for f in result["findings"] if "Token" in f.get("title", "")]
        assert len(token_findings) >= 1
        assert token_findings[0]["severity"] == "critical"

    def test_no_issues(self, tool_config):
        from tools.auth_scanner import AuthScannerTool
        tool = AuthScannerTool(tool_config)
        result = tool.parse_output("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n")
        assert len(result["findings"]) == 0


# ─── IDOR Scanner Tests ───

class TestIDORScanner:
    def test_detect_numeric_ids(self, tool_config):
        from tools.idor_scanner import IDORScannerTool
        tool = IDORScannerTool(tool_config)
        output = 'HTTP/1.1 200 OK\r\n\r\n{"id": 12345, "user_id": 67890, "name": "test"}'
        result = tool.parse_output(output)
        assert len(result["idor_surface"]) >= 1

    def test_detect_role_exposure(self, tool_config):
        from tools.idor_scanner import IDORScannerTool
        tool = IDORScannerTool(tool_config)
        output = 'HTTP/1.1 200 OK\r\n\r\n{"user": "test", "role": "admin", "is_admin": true}'
        result = tool.parse_output(output)
        role_findings = [f for f in result["findings"] if "Role" in f.get("title", "") or "Admin" in f.get("title", "")]
        assert len(role_findings) >= 1


# ─── Upload Scanner Enhanced Tests ───

class TestUploadScannerEnhanced:
    def test_detect_upload_form(self, tool_config):
        from tools.upload_scanner import UploadScannerTool
        tool = UploadScannerTool(tool_config)
        output = '<form enctype="multipart/form-data"><input type="file" name="upload"></form>'
        result = tool.parse_output(output)
        assert result["upload_forms_found"] is True
        assert len(result["findings"]) >= 1

    def test_payloads_defined(self, tool_config):
        from tools.upload_scanner import UploadScannerTool
        assert len(UploadScannerTool.UPLOAD_PAYLOADS) >= 8
        assert "php_webshell" in UploadScannerTool.UPLOAD_PAYLOADS
        assert "htaccess" in UploadScannerTool.UPLOAD_PAYLOADS


# ─── Tool Registration Tests ───

class TestToolRegistration:
    def test_all_new_tools_in_init(self):
        from tools import (
            CORSScannerTool, CookieAnalyzerTool, ErrorDetectorTool,
            SSRFScannerTool, XXEScannerTool, DeserializationScannerTool,
            AuthScannerTool, IDORScannerTool,
        )
        # Just verify imports work
        assert CORSScannerTool is not None
        assert CookieAnalyzerTool is not None
        assert ErrorDetectorTool is not None
        assert SSRFScannerTool is not None
        assert XXEScannerTool is not None
        assert DeserializationScannerTool is not None
        assert AuthScannerTool is not None
        assert IDORScannerTool is not None
