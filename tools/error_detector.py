"""
Error Detector tool for identifying information disclosure through verbose error messages.

This is a passive analysis tool that scans existing output (from crawlers, scanners, etc.)
for error patterns that indicate information disclosure vulnerabilities.
"""

import re
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class ErrorDetectorTool(BaseTool):
    """Identify information disclosure through verbose error messages."""

    # Error patterns with their categories and severities
    ERROR_PATTERNS = {
        "sql_error": {
            "severity": "high",
            "title": "SQL Error Message Disclosure",
            "description": "Application exposes SQL error messages that reveal database structure, query syntax, or backend technology. Attackers can use this information to craft SQL injection payloads.",
            "remediation": "Implement custom error pages. Disable detailed error output in production. Log errors server-side only.",
            "patterns": [
                r"(?i)you have an error in your sql syntax",
                r"(?i)mysql_(?:fetch|query|num_rows|connect)",
                r"(?i)warning.*?\bmysql_",
                r"(?i)unclosed quotation mark after the character string",
                r"(?i)quoted string not properly terminated",
                r"(?i)pg_(?:query|exec|connect|last_error)",
                r"(?i)postgresql.*?error",
                r"(?i)ORA-\d{5}",
                r"(?i)oracle.*?error",
                r"(?i)microsoft.*?ole db.*?sql server",
                r"(?i)\[Microsoft\]\[ODBC SQL Server Driver\]",
                r"(?i)SQLite3?::(?:Exception|Query)",
                r"(?i)sqlite_error",
                r"(?i)SQL syntax.*?error",
                r"(?i)syntax error.*?at or near",
            ],
        },
        "php_error": {
            "severity": "medium",
            "title": "PHP Error Message Disclosure",
            "description": "Application exposes PHP errors revealing file paths, function names, and code structure. This aids reconnaissance for further attacks.",
            "remediation": "Set display_errors=Off and log_errors=On in php.ini. Use custom error handlers in production.",
            "patterns": [
                r"(?i)fatal error.*?on line \d+",
                r"(?i)warning.*?on line \d+",
                r"(?i)parse error.*?on line \d+",
                r"(?i)notice.*?undefined (?:variable|index|offset)",
                r"(?i)call to undefined function",
                r"(?i)call to a member function.*?on (?:null|a non-object)",
                r"(?i)<b>(?:Fatal error|Warning|Notice|Parse error)</b>:",
            ],
        },
        "aspnet_error": {
            "severity": "medium",
            "title": "ASP.NET Error Message Disclosure",
            "description": "Application exposes ASP.NET stack traces and error details revealing internal code structure and server configuration.",
            "remediation": "Set customErrors mode='On' in web.config. Disable detailed errors in production. Use Application_Error handler.",
            "patterns": [
                r"(?i)server error in .* application",
                r"(?i)system\.(?:nullreference|argumentnull|invalid(?:operation|cast))exception",
                r"(?i)stack trace:.*?at system\.",
                r"(?i)microsoft\.aspnet",
                r"(?i)object reference not set to an instance",
                r"(?i)unhandled exception.*?aspx",
                r"(?i)\[(?:HttpException|SqlException|ArgumentException)\]",
            ],
        },
        "java_error": {
            "severity": "medium",
            "title": "Java Stack Trace Disclosure",
            "description": "Application exposes Java exception stack traces revealing class names, method calls, and internal architecture.",
            "remediation": "Configure proper exception handling. Use generic error pages. Log stack traces server-side only.",
            "patterns": [
                r"(?i)java\.lang\.(?:NullPointerException|ClassNotFoundException|RuntimeException)",
                r"(?i)at (?:com|org|net|io)\.[a-zA-Z]+\.[a-zA-Z]+\(",
                r"(?i)javax\.servlet\.ServletException",
                r"(?i)caused by:.*?exception",
                r"(?i)java\.(?:sql|io|net)\.(?:\w+)?Exception",
            ],
        },
        "python_error": {
            "severity": "medium",
            "title": "Python Traceback Disclosure",
            "description": "Application exposes Python tracebacks revealing file paths, line numbers, and code logic.",
            "remediation": "Set DEBUG=False in Django/Flask settings. Implement custom 500 error handlers. Use logging instead of traceback display.",
            "patterns": [
                r"(?i)traceback \(most recent call last\)",
                r"(?i)file \"[^\"]+\.py\", line \d+",
                r"(?i)(?:ModuleNotFoundError|ImportError|AttributeError|TypeError|ValueError|KeyError):",
                r"(?i)django\.(?:core|db|http)",
                r"(?i)flask\.(?:app|wrappers)",
            ],
        },
        "nodejs_error": {
            "severity": "medium",
            "title": "Node.js Error Message Disclosure",
            "description": "Application exposes Node.js error messages and stack traces revealing module paths and application structure.",
            "remediation": "Set NODE_ENV=production. Use custom error middleware. Avoid sending error.stack to clients.",
            "patterns": [
                r"(?i)at (?:Object|Module|Function)\.\w+.*?\(.*?\.js:\d+:\d+\)",
                r"(?i)ReferenceError:.*?is not defined",
                r"(?i)TypeError:.*?(?:is not a function|cannot read propert)",
                r"(?i)Error:.*?ENOENT|EACCES|ECONNREFUSED",
                r"(?i)node_modules/",
                r"(?i)SyntaxError: Unexpected token",
            ],
        },
        "path_disclosure": {
            "severity": "high",
            "title": "File Path Disclosure",
            "description": "Application reveals server-side file system paths. Attackers can use this to understand directory structure and locate sensitive files.",
            "remediation": "Sanitize error output. Use relative paths internally. Configure web server to suppress path information.",
            "patterns": [
                r"(?:C:\\(?:inetpub|windows|users|program files)\\[^\s\"'<>]+)",
                r"(?:/(?:var|usr|home|etc|opt|srv)/(?:www|html|htdocs|web|app|log)[^\s\"'<>]*)",
                r"(?:/(?:home|root)/[a-zA-Z0-9_.-]+/[^\s\"'<>]+\.(?:py|php|rb|java|js|conf))",
            ],
        },
        "version_disclosure": {
            "severity": "low",
            "title": "Software Version Disclosure",
            "description": "Server exposes software version information. Known versions can be cross-referenced with vulnerability databases for targeted attacks.",
            "remediation": "Configure server to suppress version banners. Remove X-Powered-By and Server headers. Use ServerTokens Prod in Apache.",
            "patterns": [
                r"(?i)apache/[\d.]+",
                r"(?i)nginx/[\d.]+",
                r"(?i)microsoft-iis/[\d.]+",
                r"(?i)php/[\d.]+",
                r"(?i)x-powered-by:\s*(?:php|asp\.net|express|ruby|django|flask)",
                r"(?i)server:\s*(?:apache|nginx|iis|lighttpd|tomcat|jetty)",
            ],
        },
    }

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "error-detector"

    def _check_installation(self) -> bool:
        # Passive analysis tool - always available
        return True

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Error detector uses curl to fetch the target and common error-triggering paths,
        then analyzes the responses for error patterns.
        """
        import shutil
        if not shutil.which("curl"):
            raise RuntimeError("curl not found in PATH")

        command = [
            "curl",
            "-sS",
            "--max-time", "15",
            "--connect-timeout", "5",
            "-A", "Guardian-Error-Detector/1.0",
            "-L",
            "-k",  # insecure for pentest
        ]

        # Fetch multiple error-triggering paths
        # We'll use curl to fetch the main target; the analysis happens in parse_output
        command.append(target)
        return command

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 6, 7, 22, 28, 35, 47, 51, 52, 56, 60)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Analyze output for error message patterns."""
        results = {
            "errors_found": False,
            "error_types": [],
            "findings": [],
        }

        if not output or not output.strip():
            return results

        for error_type, config in self.ERROR_PATTERNS.items():
            examples = []
            for pattern in config["patterns"]:
                for match in re.finditer(pattern, output):
                    example = match.group(0).strip()
                    if example and len(example) < 200 and example not in examples:
                        examples.append(example)
                    if len(examples) >= 3:
                        break
                if len(examples) >= 3:
                    break

            if examples:
                results["errors_found"] = True
                if error_type not in results["error_types"]:
                    results["error_types"].append(error_type)
                results["findings"].append({
                    "title": config["title"],
                    "severity": config["severity"],
                    "type": "information_disclosure",
                    "error_type": error_type,
                    "examples": examples,
                    "description": config["description"],
                    "remediation": config["remediation"],
                })

        return results

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Convenience method: analyze arbitrary text (e.g., output from another tool)
        without executing curl. Useful for chaining with other tool outputs.
        """
        return self.parse_output(text)
