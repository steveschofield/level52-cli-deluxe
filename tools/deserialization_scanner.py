"""
Insecure Deserialization Detection tool.

Detects insecure deserialization vulnerabilities by analyzing responses
for serialization markers, error messages, and known vulnerable patterns.
"""

import re
import shutil
from typing import Dict, Any, List

from tools.base_tool import BaseTool


class DeserializationScannerTool(BaseTool):
    """Detect insecure deserialization vulnerabilities."""

    # Patterns indicating deserialization surface or vulnerabilities
    DESER_PATTERNS = {
        "java_serialized": {
            "severity": "critical",
            "title": "Java Serialized Object Detected",
            "description": "Java serialized objects detected in HTTP traffic. Java deserialization is a well-known attack vector (e.g., Apache Commons Collections, Spring, Jackson) that can lead to remote code execution.",
            "remediation": "Avoid Java native serialization. Use safe alternatives like JSON. If serialization is required, implement look-ahead deserialization with class whitelisting. Update libraries (Commons Collections, Spring, etc.).",
            "patterns": [
                r"(?i)(?:rO0ABX|aced0005)",  # Base64 / hex Java serialization magic bytes
                r"(?i)content-type:.*?application/x-java-serialized-object",
                r"(?i)java\.io\.(?:ObjectInputStream|Serializable)",
                r"(?i)org\.apache\.commons\.collections\.functors",
                r"(?i)ysoserial",
            ],
        },
        "php_serialized": {
            "severity": "high",
            "title": "PHP Serialized Object Detected",
            "description": "PHP serialized data detected. Insecure unserialize() calls can lead to object injection, allowing attackers to manipulate application logic or achieve code execution via magic methods.",
            "remediation": "Never use unserialize() on user-controlled data. Use json_decode() instead. If PHP serialization is required, use the allowed_classes option to restrict deserialization.",
            "patterns": [
                r'[Oa]:\d+:(?:\{|")',              # PHP serialized object/array pattern
                r'(?i)unserialize\(\)',
                r'(?i)__(?:wakeup|destruct|toString)\(\)',
                r"(?i)php.*?object injection",
            ],
        },
        "python_pickle": {
            "severity": "critical",
            "title": "Python Pickle Deserialization Detected",
            "description": "Python pickle deserialization detected. Pickle is inherently unsafe for untrusted data and can execute arbitrary code during deserialization via __reduce__ method.",
            "remediation": "Never use pickle.loads() on untrusted data. Use JSON, MessagePack, or other safe serialization formats. If pickle is required, use the pickletools module to inspect payloads before deserializing.",
            "patterns": [
                r"(?i)pickle\.loads",
                r"(?i)cpickle|cPickle",
                r"(?i)__reduce__|__reduce_ex__",
                r"\x80[\x02-\x05]",  # Pickle protocol markers
            ],
        },
        "dotnet_serialized": {
            "severity": "critical",
            "title": ".NET Deserialization Vulnerability",
            "description": ".NET serialization markers detected. BinaryFormatter, ObjectStateFormatter, and similar .NET serializers are known vectors for remote code execution.",
            "remediation": "Avoid BinaryFormatter (deprecated by Microsoft). Use System.Text.Json or DataContractSerializer with known types. Implement type filtering with SerializationBinder.",
            "patterns": [
                r"(?i)__VIEWSTATE",
                r"(?i)BinaryFormatter",
                r"(?i)ObjectStateFormatter",
                r"(?i)LosFormatter",
                r"(?i)SoapFormatter",
                r"(?i)System\.Runtime\.Serialization",
                r"AAEAAAD/////",  # Base64 .NET BinaryFormatter magic
            ],
        },
        "viewstate_unprotected": {
            "severity": "high",
            "title": "Unprotected ASP.NET ViewState",
            "description": "ASP.NET ViewState detected without MAC validation. Unprotected ViewState can be tampered with to achieve deserialization attacks.",
            "remediation": "Enable ViewState MAC validation: <pages enableViewStateMac='true'> in web.config. Use ASP.NET 4.5+ which enables MAC by default. Consider encrypting ViewState.",
            "patterns": [
                r"(?i)__VIEWSTATE.*?value=['\"][A-Za-z0-9+/=]{20,}",
                r"(?i)__VIEWSTATEGENERATOR",
                r"(?i)enableviewstatemac\s*=\s*['\"]?false",
            ],
        },
        "yaml_deserialization": {
            "severity": "high",
            "title": "Unsafe YAML Deserialization",
            "description": "YAML deserialization with unsafe loader detected. PyYAML yaml.load() without SafeLoader can execute arbitrary Python code.",
            "remediation": "Use yaml.safe_load() instead of yaml.load(). In Ruby, use Psych.safe_load(). Never deserialize YAML from untrusted sources with full loaders.",
            "patterns": [
                r"(?i)yaml\.(?:unsafe_)?load\(",
                r"(?i)!!python/(?:object|module|apply)",
                r"(?i)!!ruby/(?:object|hash|erb)",
                r"(?i)tag:yaml\.org,2002:python",
            ],
        },
    }

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "deserialization-scanner"

    def _check_installation(self) -> bool:
        return shutil.which("curl") is not None

    def is_success_exit_code(self, exit_code: int) -> bool:
        return exit_code in (0, 22, 28, 35, 52, 56, 60)

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Fetch target and include full response headers for analysis."""
        timeout = kwargs.get("timeout", 10)
        command = [
            "curl", "-sS",
            "-D", "-",  # Include response headers
            "--max-time", str(timeout),
            "--connect-timeout", "5",
            "-A", "Guardian-Deserialization-Scanner/1.0",
            "-L", "-k",
            target,
        ]
        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Analyze response for deserialization indicators."""
        results = {
            "vulnerable": False,
            "deserialization_types": [],
            "findings": [],
        }

        if not output or not output.strip():
            return results

        for deser_type, config in self.DESER_PATTERNS.items():
            matched = False
            evidence = []
            for pattern in config["patterns"]:
                matches = re.findall(pattern, output)
                if matches:
                    matched = True
                    for m in matches[:2]:
                        if isinstance(m, str) and len(m) < 100:
                            evidence.append(m.strip())

            if matched:
                results["vulnerable"] = True
                if deser_type not in results["deserialization_types"]:
                    results["deserialization_types"].append(deser_type)
                finding = {
                    "title": config["title"],
                    "severity": config["severity"],
                    "type": "insecure_deserialization",
                    "deserialization_type": deser_type,
                    "description": config["description"],
                    "remediation": config["remediation"],
                }
                if evidence:
                    finding["evidence"] = evidence
                results["findings"].append(finding)

        return results
