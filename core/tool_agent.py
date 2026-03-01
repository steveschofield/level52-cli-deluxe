"""
Tool Selector Agent
Selects appropriate pentesting tools and configures them
"""

import asyncio
import ssl
import time
import urllib.request
from typing import Dict, Any, Optional
from core.agent import BaseAgent
from utils.error_handler import ToolExecutionError, with_error_handling
from ai.prompt_templates import (
    TOOL_SELECTOR_SYSTEM_PROMPT,
    TOOL_SELECTION_PROMPT,
    TOOL_PARAMETERS_PROMPT
)
from tools import (
    NmapTool,
    HttpxTool,
    SubfinderTool,
    NucleiTool,
)


class ToolAgent(BaseAgent):
    """Agent that selects and configures pentesting tools"""
    
    def __init__(self, config, llm_client, memory):
        super().__init__("ToolSelector", config, llm_client, memory)
        
        # Initialize available tools
        from tools import (
            NmapTool, HttpxTool, SubfinderTool, NucleiTool,
            WhatWebTool, Wafw00fTool, NiktoTool, TestSSLTool,
            SQLMapTool, FFufTool, WPScanTool, SSLyzeTool, HeadersTool, MasscanTool,
            AmassTool, WhoisTool, HydraTool, JwtTool, GraphqlCopTool, UploadScannerTool, CsrfTesterTool,
            Enum4linuxNgTool, SmbclientTool, ShowmountTool, SnmpwalkTool, OnesixtyoneTool,
            ArjunTool, XSStrikeTool, GitleaksTool, CMSeekTool, DnsReconTool,
            DnsxTool, ShufflednsTool, PurednsTool,
            RetireTool, NaabuTool, KatanaTool,
            AsnmapTool, WaybackurlsTool, SubjsTool,
            LinkfinderTool, XnlinkfinderTool, ParamspiderTool,
            SchemathesisTool, TrufflehogTool, MetasploitTool, ZapTool,
            DalfoxTool, CommixTool, GobusterTool, GodEyeTool,
            CORSScannerTool, CookieAnalyzerTool, ErrorDetectorTool,
            SSRFScannerTool, XXEScannerTool, DeserializationScannerTool,
            AuthScannerTool, IDORScannerTool,
            BloodhoundTool, SemgrepTool, TrivyTool
        )

        import platform
        
        self.available_tools = {
            "nmap": NmapTool(config),
            "subfinder": SubfinderTool(config),
            "nuclei": NucleiTool(config),
            "whatweb": WhatWebTool(config),
            "wafw00f": Wafw00fTool(config),
            "nikto": NiktoTool(config),
            "testssl": TestSSLTool(config),
            "sqlmap": SQLMapTool(config),
            "ffuf": FFufTool(config),
            "wpscan": WPScanTool(config),
            "sslyze": SSLyzeTool(config),
            "headers": HeadersTool(config),
            "masscan": MasscanTool(config),
            "amass": AmassTool(config),
            "whois": WhoisTool(config),
            "hydra": HydraTool(config),
            "jwt_tool": JwtTool(config),
            "graphql-cop": GraphqlCopTool(config),
            "upload-scanner": UploadScannerTool(config),
            "csrf-tester": CsrfTesterTool(config),
            "enum4linux-ng": Enum4linuxNgTool(config),
            # Backward-compatible alias: route legacy enum4linux calls to enum4linux-ng.
            "enum4linux": Enum4linuxNgTool(config),
            "smbclient": SmbclientTool(config),
            "showmount": ShowmountTool(config),
            "snmpwalk": SnmpwalkTool(config),
            "onesixtyone": OnesixtyoneTool(config),
            "arjun": ArjunTool(config),
            "xsstrike": XSStrikeTool(config),
            "gitleaks": GitleaksTool(config),
            "cmseek": CMSeekTool(config),
            "dnsrecon": DnsReconTool(config),
            "dnsx": DnsxTool(config),
            "shuffledns": ShufflednsTool(config),
            "puredns": PurednsTool(config),
            "retire": RetireTool(config),
            "naabu": NaabuTool(config),
            "asnmap": AsnmapTool(config),
            "waybackurls": WaybackurlsTool(config),
            "subjs": SubjsTool(config),
            "linkfinder": LinkfinderTool(config),
            "xnlinkfinder": XnlinkfinderTool(config),
            "paramspider": ParamspiderTool(config),
            "schemathesis": SchemathesisTool(config),
            "trufflehog": TrufflehogTool(config),
            "metasploit": MetasploitTool(config),
            "zap": ZapTool(config),
            "dalfox": DalfoxTool(config),
            "commix": CommixTool(config),
            "gobuster": GobusterTool(config),
            "godeye": GodEyeTool(config),
            "cors-scanner": CORSScannerTool(config),
            "cookie-analyzer": CookieAnalyzerTool(config),
            "error-detector": ErrorDetectorTool(config),
            "ssrf-scanner": SSRFScannerTool(config),
            "xxe-scanner": XXEScannerTool(config),
            "deserialization-scanner": DeserializationScannerTool(config),
            "auth-scanner": AuthScannerTool(config),
            "idor-scanner": IDORScannerTool(config),
            # SAST/Whitebox tools
            "semgrep": SemgrepTool(config),
            "trivy": TrivyTool(config),
            # MCP-based tools (Active Directory)
            "bloodhound": BloodhoundTool(config),
        }

        # Add OS-specific tools
        if platform.system().lower() != "darwin":  # Not macOS
            self.available_tools["httpx"] = HttpxTool(config)
            self.available_tools["katana"] = KatanaTool(config)
        else:  # macOS only
            pass


    def log_tool_availability(self):
        """Log availability of all registered tools and basic install hints."""
        install_hints = {
            "nmap": "apt install nmap",
            "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "whatweb": "git clone https://github.com/urbanadventurer/WhatWeb",
            "wafw00f": "pip install wafw00f",
            "nikto": "apt install nikto",
            "testssl": "git clone https://github.com/drwetter/testssl.sh.git",
            "sqlmap": "pip install sqlmap",
            "ffuf": "go install github.com/ffuf/ffuf/v2@latest",
            "wpscan": "gem install wpscan",
            "sslyze": "pip install sslyze",
            "headers": "apt install curl",
            "masscan": "apt install masscan",
            "udp-proto-scanner": "apt install udp-proto-scanner",
            "amass": "snap install amass (or apt install amass on Kali)",
            "whois": "apt install whois",
            "hydra": "apt install hydra",
            "jwt_tool": "git clone https://github.com/ticarpi/jwt_tool (jwt_tool.py)",
            "graphql-cop": "git clone https://github.com/dolevf/graphql-cop.git (or run ./setup.sh)",
            "upload-scanner": "install upload-scanner (project-specific)",
            "csrf-tester": "install CSRFTester (project-specific)",
            "jsparser": "git clone https://github.com/nahamsec/JSParser.git",
            "enum4linux-ng": "apt install enum4linux-ng",
            "enum4linux": "apt install enum4linux-ng (legacy alias)",
            "smbclient": "apt install smbclient",
            "showmount": "apt install nfs-common",
            "snmpwalk": "apt install snmp",
            "onesixtyone": "apt install onesixtyone",
            "arjun": "pip install arjun",
            "xsstrike": "git clone https://github.com/s0md3v/XSStrike.git",
            "gitleaks": "go install github.com/zricethezav/gitleaks/v8@latest",
            "cmseek": "git clone https://github.com/Tuhinshubhra/CMSeeK.git",
            "dnsrecon": "pip install dnsrecon",
            "dnsx": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
            "shuffledns": "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
            "puredns": "go install github.com/d3mondev/puredns@latest",
            "altdns": "pip install altdns",
            "retire": "npm install -g retire",
            "naabu": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
            "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "asnmap": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
            "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
            "subjs": "go install github.com/lc/subjs@latest",
            "linkfinder": "pip install git+https://github.com/GerbenJavado/LinkFinder.git",
            "xnlinkfinder": "pip install xnlinkfinder",
            "paramspider": "pip install git+https://github.com/devanshbatham/ParamSpider.git",
            "schemathesis": "pip install schemathesis",
            "trufflehog": "pip install trufflehog",
            "metasploit": "install via https://www.metasploit.com/ (msfconsole on PATH)",
            "zap": "docker pull ghcr.io/zaproxy/zaproxy:stable (requires Docker)",
            "dalfox": "go install github.com/hahwul/dalfox/v2@latest",
            "commix": "pip install commix",
            "gobuster": "apt install gobuster  # or: go install github.com/OJ/gobuster/v3@latest",
            "cors-scanner": "git clone https://github.com/chenjj/CORScanner (vendored in tools/vendor/CORScanner)",
            "cookie-analyzer": "apt install curl (uses curl)",
            "error-detector": "built-in (passive analysis, uses curl)",
            "ssrf-scanner": "built-in (uses curl for SSRF probing)",
            "xxe-scanner": "built-in (uses curl for XXE payload delivery)",
            "deserialization-scanner": "built-in (uses curl for deserialization detection)",
            "auth-scanner": "built-in (uses curl for authentication testing)",
            "idor-scanner": "built-in (uses curl for IDOR detection)",
            "semgrep": "pip install semgrep",
            "trivy": "brew install trivy (or see https://aquasecurity.github.io/trivy)",
            "bloodhound": "docker pull ghcr.io/fuzzinglabs/bloodhound-mcp:latest (requires Docker + Neo4j)",
        }

        missing = []
        for name, tool in self.available_tools.items():
            if tool.is_available:
                self.logger.info(f"Tool available: {name}")
            else:
                self.logger.warning(f"Tool missing: {name} ({install_hints.get(name, 'install manually')})")
                missing.append(name)
        if missing:
            self.logger.warning(f"Missing tools: {', '.join(missing)}. Some functionality will be limited.")

    def _health_check_config(self) -> Dict[str, Any]:
        return (self.config or {}).get("pentest", {}).get("health_check", {}) or {}

    def _should_health_check(self, tool_name: str) -> bool:
        cfg = self._health_check_config()
        if not cfg.get("enabled", False):
            return False
        tools = cfg.get("tools")
        if isinstance(tools, (list, tuple, set)):
            return tool_name in tools
        return tool_name in {"nuclei", "graphql-cop"}

    def _build_health_urls(self, target: str) -> list[str]:
        cfg = self._health_check_config()
        url_tpl = cfg.get("url") or cfg.get("health_url")
        if isinstance(url_tpl, str) and url_tpl.strip():
            url = url_tpl.replace("{target}", target).strip()
            if "://" not in url:
                url = f"https://{url}"
            return [url]

        target_str = (target or "").strip()
        if target_str.startswith("http://") or target_str.startswith("https://"):
            return [target_str]
        return [f"https://{target_str}", f"http://{target_str}"]

    def _probe_url(self, url: str, timeout: int, insecure: bool) -> tuple[bool, float | None, str | None]:
        start = time.monotonic()
        ctx = None
        if insecure and url.lower().startswith("https://"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "Guardian-HealthCheck/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                resp.read(1)
            latency_ms = (time.monotonic() - start) * 1000.0
            return True, latency_ms, None
        except Exception as exc:
            return False, None, str(exc)

    async def _run_health_check(self, target: str) -> Dict[str, Any]:
        cfg = self._health_check_config()
        timeout = int(cfg.get("timeout_seconds", 5))
        samples = int(cfg.get("samples", 3))
        insecure = bool(cfg.get("insecure", True))
        slow_threshold = float(cfg.get("slow_threshold_ms", 800))

        urls = self._build_health_urls(target)
        latencies: list[float] = []
        errors: list[str] = []
        used_url = urls[0] if urls else ""

        for url in urls:
            used_url = url
            for _ in range(samples):
                ok, latency, err = await asyncio.to_thread(self._probe_url, url, timeout, insecure)
                if ok and latency is not None:
                    latencies.append(latency)
                elif err:
                    errors.append(err)
            if latencies:
                break

        reachable = len(latencies) > 0
        avg_ms = (sum(latencies) / len(latencies)) if latencies else None
        slow = bool(reachable and avg_ms is not None and avg_ms >= slow_threshold)
        return {
            "reachable": reachable,
            "avg_ms": avg_ms,
            "slow": slow,
            "url": used_url,
            "errors": errors[-3:],
        }

    async def _maybe_apply_health_check(
        self,
        tool_name: str,
        target: str,
        tool_kwargs: Dict[str, Any],
    ) -> tuple[Dict[str, Any] | None, Dict[str, Any] | None]:
        if not self._should_health_check(tool_name):
            return tool_kwargs, None

        cfg = self._health_check_config()
        max_retries = int(cfg.get("max_retries", 2))
        backoff = float(cfg.get("backoff_seconds", 5))
        backoff_mult = float(cfg.get("backoff_multiplier", 2.0))

        attempt = 0
        result: Dict[str, Any] | None = None
        while attempt <= max_retries:
            result = await self._run_health_check(target)
            if result.get("reachable"):
                break
            if attempt == max_retries:
                break
            delay = backoff * (backoff_mult ** attempt)
            self.logger.warning(
                f"Health check failed for {tool_name} (attempt {attempt + 1}/{max_retries + 1}); retrying in {delay:.1f}s"
            )
            await asyncio.sleep(delay)
            attempt += 1

        if not result or not result.get("reachable"):
            return None, result

        if result.get("slow"):
            slow_delay = float(cfg.get("slow_delay_seconds", 5))
            tool_kwargs = dict(tool_kwargs or {})

            if tool_name == "nuclei":
                multiplier = float(cfg.get("slow_rate_multiplier", 0.5))
                min_rate = int(cfg.get("slow_min_rate", 5))
                nuclei_cfg = (self.config or {}).get("tools", {}).get("nuclei", {}) or {}
                safe_mode = (self.config or {}).get("pentest", {}).get("safe_mode", True)
                base_rate = tool_kwargs.get("rate_limit")
                if base_rate is None:
                    base_rate = nuclei_cfg.get("rate_limit", 50 if safe_mode else 150)
                new_rate = max(min_rate, int(float(base_rate) * multiplier))
                tool_kwargs["rate_limit"] = new_rate

                base_concurrency = tool_kwargs.get("concurrency")
                if base_concurrency is None:
                    base_concurrency = nuclei_cfg.get("concurrency")
                if base_concurrency is not None:
                    tool_kwargs["concurrency"] = max(1, int(float(base_concurrency) * multiplier))

                self.logger.warning(
                    f"Health check slow (avg {result.get('avg_ms'):.0f}ms); reducing nuclei rate to {tool_kwargs['rate_limit']}"
                )
            elif tool_name == "graphql-cop" and slow_delay > 0:
                self.logger.warning(
                    f"Health check slow (avg {result.get('avg_ms'):.0f}ms); delaying graphql-cop by {slow_delay:.1f}s"
                )
                await asyncio.sleep(slow_delay)

        return tool_kwargs, result

    
    async def execute(self, objective: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Select and configure the best tool for an objective
        
        Args:
            objective: What we're trying to accomplish
            target: Target to scan
            **kwargs: Additional context
        
        Returns:
            Dict with selected tool and configuration
        """
        # Determine target type and normalize for downstream tools
        target_type = self._detect_target_type(target)
        normalized_target = self._normalize_target_for_tooling(target, target_type)
        
        # Get context from memory
        context = self.memory.get_context_for_ai()
        
        # Ask AI to select tool
        prompt = TOOL_SELECTION_PROMPT.format(
            objective=objective,
            target=normalized_target,
            target_type=target_type,
            phase=self.memory.current_phase,
            context=context
        )
        
        result = await self.think(prompt, TOOL_SELECTOR_SYSTEM_PROMPT)
        
        # Parse tool selection
        tool_selection = self._parse_selection(result["response"])
        if not tool_selection.get("tool"):
            self.logger.warning("Tool parse failed; refusing to default to an arbitrary tool")
            return {
                "tool": "",
                "arguments": "",
                "reasoning": "Could not parse TOOL from ToolSelector response",
                "expected_output": ""
            }

        # Fail closed: if the model returns a tool name we don't have registered, do not attempt execution.
        if tool_selection["tool"] not in self.available_tools:
            self.logger.warning(
                f"Model selected unknown tool '{tool_selection['tool']}'; skipping selection"
            )
            return {
                "tool": "",
                "arguments": "",
                "reasoning": f"Unknown tool selected by model: {tool_selection['tool']}",
                "expected_output": ""
            }

        # Gate DNS/subdomain tools when target is IP-only
        dns_like = {"subfinder", "dnsrecon", "dnsx", "shuffledns", "puredns", "altdns", "asnmap"}
        if target_type == "ip" and tool_selection["tool"] in dns_like:
            self.logger.warning(f"Tool {tool_selection['tool']} not suitable for IP targets; skipping selection")
            return {
                "tool": "",
                "arguments": "",
                "reasoning": "Selected tool is DNS-only and target is an IP",
                "expected_output": ""
            }

        # De-duplicate httpx when no new context: if last tool was httpx with same target, skip
        if tool_selection["tool"] == "httpx":
            recent = self.memory.tool_executions[-1] if self.memory.tool_executions else None
            if recent and recent.tool == "httpx":
                recent_norm = self._normalize_target_for_tooling(recent.target, self._detect_target_type(recent.target))
                if recent_norm == normalized_target:
                    self.logger.info("Skipping redundant httpx run; recent httpx already executed for this target")
                    return {
                        "tool": "",
                        "arguments": "",
                        "reasoning": "Recent httpx already executed for this target",
                        "expected_output": ""
                    }
        
        self.log_action("ToolSelected", f"{tool_selection['tool']} for {objective}")
        
        return {
            "tool": tool_selection["tool"],
            "arguments": tool_selection.get("arguments", ""),
            "reasoning": result["reasoning"],
            "expected_output": tool_selection.get("expected_output", "")
        }
    
    async def configure_tool(self, tool_name: str, objective: str, target: str) -> Dict[str, Any]:
        """
        Generate optimal parameters for a specific tool
        
        Returns:
            Dict with tool parameters and justification
        """
        safe_mode = self.config.get("pentest", {}).get("safe_mode", True)
        timeout = (self.config.get("tools", {}).get(tool_name, {}) or {}).get("tool_timeout")
        if timeout is None:
            timeout = self.config.get("pentest", {}).get("tool_timeout", 300)
        
        prompt = TOOL_PARAMETERS_PROMPT.format(
            tool=tool_name,
            objective=objective,
            target=target,
            safe_mode=safe_mode,
            stealth=False,  # Could be configurable
            timeout=timeout
        )
        
        result = await self.think(prompt, TOOL_SELECTOR_SYSTEM_PROMPT)
        
        return {
            "parameters": result["response"],
            "justification": result["reasoning"]
        }
    
    async def execute_tool(self, tool_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute a selected tool with robust error handling
        
        Returns:
            Tool execution results
        """
        if tool_name not in self.available_tools:
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=f"Unknown tool: {tool_name}",
                exit_code=127,
                skipped=True,
            )
        
        tool = self.available_tools[tool_name]
        
        if not tool.is_available:
            # Re-check availability for tools that might have dynamic dependencies
            if hasattr(tool, '_check_installation'):
                if not tool._check_installation():
                    self.logger.warning(f"Tool {tool_name} not available (dependency check failed)")
                    return self._record_tool_failure(
                        tool_name=tool_name,
                        target=target,
                        error=f"Tool {tool_name} dependencies not available",
                        exit_code=127,
                        skipped=True,
                    )
            else:
                return self._record_tool_failure(
                    tool_name=tool_name,
                    target=target,
                    error=f"Tool {tool_name} not installed",
                    exit_code=127,
                    skipped=True,
                )
        
        try:
            # Execute tool with circuit breaker protection
            timeout = kwargs.pop('tool_timeout', self.config.get("pentest", {}).get("tool_timeout", 300))

            kwargs, health = await self._maybe_apply_health_check(tool_name, target, kwargs or {})
            if kwargs is None:
                reason = "Target not reachable"
                if health and health.get("errors"):
                    reason = f"Health check failed: {health.get('errors')[-1]}"
                return self._record_tool_failure(
                    tool_name=tool_name,
                    target=target,
                    error=reason,
                    exit_code=0,
                    skipped=True,
                )
            
            # Use enhanced error handler if available
            if hasattr(self, 'enhanced_error_handler'):
                result = await self.enhanced_error_handler.execute_with_protection(
                    "tool_execution",
                    lambda: asyncio.wait_for(tool.execute(target, **kwargs), timeout=timeout)
                )
                if not result["success"]:
                    return self._record_tool_failure(
                        tool_name=tool_name,
                        target=target,
                        error=result["error"],
                        exit_code=1,
                        skipped=False,
                    )
                result = result["result"]
            else:
                result = await asyncio.wait_for(tool.execute(target, **kwargs), timeout=timeout)

            # Record execution in memory (even on non-zero exit for audit/debug)
            from core.memory import ToolExecution
            raw_output = self._truncate_output(result.get("raw_output", "") or "")

            # Check if tool execution was successful using tool-specific exit code rules
            exit_code = result["exit_code"]
            is_success = tool.is_success_exit_code(exit_code)

            execution = ToolExecution(
                tool=tool_name,
                command=result["command"],
                target=target,
                timestamp=result.get("timestamp", ""),
                exit_code=exit_code,
                output=raw_output,
                duration=result["duration"],
                success=is_success
            )
            self.memory.add_tool_execution(execution)

            # Handle failed execution (based on tool-specific rules, not just non-zero exit)
            if not is_success:
                error_msg = result.get("error") or f"Tool exited with exit code {exit_code}"
                return {
                    "success": False,
                    "tool": tool_name,
                    "parsed": result["parsed"],
                    "raw_output": raw_output,
                    "duration": result["duration"],
                    "exit_code": exit_code,
                    "error": error_msg,
                }

            return {
                "success": True,
                "tool": tool_name,
                "parsed": result["parsed"],
                "raw_output": raw_output,
                "duration": result["duration"],
                "exit_code": exit_code,
            }
            
        except asyncio.TimeoutError:
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=f"Tool {tool_name} timed out after {timeout}s",
                exit_code=124,
                skipped=False,
            )
        except ValueError as e:
            self.logger.warning(f"Tool {tool_name} skipped: {e}")
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=str(e),
                exit_code=0,
                skipped=True,
            )
        except Exception as e:
            return self._record_tool_failure(
                tool_name=tool_name,
                target=target,
                error=f"Tool execution failed: {str(e)}",
                exit_code=1,
                skipped=False,
            )

    def _record_tool_failure(
        self,
        tool_name: str,
        target: str,
        error: str,
        exit_code: int,
        skipped: bool,
    ) -> Dict[str, Any]:
        """Record a failed or skipped tool execution and return a failure result."""
        from core.memory import ToolExecution
        timestamp = self._get_timestamp()
        output = f"skipped: {error}" if skipped else error
        execution = ToolExecution(
            tool=tool_name,
            command="",
            target=target,
            timestamp=timestamp,
            exit_code=exit_code,
            output=self._truncate_output(output),
            duration=0.0,
        )
        self.memory.add_tool_execution(execution)
        return {
            "success": False,
            "tool": tool_name,
            "error": error,
            "exit_code": exit_code,
            "skipped": skipped,
        }

    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _detect_target_type(self, target: str) -> str:
        """Detect if target is IP, domain, or URL"""
        from utils.helpers import is_valid_ip, is_valid_domain, is_valid_url, extract_domain_from_url
        # If it's a URL pointing to an IP, treat as IP
        if is_valid_url(target):
            host = extract_domain_from_url(target)
            if host and is_valid_ip(host):
                return "ip"
            return "url"
        if is_valid_ip(target):
            return "ip"
        if is_valid_domain(target):
            return "domain"
        return "unknown"

    def _normalize_target_for_tooling(self, target: str, target_type: str) -> str:
        """Strip schemes/ports for domain-only tools and gate non-domain actions."""
        from urllib.parse import urlparse

        if target_type == "url":
            parsed = urlparse(target)
            return parsed.netloc or target
        if target_type in ("ip", "domain"):
            return target
        return target

    def _truncate_output(self, output: str) -> str:
        ai_cfg = (self.config or {}).get("ai", {}) or {}
        max_chars = ai_cfg.get("max_tool_output_chars", 20000)
        try:
            max_chars = int(max_chars)
        except Exception:
            max_chars = 20000
        if max_chars > 0 and len(output) > max_chars:
            return output[:max_chars] + "\n... (truncated)"
        return output
    
    def _parse_selection(self, response: str) -> Dict[str, str]:
        """Parse AI tool selection response.

        More tolerant of markdown/bold formatting (e.g., '**TOOL**: `nuclei`')
        and fails closed (returns empty tool) when parsing fails.
        """
        import re

        selection = {
            "tool": "",
            "arguments": "",
            "expected_output": ""
        }

        if not response:
            return selection

        # Match variants like "TOOL:", "**TOOL**:", "Tool:", with optional backticks
        tool_match = re.search(
            r"(?:^|\n)\s*(?:\d+[\.\)]\s*)?\**\s*tool\**\s*:\s*`?([a-zA-Z0-9_-]+)`?",
            response,
            re.IGNORECASE,
        )
        if tool_match:
            selection["tool"] = tool_match.group(1).lower()

        args_match = re.search(
            r"(?:^|\n)\s*(?:\d+[\.\)]\s*)?\**\s*arguments\**\s*:\s*(.+?)(?:\n\s*(?:\d+[\.\)]\s*)?\**\s*expected_output\**\s*:|$)",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if args_match:
            selection["arguments"] = args_match.group(1).strip()

        expected_match = re.search(
            r"(?:^|\n)\s*(?:\d+[\.\)]\s*)?\**\s*expected_output\**\s*:\s*(.+)$",
            response,
            re.IGNORECASE | re.DOTALL,
        )
        if expected_match:
            selection["expected_output"] = expected_match.group(1).strip()

        # Fallbacks: models often answer with markdown prose ("best tool would be **dnsrecon**").
        # Prefer selecting from the "primary" portion before any "Alternative Tools" section.
        primary = re.split(r"\n\s*#{1,6}\s*alternative|\nalternative tools?:", response, flags=re.IGNORECASE)[0]

        if not selection["tool"]:
            # Try to capture a bolded/backticked tool mention near the recommendation.
            rec_match = re.search(
                r"(?:best tool|recommend(?:ation)?|would be|use)\s+(?:the\s+)?\**`?([a-zA-Z0-9_-]+)`?\**",
                primary[:600],
                re.IGNORECASE,
            )
            if rec_match:
                candidate = rec_match.group(1).lower()
                if candidate in self.available_tools:
                    selection["tool"] = candidate

        if not selection["tool"]:
            # Last-resort: pick the first known tool name mentioned in the primary section.
            for name in self.available_tools.keys():
                if re.search(rf"\b{re.escape(name)}\b", primary, re.IGNORECASE):
                    selection["tool"] = name
                    break

        # If arguments are inside a fenced code block, extract the first command-like line.
        # This is useful when models output:
        # ### ARGUMENTS:
        # ```\n dnsrecon -d example.com \n```
        if not selection["arguments"] or "```" in selection["arguments"]:
            fence_match = re.search(r"```(?:bash|sh|shell)?\s*\n([\s\S]*?)```", response, re.IGNORECASE)
            if fence_match:
                block = fence_match.group(1)
                first_line = ""
                for line in block.splitlines():
                    line = line.strip()
                    if line:
                        first_line = line
                        break
                if first_line:
                    selection["arguments"] = first_line

        # Normalize "arguments" to be args-only when it starts with the tool name.
        if selection["tool"] and selection["arguments"]:
            parts = selection["arguments"].strip().split()
            if parts and parts[0].lower() == selection["tool"]:
                selection["arguments"] = " ".join(parts[1:]).strip()

        return selection
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get status of all tools"""
        return {
            name: tool.is_available
            for name, tool in self.available_tools.items()
        }
