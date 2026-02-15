"""
Source Code Analyzer - Whitebox Security Analysis Module

Orchestrates SAST tools to extract attack surface and vulnerability context
from source code for enhanced dynamic testing.
"""

from typing import Dict, List, Any, Optional
import os
import re
import json
import asyncio
from pathlib import Path

from tools.semgrep import SemgrepTool
from tools.trivy import TrivyTool
from tools.gitleaks import GitleaksTool
from tools.trufflehog import TrufflehogTool


class SourceCodeAnalyzer:
    """Extracts attack surface and vulnerability context from source code"""

    def __init__(self, source_path: str, config: Dict, logger, ai_client=None):
        """
        Initialize source code analyzer

        Args:
            source_path: Path to source code directory
            config: Configuration dictionary with whitebox settings
            logger: Logger instance
            ai_client: Optional AI client for intelligent analysis
        """
        self.source_path = source_path
        self.config = config
        self.logger = logger
        self.ai_client = ai_client

        self.findings = {
            "sast_results": {},
            "attack_surface": {
                "endpoints": [],
                "frameworks": [],
                "auth_mechanisms": [],
                "vulnerable_params": [],
                "secrets": []
            }
        }

        # Initialize tools
        self.semgrep = SemgrepTool(logger=logger)
        self.trivy = TrivyTool(logger=logger)
        self.gitleaks = GitleaksTool(logger=logger)
        self.trufflehog = TrufflehogTool(logger=logger)

    async def analyze(self) -> Dict[str, Any]:
        """
        Run comprehensive source code analysis

        Returns:
            Dictionary containing SAST results and extracted attack surface
        """
        self.logger.info(f"Starting whitebox analysis of {self.source_path}")

        if not os.path.exists(self.source_path):
            self.logger.error(f"Source path does not exist: {self.source_path}")
            return self.findings

        # Run SAST tools in parallel
        tasks = []

        # Semgrep
        if self._is_tool_enabled("semgrep"):
            tasks.append(self._run_semgrep())

        # Trivy
        if self._is_tool_enabled("trivy"):
            tasks.append(self._run_trivy())

        # Gitleaks
        if self._is_tool_enabled("gitleaks"):
            tasks.append(self._run_gitleaks())

        # TruffleHog
        if self._is_tool_enabled("trufflehog"):
            tasks.append(self._run_trufflehog())

        # Execute all SAST tools
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"SAST tool failed: {result}")

        # Extract attack surface from findings
        await self._extract_attack_surface()

        # Detect frameworks
        self.findings["attack_surface"]["frameworks"] = self._detect_frameworks()

        # AI-enhanced analysis if available
        if self.ai_client:
            await self._ai_enhanced_analysis()

        self.logger.info(f"Whitebox analysis complete. Found {self._get_findings_count()} issues")

        return self.findings

    async def _run_semgrep(self) -> None:
        """Run Semgrep SAST analysis"""
        try:
            self.logger.info("Running Semgrep analysis...")

            rulesets = self.config.get("whitebox", {}).get("tools", {}).get("semgrep", {}).get("rulesets", ["auto"])
            severity = self.config.get("whitebox", {}).get("tools", {}).get("semgrep", {}).get("severity", None)

            cmd = self.semgrep.get_command(
                self.source_path,
                rulesets=rulesets,
                severity=severity
            )

            output = await self._execute_tool_async(cmd)
            result = self.semgrep.parse_output(output)

            self.findings["sast_results"]["semgrep"] = result
            self.logger.info(f"Semgrep found {result['summary']['total']} issues")

        except Exception as e:
            self.logger.error(f"Semgrep analysis failed: {e}")
            self.findings["sast_results"]["semgrep"] = {"error": str(e)}

    async def _run_trivy(self) -> None:
        """Run Trivy vulnerability scan"""
        try:
            self.logger.info("Running Trivy analysis...")

            scanners = self.config.get("whitebox", {}).get("tools", {}).get("trivy", {}).get("scanners", ["vuln", "config", "secret"])
            severity = self.config.get("whitebox", {}).get("tools", {}).get("trivy", {}).get("severity", ["CRITICAL", "HIGH", "MEDIUM"])

            cmd = self.trivy.get_command(
                self.source_path,
                scan_type="fs",
                scanners=scanners,
                severity=severity
            )

            output = await self._execute_tool_async(cmd)
            result = self.trivy.parse_output(output)

            self.findings["sast_results"]["trivy"] = result
            self.logger.info(f"Trivy found {result['summary']['total_vulns']} vulnerabilities")

        except Exception as e:
            self.logger.error(f"Trivy analysis failed: {e}")
            self.findings["sast_results"]["trivy"] = {"error": str(e)}

    async def _run_gitleaks(self) -> None:
        """Run Gitleaks secret scanning"""
        try:
            self.logger.info("Running Gitleaks secret scan...")

            cmd = self.gitleaks.get_command(self.source_path)
            output = await self._execute_tool_async(cmd)
            result = self.gitleaks.parse_output(output)

            self.findings["sast_results"]["gitleaks"] = result
            self.logger.info(f"Gitleaks found {result['count']} secrets")

        except Exception as e:
            self.logger.error(f"Gitleaks analysis failed: {e}")
            self.findings["sast_results"]["gitleaks"] = {"error": str(e)}

    async def _run_trufflehog(self) -> None:
        """Run TruffleHog secret scanning"""
        try:
            self.logger.info("Running TruffleHog secret scan...")

            cmd = self.trufflehog.get_command(self.source_path)
            output = await self._execute_tool_async(cmd)
            result = self.trufflehog.parse_output(output)

            self.findings["sast_results"]["trufflehog"] = result
            self.logger.info(f"TruffleHog found {result.get('count', 0)} secrets")

        except Exception as e:
            self.logger.error(f"TruffleHog analysis failed: {e}")
            self.findings["sast_results"]["trufflehog"] = {"error": str(e)}

    async def _extract_attack_surface(self) -> None:
        """Extract attack surface from SAST findings"""

        # Extract vulnerable endpoints from Semgrep
        semgrep_results = self.findings["sast_results"].get("semgrep", {})
        if semgrep_results and "vulnerable_endpoints" in semgrep_results:
            self.findings["attack_surface"]["endpoints"].extend(
                semgrep_results["vulnerable_endpoints"]
            )

        # Extract vulnerable parameters from Semgrep
        if semgrep_results and "vulnerable_params" in semgrep_results:
            self.findings["attack_surface"]["vulnerable_params"].extend(
                semgrep_results["vulnerable_params"]
            )

        # Consolidate secrets from all secret scanners
        secrets = []

        gitleaks_results = self.findings["sast_results"].get("gitleaks", {})
        if gitleaks_results and "leaks" in gitleaks_results:
            for leak in gitleaks_results["leaks"]:
                secrets.append({
                    "source": "gitleaks",
                    "type": leak.get("RuleID", "unknown"),
                    "file": leak.get("File", ""),
                    "line": leak.get("StartLine", 0),
                    "secret": leak.get("Secret", ""),
                    "match": leak.get("Match", "")
                })

        trufflehog_results = self.findings["sast_results"].get("trufflehog", {})
        if trufflehog_results and "findings" in trufflehog_results:
            for finding in trufflehog_results["findings"]:
                secrets.append({
                    "source": "trufflehog",
                    "type": finding.get("detector_name", "unknown"),
                    "file": finding.get("file", ""),
                    "line": finding.get("line", 0),
                    "secret": finding.get("raw", ""),
                })

        self.findings["attack_surface"]["secrets"] = secrets

        # Extract API routes from source files
        await self._extract_api_routes()

    async def _extract_api_routes(self) -> None:
        """Extract API routes/endpoints from source code"""

        routes = []

        # Scan source files for routing patterns
        for root, dirs, files in os.walk(self.source_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', 'dist', 'build']]

            for file in files:
                # Only scan source code files
                if not self._is_source_file(file):
                    continue

                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        extracted_routes = self._parse_routes_from_code(content, file_path)
                        routes.extend(extracted_routes)
                except Exception as e:
                    self.logger.debug(f"Failed to read {file_path}: {e}")

        # Deduplicate routes
        unique_routes = {route["endpoint"]: route for route in routes}
        self.findings["attack_surface"]["endpoints"].extend(unique_routes.values())

        self.logger.info(f"Extracted {len(unique_routes)} API endpoints from source code")

    def _parse_routes_from_code(self, content: str, file_path: str) -> List[Dict]:
        """Parse route definitions from source code"""

        routes = []

        # Flask patterns
        flask_pattern = r'@(?:app|bp|blueprint)\.route\(["\']([^"\']+)["\'](?:.*methods\s*=\s*\[([^\]]+)\])?'
        for match in re.finditer(flask_pattern, content):
            endpoint = match.group(1)
            methods = match.group(2).replace('"', '').replace("'", '').split(',') if match.group(2) else ['GET']
            routes.append({
                "endpoint": endpoint,
                "methods": [m.strip() for m in methods],
                "framework": "flask",
                "file": file_path
            })

        # FastAPI patterns
        fastapi_pattern = r'@(?:app|router)\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']'
        for match in re.finditer(fastapi_pattern, content):
            method = match.group(1).upper()
            endpoint = match.group(2)
            routes.append({
                "endpoint": endpoint,
                "methods": [method],
                "framework": "fastapi",
                "file": file_path
            })

        # Django URL patterns
        django_pattern = r'path\(["\']([^"\']+)["\']'
        for match in re.finditer(django_pattern, content):
            endpoint = "/" + match.group(1)
            routes.append({
                "endpoint": endpoint,
                "methods": ['GET', 'POST'],  # Django defaults
                "framework": "django",
                "file": file_path
            })

        # Express.js patterns
        express_pattern = r'(?:app|router)\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']'
        for match in re.finditer(express_pattern, content):
            method = match.group(1).upper()
            endpoint = match.group(2)
            routes.append({
                "endpoint": endpoint,
                "methods": [method],
                "framework": "express",
                "file": file_path
            })

        # Spring Boot patterns
        spring_pattern = r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping\(["\']([^"\']+)["\']'
        for match in re.finditer(spring_pattern, content):
            endpoint = match.group(1)
            routes.append({
                "endpoint": endpoint,
                "methods": ['GET', 'POST', 'PUT', 'DELETE'],  # Spring defaults
                "framework": "spring",
                "file": file_path
            })

        return routes

    def _detect_frameworks(self) -> List[str]:
        """Detect web frameworks from package/dependency files"""

        frameworks = []

        # Python frameworks (requirements.txt, Pipfile, pyproject.toml)
        python_files = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py']
        for file_name in python_files:
            file_path = os.path.join(self.source_path, file_name)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read().lower()
                        if 'flask' in content:
                            frameworks.append('Flask')
                        if 'django' in content:
                            frameworks.append('Django')
                        if 'fastapi' in content:
                            frameworks.append('FastAPI')
                        if 'pyramid' in content:
                            frameworks.append('Pyramid')
                except Exception as e:
                    self.logger.debug(f"Failed to read {file_path}: {e}")

        # Node.js frameworks (package.json)
        package_json = os.path.join(self.source_path, 'package.json')
        if os.path.exists(package_json):
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                    if 'express' in deps:
                        frameworks.append('Express.js')
                    if 'fastify' in deps:
                        frameworks.append('Fastify')
                    if '@nestjs/core' in deps:
                        frameworks.append('NestJS')
                    if 'next' in deps:
                        frameworks.append('Next.js')
            except Exception as e:
                self.logger.debug(f"Failed to parse package.json: {e}")

        # Java frameworks (pom.xml, build.gradle)
        pom_xml = os.path.join(self.source_path, 'pom.xml')
        if os.path.exists(pom_xml):
            try:
                with open(pom_xml, 'r') as f:
                    content = f.read()
                    if 'spring-boot' in content:
                        frameworks.append('Spring Boot')
                    if 'spring-web' in content:
                        frameworks.append('Spring MVC')
            except Exception as e:
                self.logger.debug(f"Failed to read pom.xml: {e}")

        # Ruby frameworks (Gemfile)
        gemfile = os.path.join(self.source_path, 'Gemfile')
        if os.path.exists(gemfile):
            try:
                with open(gemfile, 'r') as f:
                    content = f.read()
                    if 'rails' in content:
                        frameworks.append('Ruby on Rails')
                    if 'sinatra' in content:
                        frameworks.append('Sinatra')
            except Exception as e:
                self.logger.debug(f"Failed to read Gemfile: {e}")

        return list(set(frameworks))  # Remove duplicates

    def _is_source_file(self, filename: str) -> bool:
        """Check if file is a source code file"""
        source_extensions = [
            '.py', '.js', '.ts', '.jsx', '.tsx',  # Python, JavaScript, TypeScript
            '.java', '.kt',  # Java, Kotlin
            '.rb', '.php',  # Ruby, PHP
            '.go', '.rs',  # Go, Rust
            '.cs', '.vb',  # C#, VB.NET
        ]
        return any(filename.endswith(ext) for ext in source_extensions)

    async def _ai_enhanced_analysis(self) -> None:
        """Use AI to enhance analysis with intelligent insights"""
        if not self.ai_client:
            return

        try:
            # TODO: Implement AI-enhanced analysis
            # - Correlate findings across tools
            # - Identify complex attack chains
            # - Prioritize findings based on exploitability
            # - Generate attack scenarios
            pass
        except Exception as e:
            self.logger.error(f"AI-enhanced analysis failed: {e}")

    def _is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a SAST tool is enabled in configuration"""
        return self.config.get("whitebox", {}).get("tools", {}).get(tool_name, {}).get("enabled", True)

    def _get_findings_count(self) -> int:
        """Get total count of all findings"""
        count = 0

        semgrep = self.findings["sast_results"].get("semgrep", {})
        if semgrep:
            count += semgrep.get("summary", {}).get("total", 0)

        trivy = self.findings["sast_results"].get("trivy", {})
        if trivy:
            count += trivy.get("summary", {}).get("total_vulns", 0)

        gitleaks = self.findings["sast_results"].get("gitleaks", {})
        if gitleaks:
            count += gitleaks.get("count", 0)

        trufflehog = self.findings["sast_results"].get("trufflehog", {})
        if trufflehog:
            count += trufflehog.get("count", 0)

        return count

    async def _execute_tool_async(self, cmd: List[str]) -> str:
        """Execute tool command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                self.logger.warning(f"Tool exited with code {process.returncode}: {stderr.decode()}")

            return stdout.decode()

        except Exception as e:
            self.logger.error(f"Failed to execute tool: {e}")
            return ""
