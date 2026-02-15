"""
Skill validation and debugging framework

Validates AI agent skills for:
- Prompt template correctness
- Required placeholder presence
- Skill configuration validity
- Performance metrics
"""

import re
import time
from typing import Dict, Any, List, Set, Optional, Tuple
from pathlib import Path
import json

from utils.skill_loader import SkillLoader
from utils.logger import get_logger


class SkillValidator:
    """Validates AI agent skills and prompts"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.skill_loader = SkillLoader(config)
        self.validation_results: List[Dict[str, Any]] = []

    def validate_skill(self, skill_name: str) -> Dict[str, Any]:
        """
        Validate a single skill.

        Args:
            skill_name: Name of the skill to validate

        Returns:
            dict: Validation results
        """
        result = {
            "skill": skill_name,
            "valid": True,
            "errors": [],
            "warnings": [],
            "info": []
        }

        # Check if skill prompts exist
        try:
            prompts = self.skill_loader.load_skill_prompts(skill_name)
        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Failed to load skill: {e}")
            return result

        if not prompts:
            result["valid"] = False
            result["errors"].append("No prompts found for skill")
            return result

        result["info"].append(f"Found {len(prompts)} prompts")

        # Validate each prompt
        for prompt_name, prompt_text in prompts.items():
            prompt_validation = self._validate_prompt(prompt_name, prompt_text)

            result["errors"].extend(prompt_validation["errors"])
            result["warnings"].extend(prompt_validation["warnings"])
            result["info"].extend(prompt_validation["info"])

            if prompt_validation["errors"]:
                result["valid"] = False

        return result

    def _validate_prompt(self, prompt_name: str, prompt_text: str) -> Dict[str, Any]:
        """Validate a single prompt template"""
        result = {
            "errors": [],
            "warnings": [],
            "info": []
        }

        # Check for empty prompt
        if not prompt_text or not prompt_text.strip():
            result["errors"].append(f"{prompt_name}: Prompt is empty")
            return result

        # Extract placeholders
        placeholders = self._extract_placeholders(prompt_text)
        if placeholders:
            result["info"].append(f"{prompt_name}: Found placeholders: {', '.join(placeholders)}")

        # Check for common issues
        self._check_prompt_issues(prompt_name, prompt_text, result)

        # Validate prompt structure
        self._validate_prompt_structure(prompt_name, prompt_text, result)

        return result

    def _extract_placeholders(self, prompt_text: str) -> Set[str]:
        """Extract {placeholder} variables from prompt"""
        pattern = r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}'
        matches = re.findall(pattern, prompt_text)
        return set(matches)

    def _check_prompt_issues(self, prompt_name: str, prompt_text: str, result: Dict[str, Any]):
        """Check for common prompt issues"""
        # Check length
        if len(prompt_text) < 50:
            result["warnings"].append(f"{prompt_name}: Prompt is very short (<50 chars)")
        elif len(prompt_text) > 5000:
            result["warnings"].append(f"{prompt_name}: Prompt is very long (>5000 chars), may hit context limits")

        # Check for typos in common security terms
        common_typos = {
            "vulnerabilty": "vulnerability",
            "priveledge": "privilege",
            "authentification": "authentication",
            "exploitibility": "exploitability",
        }

        for typo, correct in common_typos.items():
            if typo in prompt_text.lower():
                result["warnings"].append(f"{prompt_name}: Possible typo '{typo}' (should be '{correct}')")

        # Check for inconsistent formatting
        if "{" in prompt_text and "}" not in prompt_text:
            result["errors"].append(f"{prompt_name}: Unmatched curly braces")

        # Check for TODO/FIXME comments
        if "TODO" in prompt_text or "FIXME" in prompt_text:
            result["warnings"].append(f"{prompt_name}: Contains TODO/FIXME comments")

    def _validate_prompt_structure(self, prompt_name: str, prompt_text: str, result: Dict[str, Any]):
        """Validate prompt structure and best practices"""
        # System prompts should define role and responsibilities
        if "SYSTEM_PROMPT" in prompt_name:
            if "responsibilities" not in prompt_text.lower() and "role" not in prompt_text.lower():
                result["warnings"].append(f"{prompt_name}: System prompt should define role/responsibilities")

        # Check for security-related prompts
        if any(keyword in prompt_name.lower() for keyword in ["exploit", "attack", "breach"]):
            # Should have authorization/safety warnings
            if "authorization" not in prompt_text.lower() and "authorized" not in prompt_text.lower():
                result["warnings"].append(f"{prompt_name}: Security-sensitive prompt missing authorization checks")

        # Check for output format specifications
        if "PROMPT" in prompt_name and "SYSTEM" not in prompt_name:
            # Should specify expected output format
            format_indicators = ["format:", "output:", "provide:", "return:"]
            if not any(indicator in prompt_text.lower() for indicator in format_indicators):
                result["warnings"].append(f"{prompt_name}: Prompt doesn't clearly specify output format")

    def validate_all_skills(self) -> Dict[str, Any]:
        """
        Validate all available skills.

        Returns:
            dict: Overall validation results
        """
        all_skills = self.skill_loader.get_all_available_skills()

        overall_result = {
            "total_skills": len(all_skills),
            "valid_skills": 0,
            "invalid_skills": 0,
            "skills": {}
        }

        for skill in all_skills:
            self.logger.info(f"Validating skill: {skill}")
            skill_result = self.validate_skill(skill)
            overall_result["skills"][skill] = skill_result

            if skill_result["valid"]:
                overall_result["valid_skills"] += 1
            else:
                overall_result["invalid_skills"] += 1

        return overall_result

    def validate_skill_config(self) -> Dict[str, Any]:
        """Validate the skills.yaml configuration"""
        result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "info": []
        }

        skill_config = self.skill_loader.skill_config

        # Check required sections
        required_sections = ["global", "skills", "profiles"]
        for section in required_sections:
            if section not in skill_config:
                result["errors"].append(f"Missing required section: {section}")
                result["valid"] = False

        # Validate skills section
        if "skills" in skill_config:
            skills_section = skill_config["skills"]
            for skill_name, skill_config_data in skills_section.items():
                # Check for required fields
                if "enabled" not in skill_config_data:
                    result["warnings"].append(f"Skill '{skill_name}' missing 'enabled' field")

                # Check if skill prompts exist
                if not self.skill_loader.is_skill_available(skill_name):
                    result["warnings"].append(f"Skill '{skill_name}' configured but prompts not found")

        # Validate profiles section
        if "profiles" in skill_config:
            profiles_section = skill_config["profiles"]
            for profile_name, profile_config in profiles_section.items():
                if "skills" not in profile_config:
                    result["warnings"].append(f"Profile '{profile_name}' missing 'skills' list")

                # Check if referenced skills exist
                for skill in profile_config.get("skills", []):
                    if skill not in skill_config.get("skills", {}):
                        result["warnings"].append(f"Profile '{profile_name}' references unknown skill '{skill}'")

        return result

    def print_validation_report(self, validation_results: Dict[str, Any]):
        """Print a human-readable validation report"""
        print("\n" + "=" * 70)
        print("SKILL VALIDATION REPORT")
        print("=" * 70)

        if "skills" in validation_results:
            # All skills validation
            print(f"\nTotal Skills: {validation_results['total_skills']}")
            print(f"Valid: {validation_results['valid_skills']}")
            print(f"Invalid: {validation_results['invalid_skills']}")
            print()

            for skill_name, skill_result in validation_results["skills"].items():
                status = "✓ VALID" if skill_result["valid"] else "✗ INVALID"
                print(f"\n{skill_name}: {status}")

                if skill_result["errors"]:
                    print("  Errors:")
                    for error in skill_result["errors"]:
                        print(f"    - {error}")

                if skill_result["warnings"]:
                    print("  Warnings:")
                    for warning in skill_result["warnings"]:
                        print(f"    - {warning}")

                if skill_result["info"] and self.config.get("debug", False):
                    print("  Info:")
                    for info in skill_result["info"]:
                        print(f"    - {info}")
        else:
            # Config validation
            status = "✓ VALID" if validation_results["valid"] else "✗ INVALID"
            print(f"\nConfiguration: {status}")

            if validation_results["errors"]:
                print("\nErrors:")
                for error in validation_results["errors"]:
                    print(f"  - {error}")

            if validation_results["warnings"]:
                print("\nWarnings:")
                for warning in validation_results["warnings"]:
                    print(f"  - {warning}")

        print("\n" + "=" * 70 + "\n")


class SkillDebugger:
    """Debug and profile AI agent skills"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.skill_loader = SkillLoader(config)
        self.performance_metrics: Dict[str, List[float]] = {}

    def test_skill_prompt(
        self,
        skill_name: str,
        prompt_name: str,
        test_variables: Dict[str, str]
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Test a skill prompt with sample variables.

        Args:
            skill_name: Name of the skill
            prompt_name: Name of the prompt constant
            test_variables: Dictionary of placeholder values

        Returns:
            tuple: (rendered_prompt, debug_info)
        """
        debug_info = {
            "skill": skill_name,
            "prompt": prompt_name,
            "variables": test_variables,
            "success": False,
            "errors": []
        }

        try:
            prompt_template = self.skill_loader.get_skill_prompt(skill_name, prompt_name)
        except Exception as e:
            debug_info["errors"].append(f"Failed to load prompt: {e}")
            return "", debug_info

        # Extract expected placeholders
        expected_placeholders = self._extract_placeholders(prompt_template)
        provided_placeholders = set(test_variables.keys())

        # Check for missing or extra placeholders
        missing = expected_placeholders - provided_placeholders
        extra = provided_placeholders - expected_placeholders

        if missing:
            debug_info["errors"].append(f"Missing placeholders: {missing}")
        if extra:
            debug_info["warnings"] = [f"Extra variables (will be ignored): {extra}"]

        # Try to render the prompt
        try:
            rendered_prompt = prompt_template.format(**test_variables)
            debug_info["success"] = True
            debug_info["rendered_length"] = len(rendered_prompt)
        except KeyError as e:
            debug_info["errors"].append(f"Missing required variable: {e}")
            rendered_prompt = ""
        except Exception as e:
            debug_info["errors"].append(f"Rendering error: {e}")
            rendered_prompt = ""

        return rendered_prompt, debug_info

    def _extract_placeholders(self, prompt_text: str) -> Set[str]:
        """Extract {placeholder} variables from prompt"""
        pattern = r'\{([a-zA-Z_][a-zA-Z0-9_]*)\}'
        matches = re.findall(pattern, prompt_text)
        return set(matches)

    def profile_skill_loading(self, skill_name: str, iterations: int = 100) -> Dict[str, Any]:
        """
        Profile skill loading performance.

        Args:
            skill_name: Name of the skill to profile
            iterations: Number of iterations to average

        Returns:
            dict: Performance metrics
        """
        load_times = []

        for _ in range(iterations):
            # Clear cache
            self.skill_loader._skills_cache.clear()

            start_time = time.time()
            self.skill_loader.load_skill_prompts(skill_name)
            end_time = time.time()

            load_times.append((end_time - start_time) * 1000)  # Convert to ms

        return {
            "skill": skill_name,
            "iterations": iterations,
            "avg_load_time_ms": sum(load_times) / len(load_times),
            "min_load_time_ms": min(load_times),
            "max_load_time_ms": max(load_times)
        }

    def inspect_prompt(self, skill_name: str, prompt_name: str) -> Dict[str, Any]:
        """
        Detailed inspection of a prompt template.

        Returns:
            dict: Prompt analysis
        """
        try:
            prompt_text = self.skill_loader.get_skill_prompt(skill_name, prompt_name)
        except Exception as e:
            return {"error": f"Failed to load prompt: {e}"}

        placeholders = self._extract_placeholders(prompt_text)

        # Analyze prompt structure
        lines = prompt_text.split('\n')
        sections = []
        current_section = None

        for line in lines:
            # Detect section headers (ALL CAPS followed by colon)
            if re.match(r'^[A-Z][A-Z\s]+:', line.strip()):
                current_section = line.strip()
                sections.append(current_section)

        return {
            "skill": skill_name,
            "prompt": prompt_name,
            "length": len(prompt_text),
            "lines": len(lines),
            "placeholders": list(placeholders),
            "sections": sections,
            "preview": prompt_text[:200] + "..." if len(prompt_text) > 200 else prompt_text
        }

    def export_skill_documentation(self, output_file: str = "docs/SKILLS_REFERENCE.md"):
        """Export documentation for all skills and their prompts"""
        all_skills = self.skill_loader.get_all_available_skills()

        doc_lines = [
            "# Guardian AI Skills Reference\n",
            "Auto-generated documentation for all AI agent skills.\n",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
            "\n---\n"
        ]

        for skill in all_skills:
            doc_lines.append(f"\n## {skill.upper()}\n")

            try:
                prompts = self.skill_loader.load_skill_prompts(skill)
            except Exception as e:
                doc_lines.append(f"\n*Error loading prompts: {e}*\n")
                continue

            for prompt_name, prompt_text in prompts.items():
                doc_lines.append(f"\n### {prompt_name}\n")

                # Extract placeholders
                placeholders = self._extract_placeholders(prompt_text)
                if placeholders:
                    doc_lines.append("\n**Required Variables:**\n")
                    for placeholder in sorted(placeholders):
                        doc_lines.append(f"- `{placeholder}`\n")

                # Show preview
                preview = prompt_text[:300] + "..." if len(prompt_text) > 300 else prompt_text
                doc_lines.append("\n**Preview:**\n")
                doc_lines.append("```\n")
                doc_lines.append(preview)
                doc_lines.append("\n```\n")

        # Write to file
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            f.writelines(doc_lines)

        self.logger.info(f"Exported skill documentation to {output_file}")
        return output_file


# CLI for validation and debugging
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Validate and debug Guardian AI skills")
    parser.add_argument("--validate", action="store_true", help="Validate all skills")
    parser.add_argument("--validate-config", action="store_true", help="Validate skills.yaml config")
    parser.add_argument("--inspect", type=str, metavar="SKILL:PROMPT", help="Inspect a specific prompt")
    parser.add_argument("--profile", type=str, metavar="SKILL", help="Profile skill loading performance")
    parser.add_argument("--export-docs", action="store_true", help="Export skill documentation")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Mock config
    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"},
        "debug": args.verbose
    }

    if args.validate:
        validator = SkillValidator(config)
        results = validator.validate_all_skills()
        validator.print_validation_report(results)
        sys.exit(0 if results["invalid_skills"] == 0 else 1)

    elif args.validate_config:
        validator = SkillValidator(config)
        results = validator.validate_skill_config()
        validator.print_validation_report(results)
        sys.exit(0 if results["valid"] else 1)

    elif args.inspect:
        if ":" not in args.inspect:
            print("Error: --inspect requires format SKILL:PROMPT")
            sys.exit(1)

        skill, prompt = args.inspect.split(":", 1)
        debugger = SkillDebugger(config)
        inspection = debugger.inspect_prompt(skill, prompt)

        print(json.dumps(inspection, indent=2))

    elif args.profile:
        debugger = SkillDebugger(config)
        metrics = debugger.profile_skill_loading(args.profile)
        print(json.dumps(metrics, indent=2))

    elif args.export_docs:
        debugger = SkillDebugger(config)
        output_file = debugger.export_skill_documentation()
        print(f"Documentation exported to: {output_file}")

    else:
        parser.print_help()
