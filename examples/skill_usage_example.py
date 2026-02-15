#!/usr/bin/env python3
"""
Guardian AI Skills Usage Examples

Demonstrates how to use the new AI skills system
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.skill_loader import SkillLoader, get_skill_loader
from utils.skill_validator import SkillValidator, SkillDebugger


def example_1_basic_skill_loading():
    """Example 1: Basic skill loading"""
    print("\n" + "=" * 70)
    print("EXAMPLE 1: Basic Skill Loading")
    print("=" * 70)

    config = {
        "ai": {
            "model": "llama3.1:8b",
            "provider": "ollama"
        },
        "exploits": {
            "auto_exploit": False
        }
    }

    loader = get_skill_loader(config)

    # Get enabled skills for web testing
    web_skills = loader.get_enabled_skills(target_type="web")
    print(f"\nWeb Testing Skills: {web_skills}")

    # Get enabled skills for network testing
    network_skills = loader.get_enabled_skills(target_type="network")
    print(f"Network Testing Skills: {network_skills}")

    # Get enabled skills for OSINT
    osint_skills = loader.get_enabled_skills(workflow="osint")
    print(f"OSINT Skills: {osint_skills}")


def example_2_loading_prompts():
    """Example 2: Loading and using skill prompts"""
    print("\n" + "=" * 70)
    print("EXAMPLE 2: Loading and Using Prompts")
    print("=" * 70)

    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"}
    }

    loader = SkillLoader(config)

    # Load analyst prompts
    analyst_prompts = loader.load_skill_prompts("analyst")
    print(f"\nAnalyst prompts available: {list(analyst_prompts.keys())}")

    # Use a specific prompt
    interpret_prompt_template = analyst_prompts["ANALYST_INTERPRET_PROMPT"]

    # Fill in the template
    rendered_prompt = interpret_prompt_template.format(
        tool="nmap",
        target="192.168.1.1",
        command="nmap -sV 192.168.1.1",
        output="PORT    STATE SERVICE VERSION\n22/tcp  open  ssh     OpenSSH 7.4"
    )

    print(f"\nRendered prompt preview:")
    print(rendered_prompt[:200] + "...")


def example_3_osint_workflow():
    """Example 3: OSINT skill usage"""
    print("\n" + "=" * 70)
    print("EXAMPLE 3: OSINT Workflow")
    print("=" * 70)

    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"}
    }

    loader = SkillLoader(config)

    # Load OSINT prompts
    osint_prompts = loader.load_skill_prompts("osint")
    print(f"\nOSINT prompts available: {list(osint_prompts.keys())}")

    # Domain profiling
    domain_profile_prompt = osint_prompts["OSINT_DOMAIN_PROFILE_PROMPT"].format(
        domain="example.com"
    )
    print("\nDomain profiling prompt ready")

    # Subdomain discovery
    subdomain_prompt = osint_prompts["OSINT_SUBDOMAIN_DISCOVERY_PROMPT"].format(
        domain="example.com"
    )
    print("Subdomain discovery prompt ready")

    # Breach intelligence
    breach_prompt = osint_prompts["OSINT_BREACH_INTELLIGENCE_PROMPT"].format(
        domain="example.com",
        email_pattern="*@example.com"
    )
    print("Breach intelligence prompt ready")


def example_4_exploitation_workflow():
    """Example 4: Exploitation skill (with authorization)"""
    print("\n" + "=" * 70)
    print("EXAMPLE 4: Exploitation Workflow (Authorization Required)")
    print("=" * 70)

    # Config with exploitation enabled
    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"},
        "exploits": {
            "auto_exploit": True,  # Enable exploitation
            "auto_exploit_require_confirmation": True
        }
    }

    loader = SkillLoader(config)

    # Check if exploitation is enabled
    autonomous_skills = loader.get_enabled_skills(workflow="autonomous")

    if "exploitation" in autonomous_skills:
        print("\n✓ Exploitation skill is ENABLED (authorized)")

        # Load exploitation prompts
        exploit_prompts = loader.load_skill_prompts("exploitation")
        print(f"\nExploitation prompts: {list(exploit_prompts.keys())}")

        # Example: Exploit selection
        selection_prompt = exploit_prompts["EXPLOITATION_SELECTION_PROMPT"].format(
            vulnerability_title="Remote Code Execution in Apache Struts",
            severity="CRITICAL",
            cve="CVE-2017-5638",
            service="Apache Struts 2",
            version="2.3.5",
            target="192.168.1.100",
            context="Web application running on port 8080"
        )
        print("\nExploit selection prompt ready")
    else:
        print("\n✗ Exploitation skill is DISABLED (not authorized)")


def example_5_validation_workflow():
    """Example 5: Validation skill for false positive filtering"""
    print("\n" + "=" * 70)
    print("EXAMPLE 5: Validation Workflow")
    print("=" * 70)

    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"}
    }

    loader = SkillLoader(config)

    # Load validation prompts
    validation_prompts = loader.load_skill_prompts("validation")
    print(f"\nValidation prompts: {list(validation_prompts.keys())}")

    # Example: Validate a finding
    finding_assessment = validation_prompts["VALIDATION_FINDING_ASSESSMENT_PROMPT"].format(
        title="Missing X-Frame-Options Header",
        severity="MEDIUM",
        tool="nuclei",
        target="https://example.com",
        description="X-Frame-Options header is not set",
        evidence="HTTP/1.1 200 OK\nServer: nginx",
        related_findings="None",
        target_type="web",
        scan_config="default"
    )
    print("\nFinding assessment prompt ready")

    # Cross-tool correlation
    correlation_prompt = validation_prompts["VALIDATION_CROSS_TOOL_CORRELATION_PROMPT"].format(
        findings_list="[Finding 1 from nmap, Finding 2 from nuclei]",
        target="example.com"
    )
    print("Cross-tool correlation prompt ready")


def example_6_profile_settings():
    """Example 6: Getting profile settings"""
    print("\n" + "=" * 70)
    print("EXAMPLE 6: Profile Settings")
    print("=" * 70)

    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"}
    }

    loader = SkillLoader(config)

    # Get web profile settings
    web_settings = loader.get_profile_settings(target_type="web")
    print("\nWeb Profile Settings:")
    print(f"  Profile Name: {web_settings['profile_name']}")
    print(f"  Enabled Skills: {web_settings['enabled_skills']}")
    print(f"  Tool Preferences: {web_settings['tool_preferences']}")
    print(f"  Analyst Settings: {web_settings['analyst_settings']}")

    # Get network profile settings
    network_settings = loader.get_profile_settings(target_type="network")
    print("\nNetwork Profile Settings:")
    print(f"  Profile Name: {network_settings['profile_name']}")
    print(f"  Enabled Skills: {network_settings['enabled_skills']}")


def example_7_validation_and_debugging():
    """Example 7: Skill validation and debugging"""
    print("\n" + "=" * 70)
    print("EXAMPLE 7: Validation and Debugging")
    print("=" * 70)

    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"},
        "debug": True
    }

    # Validate all skills
    validator = SkillValidator(config)

    print("\nValidating analyst skill...")
    analyst_validation = validator.validate_skill("analyst")
    print(f"  Valid: {analyst_validation['valid']}")
    print(f"  Errors: {len(analyst_validation['errors'])}")
    print(f"  Warnings: {len(analyst_validation['warnings'])}")

    print("\nValidating exploitation skill...")
    exploit_validation = validator.validate_skill("exploitation")
    print(f"  Valid: {exploit_validation['valid']}")
    print(f"  Errors: {len(exploit_validation['errors'])}")
    print(f"  Warnings: {len(exploit_validation['warnings'])}")

    # Inspect a specific prompt
    debugger = SkillDebugger(config)
    inspection = debugger.inspect_prompt("analyst", "ANALYST_SYSTEM_PROMPT")
    print(f"\nPrompt Inspection:")
    print(f"  Length: {inspection['length']} chars")
    print(f"  Lines: {inspection['lines']}")
    print(f"  Placeholders: {inspection['placeholders']}")


def example_8_safe_mode():
    """Example 8: Safe mode (disables exploitation)"""
    print("\n" + "=" * 70)
    print("EXAMPLE 8: Safe Mode")
    print("=" * 70)

    config = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"},
        "exploits": {"auto_exploit": True}  # Even with this enabled...
    }

    loader = SkillLoader(config)

    # Normal mode
    normal_skills = loader.get_enabled_skills(workflow="autonomous", safe_mode=False)
    print(f"\nNormal Mode Skills: {normal_skills}")

    # Safe mode (disables exploitation and post-exploit)
    safe_skills = loader.get_enabled_skills(workflow="autonomous", safe_mode=True)
    print(f"Safe Mode Skills: {safe_skills}")

    print("\nNote: exploitation and post_exploit are disabled in safe mode")


def example_9_model_specific_loading():
    """Example 9: Model-specific prompt loading"""
    print("\n" + "=" * 70)
    print("EXAMPLE 9: Model-Specific Prompts")
    print("=" * 70)

    # Llama 3.1 8B (mid-size model)
    config_llama = {
        "ai": {"model": "llama3.1:8b", "provider": "ollama"}
    }
    loader_llama = SkillLoader(config_llama)
    print("\nLlama 3.1 8B:")
    print(f"  Prompt set: {loader_llama.skill_loader.get_prompt_set() if hasattr(loader_llama, 'skill_loader') else 'N/A'}")

    # DeepSeek R1 8B (reasoning-focused)
    config_deepseek = {
        "ai": {"model": "deepseek-r1:8b", "provider": "ollama"}
    }
    loader_deepseek = SkillLoader(config_deepseek)
    print("\nDeepSeek R1 8B:")
    print(f"  Optimized for: reasoning tasks (analyst, validation)")

    # Llama 3.2 3B (smaller model)
    config_small = {
        "ai": {"model": "llama3.2:3b", "provider": "ollama"}
    }
    loader_small = SkillLoader(config_small)
    autonomous_small = loader_small.get_enabled_skills(workflow="autonomous")
    print("\nLlama 3.2 3B:")
    print(f"  Enabled skills: {autonomous_small}")
    print("  Note: post_exploit disabled (too complex for 3B model)")


def main():
    """Run all examples"""
    print("\n" + "#" * 70)
    print("# Guardian AI Skills System - Usage Examples")
    print("#" * 70)

    examples = [
        example_1_basic_skill_loading,
        example_2_loading_prompts,
        example_3_osint_workflow,
        example_4_exploitation_workflow,
        example_5_validation_workflow,
        example_6_profile_settings,
        example_7_validation_and_debugging,
        example_8_safe_mode,
        example_9_model_specific_loading,
    ]

    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"\n✗ Example failed: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "#" * 70)
    print("# Examples Complete!")
    print("#" * 70 + "\n")


if __name__ == "__main__":
    main()
