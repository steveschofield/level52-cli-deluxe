"""
Dynamic skill loader for Guardian AI agents

Loads appropriate AI agent skills based on:
- Target type (web, network, api, etc.)
- Engagement profile
- Model capabilities
- Authorization level
"""

import importlib
import logging
from typing import Dict, Any, List, Optional, Set
from pathlib import Path
import yaml

from utils.logger import get_logger


class SkillLoader:
    """Manages dynamic loading of AI agent skills based on configuration"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)
        self.skill_config = self._load_skill_config()
        self._skills_cache: Dict[str, Dict[str, str]] = {}

    def _load_skill_config(self) -> Dict[str, Any]:
        """Load skill configuration from skills.yaml"""
        skill_config_path = Path("config/skills.yaml")

        if not skill_config_path.exists():
            self.logger.warning(f"Skills config not found at {skill_config_path}, using defaults")
            return self._get_default_skill_config()

        try:
            with open(skill_config_path, 'r') as f:
                skill_config = yaml.safe_load(f)
                self.logger.info(f"Loaded skill configuration from {skill_config_path}")
                return skill_config
        except Exception as e:
            self.logger.error(f"Failed to load skills config: {e}, using defaults")
            return self._get_default_skill_config()

    def _get_default_skill_config(self) -> Dict[str, Any]:
        """Default skill configuration if skills.yaml not found"""
        return {
            "global": {"ai_enabled": True},
            "skills": {
                "analyst": {"enabled": True, "required_for": ["all"]},
                "planner": {"enabled": True, "required_for": ["all"]},
                "reporter": {"enabled": True, "required_for": ["all"]},
                "tool_selector": {"enabled": True, "required_for": ["all"]},
            },
            "profiles": {
                "default": {
                    "skills": ["analyst", "planner", "reporter", "tool_selector"]
                }
            }
        }

    def get_target_profile(self, target_type: Optional[str] = None, workflow: Optional[str] = None) -> str:
        """
        Determine which profile to use based on target type or workflow.

        Args:
            target_type: Type of target (web, network, api, etc.)
            workflow: Workflow name (recon, autonomous, etc.)

        Returns:
            str: Profile name to use
        """
        # Priority: workflow > target_type > default
        if workflow and workflow in self.skill_config.get("profiles", {}):
            self.logger.debug(f"Using profile from workflow: {workflow}")
            return workflow

        if target_type and target_type in self.skill_config.get("profiles", {}):
            self.logger.debug(f"Using profile from target_type: {target_type}")
            return target_type

        self.logger.debug("Using default profile")
        return "default"

    def get_enabled_skills(
        self,
        target_type: Optional[str] = None,
        workflow: Optional[str] = None,
        safe_mode: bool = False,
        stealth_mode: bool = False,
    ) -> List[str]:
        """
        Get list of enabled skills for the current engagement.

        Args:
            target_type: Type of target (web, network, api)
            workflow: Workflow name
            safe_mode: Whether safe mode is enabled
            stealth_mode: Whether stealth mode is enabled

        Returns:
            List of enabled skill names
        """
        profile = self.get_target_profile(target_type, workflow)
        profile_config = self.skill_config.get("profiles", {}).get(profile, {})

        # Get base skills from profile
        enabled_skills = profile_config.get("skills", [])

        # Check global skill settings
        global_skills = self.skill_config.get("skills", {})
        filtered_skills = []

        for skill in enabled_skills:
            skill_config = global_skills.get(skill, {})

            # Skip if globally disabled
            if not skill_config.get("enabled", True):
                self.logger.debug(f"Skill '{skill}' is globally disabled")
                continue

            # Skip if requires authorization and not granted
            if skill_config.get("requires_authorization", False):
                # Check if authorization is granted in config
                auto_exploit = self.config.get("exploits", {}).get("auto_exploit", False)
                if not auto_exploit and skill in ["exploitation", "post_exploit"]:
                    self.logger.debug(f"Skill '{skill}' requires authorization, skipping")
                    continue

            filtered_skills.append(skill)

        # Apply modifiers
        if safe_mode:
            disabled_in_safe_mode = self.skill_config.get("modifiers", {}).get(
                "safe_mode", {}
            ).get("disabled_skills", [])
            filtered_skills = [s for s in filtered_skills if s not in disabled_in_safe_mode]
            self.logger.info(f"Safe mode enabled, disabled skills: {disabled_in_safe_mode}")

        # Check model capabilities
        model_name = self.config.get("ai", {}).get("model", "").lower()
        model_optimizations = self.skill_config.get("model_optimizations", {})

        for model_key, model_config in model_optimizations.items():
            if model_key.lower() in model_name:
                disabled_for_model = model_config.get("disabled_skills", [])
                filtered_skills = [s for s in filtered_skills if s not in disabled_for_model]
                if disabled_for_model:
                    self.logger.info(f"Model {model_name} has disabled skills: {disabled_for_model}")
                break

        self.logger.info(f"Enabled skills for profile '{profile}': {filtered_skills}")
        return filtered_skills

    def load_skill_prompts(self, skill_name: str) -> Dict[str, str]:
        """
        Load prompt templates for a specific skill.

        Args:
            skill_name: Name of the skill (analyst, planner, exploitation, etc.)

        Returns:
            dict: All prompt constants for this skill
        """
        # Return cached if available
        if skill_name in self._skills_cache:
            return self._skills_cache[skill_name]

        # Get model-specific prompt set (llama3_1_8b, deepseek_r1_8b, etc.)
        from utils.prompt_loader import PromptLoader
        prompt_loader = PromptLoader(self.config)
        prompt_set = prompt_loader.get_prompt_set()

        # Try to load model-specific skill prompts first
        prompts = {}
        module_loaded = False

        if prompt_set != "default":
            # Try: ai.prompt_templates.llama3_1_8b.exploitation
            try:
                module = importlib.import_module(f"ai.prompt_templates.{prompt_set}.{skill_name}")
                prompts = self._extract_prompts_from_module(module)
                module_loaded = True
                self.logger.info(f"✓ Loaded '{skill_name}' skill (optimized for {prompt_set})")
            except (ImportError, ModuleNotFoundError):
                self.logger.debug(f"No {skill_name} prompts in {prompt_set} set, trying default")

        # Fall back to default prompts
        if not module_loaded:
            try:
                module = importlib.import_module(f"ai.prompt_templates.{skill_name}")
                prompts = self._extract_prompts_from_module(module)
                self.logger.info(f"✓ Loaded '{skill_name}' skill (default prompts)")
            except (ImportError, ModuleNotFoundError):
                self.logger.warning(f"✗ Skill '{skill_name}' prompts not found")
                return {}

        # Cache the results
        self._skills_cache[skill_name] = prompts
        return prompts

    def _extract_prompts_from_module(self, module) -> Dict[str, str]:
        """Extract all prompt constants from a module"""
        prompts = {}
        for attr in dir(module):
            if attr.isupper() and "PROMPT" in attr:
                prompts[attr] = getattr(module, attr)
        return prompts

    def get_skill_prompt(self, skill_name: str, prompt_name: str) -> str:
        """
        Get a specific prompt from a skill.

        Args:
            skill_name: Name of the skill (analyst, exploitation, etc.)
            prompt_name: Name of the prompt constant (EXPLOITATION_SELECTION_PROMPT, etc.)

        Returns:
            str: The prompt text

        Raises:
            KeyError: If skill or prompt not found
        """
        skill_prompts = self.load_skill_prompts(skill_name)

        if prompt_name not in skill_prompts:
            raise KeyError(f"Prompt '{prompt_name}' not found in skill '{skill_name}'")

        return skill_prompts[prompt_name]

    def get_profile_settings(
        self,
        target_type: Optional[str] = None,
        workflow: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get all settings for the current profile.

        Returns:
            dict: Profile settings including tool preferences, analyst settings, etc.
        """
        profile = self.get_target_profile(target_type, workflow)
        profile_config = self.skill_config.get("profiles", {}).get(profile, {})

        return {
            "profile_name": profile,
            "enabled_skills": self.get_enabled_skills(target_type, workflow),
            "tool_preferences": profile_config.get("tool_preferences", {}),
            "analyst_settings": profile_config.get("analyst_settings", {}),
            "planner_settings": profile_config.get("planner_settings", {}),
        }

    def is_skill_available(self, skill_name: str) -> bool:
        """Check if a skill is available (has prompts loaded)"""
        try:
            prompts = self.load_skill_prompts(skill_name)
            return len(prompts) > 0
        except Exception:
            return False

    def get_all_available_skills(self) -> List[str]:
        """Get list of all skills that have prompts available"""
        available_skills = []
        skill_names = [
            "analyst", "planner", "reporter", "tool_selector",
            "exploitation", "osint", "validation", "post_exploit"
        ]

        for skill in skill_names:
            if self.is_skill_available(skill):
                available_skills.append(skill)

        return available_skills

    def log_active_skills(self, target_type: Optional[str] = None, workflow: Optional[str] = None):
        """Log which skills are active for this engagement"""
        profile = self.get_target_profile(target_type, workflow)
        enabled_skills = self.get_enabled_skills(target_type, workflow)

        self.logger.info("")
        self.logger.info("┌─────────────────────────────────────────────────┐")
        self.logger.info("│         🧠 AI Skills Configuration              │")
        self.logger.info("└─────────────────────────────────────────────────┘")
        self.logger.info(f"  Profile: {profile}")
        self.logger.info(f"  Active Skills ({len(enabled_skills)}): {', '.join(enabled_skills)}")

        settings = self.get_profile_settings(target_type, workflow)

        # Show key settings if available
        if settings.get("analyst_settings", {}).get("focus_areas"):
            focus = settings["analyst_settings"]["focus_areas"]
            self.logger.info(f"  Focus Areas: {', '.join(focus[:3])}{'...' if len(focus) > 3 else ''}")

        self.logger.info("─────────────────────────────────────────────────")
        self.logger.info("")


def get_skill_loader(config: Dict[str, Any]) -> SkillLoader:
    """
    Convenience function to get a skill loader instance.

    Args:
        config: Guardian configuration dictionary

    Returns:
        SkillLoader: Configured skill loader
    """
    return SkillLoader(config)


# Example usage and testing
if __name__ == "__main__":
    # Test the skill loader
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    # Mock config
    config = {
        "ai": {
            "model": "llama3.1:8b",
            "provider": "ollama"
        },
        "exploits": {
            "auto_exploit": False
        }
    }

    loader = SkillLoader(config)

    # Test profile selection
    print("\n=== Testing Profile Selection ===")
    print(f"Web profile: {loader.get_target_profile(target_type='web')}")
    print(f"Network profile: {loader.get_target_profile(target_type='network')}")
    print(f"Recon workflow: {loader.get_target_profile(workflow='recon')}")

    # Test enabled skills
    print("\n=== Testing Enabled Skills ===")
    print(f"Web skills: {loader.get_enabled_skills(target_type='web')}")
    print(f"Network skills: {loader.get_enabled_skills(target_type='network')}")
    print(f"OSINT skills: {loader.get_enabled_skills(workflow='osint')}")

    # Test safe mode
    print("\n=== Testing Safe Mode ===")
    print(f"Autonomous (safe): {loader.get_enabled_skills(workflow='autonomous', safe_mode=True)}")
    print(f"Autonomous (unsafe): {loader.get_enabled_skills(workflow='autonomous', safe_mode=False)}")

    # Test skill prompt loading
    print("\n=== Testing Skill Prompt Loading ===")
    try:
        analyst_prompts = loader.load_skill_prompts("analyst")
        print(f"Analyst prompts loaded: {list(analyst_prompts.keys())}")
    except Exception as e:
        print(f"Failed to load analyst prompts: {e}")

    try:
        exploitation_prompts = loader.load_skill_prompts("exploitation")
        print(f"Exploitation prompts loaded: {list(exploitation_prompts.keys())}")
    except Exception as e:
        print(f"Failed to load exploitation prompts: {e}")

    # Test available skills
    print("\n=== Available Skills ===")
    print(f"All available: {loader.get_all_available_skills()}")

    # Test profile settings
    print("\n=== Profile Settings ===")
    settings = loader.get_profile_settings(target_type="web")
    print(f"Web profile settings: {settings}")
