# Guardian AI Skills - Quick Start

Get started with Guardian's advanced AI skills system in 5 minutes.

## What Was Added

### 🎯 New Specialized Skills

1. **Exploitation Agent** (`ai/prompt_templates/exploitation.py`)
   - Exploit selection and validation
   - Metasploit integration
   - Safe exploitation strategies
   - Post-exploitation planning

2. **OSINT Agent** (`ai/prompt_templates/osint.py`)
   - Domain profiling
   - Subdomain discovery
   - Breach intelligence
   - People enumeration
   - Technology profiling

3. **Validation Agent** (`ai/prompt_templates/validation.py`)
   - False positive filtering
   - Cross-tool correlation
   - Severity validation
   - Exploitability verification

4. **Post-Exploitation Agent** (`ai/prompt_templates/post_exploit.py`)
   - System enumeration
   - Privilege escalation
   - Credential harvesting
   - Lateral movement
   - Persistence (authorized)
   - Data exfiltration (authorized)

### 🔧 Configuration System

- **Skills Config**: `config/skills.yaml`
  - Target-specific profiles (web, network, api, osint, etc.)
  - Model-specific optimizations
  - Safety modifiers (safe_mode, stealth_mode)
  - Authorization requirements

- **Skill Loader**: `utils/skill_loader.py`
  - Dynamic skill loading based on target type
  - Model capability detection
  - Authorization enforcement

### ✓ Validation Framework

- **Skill Validator**: `utils/skill_validator.py`
  - Validates all prompts for correctness
  - Checks configuration validity
  - Performance profiling
  - Documentation export

## Quick Start

### 1. Validate Installation

```bash
# Validate all skills
python -m utils.skill_validator --validate

# Validate configuration
python -m utils.skill_validator --validate-config
```

### 2. View Available Skills

```python
from utils.skill_loader import SkillLoader

config = {"ai": {"model": "llama3.1:8b", "provider": "ollama"}}
loader = SkillLoader(config)

# Get all available skills
print(loader.get_all_available_skills())
# ['analyst', 'planner', 'reporter', 'tool_selector',
#  'exploitation', 'osint', 'validation', 'post_exploit']
```

### 3. Use a Profile

```python
# Web application testing
web_skills = loader.get_enabled_skills(target_type="web")
# ['analyst', 'planner', 'reporter', 'tool_selector', 'validation']

# OSINT reconnaissance
osint_skills = loader.get_enabled_skills(workflow="osint")
# ['osint', 'analyst', 'reporter', 'validation']

# Full autonomous testing
auto_skills = loader.get_enabled_skills(workflow="autonomous")
# ['analyst', 'planner', 'reporter', 'tool_selector',
#  'validation', 'exploitation', 'post_exploit', 'osint']
```

### 4. Load Skill Prompts

```python
# Load OSINT prompts
osint_prompts = loader.load_skill_prompts("osint")

# Use domain profiling
domain_prompt = osint_prompts["OSINT_DOMAIN_PROFILE_PROMPT"].format(
    domain="example.com"
)

# Load validation prompts
validation_prompts = loader.load_skill_prompts("validation")

# Validate a finding
assessment_prompt = validation_prompts["VALIDATION_FINDING_ASSESSMENT_PROMPT"].format(
    title="Missing Security Header",
    severity="LOW",
    tool="nuclei",
    target="example.com",
    description="...",
    evidence="...",
    related_findings="...",
    target_type="web",
    scan_config="default"
)
```

## Common Use Cases

### Use Case 1: Web App Testing with Validation

```yaml
# In guardian.yaml or CLI args
target_type: web
```

```python
loader = SkillLoader(config)
enabled = loader.get_enabled_skills(target_type="web")
# Automatically includes validation skill

# Load analyst and validation
analyst_prompts = loader.load_skill_prompts("analyst")
validation_prompts = loader.load_skill_prompts("validation")

# 1. Analyze tool output
# 2. Validate findings
# 3. Filter false positives
```

### Use Case 2: OSINT-Only Reconnaissance

```python
enabled = loader.get_enabled_skills(workflow="osint")

osint_prompts = loader.load_skill_prompts("osint")

# Subdomain discovery (passive)
subdomain_prompt = osint_prompts["OSINT_SUBDOMAIN_DISCOVERY_PROMPT"]

# Breach intelligence
breach_prompt = osint_prompts["OSINT_BREACH_INTELLIGENCE_PROMPT"]

# Technology profiling
tech_prompt = osint_prompts["OSINT_TECHNOLOGY_PROFILING_PROMPT"]
```

### Use Case 3: Authorized Exploitation

```yaml
# In config/guardian.yaml
exploits:
  auto_exploit: true
  auto_exploit_require_confirmation: true
```

```python
config = {
    "ai": {"model": "llama3.1:8b"},
    "exploits": {"auto_exploit": True}
}

loader = SkillLoader(config)
enabled = loader.get_enabled_skills(workflow="autonomous")
# Now includes 'exploitation' and 'post_exploit'

exploit_prompts = loader.load_skill_prompts("exploitation")

# Select exploit
selection_prompt = exploit_prompts["EXPLOITATION_SELECTION_PROMPT"].format(
    vulnerability_title="...",
    severity="CRITICAL",
    cve="CVE-XXXX-XXXX",
    # ... other fields
)

# Post-exploitation
post_exploit_prompts = loader.load_skill_prompts("post_exploit")
enum_prompt = post_exploit_prompts["POST_EXPLOIT_ENUMERATION_PROMPT"]
```

### Use Case 4: Safe Mode (No Exploitation)

```python
# Even with exploitation enabled in config
config = {
    "exploits": {"auto_exploit": True}
}

loader = SkillLoader(config)

# Safe mode disables dangerous skills
safe_skills = loader.get_enabled_skills(
    workflow="autonomous",
    safe_mode=True  # Disables exploitation, post_exploit
)
# ['analyst', 'planner', 'reporter', 'tool_selector', 'validation', 'osint']
```

## Configuration

### Edit `config/skills.yaml`

```yaml
# Enable/disable skills globally
skills:
  exploitation:
    enabled: true
    requires_authorization: true

  osint:
    enabled: true
    safe_mode_compatible: true

# Define target profiles
profiles:
  web:
    skills:
      - analyst
      - validation
      - tool_selector

    analyst_settings:
      focus_areas:
        - xss
        - sqli
```

## Validation Commands

```bash
# Validate all skills
python -m utils.skill_validator --validate

# Validate configuration
python -m utils.skill_validator --validate-config

# Inspect a specific prompt
python -m utils.skill_validator --inspect osint:OSINT_DOMAIN_PROFILE_PROMPT

# Profile performance
python -m utils.skill_validator --profile analyst

# Export documentation
python -m utils.skill_validator --export-docs
```

## Testing

Run the examples:

```bash
python examples/skill_usage_example.py
```

Output shows:
- Basic skill loading
- Prompt rendering
- OSINT workflows
- Exploitation workflows
- Validation workflows
- Profile settings
- Safe mode
- Model-specific loading

## Integration with Guardian

### Option 1: Integrate into Core Workflow

```python
# In core/workflow.py or similar
from utils.skill_loader import SkillLoader

def run_workflow(config, target, workflow_name):
    loader = SkillLoader(config)

    # Get enabled skills for this workflow
    enabled_skills = loader.get_enabled_skills(workflow=workflow_name)

    # Load skills
    for skill in enabled_skills:
        prompts = loader.load_skill_prompts(skill)
        # Use prompts with LLM...
```

### Option 2: Use in Existing Agents

```python
# In ai/agent.py or similar
from utils.skill_loader import SkillLoader

class GuardianAgent:
    def __init__(self, config):
        self.skill_loader = SkillLoader(config)

    def analyze_finding(self, finding):
        # Load validation skill
        validation_prompts = self.skill_loader.load_skill_prompts("validation")

        # Use validation prompt
        prompt = validation_prompts["VALIDATION_FINDING_ASSESSMENT_PROMPT"].format(
            **finding
        )

        # Send to LLM
        response = self.llm.query(prompt)
        return response
```

## Next Steps

1. **Read Full Documentation**: `docs/AI_SKILLS_GUIDE.md`
2. **Review Skills**: Explore `ai/prompt_templates/`
3. **Customize Configuration**: Edit `config/skills.yaml`
4. **Run Examples**: `python examples/skill_usage_example.py`
5. **Validate Setup**: `python -m utils.skill_validator --validate`

## File Reference

```
level52-cli-deluxe/
├── ai/prompt_templates/
│   ├── exploitation.py      # NEW: Exploitation agent
│   ├── osint.py             # NEW: OSINT agent
│   ├── validation.py        # NEW: Validation agent
│   ├── post_exploit.py      # NEW: Post-exploitation agent
│   ├── analyst.py           # Existing
│   ├── planner.py           # Existing
│   ├── reporter.py          # Existing
│   └── tool_selector.py     # Existing
│
├── config/
│   └── skills.yaml          # NEW: Skills configuration
│
├── utils/
│   ├── skill_loader.py      # NEW: Dynamic skill loading
│   ├── skill_validator.py   # NEW: Validation framework
│   └── prompt_loader.py     # Existing (enhanced)
│
├── docs/
│   ├── AI_SKILLS_GUIDE.md   # NEW: Complete guide
│   └── SKILLS_QUICK_START.md # NEW: This file
│
└── examples/
    └── skill_usage_example.py # NEW: Usage examples
```

## Support

- **Full Guide**: `docs/AI_SKILLS_GUIDE.md`
- **Examples**: `examples/skill_usage_example.py`
- **Validation**: `python -m utils.skill_validator --help`
- **Issues**: Check validation output for errors

---

**You're ready to use Guardian's advanced AI skills system!**
