# Guardian AI Skills System

Complete guide to Guardian's advanced AI agent skill system.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Available Skills](#available-skills)
4. [Configuration](#configuration)
5. [Usage Examples](#usage-examples)
6. [Creating Custom Skills](#creating-custom-skills)
7. [Validation & Debugging](#validation--debugging)
8. [Best Practices](#best-practices)

---

## Overview

Guardian's AI Skills System provides specialized AI agents for different penetration testing tasks. Each "skill" is a focused AI agent with domain-specific knowledge and prompt templates.

### Key Features

- **🎯 Specialized Agents**: Focused AI agents for analysis, exploitation, OSINT, validation
- **🔧 Configurable**: Load different skills based on target type and engagement
- **🛡️ Safe**: Built-in safety checks and authorization requirements
- **📊 Validated**: Automatic validation of prompts and configuration
- **🚀 Performance**: Optimized prompts for different model sizes

---

## Architecture

```
Guardian AI Skills Architecture

┌─────────────────────────────────────────────────────────────┐
│                     Configuration Layer                      │
│  ┌───────────────┐  ┌──────────────┐  ┌──────────────────┐ │
│  │ skills.yaml   │  │ guardian.yaml│  │ Model Detection  │ │
│  │ (skill config)│  │ (AI provider)│  │ (llama/deepseek) │ │
│  └───────┬───────┘  └──────┬───────┘  └────────┬─────────┘ │
└──────────┼──────────────────┼───────────────────┼───────────┘
           │                  │                   │
           v                  v                   v
┌─────────────────────────────────────────────────────────────┐
│                      Skill Loader                            │
│  • Loads prompts based on profile (web, network, recon)     │
│  • Applies model-specific optimizations                     │
│  • Enforces authorization requirements                      │
│  • Caches loaded skills for performance                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
        v                             v
┌───────────────────┐       ┌──────────────────┐
│  Core Skills      │       │ Advanced Skills  │
│  • Analyst        │       │ • Exploitation   │
│  • Planner        │       │ • OSINT          │
│  • Reporter       │       │ • Validation     │
│  • Tool Selector  │       │ • Post-Exploit   │
└───────────────────┘       └──────────────────┘
        │                             │
        └──────────────┬──────────────┘
                       │
                       v
        ┌──────────────────────────────┐
        │    LLM Provider (AI Engine)   │
        │  • Ollama                     │
        │  • OpenRouter                 │
        │  • Google Gemini              │
        │  • Hugging Face               │
        └───────────────────────────────┘
```

### Components

1. **Skill Templates** (`ai/prompt_templates/`)
   - Python files with prompt constants
   - Organized by skill (analyst.py, exploitation.py, etc.)
   - Model-specific variants (llama3_1_8b/, deepseek_r1_8b/)

2. **Skill Loader** (`utils/skill_loader.py`)
   - Dynamically loads skills based on configuration
   - Handles model-specific optimizations
   - Manages skill caching

3. **Configuration** (`config/skills.yaml`)
   - Global skill settings
   - Target-specific profiles
   - Authorization requirements

4. **Validator** (`utils/skill_validator.py`)
   - Validates prompt templates
   - Checks configuration correctness
   - Performance profiling

---

## Available Skills

### Core Skills (Always Active)

#### **Analyst**
- **Purpose**: Interprets security tool outputs and identifies vulnerabilities
- **Prompts**:
  - `ANALYST_SYSTEM_PROMPT`: Defines analyst role
  - `ANALYST_INTERPRET_PROMPT`: Analyzes tool output
  - `ANALYST_CORRELATION_PROMPT`: Correlates findings across tools
  - `ANALYST_FALSE_POSITIVE_PROMPT`: Evaluates false positive probability

**Example Usage**:
```python
from utils.skill_loader import SkillLoader

loader = SkillLoader(config)
analyst_prompts = loader.load_skill_prompts("analyst")

# Use the interpret prompt
prompt = analyst_prompts["ANALYST_INTERPRET_PROMPT"].format(
    tool="nmap",
    target="192.168.1.1",
    command="nmap -sV 192.168.1.1",
    output=raw_nmap_output
)
```

#### **Planner**
- **Purpose**: Decides next steps in penetration testing workflow
- **Prompts**:
  - `PLANNER_SYSTEM_PROMPT`: Strategic planning role
  - `PLANNER_DECISION_PROMPT`: Selects next action
  - `PLANNER_ANALYSIS_PROMPT`: Strategic analysis

#### **Reporter**
- **Purpose**: Generates professional penetration test reports
- **Prompts**:
  - `REPORTER_SYSTEM_PROMPT`: Report generation role
  - `REPORTER_EXECUTIVE_SUMMARY_PROMPT`: Business-focused summary
  - `REPORTER_TECHNICAL_FINDINGS_PROMPT`: Technical details
  - `REPORTER_REMEDIATION_PROMPT`: Prioritized fixes

#### **Tool Selector**
- **Purpose**: Selects appropriate tools for each task
- **Prompts**:
  - `TOOL_SELECTOR_SYSTEM_PROMPT`: Tool selection expertise
  - `TOOL_SELECTION_PROMPT`: Chooses best tool
  - `TOOL_PARAMETERS_PROMPT`: Optimizes tool parameters

### Advanced Skills

#### **Exploitation** 🔴
- **Purpose**: Exploit selection, validation, and execution
- **Authorization**: Requires `auto_exploit: true` in config
- **Prompts**:
  - `EXPLOITATION_SYSTEM_PROMPT`: Exploitation specialist role
  - `EXPLOITATION_SELECTION_PROMPT`: Selects appropriate exploit
  - `EXPLOITATION_VALIDATION_PROMPT`: Validates prerequisites
  - `EXPLOITATION_POST_EXPLOIT_PROMPT`: Post-exploitation planning
  - `EXPLOITATION_METASPLOIT_PROMPT`: Generates MSF resource scripts
  - `EXPLOITATION_REPORTING_PROMPT`: Documents exploitation attempts

**Safety Features**:
- ✓ Requires explicit authorization
- ✓ Validates target scope
- ✓ Assesses DoS/data loss risks
- ✓ Respects safe_mode settings
- ✓ Full audit logging

#### **OSINT** 🔍
- **Purpose**: Open-source intelligence gathering
- **Safe Mode**: ✓ Compatible (passive only)
- **Prompts**:
  - `OSINT_SYSTEM_PROMPT`: OSINT specialist role
  - `OSINT_DOMAIN_PROFILE_PROMPT`: Comprehensive domain profiling
  - `OSINT_SUBDOMAIN_DISCOVERY_PROMPT`: Passive subdomain enumeration
  - `OSINT_BREACH_INTELLIGENCE_PROMPT`: Compromised credential search
  - `OSINT_PEOPLE_ENUMERATION_PROMPT`: Key personnel identification
  - `OSINT_TECHNOLOGY_PROFILING_PROMPT`: Technology stack analysis
  - `OSINT_CORRELATION_PROMPT`: Cross-source data correlation

**Data Sources**:
- Certificate Transparency logs
- DNS aggregators (SecurityTrails, VirusTotal)
- Breach databases (HaveIBeenPwned)
- Code repositories (GitHub)
- Public scan data (Shodan, Censys)

#### **Validation** ✓
- **Purpose**: False positive elimination and finding verification
- **Recommended**: Yes (improves report quality)
- **Prompts**:
  - `VALIDATION_SYSTEM_PROMPT`: Validation specialist role
  - `VALIDATION_FINDING_ASSESSMENT_PROMPT`: Validates single finding
  - `VALIDATION_CROSS_TOOL_CORRELATION_PROMPT`: Cross-references tools
  - `VALIDATION_SEVERITY_ASSESSMENT_PROMPT`: CVSS-based severity validation
  - `VALIDATION_TOOL_OUTPUT_ANALYSIS_PROMPT`: Distinguishes vulns from errors
  - `VALIDATION_EXPLOITABILITY_VERIFICATION_PROMPT`: Confirms exploitability
  - `VALIDATION_BATCH_PROCESSING_PROMPT`: Bulk false positive filtering

**Reduces**:
- Tool errors misinterpreted as vulnerabilities
- Generic warnings (missing headers)
- Informational findings marked as vulnerabilities
- Duplicate findings across tools

#### **Post-Exploit** 🎯
- **Purpose**: Post-exploitation enumeration and privilege escalation
- **Authorization**: Requires successful exploitation
- **Prompts**:
  - `POST_EXPLOIT_SYSTEM_PROMPT`: Post-exploitation specialist
  - `POST_EXPLOIT_ENUMERATION_PROMPT`: Systematic enumeration
  - `POST_EXPLOIT_PRIVESC_PROMPT`: Privilege escalation vectors
  - `POST_EXPLOIT_CREDENTIAL_HARVESTING_PROMPT`: Credential extraction
  - `POST_EXPLOIT_LATERAL_MOVEMENT_PROMPT`: Network pivoting
  - `POST_EXPLOIT_PERSISTENCE_PROMPT`: Persistence mechanisms (authorized only)
  - `POST_EXPLOIT_DATA_EXFILTRATION_PROMPT`: Data identification (authorized only)

**Safety**:
- ⚠️ Persistence requires explicit authorization
- ⚠️ Data exfiltration requires explicit authorization
- ✓ Logs all commands executed
- ✓ Respects engagement scope

---

## Configuration

### Global Settings (`config/skills.yaml`)

```yaml
global:
  ai_enabled: true
  log_ai_decisions: true
  verbosity: normal  # minimal, normal, detailed
  auto_execute_threshold: 0.8  # 0.0-1.0
```

### Skill Definitions

```yaml
skills:
  analyst:
    enabled: true
    description: "Interprets scan results"
    required_for: ["all"]

  exploitation:
    enabled: true
    description: "Handles exploit execution"
    required_for: ["network", "web", "autonomous"]
    requires_authorization: true

  osint:
    enabled: true
    description: "OSINT gathering"
    required_for: ["recon", "osint"]
    safe_mode_compatible: true
```

### Target Profiles

Profiles define which skills are active for different engagement types:

```yaml
profiles:
  web:
    skills:
      - analyst
      - planner
      - reporter
      - tool_selector
      - validation
      - exploitation

    tool_preferences:
      web_scanner: nuclei
      directory_brute: feroxbuster
      xss_scanner: dalfox

    analyst_settings:
      focus_areas:
        - xss
        - sqli
        - authentication
      severity_bias: high

  network:
    skills:
      - analyst
      - planner
      - reporter
      - tool_selector
      - validation
      - exploitation
      - post_exploit

    analyst_settings:
      focus_areas:
        - remote_code_execution
        - authentication_bypass
      severity_bias: critical

  recon:
    skills:
      - analyst
      - planner
      - reporter
      - tool_selector
      - osint
      - validation

    tool_preferences:
      subdomain_enum: subfinder
      passive_osint: amass

    analyst_settings:
      severity_bias: info

  osint:
    skills:
      - osint
      - analyst
      - reporter
      - validation

    tool_preferences:
      passive_only: true
```

### Modifiers

```yaml
modifiers:
  safe_mode:
    disabled_skills:
      - exploitation
      - post_exploit

  stealth_mode:
    planner_settings:
      prefer_passive: true
      avoid_noisy_scans: true

  thorough_mode:
    planner_settings:
      max_tools: unlimited
      redundancy: high
```

### Model Optimizations

```yaml
model_optimizations:
  llama3_1_8b:
    prompt_style: concise
    max_context_per_skill: 2000

  llama3_2_3b:
    prompt_style: minimal
    max_context_per_skill: 1000
    disabled_skills:
      - post_exploit  # Too complex for 3B model

  deepseek_r1_8b:
    prompt_style: reasoning
    preferred_skills:
      - analyst
      - validation

  deephat_v1_7b:
    prompt_style: tactical
    preferred_skills:
      - exploitation
      - post_exploit
```

---

## Usage Examples

### Example 1: Web Application Testing

```python
from utils.skill_loader import SkillLoader

config = {
    "ai": {"model": "llama3.1:8b", "provider": "ollama"},
    "exploits": {"auto_exploit": False}
}

loader = SkillLoader(config)

# Load web profile skills
enabled_skills = loader.get_enabled_skills(target_type="web")
# Result: ['analyst', 'planner', 'reporter', 'tool_selector', 'validation']

# Get profile settings
settings = loader.get_profile_settings(target_type="web")
print(settings["tool_preferences"]["web_scanner"])  # nuclei
print(settings["analyst_settings"]["focus_areas"])  # ['xss', 'sqli', ...]

# Load analyst prompts for web testing
analyst_prompts = loader.load_skill_prompts("analyst")

# Use validation skill to filter false positives
validation_prompts = loader.load_skill_prompts("validation")
```

### Example 2: OSINT-Only Reconnaissance

```python
loader = SkillLoader(config)

# Load OSINT profile
enabled_skills = loader.get_enabled_skills(workflow="osint")
# Result: ['osint', 'analyst', 'reporter', 'validation']

# Get OSINT prompts
osint_prompts = loader.load_skill_prompts("osint")

# Domain profiling
domain_profile_prompt = osint_prompts["OSINT_DOMAIN_PROFILE_PROMPT"].format(
    domain="example.com"
)

# Breach intelligence
breach_prompt = osint_prompts["OSINT_BREACH_INTELLIGENCE_PROMPT"].format(
    domain="example.com",
    email_pattern="*@example.com"
)
```

### Example 3: Autonomous Testing with All Skills

```python
config = {
    "ai": {"model": "llama3.1:8b", "provider": "ollama"},
    "exploits": {"auto_exploit": True, "auto_exploit_require_confirmation": True}
}

loader = SkillLoader(config)

# Load autonomous profile (all skills enabled)
enabled_skills = loader.get_enabled_skills(workflow="autonomous")
# Result: ['analyst', 'planner', 'reporter', 'tool_selector',
#          'validation', 'exploitation', 'post_exploit', 'osint']

# Log active configuration
loader.log_active_skills(workflow="autonomous")
```

### Example 4: Safe Mode Network Scan

```python
loader = SkillLoader(config)

# Safe mode disables exploitation skills
enabled_skills = loader.get_enabled_skills(
    target_type="network",
    safe_mode=True
)
# Result: Exploitation and post_exploit are excluded
```

---

## Creating Custom Skills

### Step 1: Create Prompt Template

Create a new file in `ai/prompt_templates/`:

```python
# ai/prompt_templates/custom_skill.py

"""
Prompt templates for Custom Skill
Describe what this skill does
"""

CUSTOM_SYSTEM_PROMPT = """You are Guardian's Custom Specialist.

Core responsibilities:
- List key responsibilities
- Define expertise areas
- Specify methodology

Critical rules:
- Safety requirements
- Authorization checks
- Logging requirements

Workflow:
1. Step one
2. Step two
3. Step three
"""

CUSTOM_ACTION_PROMPT = """Perform custom action on target.

TARGET: {target}
OBJECTIVE: {objective}

Context:
{context}

Analyze and provide:
1. Analysis of current state
2. Recommended actions
3. Expected outcomes
4. Risk assessment

OUTPUT FORMAT:
Action: <action to take>
Reasoning: <why this action>
Risk: <risk level>
"""
```

### Step 2: Add to Configuration

Edit `config/skills.yaml`:

```yaml
skills:
  custom_skill:
    enabled: true
    description: "Custom specialized skill"
    required_for: ["custom_profile"]
    requires_authorization: false  # Set to true if needed

profiles:
  custom_profile:
    skills:
      - analyst
      - custom_skill

    custom_skill_settings:
      setting1: value1
      setting2: value2
```

### Step 3: Load and Use

```python
from utils.skill_loader import SkillLoader

loader = SkillLoader(config)

# Load custom skill
custom_prompts = loader.load_skill_prompts("custom_skill")

# Use the prompts
action_prompt = custom_prompts["CUSTOM_ACTION_PROMPT"].format(
    target="example.com",
    objective="Custom objective",
    context="Additional context"
)
```

### Step 4: Validate

```bash
python -m utils.skill_validator --validate
```

---

## Validation & Debugging

### Validate All Skills

```bash
python -m utils.skill_validator --validate
```

Output:
```
======================================================================
SKILL VALIDATION REPORT
======================================================================

Total Skills: 8
Valid: 8
Invalid: 0

analyst: ✓ VALID
  Info:
    - Found 4 prompts
    - ANALYST_SYSTEM_PROMPT: Found placeholders: ...

exploitation: ✓ VALID
  Warnings:
    - EXPLOITATION_SELECTION_PROMPT: Prompt is very long (>5000 chars)
```

### Validate Configuration

```bash
python -m utils.skill_validator --validate-config
```

### Inspect a Prompt

```bash
python -m utils.skill_validator --inspect exploitation:EXPLOITATION_SELECTION_PROMPT
```

Output:
```json
{
  "skill": "exploitation",
  "prompt": "EXPLOITATION_SELECTION_PROMPT",
  "length": 3456,
  "lines": 87,
  "placeholders": [
    "vulnerability_title",
    "severity",
    "cve",
    "service",
    "version",
    "target",
    "context"
  ],
  "sections": [
    "EXPLOITABILITY ASSESSMENT:",
    "RECOMMENDED EXPLOIT:",
    "EXECUTION STRATEGY:",
    "RISK ANALYSIS:"
  ],
  "preview": "Select appropriate exploit for the..."
}
```

### Profile Performance

```bash
python -m utils.skill_validator --profile analyst
```

Output:
```json
{
  "skill": "analyst",
  "iterations": 100,
  "avg_load_time_ms": 2.3,
  "min_load_time_ms": 1.8,
  "max_load_time_ms": 5.1
}
```

### Export Documentation

```bash
python -m utils.skill_validator --export-docs
```

Generates: `docs/SKILLS_REFERENCE.md`

---

## Best Practices

### 1. Choose Appropriate Profiles

- **Web Apps**: Use `web` profile for XSS, SQLi, authentication focus
- **Networks**: Use `network` profile for RCE, service exploitation
- **Reconnaissance**: Use `recon` or `osint` for passive intelligence
- **Full Pentests**: Use `autonomous` with all skills enabled

### 2. Enable Validation Skill

Always include the `validation` skill to reduce false positives:

```yaml
profiles:
  my_profile:
    skills:
      - analyst
      - validation  # Recommended!
```

### 3. Use Safe Mode for Scanning

For non-exploitative assessments:

```python
enabled_skills = loader.get_enabled_skills(
    target_type="web",
    safe_mode=True  # Disables exploitation skills
)
```

### 4. Model-Specific Optimization

Choose appropriate models for different skills:

- **Llama 3.1 8B**: Balanced, good for all skills
- **Llama 3.2 3B**: Lightweight, core skills only
- **DeepSeek R1 8B**: Excellent for analyst/validation (reasoning)
- **DeepHat v1 7B**: Red team optimized, best for exploitation

### 5. Authorization Management

Always require authorization for dangerous skills:

```yaml
skills:
  exploitation:
    requires_authorization: true

  post_exploit:
    requires_authorization: true
```

And in main config:

```yaml
exploits:
  auto_exploit: false  # Default to safe
  auto_exploit_require_confirmation: true
```

### 6. Logging for Compliance

Enable comprehensive logging:

```yaml
logging:
  log_skill_usage: true
  log_responses: true
  track_performance: true
  decision_log: reports/ai_decisions.log
```

### 7. Regular Validation

Validate skills after changes:

```bash
# Before running Guardian
python -m utils.skill_validator --validate --validate-config

# If validation fails, fix errors before proceeding
```

### 8. Prompt Optimization

For small models (3B parameters):
- Keep prompts concise
- Use simple vocabulary
- Limit context length
- Disable complex skills

For large models (8B+ parameters):
- Can use detailed prompts
- Include examples
- Multi-step reasoning
- All skills available

---

## Troubleshooting

### Issue: Skill not loading

**Solution**:
```bash
python -m utils.skill_validator --validate
```

Check if prompt file exists and is valid.

### Issue: Wrong skills enabled

**Solution**:
Check profile configuration in `config/skills.yaml`:
```bash
python -m utils.skill_validator --validate-config
```

### Issue: Placeholders not rendering

**Solution**:
Inspect the prompt to see required variables:
```bash
python -m utils.skill_validator --inspect skill_name:PROMPT_NAME
```

### Issue: Poor AI performance

**Solution**:
1. Check model optimization settings
2. Reduce prompt complexity for smaller models
3. Enable verbose logging to see AI reasoning

---

## Advanced Topics

### Dynamic Skill Loading

Load skills programmatically:

```python
from utils.skill_loader import SkillLoader

loader = SkillLoader(config)

# Get all available skills
all_skills = loader.get_all_available_skills()

# Check if specific skill available
if loader.is_skill_available("exploitation"):
    exploit_prompts = loader.load_skill_prompts("exploitation")
```

### Custom Prompt Rendering

```python
from utils.skill_validator import SkillDebugger

debugger = SkillDebugger(config)

# Test prompt with variables
test_vars = {
    "target": "example.com",
    "tool": "nmap",
    "output": "..."
}

rendered, debug_info = debugger.test_skill_prompt(
    "analyst",
    "ANALYST_INTERPRET_PROMPT",
    test_vars
)

if debug_info["success"]:
    print(rendered)
else:
    print("Errors:", debug_info["errors"])
```

### Performance Monitoring

```python
from utils.skill_validator import SkillDebugger

debugger = SkillDebugger(config)

# Profile all skills
for skill in loader.get_all_available_skills():
    metrics = debugger.profile_skill_loading(skill)
    print(f"{skill}: {metrics['avg_load_time_ms']:.2f}ms")
```

---

## Summary

Guardian's AI Skills System provides:

✓ **Specialized AI agents** for different pentesting tasks
✓ **Configurable profiles** for different target types
✓ **Safety controls** with authorization requirements
✓ **Validation tools** for quality assurance
✓ **Model optimization** for different LLM sizes
✓ **Comprehensive logging** for compliance

Get started with:
1. Review `config/skills.yaml`
2. Choose appropriate profile for your target
3. Validate configuration: `python -m utils.skill_validator --validate`
4. Run Guardian with the profile

For questions or issues, see the troubleshooting section or create an issue.
