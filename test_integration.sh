#!/bin/bash
# Test Guardian AI Skills Integration

echo "========================================"
echo "Guardian AI Skills Integration Test"
echo "========================================"
echo

# Check Python version
echo "1. Checking Python version..."
python3 --version || { echo "ERROR: Python 3 not found"; exit 1; }
echo "✓ Python OK"
echo

# Check required files exist
echo "2. Checking required files..."

FILES=(
    "utils/skill_loader.py"
    "utils/skill_validator.py"
    "config/skills.yaml"
    "ai/prompt_templates/exploitation.py"
    "ai/prompt_templates/osint.py"
    "ai/prompt_templates/validation.py"
    "ai/prompt_templates/post_exploit.py"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ MISSING: $file"
        exit 1
    fi
done
echo

# Validate skills
echo "3. Validating all skills..."
python3 -m utils.skill_validator --validate
if [ $? -eq 0 ]; then
    echo "✓ All skills valid"
else
    echo "✗ Skill validation failed"
    exit 1
fi
echo

# Validate configuration
echo "4. Validating skills.yaml configuration..."
python3 -m utils.skill_validator --validate-config
if [ $? -eq 0 ]; then
    echo "✓ Configuration valid"
else
    echo "✗ Configuration validation failed"
    exit 1
fi
echo

# Test skill loading
echo "5. Testing skill loading..."
python3 -c "
from utils.skill_loader import SkillLoader

config = {'ai': {'model': 'llama3.1:8b', 'provider': 'ollama'}}
loader = SkillLoader(config)

# Test loading analyst
analyst = loader.load_skill_prompts('analyst')
print(f'  ✓ Analyst loaded: {len(analyst)} prompts')

# Test loading planner
planner = loader.load_skill_prompts('planner')
print(f'  ✓ Planner loaded: {len(planner)} prompts')

# Test loading new skills
exploitation = loader.load_skill_prompts('exploitation')
print(f'  ✓ Exploitation loaded: {len(exploitation)} prompts')

osint = loader.load_skill_prompts('osint')
print(f'  ✓ OSINT loaded: {len(osint)} prompts')

validation = loader.load_skill_prompts('validation')
print(f'  ✓ Validation loaded: {len(validation)} prompts')

post_exploit = loader.load_skill_prompts('post_exploit')
print(f'  ✓ Post-Exploit loaded: {len(post_exploit)} prompts')
"
if [ $? -eq 0 ]; then
    echo "✓ Skill loading successful"
else
    echo "✗ Skill loading failed"
    exit 1
fi
echo

# Test profile selection
echo "6. Testing profile selection..."
python3 -c "
from utils.skill_loader import SkillLoader

config = {'ai': {'model': 'llama3.1:8b', 'provider': 'ollama'}}
loader = SkillLoader(config)

# Test web profile
web_skills = loader.get_enabled_skills(target_type='web')
print(f'  ✓ Web profile: {len(web_skills)} skills')

# Test network profile
network_skills = loader.get_enabled_skills(target_type='network')
print(f'  ✓ Network profile: {len(network_skills)} skills')

# Test OSINT profile
osint_skills = loader.get_enabled_skills(workflow='osint')
print(f'  ✓ OSINT profile: {len(osint_skills)} skills')

# Test autonomous profile
auto_skills = loader.get_enabled_skills(workflow='autonomous')
print(f'  ✓ Autonomous profile: {len(auto_skills)} skills')
"
if [ $? -eq 0 ]; then
    echo "✓ Profile selection successful"
else
    echo "✗ Profile selection failed"
    exit 1
fi
echo

# Summary
echo "========================================"
echo "✓ ALL TESTS PASSED"
echo "========================================"
echo
echo "Integration successful! The AI skills system is ready to use."
echo
echo "Next steps:"
echo "  1. Read docs/SKILLS_QUICK_START.md for usage guide"
echo "  2. Run: python examples/skill_usage_example.py"
echo "  3. Test with your existing workflows"
echo
