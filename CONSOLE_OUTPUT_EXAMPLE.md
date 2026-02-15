# Console Output - AI Skills in Action

## What You'll See When Running Guardian

### 1. Startup - Skills Configuration

When you run a workflow, you'll see which skills are active:

```
$ python -m cli.main workflow run --name web --target example.com

[INFO] Guardian CLI v2.0
[INFO] Target: example.com

┌─────────────────────────────────────────────────┐
│         🧠 AI Skills Configuration              │
└─────────────────────────────────────────────────┘
  Profile: web
  Active Skills (5): analyst, planner, reporter, tool_selector, validation
  Focus Areas: xss, sqli, authentication...
─────────────────────────────────────────────────

[INFO] Starting web workflow...
```

### 2. Skill Loading - As They're Used

When each agent initializes, you'll see:

```
[INFO] ✓ Loaded 'analyst' skill (optimized for llama3_1_8b)
[INFO] ✓ Loaded 'planner' skill (optimized for llama3_1_8b)
[INFO] ✓ Loaded 'validation' skill (default prompts)
```

**What this tells you:**
- ✅ `analyst` - Using Llama 3.1 8B optimized prompts
- ✅ `planner` - Using Llama 3.1 8B optimized prompts
- ✅ `validation` - Using default prompts (no model-specific version)

### 3. During Execution - Agent Actions

Existing logs continue as normal:

```
[INFO] Running nuclei against https://example.com
[INFO] [Analyst] Analyzing nuclei output...
[INFO] [Analyst] Found 12 potential findings
[INFO] [Validation] Filtering false positives...
[INFO] [Validation] Filtered 12 findings → 4 confirmed vulnerabilities
[INFO] [Planner] Deciding next action...
[INFO] [Planner] Next action: vulnerability_scanning
```

### 4. Different Models Show Different Output

**With Llama 3.1 8B:**
```
✓ Loaded 'analyst' skill (optimized for llama3_1_8b)
✓ Loaded 'exploitation' skill (default prompts)
```

**With DeepSeek R1 8B:**
```
✓ Loaded 'analyst' skill (optimized for deepseek_r1_8b)
✓ Loaded 'exploitation' skill (default prompts)
```

**With Claude/GPT (via OpenRouter):**
```
✓ Loaded 'analyst' skill (default prompts)
✓ Loaded 'exploitation' skill (default prompts)
```

## How to See More Detail

### Enable Debug Logging

**In your config (`config/guardian.yaml`):**
```yaml
logging:
  level: debug  # Shows detailed skill loading
```

**Debug output example:**
```
[DEBUG] [SkillLoader] Using profile from target_type: web
[DEBUG] [SkillLoader] Model detected: llama3.1:8b → llama3_1_8b
[DEBUG] [SkillLoader] Trying: ai.prompt_templates.llama3_1_8b.analyst
[INFO]  ✓ Loaded 'analyst' skill (optimized for llama3_1_8b)
[DEBUG] [SkillLoader] Trying: ai.prompt_templates.llama3_1_8b.exploitation
[DEBUG] [SkillLoader] No exploitation prompts in llama3_1_8b set, trying default
[INFO]  ✓ Loaded 'exploitation' skill (default prompts)
[DEBUG] [Analyst] Loaded 4 prompts
```

### Show Active Skills Before Running

**Add to your workflow initialization:**
```python
# In workflow code
from utils.skill_loader import SkillLoader

loader = SkillLoader(config)
loader.log_active_skills(target_type="web")
```

**Output:**
```
┌─────────────────────────────────────────────────┐
│         🧠 AI Skills Configuration              │
└─────────────────────────────────────────────────┘
  Profile: web
  Active Skills (5): analyst, planner, reporter, tool_selector, validation
  Focus Areas: xss, sqli, authentication...
─────────────────────────────────────────────────
```

## Real-World Example: Web Workflow

```
$ python -m cli.main workflow run --name web --target https://example.com

[INFO] Guardian CLI - Starting web workflow
[INFO] Target: https://example.com

┌─────────────────────────────────────────────────┐
│         🧠 AI Skills Configuration              │
└─────────────────────────────────────────────────┘
  Profile: web
  Active Skills (5): analyst, planner, reporter, tool_selector, validation
  Focus Areas: xss, sqli, authentication...
─────────────────────────────────────────────────

[INFO] ✓ Loaded 'analyst' skill (optimized for llama3_1_8b)
[INFO] ✓ Loaded 'planner' skill (optimized for llama3_1_8b)

[INFO] Phase: Reconnaissance
[INFO] Running nuclei...
[INFO] Nuclei found 47 issues

[INFO] [Analyst] Analyzing nuclei output...
[INFO] ✓ Loaded 'validation' skill (default prompts)
[INFO] [Analyst] Extracted 47 findings from nuclei
[INFO] [Validation] Checking findings for false positives...
[INFO] [Validation] Filtered 47 → 8 confirmed vulnerabilities

[HIGH] SQL Injection in /api/users
[HIGH] XSS in search parameter
[MEDIUM] Missing CORS headers
...

[INFO] [Planner] Deciding next action...
[INFO] [Planner] Decision: Run sqlmap to validate SQL injection
```

## Comparison: Before vs After

### Before (Generic)
```
[INFO] Running nuclei...
[INFO] Analyzing nuclei output...
[INFO] Found 47 findings
```

### After (With Skills)
```
[INFO] Running nuclei...
[INFO] ✓ Loaded 'analyst' skill (optimized for llama3_1_8b)
[INFO] [Analyst] Analyzing nuclei output with web-focused analysis...
[INFO] ✓ Loaded 'validation' skill (default prompts)
[INFO] [Validation] Filtering 47 findings...
[INFO] [Validation] Confirmed 8 true vulnerabilities
```

**You see:**
- ✅ Which skills are being used
- ✅ Whether they're optimized for your model
- ✅ What each skill is doing
- ✅ Results of validation (false positive filtering)

## Turn Off Skill Logging

If you want minimal output, set logging to WARNING:

```yaml
logging:
  level: warning  # Only shows warnings and errors
```

Then you'll only see:
```
[INFO] Running nuclei...
[INFO] Found 8 vulnerabilities
[INFO] Next action: sqlmap
```

## Summary

**You'll see skills in action through:**
1. ✅ Startup banner showing active skills
2. ✅ Skill loading messages (which prompts are used)
3. ✅ Agent actions showing which skill is working
4. ✅ Validation results (before/after filtering)

**Control verbosity:**
- `level: info` - Shows skill loading and actions (recommended)
- `level: debug` - Shows everything including fallback logic
- `level: warning` - Minimal output, only issues

**Test it:**
```bash
./test_integration.sh  # Shows skill loading
python -m cli.main workflow run --name web --target example.com  # See it in action
```
