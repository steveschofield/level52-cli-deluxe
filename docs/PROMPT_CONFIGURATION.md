# Prompt Configuration Guide

Guardian supports dynamic prompt loading optimized for different LLM models. This allows the framework to automatically adjust its prompts based on the model's capabilities and constraints.

## Overview

Guardian includes five prompt sets optimized for different scenarios:

1. **default** - Standard prompts for large, capable models (GPT-4, Claude, Gemini)
2. **llama3_2_3b** - Token-efficient prompts for Llama 3.2 3B (small model)
3. **llama3_1_8b** - Balanced prompts for Llama 3.1 8B (mid-size model)
4. **deepseek_r1_8b** - Reasoning-focused prompts for DeepSeek-R1 8B
5. **deephat_v1_7b** - Red team/offensive security prompts for DeepHat cybersecurity model

## How It Works

### Auto-Detection

Guardian automatically detects the appropriate prompt set based on your model name:

```yaml
ai:
  provider: ollama
  model: "llama3.1:8b"  # Automatically uses llama3_1_8b prompts
```

Model name patterns:
- `llama3.2:3b`, `llama3.2-3b`, `llama-3.2-3b` → `llama3_2_3b`
- `llama3.1:8b`, `llama3.1-8b`, `llama-3.1-8b` → `llama3_1_8b`
- `deepseek-r1:8b`, `deepseek-r1-8b`, `deepseek_r1` → `deepseek_r1_8b`
- `deephat`, `deep-hat`, `deephat-v1` → `deephat_v1_7b`
- Everything else → `default`

### Explicit Configuration

You can explicitly specify a prompt set:

```yaml
ai:
  provider: ollama
  model: "custom-model:latest"
  prompt_set: "llama3_1_8b"  # Force specific prompt set
```

## Prompt Set Details

### default (Standard Prompts)

**Best for:** GPT-4, Claude 3+, Gemini 2.5+, large open models

**Characteristics:**
- Comprehensive, detailed prompts
- Full context and examples
- No token optimization
- Verbose reasoning

**Example usage:**
```yaml
ai:
  provider: openrouter
  model: "google/gemini-3-flash-preview"
  # prompt_set auto-detects to "default"
```

---

### llama3_2_3b (Small Model Optimization)

**Best for:** Llama 3.2 3B, Phi-3 Mini, Mistral 7B

**Characteristics:**
- 40-60% token reduction
- Explicit examples
- Compact formatting with symbols
- Clear structure with bullets/numbers

**Token efficiency:**
- Analyst System Prompt: 852 → 477 chars (44% reduction)
- Planner System Prompt: 731 → 403 chars (45% reduction)
- Reporter System Prompt: 1,124 → 615 chars (45% reduction)

**Example usage:**
```yaml
ai:
  provider: ollama
  model: "llama3.2:3b"
  base_url: "http://localhost:11434"
  temperature: 0.2
  max_tokens: 4096
```

**Optimizations applied:**
- Removed redundant text
- Used symbols (→, ✓, ✗) instead of words
- Shortened examples
- Direct, imperative language

---

### llama3_1_8b (Balanced Mid-Size)

**Best for:** Llama 3.1 8B, Mistral 8x7B, similar mid-size models

**Characteristics:**
- Efficient but detailed
- Clear workflow definitions
- Evidence-based approach
- Moderate token usage

**Token efficiency:**
- Analyst System Prompt: 852 → 568 chars (33% reduction)
- Planner System Prompt: 731 → 495 chars (32% reduction)
- Reporter System Prompt: 1,124 → 758 chars (33% reduction)

**Example usage:**
```yaml
ai:
  provider: ollama
  model: "llama3.1:8b"
  base_url: "http://localhost:11434"
  temperature: 0.2
  max_tokens: 8192
  context_window: 128000
```

**Key features:**
- Structured analysis workflows
- Explicit severity scales
- Clear deliverables
- Balanced detail vs. brevity

**Hardware requirements:**
- Recommended: M3 MacBook with 24GB RAM
- Quantization: Q4_K_M or higher
- Context window: 128K tokens

---

### deepseek_r1_8b (Reasoning-Focused)

**Best for:** DeepSeek-R1 8B, models with strong reasoning capabilities

**Characteristics:**
- Step-by-step reasoning chains
- Logical analysis emphasis
- Code-level vulnerability assessment
- Evidence → reasoning → conclusion flow

**Token efficiency:**
- Analyst System Prompt: 852 → 581 chars (32% reduction)
- Planner System Prompt: 731 → 508 chars (31% reduction)
- Reporter System Prompt: 1,124 → 771 chars (31% reduction)

**Example usage:**
```yaml
ai:
  provider: ollama
  model: "deepseek-r1:8b"
  base_url: "http://localhost:11434"
  temperature: 0.3
  max_tokens: 8192
  context_window: 200000
```

**Reasoning approach:**
- Evidence parsing
- Pattern recognition
- Impact analysis
- Logical conclusions

**Best practices:**
- Allow higher temperature (0.3-0.4) for creative reasoning
- Provide rich context (use full context window)
- Works well with code analysis tasks

**Hardware requirements:**
- Recommended: M3 MacBook with 24GB RAM
- Quantization: Q4_K_M or higher
- Context window: 200K tokens (DeepSeek specialty)

---

### deephat_v1_7b (Red Team/Offensive Security)

**Best for:** DeepHat V1 7B cybersecurity model, offensive security workflows

**Characteristics:**
- Red team/attacker mindset
- MITRE ATT&CK mapping
- Exploitation-focused analysis
- Attack chain construction
- Offensive security terminology

**Token efficiency:**
- Analyst System Prompt: 852 → 623 chars (27% reduction)
- Planner System Prompt: 731 → 551 chars (25% reduction)
- Reporter System Prompt: 1,124 → 891 chars (21% reduction)

**Example usage:**
```yaml
ai:
  provider: ollama
  model: "DeepHat/DeepHat-V1-7B:latest"
  base_url: "http://192.168.1.69:11434"
  temperature: 0.3
  max_tokens: 8192
```

**Red team focus:**
- Exploitation paths and weaponizability
- Real-world adversary simulation
- Attack narratives and kill chains
- MITRE ATT&CK TTP mapping
- IOCs and detection signatures
- Business impact of compromise

**Severity scale (exploitation-focused):**
- CRITICAL: Full compromise, RCE, admin access
- HIGH: Significant access, data theft, privilege escalation
- MEDIUM: Limited access, information disclosure
- LOW: Theoretical risk, requires additional exploitation
- INFO: No security impact

**Example output sections:**
- Executive Summary: Attack scenario and business impact
- Attack Narrative: Story of compromise
- Exploitation Details: Technical findings with PoCs
- MITRE ATT&CK Mapping: TTPs used
- Remediation Roadmap: Adversary-informed defense
- IOCs and Detection Signatures

**Model background:**
- Based on Qwen2.5-Coder-7B-Instruct
- Fine-tuned on cybersecurity datasets
- Uncensored for red team operations
- 7.61B parameters
- Context window: 128K tokens

## Configuration Examples

### Use Case 1: MacBook M3 with 24GB RAM

**Llama 3.1 8B (Recommended):**
```yaml
ai:
  provider: ollama
  model: "llama3.1:8b"
  base_url: "http://localhost:11434"
  temperature: 0.2
  max_tokens: 8192
  context_window: 128000
  # prompt_set auto-detects to llama3_1_8b
```

**DeepSeek-R1 8B (High reasoning):**
```yaml
ai:
  provider: ollama
  model: "deepseek-r1:8b"
  base_url: "http://localhost:11434"
  temperature: 0.3
  max_tokens: 8192
  context_window: 200000
  # prompt_set auto-detects to deepseek_r1_8b
```

### Use Case 2: Low-Resource Environment

**Llama 3.2 3B:**
```yaml
ai:
  provider: ollama
  model: "llama3.2:3b"
  base_url: "http://localhost:11434"
  temperature: 0.2
  max_tokens: 4096
  context_window: 32000
  # prompt_set auto-detects to llama3_2_3b
```

### Use Case 3: Red Team Engagement

**DeepHat V1 7B:**
```yaml
ai:
  provider: ollama
  model: "DeepHat/DeepHat-V1-7B:latest"
  base_url: "http://localhost:11434"
  temperature: 0.3
  max_tokens: 8192
  # prompt_set auto-detects to deephat_v1_7b

workflows:
  offensive_recon:
    description: "Red team reconnaissance"
    # ... workflow steps
```

### Use Case 4: Cloud Providers (Default Prompts)

**OpenRouter with Gemini:**
```yaml
ai:
  provider: openrouter
  model: "google/gemini-3-flash-preview"
  base_url: "https://openrouter.ai/api/v1"
  temperature: 0.2
  max_tokens: 8192
  # prompt_set auto-detects to default
```

**Vertex AI:**
```yaml
ai:
  provider: gemini
  model: "gemini-3-flash-preview"
  temperature: 0.2
  vertexai: true
  project: "my-project-id"
  location: "global"
  # prompt_set auto-detects to default
```

## Testing Your Configuration

Run the validation test to ensure your prompt set loads correctly:

```bash
cd /Users/ss/code/guardian-cli-deluxe
python test_prompt_validation.py
```

Expected output:
```
============================================================
Prompt Set Validation Tests
============================================================
✓ Model 'llama3.1:8b' → Prompt set 'llama3_1_8b' ✓ (12 prompts loaded)
✓ Model 'deepseek-r1:8b' → Prompt set 'deepseek_r1_8b' ✓ (12 prompts loaded)
...
============================================================
Results: 16 passed, 0 failed
============================================================

✓ All prompt sets validated successfully!
```

## Troubleshooting

### Prompt set not auto-detecting

**Problem:** Guardian uses default prompts instead of model-specific ones

**Solution:** Check model name format:
```yaml
# ✓ Correct (auto-detects)
model: "llama3.1:8b"

# ✗ Incorrect (uses default)
model: "llama-3-1-8b-instruct"
```

Use explicit prompt_set:
```yaml
model: "llama-3-1-8b-instruct"
prompt_set: "llama3_1_8b"  # Force specific prompts
```

### Import errors

**Problem:** `ModuleNotFoundError: No module named 'ai.prompt_templates.llama3_1_8b'`

**Solution:** Ensure directory structure is correct:
```
ai/prompt_templates/
├── __init__.py
├── llama3_1_8b/
│   ├── __init__.py
│   ├── analyst.py
│   ├── planner.py
│   └── reporter.py
├── deepseek_r1_8b/
│   ├── __init__.py
│   ├── analyst.py
│   ├── planner.py
│   └── reporter.py
...
```

### Performance issues with small models

**Problem:** Llama 3.2 3B generates poor results

**Symptoms:**
- Incomplete analysis
- Missing evidence
- Generic findings
- Hallucinations

**Solutions:**
1. Reduce context: Lower `max_tool_output_chars`
   ```yaml
   ai:
     max_tool_output_chars: 15000  # Default: 25000
   ```

2. Increase temperature slightly:
   ```yaml
   ai:
     temperature: 0.3  # Default: 0.2
   ```

3. Run fewer tools in parallel:
   ```yaml
   pentest:
     max_parallel_tools: 2  # Default: 5
   ```

4. Use explicit examples in workflows:
   ```yaml
   workflows:
     custom_scan:
       steps:
         - name: example_finding
           type: example
           content: |
             CRITICAL: SQL Injection in /api/login
             Evidence: Input 'username' reflects in query: SELECT * FROM users WHERE name='admin' OR '1'='1'
             Impact: Complete database compromise
   ```

## Creating Custom Prompt Sets

You can create your own optimized prompts for specific models or use cases:

1. **Create directory:**
   ```bash
   mkdir -p ai/prompt_templates/my_custom_prompts
   ```

2. **Create prompt files:**
   ```bash
   touch ai/prompt_templates/my_custom_prompts/__init__.py
   touch ai/prompt_templates/my_custom_prompts/analyst.py
   touch ai/prompt_templates/my_custom_prompts/planner.py
   touch ai/prompt_templates/my_custom_prompts/reporter.py
   ```

3. **Define prompts** (see existing prompt sets as templates)

4. **Update prompt_loader.py:**
   ```python
   def get_prompt_set(self) -> str:
       # ... existing code ...

       if any(pattern in model_name for pattern in ["my-model", "custom-model"]):
           return "my_custom_prompts"

       return "default"

   def load_prompts(self) -> Dict[str, str]:
       # ... existing code ...

       elif prompt_set == "my_custom_prompts":
           from ai.prompt_templates import my_custom_prompts as prompt_module
           prompts = {}
           for attr in dir(prompt_module):
               if attr.isupper() and "PROMPT" in attr:
                   prompts[attr] = getattr(prompt_module, attr)
   ```

5. **Update configuration:**
   ```yaml
   ai:
     model: "my-model:latest"
     prompt_set: "my_custom_prompts"
   ```

6. **Test:**
   ```bash
   python test_prompt_validation.py
   ```

## Best Practices

### 1. Match Prompts to Model Size

- **< 4B params:** Use llama3_2_3b (token-efficient)
- **4-10B params:** Use llama3_1_8b or deepseek_r1_8b (balanced)
- **> 10B params:** Use default (full prompts)

### 2. Temperature Settings

- **Small models (3B):** 0.2-0.3 (prevent hallucination)
- **Mid-size (8B):** 0.2-0.4 (allow reasoning)
- **Large models:** 0.1-0.2 (maximize accuracy)

### 3. Context Window Usage

- **Llama 3.2 3B:** Keep context < 32K tokens
- **Llama 3.1 8B:** Can use up to 128K tokens
- **DeepSeek-R1 8B:** Excels at 200K tokens (long context specialty)

### 4. Task-Specific Prompt Sets

- **General pentesting:** llama3_1_8b or default
- **Red team engagements:** deephat_v1_7b
- **Code analysis:** deepseek_r1_8b
- **Quick scans:** llama3_2_3b

### 5. Verification

Always verify prompt selection with:
```bash
python -m guardian scan --target https://example.com --dry-run
# Check log output for: "Using prompt set: llama3_1_8b"
```

## Performance Benchmarks

Based on M3 MacBook with 24GB RAM running Ollama:

| Model | Prompt Set | Tokens/sec | Memory | Context | Quality |
|-------|-----------|------------|---------|---------|---------|
| Llama 3.2 3B | llama3_2_3b | ~80 | 4GB | 32K | Good |
| Llama 3.1 8B | llama3_1_8b | ~35 | 8GB | 128K | Excellent |
| DeepSeek-R1 8B | deepseek_r1_8b | ~30 | 9GB | 200K | Excellent |
| DeepHat V1 7B | deephat_v1_7b | ~40 | 7GB | 128K | Excellent (security) |

**Notes:**
- Tokens/sec measured with Q4_K_M quantization
- Memory usage includes model + context
- Quality subjective, based on pentesting accuracy

## References

- [Llama 3.2 Model Card](https://huggingface.co/meta-llama/Llama-3.2-3B-Instruct)
- [Llama 3.1 Model Card](https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct)
- [DeepSeek-R1 Technical Report](https://github.com/deepseek-ai/DeepSeek-R1)
- [DeepHat Hugging Face](https://huggingface.co/DeepHat/DeepHat-V1-7B)
- [Ollama Documentation](https://ollama.ai/library)

## Support

For issues with prompt configuration:
1. Check validation test: `python test_prompt_validation.py`
2. Review logs: `reports/*/llm_io_*.jsonl`
3. Enable debug logging: `output.verbosity: debug`
4. Open issue: https://github.com/yourusername/guardian-cli-deluxe/issues
