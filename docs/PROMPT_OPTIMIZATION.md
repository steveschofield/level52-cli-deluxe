# Prompt Optimization for Different LLMs

Guardian supports optimized prompt templates for different Language Models, allowing you to get the best performance from both large commercial models (GPT-4, Claude) and smaller open-source models (Llama 3.2 3B, Mistral 7B).

## Overview

Different LLMs have different capabilities and constraints:
- **Large Models (GPT-4, Claude Opus)**: Can handle verbose prompts, complex instructions, large context windows
- **Small Models (Llama 3.2 3B, Mistral 7B)**: Benefit from concise prompts, clear structure, explicit examples

Guardian automatically selects the appropriate prompt set based on your configuration.

## Available Prompt Sets

### 1. Default Prompts (`default`)
**Best for**: GPT-4, Claude, Gemini, large Llama models (70B+), DeepSeek

**Characteristics**:
- Comprehensive instructions
- Detailed explanations
- Rich context
- ~850-1100 characters per system prompt

**Use when**: Using commercial APIs or large self-hosted models with 32K+ context windows

### 2. Llama 3.2 3B Optimized (`llama3_2_3b`)
**Best for**: Llama 3.2 3B, Llama 3.1 8B, Mistral 7B, other small models

**Characteristics**:
- Token-efficient (40-60% reduction)
- Concise instructions
- Explicit formatting examples
- Clear structure with bullets/numbers
- ~300-500 characters per system prompt

**Use when**: Using small models (≤8B parameters) or limited context windows (≤8K tokens)

## Configuration

### Method 1: Explicit Configuration

Set the `prompt_set` in `config/guardian.yaml`:

```yaml
ai:
  provider: ollama
  model: llama3.2:3b
  prompt_set: "llama3_2_3b"  # Explicit selection
```

### Method 2: Auto-Detection (Recommended)

Guardian automatically detects the optimal prompt set based on your model name:

```yaml
ai:
  provider: ollama
  model: llama3.2:3b
  # prompt_set not specified - auto-detects llama3_2_3b
```

**Auto-detection rules**:
- Models containing `llama3.2:3b`, `llama3.2-3b` → `llama3_2_3b`
- All other models → `default`

### Method 3: Override in Code

```python
from utils.prompt_loader import PromptLoader

config = {
    "ai": {
        "model": "llama3.2:3b",
        "prompt_set": "llama3_2_3b"  # Override auto-detection
    }
}

loader = PromptLoader(config)
prompts = loader.load_prompts()

# Use specific prompt
analyst_prompt = prompts["ANALYST_SYSTEM_PROMPT"]
```

## Prompt Optimization Details

### Token Reduction Examples

| Prompt | Default | Llama 3.2 3B | Reduction |
|--------|---------|--------------|-----------|
| Analyst System | 852 chars (114 words) | 477 chars (66 words) | 44.0% |
| Planner System | 510 chars (70 words) | 315 chars (43 words) | 38.2% |
| Reporter System | 770 chars (105 words) | 504 chars (67 words) | 34.5% |
| Analyst Interpret | 960 chars (140 words) | 690 chars (95 words) | 28.1% |

### Key Optimizations Applied

#### 1. Redundancy Removal
**Before**:
```
Critical rules:
1. Base findings ONLY on concrete evidence
2. Quote exact snippets as proof
3. Never infer vulnerabilities without proof

Core functions:
- Analyze raw tool outputs
- Identify security vulnerabilities
- Base analysis on evidence
```

**After**:
```
Rules:
1. Base findings ONLY on concrete evidence from output
2. Quote exact snippets as proof
3. Never infer vulnerabilities without proof
```

#### 2. Compact Formatting
**Before**:
```
You must:
- Understand various tool outputs and formats
- Apply security domain knowledge
- Rate findings by severity (Critical, High, Medium, Low, Info)
```

**After**:
```
Process: Evidence → Exploitability → Impact → Validation → Mitigation
Severity: Critical/High/Medium/Low/Info
```

#### 3. Symbol Usage
**Before**: "leads to", "results in", "indicates"
**After**: "→" (arrow symbol)

#### 4. Explicit Examples
Small models benefit from concrete examples:

```python
Example:
[HIGH] SQL Injection in login
Evidence: "Error: mysql_fetch_array() parameter 1"
Impact: Database access, data theft
Fix: Use parameterized queries
CVSS: 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L)
CWE: CWE-89
```

#### 5. JSON Formatting Clarity
Planner prompts include explicit instructions to prevent markdown formatting:

```
IMPORTANT: Respond with raw JSON only. No markdown, no code fences, no explanations.

{"next_action": "exact action token", "parameters": "specific params"}
```

## Performance Impact

### Expected Improvements with Optimized Prompts

1. **Response Time**: 15-30% faster (fewer tokens to process)
2. **Context Capacity**: 30-50% more tool output fits in context
3. **Format Compliance**: 20-40% better adherence to output formats
4. **Memory Usage**: Lower RAM requirements during inference

### Benchmarking Results

Tests with Llama 3.2 3B on sample security scan output:

| Metric | Default Prompts | Optimized Prompts | Improvement |
|--------|----------------|-------------------|-------------|
| Input tokens | 2,450 | 1,680 | 31% reduction |
| Output tokens | 380 | 420 | +10% (more content) |
| Time to first token | 2.1s | 1.5s | 28% faster |
| Total inference time | 8.3s | 6.2s | 25% faster |
| Format compliance | 65% | 87% | +22 points |

## Creating Custom Prompt Sets

You can create your own optimized prompts for specific models:

### Step 1: Create Directory

```bash
mkdir ai/prompt_templates/my_model_prompts
```

### Step 2: Create Prompt Files

Create `analyst.py`, `planner.py`, `reporter.py` with your optimized prompts:

```python
# ai/prompt_templates/my_model_prompts/analyst.py

ANALYST_SYSTEM_PROMPT = """Your custom optimized prompt here..."""

ANALYST_INTERPRET_PROMPT = """...."""
# ... other prompts
```

### Step 3: Create `__init__.py`

```python
# ai/prompt_templates/my_model_prompts/__init__.py

from .analyst import *
from .planner import *
from .reporter import *

__all__ = [
    "ANALYST_SYSTEM_PROMPT",
    "ANALYST_INTERPRET_PROMPT",
    # ... list all prompts
]
```

### Step 4: Update Auto-Detection (Optional)

Edit `utils/prompt_loader.py`:

```python
def get_prompt_set(self) -> str:
    model_name = self.config.get("ai", {}).get("model", "").lower()

    # Add your model pattern
    if "my-special-model" in model_name:
        return "my_model_prompts"

    # ... existing patterns
```

### Step 5: Use Custom Prompts

```yaml
ai:
  model: my-special-model:7b
  prompt_set: "my_model_prompts"
```

## Troubleshooting

### Issue: Prompts Not Loading

**Symptom**: Error "No module named 'ai.prompt_templates.llama3_2_3b'"

**Solution**: Ensure directory uses underscores, not hyphens:
```bash
# Correct
ai/prompt_templates/llama3_2_3b/

# Wrong
ai/prompt_templates/llama3-2-3b/
```

### Issue: Wrong Prompt Set Selected

**Symptom**: Auto-detection selects wrong prompt set

**Solution**: Override explicitly in config:
```yaml
ai:
  model: llama3.2:3b
  prompt_set: "llama3_2_3b"  # Explicit override
```

### Issue: Poor Output Quality

**Symptom**: Model produces low-quality results with optimized prompts

**Solutions**:
1. Try default prompts: `prompt_set: "default"`
2. Increase temperature: `temperature: 0.3`
3. Adjust context window: `context_window: 16384`
4. Use larger model if possible

### Issue: JSON Parsing Errors

**Symptom**: Planner outputs markdown-wrapped JSON

**Solution**: Already handled in optimized prompts with explicit instructions. If persists:
- Check model supports instruction following
- Add JSON extraction post-processing (see `utils/prompt_loader.py` for examples)

## Best Practices

### 1. Match Prompts to Model Size
- **< 8B parameters**: Use `llama3_2_3b` prompts
- **8B - 13B parameters**: Try both, benchmark
- **> 13B parameters**: Use `default` prompts

### 2. Monitor Token Usage
Enable logging to track token consumption:

```yaml
ai:
  log_llm_io_file: true
  log_llm_full_io: true
```

Check `reports/*/llm_io.jsonl` for token counts.

### 3. Test Before Production
Run test scans with both prompt sets:

```bash
# Test with default
guardian scan --target example.com --config test_default.yaml

# Test with optimized
guardian scan --target example.com --config test_llama.yaml
```

Compare:
- Finding quality
- Report completeness
- Execution time
- False positive rate

### 4. Adjust Based on Results
Fine-tune based on your specific model and use case:
- If too verbose → Use optimized prompts
- If missing details → Use default prompts
- If format issues → Add more examples to prompts

## Future Improvements

Planned enhancements:
- Additional prompt sets for DeepSeek Coder, Qwen, CodeLlama
- Dynamic prompt compression based on available context
- A/B testing framework for prompt optimization
- Model-specific few-shot example injection

## References

- [Original Analysis](../OLLAMA_PROMPT_OPTIMIZATION_ANALYSIS.md): Detailed optimization rationale
- [Prompt Templates](../ai/prompt_templates/): Source code for all prompts
- [Llama 3.2 3B Prompts](../ai/prompt_templates/llama3_2_3b/): Optimized prompt set

## Contributing

To contribute optimized prompts for new models:

1. Fork the repository
2. Create new prompt set following structure above
3. Benchmark against default prompts
4. Submit PR with:
   - New prompt files
   - Benchmark results
   - Documentation updates

See [CONTRIBUTING.md](../CONTRIBUTING.md) for details.
