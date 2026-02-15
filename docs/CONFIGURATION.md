# Guardian Configuration

Guardian is configured via a YAML file plus environment variables for any secrets (API keys/tokens).

## Config File Locations

- **From source (this repo):** defaults to `config/guardian.yaml`
- **Installed CLI:** if `config/guardian.yaml` is not found in the current working directory, Guardian falls back to `~/.guardian/guardian.yaml` (created by `guardian init`)
- **Explicit:** pass `--config /path/to/guardian.yaml` to any command

### Repo Override Layer

When using the default repo config (`config/guardian.yaml`), Guardian also deep-merges the repo-root `guardian.yaml` on top as an override layer.

## `.env` and Environment Variables

Guardian reads environment variables from:

- a `.env` file in the current working directory (if present)
- a `.env` file next to the resolved config file (e.g., `~/.guardian/.env` when using `guardian init`)

Recommended: keep secrets in `.env` and **do not** commit them.

Common env vars:

- **Gemini:** `GOOGLE_API_KEY` (API key mode)
- **OpenRouter:** `OPENROUTER_API_KEY` (optional: `OPENROUTER_SITE_URL`, `OPENROUTER_APP_NAME`)
- **Hugging Face:** `HF_TOKEN` (or `HUGGINGFACEHUB_API_TOKEN`)
- **Ollama:** `OLLAMA_BASE_URL` (optional), `OLLAMA_NUM_CTX` (optional)

## Top-Level Sections

### `ai`

Controls the LLM backend and prompt/response limits.

Common keys:

- `provider`: `gemini` | `ollama` | `openrouter` | `huggingface`
- `model`: provider-specific model name/slug
- `base_url`: provider endpoint (Ollama/OpenRouter/HF)
- `temperature`, `max_tokens`
- `timeout`: provider request timeout (seconds)
- `llm_timeout_seconds`: overall per-call time budget enforced by Guardian (seconds)
- `max_input_chars`: cap total prompt size (best-effort)
- `max_tool_output_chars`: cap tool output included in prompts

Provider examples (put in your config file):

```yaml
ai:
  provider: ollama
  model: "llama3.1:8b"
  base_url: "http://127.0.0.1:11434"
```

```yaml
ai:
  provider: openrouter
  model: "openai/gpt-4o-mini"
  base_url: "https://openrouter.ai/api/v1"
```

```yaml
ai:
  provider: gemini
  model: "gemini-2.5-flash"
  temperature: 0.2
  vertexai: true
  project: "your-gcp-project-id-or-number"
  location: "us-central1"
```

```yaml
ai:
  provider: huggingface
  model: "meta-llama/Meta-Llama-3-8B-Instruct"
  base_url: "https://router.huggingface.co/hf-inference/models"
```

```yaml
ai:
  provider: huggingface
  model: "openai/gpt-oss-120b"
  base_url: "https://router.huggingface.co/v1"
```

### `pentest`

Safety and execution guardrails:

- `safe_mode`: keep active/destructive steps gated
- `require_confirmation`: prompt before tool execution
- `max_parallel_tools`: concurrency limit
- `tool_timeout`: tool execution timeout (seconds)

### `scope`

Scope validation and guardrails:

- `blacklist`: CIDR ranges that are never allowed targets
- `require_scope_file`: require a scope file to authorize targets

### `tools`

Per-tool toggles and parameters. Every wrapper reads `tools.<tool>.enabled` plus tool-specific keys.

Some tools support overriding the binary path via config and/or environment variables:

- `tools.httpx.binary` or `GUARDIAN_HTTPX_BIN`
- `tools.nuclei.binary` or `GUARDIAN_NUCLEI_BIN`
- `tools.zap.binary` or `GUARDIAN_ZAP_BIN` (local mode)

OWASP ZAP is configured under `tools.zap` and supports `mode: docker` (recommended) or daemon/local options.

Advanced ZAP options (AJAX spider, auth context, seed URLs) use the daemon API. If `mode: docker`,
Guardian will automatically run a temporary ZAP daemon container when these options are enabled.

Global tool path overrides (optional):

```yaml
tools:
  auto_discover: true
  paths:
    nmap: /usr/bin/nmap
    nuclei: /usr/local/bin/nuclei
```

Nmap arguments (defaults shown):

```yaml
tools:
  nmap:
    # Recon / baseline enumeration
    default_args: "-sV -sC"
    # Vulnerability scripts (NSE "vuln" + vulners)
    vuln_args: "-sV --script vuln,vulners"
```

### Workflow-Specific Tool Configuration

Some workflow steps only run when required arguments or tokens are present:

- **Web workflow:** `tools.hydra` (userlist/passlist/service or `args`), `tools.jwt_tool` (`token` or `args`),
  `tools.graphql_cop.args`, `tools.kiterunner.wordlist` (or `args`),
  `tools.upload_scanner.args`, `tools.csrf_tester.args`.
- **Vhost enumeration:** `tools.ffuf.vhost_wordlist` controls the wordlist used by the web workflow.
- **Recon workflow:** `tools.whatweb` / `tools.retire` affect technology detection.
- **Network workflow:** `tools.enum4linux` (null session defaults), `tools.onesixtyone.community` (passed to `snmpwalk`).

If a tool isn't installed or the required config is missing, the step is skipped and logged. See
`workflows/*.yaml` for exact step definitions and conditions.

### `output`

Report/output location and verbosity:

- `format`: `markdown` | `html` | `json`
- `save_path`: where sessions/reports are written (default `./reports`)
- `verbosity`: `quiet` | `normal` | `verbose` | `debug`

### `reporting`

Reporting-time enrichment and filtering:

- `deduplicate_findings`: merge duplicate findings across tools
- `merge_duplicate_evidence`: merge evidence text from duplicates
- `enable_confidence_scoring`: annotate findings with confidence scores
- `min_confidence`: `high` | `medium` | `low`
- `verbose_reporting`: include low-confidence findings even if filtering is enabled
- `filter_low_confidence`: drop findings below `min_confidence`

### `logging`

Audit and runtime logging:

- `enabled`: enable logs
- `path`: log file path (default `./logs/guardian.log`)
- `level`: `DEBUG` | `INFO` | `WARNING` | `ERROR`
- `log_ai_decisions`: include AI decision traces in logs
