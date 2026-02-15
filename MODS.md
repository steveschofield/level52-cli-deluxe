# Guardian Modding Guide

Quick pointers for extending Guardian with new tools, workflows, or AI backends.

## Adding a New Tool
- Implement a tool class in `tools/` following existing patterns (e.g., `NmapTool`, `HttpxTool`).
- Wire it into `tools/__init__.py` and register it in `core/tool_agent.py` `available_tools`.
- Provide sensible defaults and guardrails (timeouts, safe args) in the tool config block in `config/guardian.yaml`.
- Update `setup.sh` with install steps (pip/go/gem/apt) so fresh environments can pull it automatically.
- If the tool needs external binaries, update the Dockerfile and/or docs and note platform quirks.

## Adding a Workflow
- Define a workflow YAML in `workflows/` or extend `_load_workflow` logic if using code-driven steps.
- Keep step names descriptive; ensure each step maps to a tool/action the agents understand.
- Update docs/README if the workflow should be user-facing.

## Changing AI Providers
- Guardian now supports Gemini (API key or Vertex/ADC), local LLMs via Ollama, and hosted models via OpenRouter (OpenAI-compatible API).
- Configure in `config/guardian.yaml` (or `~/.guardian/guardian.yaml`):
  ```yaml
  ai:
    provider: ollama   # or gemini / openrouter
    model: "llama3.1:8b"
    base_url: "http://127.0.0.1:11434"
  ```
- To add a new provider, implement a client in `ai/`, extend `ai/provider_factory.py`, and ensure it exposes `generate`, `generate_sync`, and `generate_with_reasoning`.
- Add any needed pip deps to `pyproject.toml` and Dockerfile.
- For Gemini higher limits without API keys, use Vertex AI + ADC: `gcloud auth application-default login` and set `ai.vertexai: true`, `ai.project`, `ai.location`.

## Adding OWASP ZAP
- ZAP is integrated as a Docker-first headless scanner (`tools/zap.py`) and can be enabled in `config/guardian.yaml` under `tools.zap`.
- Baseline scan is passive (safer). Full scan is active and should be gated behind `pentest.safe_mode: false` + confirmation.

## Scope/Safety
- Default scope blacklist lives in `config/guardian.yaml` (`scope.blacklist`). Adjust for lab/production needs.
- `safe_mode` and `require_confirmation` live under `pentest` config. Keep destructive actions gated.

## Testing Changes
- Run a local workflow: `python -m cli.main workflow run --name autonomous --target http://target`.
- For CLI help: `python -m cli.main --help`.
- Consider adding lightweight unit tests under `tests/` for new parsers/logic.

## Session Exports
- Workflows now emit helper files per session in `reports/`: `urls_<session>.txt` (deduped URLs) and `payloads_<session>.txt` (tool commands/payloads) for quick import into proxy/ZAP or other testers.
- When wiring new tools, make sure URLs are present in commands/output so `_extract_urls` can pick them up; keep files plaintext and newline-delimited.
- If you change report/output paths, ensure these exports remain easy to find and documented.

## Docs
- Update `README.md` when adding user-facing features or new requirements (including new tools).
- Keep install tables accurate (optional tools section, default config hints) when tooling changes.
