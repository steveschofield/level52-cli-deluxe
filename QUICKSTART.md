# Guardian Quick Start Guide

## Installation (Kali Linux)

1. **Navigate to project directory**:
   ```bash
   cd /path/to/guardian-cli-deluxe
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Guardian and tools**:
   ```bash
   ./setup.sh 2>&1 | tee setup.log
   ```

4. **Initialize configuration**:
   ```bash
   python -m cli.main init
   ```

## Common Commands

### List Available Workflows
```bash
python -m cli.main workflow list
```

### Dry Run Reconnaissance
```bash
python -m cli.main recon --domain example.com --dry-run
```

### Run Port Scan (requires nmap)
```bash
python -m cli.main scan --target scanme.nmap.org
```

### Run Full Workflow
```bash
python -m cli.main workflow run --name recon --target example.com
python -m cli.main workflow run --name recon_quick --target example.com
python -m cli.main workflow run --name quick_vuln_scan --target https://example.com
```

## Configuration

Edit `config/guardian.yaml` (when running from this repo) or `~/.guardian/guardian.yaml` (when using `guardian init`) to customize:
- AI model and settings
- Tool configurations
- Security guardrails
- Output formats

If you’re using `~/.guardian/guardian.yaml`, pass it explicitly:
```bash
python -m cli.main recon --domain example.com --config ~/.guardian/guardian.yaml
```

## Getting Help

```bash
python -m cli.main --help
python -m cli.main <command> --help
```

## Important Notes

- **API Key**: Required for hosted LLMs (Gemini: https://makersuite.google.com/app/apikey, OpenRouter: https://openrouter.ai/keys). Not required for local Ollama.
- **External Tools**: Installed via `./setup.sh` (nmap, httpx, subfinder, nuclei, nikto, etc.).
- **Authorization**: Only scan systems you have explicit permission to test.
- **Workflow steps**: Default YAML workflows include DNS/OSINT, vhost, SMB/SNMP, and client-side checks. Some steps (hydra/jwt/graphql/upload/csrf) require config and are skipped if not set.

## Troubleshooting

### Command not found
- Make sure you're in the project directory
- Activate the virtual environment
- Use `python -m cli.main` instead of `guardian`

### Import errors
- Reinstall dependencies: run `./setup.sh`
- Check Python version: `python --version` (requires 3.11+)

### masscan permission denied
- `./setup.sh` attempts to set capabilities for non-root use
- If it still fails: `sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)"`

### API errors
- Verify your Gemini API key in `.env` (project root) or `~/.guardian/.env`
- If using OpenRouter, verify `OPENROUTER_API_KEY` in `.env` (project root) or `~/.guardian/.env`
- If using Gemini Vertex/ADC, ensure `gcloud auth application-default login` has been run and `ai.project` is set in your config
- Check internet connectivity

## Next Steps

1. Review `config/guardian.yaml` and customize settings
2. Run `--dry-run` mode to see what would be executed
3. Start with safe targets like `scanme.nmap.org`
4. Review logs in `logs/guardian.log`
