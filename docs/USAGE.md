# Guardian CLI Usage

This is a short reference for the built-in commands. Use `python -m cli.main ...` when `guardian` is not on PATH.

## Help

```bash
python -m cli.main --help
python -m cli.main <command> --help
```

## Initialize Config

Creates `~/.guardian/guardian.yaml` (and optionally `~/.guardian/.env`):

```bash
python -m cli.main init
```

## Quick Scan (Nmap)

```bash
python -m cli.main scan --target scanme.nmap.org
python -m cli.main scan --target scanme.nmap.org --ports 80,443
```

## Recon Workflow

```bash
python -m cli.main recon --domain example.com
python -m cli.main recon --domain example.com --dry-run
```
> Note: Nmap vuln scans use `--script vuln,vulners` by default (see `tools.nmap.vuln_args`).

## Workflows

```bash
python -m cli.main workflow list
python -m cli.main workflow run --name recon --target example.com
python -m cli.main workflow run --name recon_quick --target example.com
python -m cli.main workflow run --name web --target https://example.com
python -m cli.main workflow run --name quick_vuln_scan --target https://example.com
python -m cli.main workflow run --name wordpress_audit --target https://example.com
python -m cli.main workflow run --name autonomous --target example.com
```

## Reports

```bash
python -m cli.main report --session <SESSION_ID>
python -m cli.main report --session <SESSION_ID> --output ./reports/my_report
```

## Explain AI Decisions

```bash
python -m cli.main ai --help
python -m cli.main ai --last
```

## Using a Specific Config File

Every command accepts `--config`:

```bash
python -m cli.main recon --domain example.com --config ~/.guardian/guardian.yaml
```
