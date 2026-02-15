"""
guardian init - Initialize Guardian configuration
"""

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from pathlib import Path
import yaml

console = Console()


def init_command(
    config_dir: Path = typer.Option(
        Path.home() / ".guardian",
        "--config-dir",
        "-c",
        help="Configuration directory"
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Overwrite existing configuration"
    )
):
    """
    Initialize Guardian configuration
    
    Creates configuration files and sets up the environment.
    """
    console.print("[bold cyan]🔧 Initializing Guardian...[/bold cyan]\n")
    
    # Create config directory
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy default config
    config_file = config_dir / "guardian.yaml"
    env_file = config_dir / ".env"

    will_write_config = True
    if config_file.exists() and not force:
        if not Confirm.ask(f"Config file already exists at {config_file}. Overwrite?"):
            will_write_config = False
            console.print("[yellow]Skipping configuration file[/yellow]")

    provider: str | None = None
    if will_write_config or (not env_file.exists() or force):
        default_provider = "ollama"
        try:
            if config_file.exists():
                with open(config_file, "r") as f:
                    existing = yaml.safe_load(f) or {}
                default_provider = (existing.get("ai", {}) or {}).get("provider") or default_provider
        except Exception:
            pass

        provider = Prompt.ask(
            "Choose LLM provider",
            choices=["ollama", "gemini", "openrouter"],
            default=str(default_provider),
        ).strip()

    if will_write_config:
        _copy_default_config(config_file, provider=provider or "ollama")

    # Create .env file (optional for Gemini)
    if not env_file.exists() or force:
        console.print("\n[bold]API Key Setup[/bold]")
        provider = provider or "ollama"

        env_lines = []
        if provider == "gemini":
            api_key = Prompt.ask(
                "Enter your Google Gemini API key (leave blank to skip)", password=True
            ).strip()
            if api_key:
                env_lines.append(f"GOOGLE_API_KEY={api_key}\n")
        elif provider == "openrouter":
            api_key = Prompt.ask(
                "Enter your OpenRouter API key (leave blank to skip)", password=True
            ).strip()
            if api_key:
                env_lines.append(f"OPENROUTER_API_KEY={api_key}\n")

            site_url = Prompt.ask(
                "Optional: site URL for OpenRouter HTTP-Referer header (leave blank to skip)",
                default="",
            ).strip()
            if site_url:
                env_lines.append(f"OPENROUTER_SITE_URL={site_url}\n")

            app_name = Prompt.ask(
                "Optional: app name for OpenRouter X-Title header (leave blank to skip)",
                default="",
            ).strip()
            if app_name:
                env_lines.append(f"OPENROUTER_APP_NAME={app_name}\n")

        if env_lines:
            with open(env_file, "w") as f:
                f.writelines(env_lines)
            console.print(f"[green]✓[/green] Created environment file at {env_file}")
        else:
            console.print("[yellow]Skipped .env creation (no API key provided)[/yellow]")

    # Create reports directory
    reports_dir = Path("./reports")
    reports_dir.mkdir(exist_ok=True)
    console.print(f"[green]✓[/green] Created reports directory at {reports_dir}")
    
    # Create logs directory
    logs_dir = Path("./logs")
    logs_dir.mkdir(exist_ok=True)
    console.print(f"[green]✓[/green] Created logs directory at {logs_dir}")
    
    console.print(f"\n[bold green]✓ Guardian initialized successfully![/bold green]")
    console.print(f"\nConfiguration directory: [cyan]{config_dir}[/cyan]")
    console.print(f"Next steps:")
    console.print(f"  1. Edit {config_file} to customize settings")
    console.print(f"  2. Run 'guardian scan --target example.com' to start scanning")


def _copy_default_config(dest: Path, provider: str = "ollama"):
    """Copy default configuration file"""
    provider = (provider or "ollama").strip().lower()
    if provider not in {"ollama", "gemini", "openrouter"}:
        provider = "ollama"

    if provider == "gemini":
        ai_block = """ai:
  provider: gemini
  model: "gemini-2.5-pro"
  temperature: 0.2
"""
    elif provider == "openrouter":
        ai_block = """ai:
  provider: openrouter
  model: "openai/gpt-4o-mini"
  base_url: "https://openrouter.ai/api/v1"
  temperature: 0.2
"""
    else:
        ai_block = """ai:
  provider: ollama
  model: "llama3.1:8b"
  base_url: "http://127.0.0.1:11434"
  temperature: 0.2
"""

    default_config = f"""# Guardian Configuration
{ai_block}
# Alternate providers:
# ai:
#   provider: gemini
#   model: "gemini-2.5-pro"
#
# ai:
#   provider: openrouter
#   model: "openai/gpt-4o-mini"
#   base_url: "https://openrouter.ai/api/v1"

pentest:
  safe_mode: true
  require_confirmation: true
  max_parallel_tools: 3

output:
  format: markdown
  save_path: ./reports
  verbosity: normal

scope:
  blacklist:
    - 127.0.0.0/8
"""

    with open(dest, "w") as f:
        f.write(default_config)

    console.print(f"[green]✓[/green] Created configuration file at {dest}")
