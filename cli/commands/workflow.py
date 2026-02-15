"""
guardian workflow - Run predefined workflows
"""

import typer
import asyncio
import yaml
from rich.console import Console
from rich.table import Table
from pathlib import Path

from utils.helpers import load_config
from utils.session_paths import resolve_session_file, find_latest_session_file
from core.memory import PentestMemory
from core.workflow import WorkflowEngine

console = Console()


def workflow_command(
    action: str = typer.Argument(..., help="Action: 'run' or 'list'"),
    name: str = typer.Option(None, "--name", "-n", help="Workflow name (recon, web, network, autonomous)"),
    target: str = typer.Option(None, "--target", "-t", help="Target for the workflow"),
    source: str = typer.Option(None, "--source", "-s", help="Path to source code for whitebox analysis (web and autonomous workflows)"),
    resume: str = typer.Option(None, "--resume", help="Resume from a session id or path (use 'latest' for newest)"),
    auto_exploit: bool = typer.Option(False, "--auto-exploit", help="Enable automatic exploitation of findings"),
    auto_exploit_no_confirm: bool = typer.Option(False, "--auto-exploit-no-confirm", help="Skip confirmation prompts for auto-exploit"),
    config_file: Path = typer.Option(
        "config/guardian.yaml",
        "--config",
        "-c",
        help="Configuration file path"
    )
):
    """
    Run or list penetration testing workflows
    
    Available workflows:
    - recon: Reconnaissance workflow
    - web: Web application pentest
    - network: Network infrastructure pentest
    - autonomous: AI-driven autonomous testing
    """
    if action == "list":
        _list_workflows()
        return
    
    if action == "run":
        if not name:
            console.print("[bold red]Error:[/bold red] --name is required for 'run' action")
            raise typer.Exit(1)

        if not target and not resume:
            console.print("[bold red]Error:[/bold red] --target is required for 'run' action unless --resume is used")
            raise typer.Exit(1)

        _run_workflow(name, target, config_file, resume, auto_exploit, auto_exploit_no_confirm, source)
    else:
        console.print(f"[bold red]Error:[/bold red] Unknown action: {action}")
        raise typer.Exit(1)


def _list_workflows():
    """List available workflows"""
    table = Table(title="Available Workflows")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")

    workflows_dir = Path(__file__).resolve().parent.parent.parent / "workflows"

    aliases = {
        "recon": "recon",
        "web": "web_pentest",
        "network": "network_pentest",
        "autonomous": "autonomous",
    }

    workflows: dict[str, str] = {}
    for name, target in aliases.items():
        description = "Workflow"
        if workflows_dir.exists():
            path = workflows_dir / f"{target}.yaml"
            if path.exists():
                try:
                    data = yaml.safe_load(path.read_text()) or {}
                    description = data.get("description") or description
                except Exception:
                    pass
        if target != name:
            description = f"{description} (workflow: {target})"
        workflows[name] = description

    if workflows_dir.exists():
        for path in sorted(workflows_dir.glob("*.yaml")):
            name = path.stem
            if name in workflows or name in aliases.values():
                continue
            description = "Custom workflow"
            try:
                data = yaml.safe_load(path.read_text()) or {}
                description = data.get("description") or description
            except Exception:
                pass
            workflows[name] = description

    for name, description in workflows.items():
        table.add_row(name, description)

    console.print(table)


def _run_workflow(name: str, target: str, config_file: Path, resume: str = None, auto_exploit: bool = False, auto_exploit_no_confirm: bool = False, source: str = None):
    """Run a workflow"""
    try:
        config = load_config(str(config_file))
        if not config:
            console.print("[bold red]Error:[/bold red] Failed to load configuration")
            raise typer.Exit(1)

        # Validate source path if provided
        if source:
            source_path = Path(source)
            if not source_path.exists():
                console.print(f"[bold red]Error:[/bold red] Source path does not exist: {source}")
                raise typer.Exit(1)
            if not source_path.is_dir():
                console.print(f"[bold red]Error:[/bold red] Source path must be a directory: {source}")
                raise typer.Exit(1)

            # Check if workflow supports whitebox analysis
            if name not in ["web", "autonomous", "web_pentest"]:
                console.print(f"[bold yellow]⚠️  Warning:[/bold yellow] Workflow '{name}' may not fully support whitebox analysis")
                console.print("[yellow]Whitebox analysis is optimized for 'web' and 'autonomous' workflows[/yellow]")

            console.print(f"[bold cyan]🔍 Whitebox analysis enabled for source: {source}[/bold cyan]")

        # Override config with CLI flags for auto-exploit
        if auto_exploit:
            if "exploits" not in config:
                config["exploits"] = {}
            config["exploits"]["auto_exploit"] = True
            console.print("[bold yellow]⚠️  Auto-exploit enabled[/bold yellow]")

            if auto_exploit_no_confirm:
                config["exploits"]["auto_exploit_require_confirmation"] = False
                console.print("[bold yellow]⚠️  Auto-exploit confirmation disabled - exploits will run automatically![/bold yellow]")
            else:
                # Ensure confirmation is required by default when using CLI flag
                config["exploits"]["auto_exploit_require_confirmation"] = config.get("exploits", {}).get("auto_exploit_require_confirmation", True)
        
        memory = None
        if resume:
            if resume == "latest":
                session_file = find_latest_session_file(config)
            else:
                resume_path = Path(resume)
                if resume_path.exists():
                    session_file = resume_path
                else:
                    session_file = resolve_session_file(config, resume)
            if not session_file or not session_file.exists():
                console.print(f"[bold red]Error:[/bold red] Session not found for resume: {resume}")
                raise typer.Exit(1)

            memory = PentestMemory(target="")
            if not memory.load_state(session_file):
                console.print(f"[bold red]Error:[/bold red] Failed to load session state: {session_file}")
                raise typer.Exit(1)

            if target and target != memory.target:
                console.print(
                    f"[yellow]Warning:[/yellow] --target differs from session target; using {memory.target}"
                )
            target = memory.target

        if resume:
            console.print(f"[bold cyan]🔄 Resuming {name} workflow on {target}[/bold cyan]\n")
        else:
            console.print(f"[bold cyan]🚀 Running {name} workflow on {target}[/bold cyan]\n")

        engine = WorkflowEngine(config, target, memory=memory, source=source)
        
        if name == "autonomous":
            results = asyncio.run(engine.run_autonomous())
        else:
            results = asyncio.run(engine.run_workflow(name))

        status = results.get("status")
        if status == "stopped":
            console.print(f"\n[bold yellow]⏸ Workflow stopped[/bold yellow]")
            if results.get("stop_reason"):
                console.print(f"[yellow]{results['stop_reason']}[/yellow]")
            if results.get("session_id"):
                console.print(f"Session: [cyan]{results['session_id']}[/cyan]")
            if results.get("resume_command"):
                console.print(f"[cyan]Resume:[/cyan] {results['resume_command']}")
            if results.get("stop_file"):
                console.print(f"[dim]Details written to {results['stop_file']}[/dim]")
            return

        console.print(f"\n[bold green]✓ Workflow completed![/bold green]")
        console.print(f"Findings: [cyan]{results['findings']}[/cyan]")
        console.print(f"Session: [cyan]{results['session_id']}[/cyan]")
        
    except Exception as e:
        import traceback
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        console.print(f"[dim]Traceback: {traceback.format_exc()}[/dim]")
        raise typer.Exit(1)
