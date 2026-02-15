"""
guardian ai explain - Explain AI decisions
"""

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json

from utils.helpers import load_config
from utils.session_paths import resolve_session_file, find_latest_session_file

console = Console()


def explain_command(
    session_id: str = typer.Option(None, "--session", "-s", help="Session ID to explain"),
    last: bool = typer.Option(False, "--last", "-l", help="Explain last AI decision"),
    all: bool = typer.Option(False, "--all", "-a", help="Show all AI decisions"),
    format: str = typer.Option("table", "--format", "-f", help="Output format (table, json)")
):
    """
    Explain AI decisions and reasoning
    
    Shows the decision-making process of Guardian's AI agents,
    including what actions were taken and why.
    """
    console.print("[bold cyan]🤖 AI Decision Explanation[/bold cyan]\n")

    config = load_config()
    if not session_id and not last:
        console.print("[yellow]Please specify --session <id> or use --last[/yellow]")
        console.print("Use 'ls reports/' to see available sessions")
        raise typer.Exit(1)
    
    # Load session data
    if session_id:
        session_file = resolve_session_file(config, session_id)
    else:
        # Find most recent session
        session_file = find_latest_session_file(config)
    
    if not session_file or not session_file.exists():
        console.print(f"[red]Session file not found: {session_file}[/red]")
        raise typer.Exit(1)
    
    # Load and display decisions
    with open(session_file, 'r') as f:
        session = json.load(f)
    
    ai_decisions = session.get("ai_decisions", [])
    
    if not ai_decisions:
        console.print("[yellow]No AI decisions found in this session[/yellow]")
        return
    
    if format == "json":
        console.print_json(data=ai_decisions)
    else:
        _display_decisions_table(ai_decisions, all=all)


def _display_decisions_table(decisions: list, all: bool = False):
    """Display AI decisions in a rich table"""
    table = Table(title="AI Decisions")
    table.add_column("Agent", style="cyan")
    table.add_column("Decision", style="green")
    table.add_column("Reasoning", style="white")
    table.add_column("Time", style="yellow")
    
    # Show only last decision or all
    display_decisions = decisions if all else decisions[-1:]
    
    for d in display_decisions:
        agent = d.get("agent", "Unknown")
        decision = d.get("decision", "")[:50]
        reasoning = d.get("reasoning", "")[:100]
        timestamp = d.get("timestamp", "")[:19]
        
        table.add_row(agent, decision, reasoning + "...", timestamp)
    
    console.print(table)
    
    # Show detailed panel for last decision
    if not all and decisions:
        last_decision = decisions[-1]
        
        detail = f"""[bold]Agent:[/bold] {last_decision.get('agent')}
[bold]Decision:[/bold] {last_decision.get('decision')}

[bold]Full Reasoning:[/bold]
{last_decision.get('reasoning')}
"""
        
        console.print(Panel(detail, title="Latest AI Decision", border_style="cyan"))
        
        if len(decisions) > 1:
            console.print(f"\n[dim]Showing 1 of {len(decisions)} decisions. Use --all to see all.[/dim]")
