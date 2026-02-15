"""
guardian report - Generate reports
"""

import typer
from rich.console import Console
from pathlib import Path

console = Console()


def report_command(
    session_id: str = typer.Option(..., "--session", "-s", help="Session ID to generate report for"),
    format: str = typer.Option("markdown", "--format", "-f", help="Report format (markdown, html, json)"),
    output: Path = typer.Option(None, "--output", "-o", help="Output file path"),
    config_file: Path = typer.Option(
        "config/guardian.yaml",
        "--config",
        "-c",
        help="Configuration file path"
    )
):
    """
    Generate penetration testing report
    
    Creates a professional report from session data.
    """
    import asyncio
    from pathlib import Path
    from utils.helpers import load_config
    from utils.session_paths import apply_session_paths, resolve_session_file
    from core.memory import PentestMemory
    from core.reporter_agent import ReporterAgent
    from ai.provider_factory import get_llm_client
    
    console.print(f"[bold cyan]📄 Generating Report: {session_id}[/bold cyan]\n")
    
    try:
        # Load configuration and session
        config = load_config(str(config_file))
        if not config:
            console.print("[bold red]Error:[/bold red] Failed to load configuration")
            raise typer.Exit(1)

        session_file = resolve_session_file(config, session_id)
        if not session_file.exists():
            console.print(f"[red]Session not found: {session_file}[/red]")
            raise typer.Exit(1)

        session_dir = apply_session_paths(config, session_id)
        memory = PentestMemory(target="")
        memory.load_state(session_file)
        
        # Initialize Reporter Agent
        llm_client = get_llm_client(config)
        reporter = ReporterAgent(config, llm_client, memory)
        
        async def _generate_reports():
            outputs = []
            sections = await reporter.generate_sections()
            for fmt, ext in (("markdown", "md"), ("html", "html")):
                console.print(f"Generating {fmt} report...")
                content = await reporter.assemble_report(fmt, sections)

                if output:
                    base = output.with_suffix("")
                    out_path = base.with_suffix(f".{ext}")
                else:
                    out_path = session_dir / f"report_{session_id}.{ext}"

                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                outputs.append((fmt, out_path))
            return outputs

        # Generate markdown and html in one event loop
        outputs = asyncio.run(_generate_reports())
        
        console.print(f"\n[green]✓ Reports generated successfully![/green]")
        for fmt, path in outputs:
            console.print(f"{fmt.upper()}: [cyan]{path}[/cyan]")
        console.print(f"Findings: [cyan]{len(memory.findings)}[/cyan]")
        
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise typer.Exit(1)
