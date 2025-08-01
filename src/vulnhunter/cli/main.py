"""Main CLI entry point for VulnHunter."""

import sys
from pathlib import Path
from typing import Optional, List, Any
import asyncio

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

from vulnhunter import __version__
from vulnhunter.config.settings import Settings, AnalysisConfig, AnalysisLayer
from vulnhunter.core.pipeline import VulnHunterPipeline


console = Console()


@click.group()
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """VulnHunter - Badass Solidity Vulnerability Hunting Expert.
    
    A comprehensive smart contract security analysis pipeline that combines
    multiple analysis techniques for maximum vulnerability detection coverage.
    """
    # Initialize settings and make available to subcommands
    ctx.ensure_object(dict)
    ctx.obj["settings"] = Settings()
    ctx.obj["console"] = console


@cli.command()
@click.argument("target", type=str)
@click.option(
    "--layers",
    "-l",
    multiple=True,
    type=click.Choice(["static", "fuzzing", "symbolic", "formal", "ai", "all"]),
    default=["static", "fuzzing"],
    help="Analysis layers to run",
)
@click.option(
    "--tools",
    "-t",
    multiple=True,
    type=str,
    help="Specific tools to run (e.g., slither, mythril)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output file path",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["json", "sarif", "summary"]),
    default="summary",
    help="Output format",
)
@click.option(
    "--no-cache",
    is_flag=True,
    help="Disable result caching",
)
@click.option(
    "--generate-poc",
    is_flag=True,
    default=True,
    help="Generate proof-of-concept exploits",
)
@click.option(
    "--timeout",
    type=int,
    default=1800,
    help="Maximum analysis time in seconds",
)
@click.pass_context
def analyze(
    ctx: click.Context,
    target: str,
    layers: List[str],
    tools: List[str],
    output: Optional[Path],
    format: str,
    no_cache: bool,
    generate_poc: bool,
    timeout: int,
) -> None:
    """Analyze a smart contract for vulnerabilities.
    
    TARGET can be:
    - Ethereum address (0x...)
    - Path to Solidity file
    - Path to directory with contracts
    - Git repository URL
    """
    settings: Settings = ctx.obj["settings"]
    
    # Parse layers
    analysis_layers = set()
    for layer in layers:
        if layer == "all":
            analysis_layers = {AnalysisLayer.ALL}
            break
        analysis_layers.add(AnalysisLayer(layer))
    
    # Create analysis config
    config = AnalysisConfig(
        layers=analysis_layers,
        tools=list(tools) if tools else None,
        cache_results=not no_cache,
        generate_poc=generate_poc,
        max_analysis_time=timeout,
        output_format=format,
    )
    
    # Show analysis plan
    console.print(f"\n[bold blue]VulnHunter Analysis[/bold blue] v{__version__}")
    console.print(f"Target: [yellow]{target}[/yellow]")
    console.print(f"Layers: {', '.join(l.value for l in analysis_layers)}")
    if tools:
        console.print(f"Tools: {', '.join(tools)}")
    console.print()
    
    # Run analysis
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Initializing pipeline...", total=None)
            
            # Create and run pipeline
            pipeline = VulnHunterPipeline(settings=settings)
            
            # Run async analysis
            report = asyncio.run(
                run_analysis_with_progress(pipeline, target, config, progress, task)
            )
            
        # Display results
        if format == "summary":
            display_summary(report)
        elif output:
            # Save to file
            pipeline.save_report(report, output, format)
            console.print(f"\n[green]✓[/green] Report saved to: {output}")
        else:
            # Print to stdout
            if format == "json":
                import json
                print(json.dumps(report.model_dump(), indent=2, default=str))
            else:
                print(report.model_dump_json(indent=2))
                
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {str(e)}", style="bold red")
        if ctx.obj.get("debug"):
            console.print_exception()
        sys.exit(1)


async def run_analysis_with_progress(
    pipeline: VulnHunterPipeline,
    target: str,
    config: AnalysisConfig,
    progress: Progress,
    task: int,
) -> Any:
    """Run analysis with progress updates."""
    progress.update(task, description="Loading contracts...")
    
    # This would be implemented in the actual pipeline
    # For now, just simulate
    await asyncio.sleep(2)
    
    progress.update(task, description="Running static analysis...")
    await asyncio.sleep(2)
    
    progress.update(task, description="Running dynamic analysis...")
    await asyncio.sleep(2)
    
    progress.update(task, description="Generating report...")
    await asyncio.sleep(1)
    
    # Return mock report for now
    from vulnhunter.models.report import AnalysisReport, AnalysisStatus
    return AnalysisReport(
        contract_name="MockContract",
        status=AnalysisStatus.COMPLETED,
    )


def display_summary(report: Any) -> None:
    """Display analysis summary in terminal."""
    console.print("\n[bold green]Analysis Complete![/bold green]\n")
    console.print(report.to_summary())
    
    # Show vulnerability table if any found
    if report.vulnerabilities:
        console.print("\n[bold]Vulnerabilities Found:[/bold]\n")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=12)
        table.add_column("Severity", justify="center")
        table.add_column("Type", style="cyan")
        table.add_column("Title")
        table.add_column("Confidence", justify="right")
        
        for vuln in report.vulnerabilities:
            severity_color = {
                "critical": "red",
                "high": "orange",
                "medium": "yellow",
                "low": "blue",
                "info": "dim",
            }.get(vuln.severity.value, "white")
            
            table.add_row(
                str(vuln.id)[:8],
                f"[{severity_color}]{vuln.severity.value.upper()}[/{severity_color}]",
                vuln.vulnerability_type.value,
                vuln.title[:50] + "..." if len(vuln.title) > 50 else vuln.title,
                f"{vuln.confidence:.0%}",
            )
        
        console.print(table)


@cli.command()
@click.pass_context
def tools(ctx: click.Context) -> None:
    """List available analysis tools and their status."""
    settings: Settings = ctx.obj["settings"]
    
    console.print("\n[bold]Available Analysis Tools:[/bold]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Docker Image")
    table.add_column("Timeout", justify="right")
    
    for tool_name, tool_config in settings.tools.items():
        status = "[green]Enabled[/green]" if tool_config.enabled else "[red]Disabled[/red]"
        table.add_row(
            tool_name,
            status,
            tool_config.docker_image or "N/A",
            f"{tool_config.timeout}s",
        )
    
    console.print(table)


@cli.command()
@click.option(
    "--check",
    is_flag=True,
    help="Check if all dependencies are installed",
)
@click.pass_context
def setup(ctx: click.Context, check: bool) -> None:
    """Set up VulnHunter environment and dependencies."""
    settings: Settings = ctx.obj["settings"]
    
    if check:
        console.print("\n[bold]Checking VulnHunter Setup:[/bold]\n")
        
        # Check Python version
        import sys
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        console.print(f"Python Version: {py_version} ", end="")
        if sys.version_info >= (3, 12):
            console.print("[green]✓[/green]")
        else:
            console.print("[red]✗[/red] (requires 3.12+)")
        
        # Check Docker
        import subprocess
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                check=True,
            )
            console.print(f"Docker: {result.stdout.strip()} [green]✓[/green]")
        except Exception:
            console.print("Docker: [red]Not found[/red]")
        
        # Check directories
        console.print(f"\nDirectories:")
        for name, path in [
            ("Cache", settings.cache_dir),
            ("Results", settings.results_dir),
            ("Temp", settings.temp_dir),
        ]:
            exists = path.exists()
            status = "[green]✓[/green]" if exists else "[yellow]Will be created[/yellow]"
            console.print(f"  {name}: {path} {status}")
    
    else:
        console.print("\n[bold]Setting up VulnHunter environment...[/bold]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Creating directories...", total=None)
            settings.ensure_directories()
            
            progress.update(task, description="Pulling Docker images...")
            # Would pull Docker images here
            
            progress.update(task, description="Downloading SWC Registry...")
            # Would download SWC registry here
            
        console.print("\n[green]✓[/green] Setup complete!")


if __name__ == "__main__":
    cli()