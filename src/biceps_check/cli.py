"""
Command-line interface for Biceps-Check.

This module provides the CLI entry point and command definitions for
the biceps-check tool.
"""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from biceps_check import __version__
from biceps_check.config import load_config
from biceps_check.output.cli_formatter import CLIFormatter
from biceps_check.output.json_formatter import JSONFormatter
from biceps_check.output.sarif_formatter import SARIFFormatter
from biceps_check.rules.base import Severity
from biceps_check.runner import BicepsCheckRunner

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="biceps-check")
def main() -> None:
    """Biceps-Check: Security scanner for Azure Bicep templates."""


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["cli", "json", "sarif"]),
    default="cli",
    help="Output format",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(),
    help="Output file path (stdout if not specified)",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Path to configuration file",
)
@click.option(
    "--check",
    multiple=True,
    help="Specific check IDs to run (can be specified multiple times)",
)
@click.option(
    "--skip-check",
    multiple=True,
    help="Check IDs to skip (can be specified multiple times)",
)
@click.option(
    "--min-severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    default="INFO",
    help="Minimum severity level to report",
)
@click.option(
    "--compact",
    is_flag=True,
    help="Use compact output format",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable colored output",
)
@click.option(
    "--fail-on",
    type=click.Choice(["any", "high", "critical"]),
    default="any",
    help="Exit with error code when findings match severity",
)
@click.option(
    "--recursive/--no-recursive",
    default=True,
    help="Scan directories recursively",
)
def scan(
    path: str,
    output: str,
    output_file: Optional[str],
    config: Optional[str],
    check: tuple[str, ...],
    skip_check: tuple[str, ...],
    min_severity: str,
    compact: bool,
    no_color: bool,
    fail_on: str,
    recursive: bool,
) -> None:
    """Scan Bicep files for security issues.

    PATH can be a file or directory to scan.
    """
    # Load configuration
    cfg = load_config(config)

    # Override config with CLI options
    if check:
        cfg.checks.enable = list(check)
    if skip_check:
        cfg.checks.skip = list(skip_check)

    cfg.min_severity = Severity[min_severity]

    # Create runner
    runner = BicepsCheckRunner(config=cfg)

    # Run scan
    scan_path = Path(path)
    if scan_path.is_file():
        results = runner.scan_file(scan_path)
    else:
        results = runner.scan_directory(scan_path, recursive=recursive)

    # Format output
    formatter = _get_formatter(output, no_color, compact)
    formatted_output = formatter.format(results)

    # Write output
    if output_file:
        Path(output_file).write_text(formatted_output)
        console.print(f"Results written to: {output_file}")
    else:
        console.print(formatted_output)

    # Exit code
    exit_code = _get_exit_code(results, fail_on)
    raise SystemExit(exit_code)


@main.command()
@click.option(
    "--rule",
    "-r",
    help="Show details for a specific rule ID",
)
@click.option(
    "--category",
    "-c",
    type=click.Choice(
        [
            "compute",
            "storage",
            "networking",
            "database",
            "identity",
            "monitoring",
            "messaging",
            "integration",
            "analytics",
            "security",
        ]
    ),
    help="Filter rules by category",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    help="Filter rules by severity",
)
def list_rules(
    rule: Optional[str],
    category: Optional[str],
    severity: Optional[str],
) -> None:
    """List available security rules."""
    from biceps_check.rules.registry import RuleRegistry

    registry = RuleRegistry()
    registry.load_all_rules()

    if rule:
        # Show specific rule details
        rule_obj = registry.get_rule(rule)
        if rule_obj:
            _print_rule_details(rule_obj)
        else:
            console.print(f"[red]Rule not found: {rule}[/red]")
            raise SystemExit(1)
    else:
        # List rules with filters
        rules = registry.get_rules(
            category=category,
            severity=Severity[severity] if severity else None,
        )
        _print_rules_table(rules)


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--check",
    "-c",
    required=True,
    help="Check ID to generate fix for",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show proposed changes without applying",
)
def fix(path: str, check: str, dry_run: bool) -> None:
    """Generate and optionally apply fixes for security issues."""
    console.print("[yellow]Auto-fix feature coming soon![/yellow]")
    raise SystemExit(0)


@main.command()
def init() -> None:
    """Initialize a new .biceps-check.yaml configuration file."""
    from biceps_check.config import generate_default_config

    config_path = Path(".biceps-check.yaml")
    if config_path.exists():
        console.print("[yellow]Configuration file already exists.[/yellow]")
        raise SystemExit(1)

    config_content = generate_default_config()
    config_path.write_text(config_content)
    console.print(f"[green]Created configuration file: {config_path}[/green]")


def _get_formatter(output: str, no_color: bool, compact: bool):
    """Get the appropriate output formatter."""
    formatters = {
        "cli": CLIFormatter(no_color=no_color, compact=compact),
        "json": JSONFormatter(),
        "sarif": SARIFFormatter(),
    }
    formatter = formatters.get(output)
    if formatter is None:
        raise click.UsageError(f"Output format '{output}' is not yet implemented.")
    return formatter


def _get_exit_code(results, fail_on: str) -> int:
    """Determine exit code based on results and fail_on setting."""
    if not results.failed_checks:
        return 0

    if fail_on == "any":
        return 1

    severities = {check.severity for check in results.failed_checks}

    if fail_on == "critical" and Severity.CRITICAL in severities:
        return 1
    if fail_on == "high" and (Severity.CRITICAL in severities or Severity.HIGH in severities):
        return 1

    return 0


def _print_rule_details(rule) -> None:
    """Print detailed information about a rule."""
    from rich.markdown import Markdown
    from rich.panel import Panel

    content = f"""
**ID:** {rule.id}
**Name:** {rule.name}
**Severity:** {rule.severity.name}
**Category:** {rule.category}

**Description:**
{rule.description}

**Resource Types:**
{", ".join(rule.resource_types)}

**Remediation:**
{rule.remediation}

**References:**
{chr(10).join(f"- {ref}" for ref in rule.references)}
"""
    console.print(Panel(Markdown(content), title=f"Rule: {rule.id}"))


def _print_rules_table(rules) -> None:
    """Print a table of rules."""
    from rich.table import Table

    table = Table(title="Security Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Resource Types")

    for rule in rules:
        severity_color = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "orange1",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "dim",
        }.get(rule.severity, "white")

        table.add_row(
            rule.id,
            rule.name,
            f"[{severity_color}]{rule.severity.name}[/{severity_color}]",
            rule.category,
            ", ".join(rule.resource_types[:2]) + ("..." if len(rule.resource_types) > 2 else ""),
        )

    console.print(table)


if __name__ == "__main__":
    main()
