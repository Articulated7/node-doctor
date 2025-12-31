#!/usr/bin/env python3
"""
Command-line interface for Node Doctor.
"""

import click
from node_doctor import __version__
from node_doctor.scanner import Scanner


@click.group()
@click.version_option(version=__version__)
def main():
    """Node Doctor - Tor relay configuration and security auditing tool."""
    pass


@main.command()
@click.option('--system', is_flag=True, help='Include system-level checks (may require sudo)')
@click.option('--network', is_flag=True, help='Include network connectivity checks')
@click.option('--full', is_flag=True, help='Run all checks')
def scan(system, network, full):
    """Scan the Tor relay configuration for issues."""
    if full:
        system = True
        network = True
    
    click.echo(f"Node Doctor v{__version__}")
    click.echo("=" * 70)
    click.echo()
    
    click.echo("🔍 Starting relay configuration scan...")
    click.echo()
    
    # Confirm for privileged operations
    if system:
        click.echo("⚠️  System-level checks requested (may require elevated privileges)")
        if not click.confirm("Continue with system checks?", default=True):
            click.echo("Skipping system checks.")
            system = False
        click.echo()
    
    if network:
        click.echo("⚠️  Network checks will make external connections")
        if not click.confirm("Continue with network checks?", default=True):
            click.echo("Skipping network checks.")
            network = False
        click.echo()
    
    # Create and run scanner
    scanner = Scanner(include_system=system, include_network=network)
    scanner.run_all_checks()
    scanner.print_results()


if __name__ == '__main__':
    main()
