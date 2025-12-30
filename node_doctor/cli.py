#!/usr/bin/env python3
"""
Command-line interface for Node Doctor.
"""

import click
from node_doctor import __version__


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
    
    click.echo("Node Doctor v{}".format(__version__))
    click.echo("=" * 50)
    click.echo()
    
    # TODO: Implement actual scanning logic
    click.echo("🔍 Starting relay configuration scan...")
    click.echo()
    
    if system:
        click.echo("⚠️  System-level checks requested (may require elevated privileges)")
        if not click.confirm("Continue with system checks?"):
            click.echo("Skipping system checks.")
            system = False
    
    if network:
        click.echo("⚠️  Network checks will make external connections")
        if not click.confirm("Continue with network checks?"):
            click.echo("Skipping network checks.")
            network = False
    
    click.echo()
    click.echo("✅ Scan complete!")
    click.echo()
    click.echo("Note: This is a development version. Actual checks not yet implemented.")


if __name__ == '__main__':
    main()
