#!/usr/bin/env python3

import click
import shodan
import os
import sys

from modules.orca_helpers import setup_pyasn, check_pyasn_ready
from modules.orca_dbconn import OrcaDbConnector

# CONSTANTS
import settings
settings.ORCA_PROJECTS = OrcaDbConnector().list_projects()

# CLI Subcommands
from cli.add import add
from cli.discover import discover
from cli.enumerate import enum
from cli.explore import explore
from cli.export import export

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def cli():
    pass


cli.add_command(add)
cli.add_command(discover)
cli.add_command(enum)
cli.add_command(explore)
cli.add_command(export)


@cli.command()
@click.argument('key', metavar='<shodan api key>')
def init(key):
    """Initialize the Orca command-line"""
    # Create the directory if necessary
    orca_dir = os.path.expanduser(settings.ORCA_CONFIG_DIR)
    if not os.path.isdir(orca_dir):
        try:
            os.mkdir(orca_dir)
        except OSError:
            raise click.ClickException('Unable to create directory to store the Shodan API key ({})'.format(orca_dir))

    # Make sure it's a valid API key
    key = key.strip()
    try:
        api = shodan.Shodan(key)
        api.info()
    except shodan.APIError as e:
        click.echo(click.style('Error, invalid API key', bg='red'))
        raise click.ClickException(e.value)

    # Store the API key in the user's directory
    keyfile = orca_dir + '/shodan_api_key'
    with open(keyfile, 'w') as fout:
        fout.write(key.strip())
        click.echo(click.style('API Successfully initialized. Profile stored in: {}'.format(orca_dir), fg='green'))

    os.chmod(keyfile, 0o600)

    check_ready()


def check_ready():
    if not check_pyasn_ready():
        setup_pyasn()
        sys.exit()


if __name__ == '__main__':
    cli()

