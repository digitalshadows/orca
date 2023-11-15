import click
from modules import orca_reporting
from modules.orca_dbconn import OrcaDbConnector
from modules.orca_helpers import validate_filename
from settings import ORCA_PROJECTS

from . import CONTEXT_SETTINGS


@click.group(context_settings=CONTEXT_SETTINGS, short_help='Export data to a file.')
def export():
    pass


@export.command('file_xlsx', short_help='Output results to XLSX file.')
@click.option("--filename", required=True, callback=validate_filename, help='File name to save the results into')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def export_data_xlsx(project, filename):
    orca_dbconn = OrcaDbConnector(project)
    orca_reporting.create_xlsx(orca_dbconn, project, filename)
