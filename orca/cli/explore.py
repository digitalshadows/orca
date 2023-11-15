import csv
import io
import textwrap

import click
from modules import orca_helpers, orca_tagging
from modules.orca_dbconn import OrcaDbConnector
from settings import ORCA_PROJECTS
from terminaltables import AsciiTable

from . import CONTEXT_SETTINGS


@click.group(context_settings=CONTEXT_SETTINGS, short_help='Explore discovered data, and manage projects.')
def explore():
    pass


@explore.command('delete_project', short_help='Delete an Orca project from the database')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def delete_project_db(project):
    if click.confirm(
            click.style("[?]", fg='yellow')
            + f" Are you sure you want to delete the {project} project?"
    ):
        click.secho(f"[!] Deleting all entries for {project}", bg='red')
        orca_dbconn = OrcaDbConnector(project)
        orca_dbconn.delete_all_entries(project)


@explore.command('show_assets', short_help='Show assets in the DB')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def show_assets_db(project):
    orca_dbconn = OrcaDbConnector(project)

    results = orca_dbconn.get_all_ad_entries()

    table_data = [["Asset ID", "Value", "Type", "Origin", "Infrastructure Check", "Verified", "Insert Time"]]
    table_data.extend(
        [
            str(result['asset_id']),
            result['asset_data_value'],
            result['asset_data_type'],
            result['asset_data_origin'],
            str(result['infra_check']),
            str(result['verified']),
            str(result['insert_time']),
        ]
        for result in results
    )
    table = AsciiTable(table_data)
    click.echo(table.table)


@explore.command('show_hosts', short_help='Show hosts in the host table in the DB')
@click.option('--output', '-o', 'output', help='Select how you would like the data to be displayed.'
                                               'Some information, such as banners, may be missing.',
              type=click.Choice(['table', 'csv']), default='table', show_default='table')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def show_hosts_db(project, output):
    orca_dbconn = OrcaDbConnector(project)

    results = orca_dbconn.get_all_host_table_entries()

    table_data = [["Host ID", "IP Address", "Hostname", "Shodan Hostname", "Asset ID", "In Shodan", "Host Data Origin"]]

    table_data.extend(
        [
            str(result['host_id']),
            result['ipaddr'],
            orca_helpers.list_to_string(result['hostname']),
            orca_helpers.list_to_string(result['shodan_hostname']).replace(
                ",", "\n"
            ),
            str(result['asset_id']),
            str(result['shodan']),
            str(result['host_data_origin']),
        ]
        for result in results
    )
    if output == 'csv':
        table_data = [[x.replace('\n', ',') for x in line] for line in table_data]  # remove newlines from rest of table

        output = io.StringIO()
        wr = csv.writer(output)
        wr.writerows(table_data)
        click.echo(output.getvalue())

    elif output == 'table':
        table = AsciiTable(table_data)
        table.title = 'Hosts Data'
        table.inner_row_border = True

        click.echo(table.table)


@explore.command('show_shodan', short_help='Show SHODAN results in the DB')
@click.option('--output', '-o', 'output', help='Select how you would like the data to be displayed.'
                                               'Some information, such as banners, may be missing.',
              type=click.Choice(['table', 'csv']))
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def show_shodan_db(project, output):
    orca_dbconn = OrcaDbConnector(project)

    def generate_table_data():
        results = orca_dbconn.get_all_shodan_entries()
        table_data = [
            ["Shodan\nID", "IP Address", "Asset\nID", "Host\nID", "Last Updated", "Modules", "Ports", "CPE", "Hostname",
             "Netname", "CIDR", "ASN", "Country"]]

        for result in results:
            table_data.append([
                str(result['shodan_id']), result['ipaddr'],
                str(result['asset_id']), str(result['host_id']),
                str(result['last_updated']),
                "\n".join(result['cli']),
                "\n".join(list(map(str, result['ports']))),
                orca_helpers.cpe_to_string(result['cpe']).replace(",", "\n"),
                orca_helpers.list_to_string(result['hostname']).replace(",", "\n"), str(result['netname']),
                str(result['cidr']), str(result['asn']),
                str(result['country'])
            ])
        return table_data

    if output == 'table':
        table = AsciiTable(generate_table_data())
        table.title = 'Shodan Data'
        table.inner_row_border = True

        if table.ok:
            click.echo(table.table)
        else:
            if click.confirm(
                    "[?] Your terminal is too small to display the table, the output might be a bit malformed. Would you like to continue?"):
                click.echo(table.table)

    elif output == 'csv':
        data = generate_table_data()
        data[0] = [x.replace('\n', ' ') for x in data[0]]  # Remove newlines from header of the table
        data = [[x.replace('\n', ',') for x in line] for line in data]  # remove newlines from rest of table

        output = io.StringIO()
        wr = csv.writer(output)
        wr.writerows(data)
        click.echo(output.getvalue())

    else:  # By default, print the host and service information separately.
        results = orca_dbconn.get_all_shodan_entries()

        for result in results:
            click.echo("\n")
            table_data = [
                ["Shodan Updated", str(result['last_updated'])],
                ["Date Added", str(result['added'])],
                ["Hostnames", orca_helpers.list_to_string(result['hostname']).replace(",", "\n")],
                ["Ports", ", ".join(list(map(str, result['ports'])))],
                ["Net Range", str(result['cidr'])],
                ["ASN", str(result['asn'])],
                ["Netname", str(result['netname'])],
                ["Country", str(result['country'])],
                ["Shodan Modules", ", ".join(result['cli'])]
                # ["CPEs ", orca_helpers.cpe_to_string(result['cpe']).replace(",", "\n")]
            ]

            table = AsciiTable(table_data)
            table.title = '[ Host - {}]'.format(result['ipaddr'])
            table.inner_heading_row_border = False
            click.echo(table.table)

            # Create a dict from the result data
            if result['cpe'] and 'cpe' in result['cpe']:
                cpedict = {}
                for k, v in [(key, d[key]) for d in result['cpe']['cpe'] for key in d]:
                    if k not in cpedict:
                        cpedict[k] = [v]
                    else:
                        cpedict[k].append(v)
            else:
                cpedict = None

            table_data = [["Shodan Module", "Port", "CPEs", "Banner"]]

            for i in range(len(list(dict.fromkeys(result['cli'])))):

                service_module = list(dict.fromkeys(result['cli']))[i]

                # Handles edge case where more cli than ports due to services listening on TCP & UDP with the same port number
                if i < len(result['ports']):
                    service_port = result['ports'][i]
                service_banner = textwrap.wrap(result['banner_shodan'][i].rstrip(), 100)

                if cpedict and service_module in cpedict:
                    service_cpes = cpedict[service_module][0]
                else:
                    service_cpes = None

                table_data.append([service_module, service_port, service_cpes, "\n".join(service_banner)])

            table = AsciiTable(table_data)
            table.title = '[ Services - {} ]'.format(result['ipaddr'])
            table.inner_heading_row_border = True
            table.inner_row_border = True
            click.echo(table.table)


@explore.command('list_projects', short_help='List the Orca projects in the database.')
def list_projects_db():
    click.echo(click.style("[?]", fg='yellow') + " Current Orca projects in the database:\n")
    orca_dbconn = OrcaDbConnector()

    table_data = [["Project", "Assets", "Hosts", "DNS Entries", "Shodan", "Vulnerabilities"]]
    for project in orca_dbconn.list_projects():
        summary = orca_dbconn.get_summary_counts(project)
        table_data.append(
            [project, summary['asset_count'], summary['host_count'], summary['dns_count'], summary['shodan_count'],
             summary['vuln_count']])

    table = AsciiTable(table_data)
    table.title = 'Current Projects'
    click.echo(table.table)
    click.echo("")


@explore.command('tag_results', short_help='Tag results in the database.')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def tag_results(project):
    orca_dbconn = OrcaDbConnector(project)

    orca_tagging.tagging(orca_dbconn)
    orca_tagging.banner_search(orca_dbconn)
    orca_tagging.regex_search(orca_dbconn)
    orca_tagging.cpe_tagging(orca_dbconn)
