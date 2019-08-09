import click
import shodan

from modules import orca_helpers, orca_org_search_google
from modules.orca_dbconn import OrcaDbConnector
from settings import ORCA_PROJECTS

from . import CONTEXT_SETTINGS


def add_asset(orca_dbconn, asset, asset_type, source):
    # click.echo("Processing asset {}".format(asset))
    if asset_type == 'ipaddr':
        if orca_helpers.is_ipaddr(asset):
            orca_dbconn.store_asset(asset, asset_type=asset_type, source=source)
    elif asset_type == 'cidr':
        if orca_helpers.is_cidr(asset):
            orca_dbconn.store_asset(asset, asset_type=asset_type, source=source)
    elif asset_type == 'hostname':
        orca_dbconn.store_asset(asset, asset_type=asset_type, source=source)
    elif asset_type == 'domain':
        orca_dbconn.store_asset(asset, asset_type=asset_type, source=source)
    else:
        click.secho("[!] No valid asset data type provided", bg='red')


@click.group(context_settings=CONTEXT_SETTINGS, short_help='Discover asset data for enumeration.')
def discover():
    pass


@discover.command('domains_google', short_help='Get domains from Googling the company name.')
@click.option('--organization', '-o', callback=orca_helpers.validate_orgname, prompt=True, help='Organization name to use for discovery')
@click.option('--count', default=20, type=int, help='Number of results to scrape', show_default='20')
@click.argument('project', callback=orca_helpers.validate_projectname)
def domains_google(project, organization, count):
    orca_dbconn = OrcaDbConnector(project)

    click.echo(click.style("[?]", fg='yellow') + " Starting Google scraping for domains for {}...".format(organization))
    domain_list = list(orca_org_search_google.search_org_name(organization, results_number=count))

    click.echo(click.style("[+]", fg='green') + " Found {} domains from Google".format(len(domain_list)))

    for domain in domain_list:
        click.secho(click.style("\n[!]", fg='green') + " Discovered domain: {}".format(domain))

        if click.confirm(click.style("[?]", fg='yellow') + " Add to asset data for enumeration?"):
            click.echo(click.style("[+]", fg='green') + " Adding {} to assets...".format(domain))
            add_asset(orca_dbconn, domain, 'domain', source='google_search')
        else:
            click.echo(click.style("[-]", fg='yellow') + " Skipping {}...".format(domain))


@discover.command('domains_shodan', short_help='Get domains from SHODAN by searching the company name.')
@click.option('--limit', '-l', help="Number of results to return", default=100, type=int)
@click.option('--organization', '-o', callback=orca_helpers.validate_orgname, prompt=True, help='Organization name to use for discovery')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def domains_shodan(project, limit, organization):
    # Check Shodan has been initialized
    orca_helpers.get_shodan_key()

    all_domains = []

    orca_dbconn = OrcaDbConnector(project)

    try:
        # Setup the api
        api = shodan.Shodan(orca_helpers.get_shodan_key())

        # Perform the search
        query = 'org:"{}"'.format(organization)
        result = api.count(query, facets=[('domain', limit), ])

        for service in result['facets']['domain']:
            all_domains += [service['value'].lower()]
    except Exception as e:
        click.secho('Error: {}'.format(e), fg='red')

    results = orca_helpers.unique(all_domains)
    for domain in results:
        click.secho(click.style("\n[!]", fg='green') + " Discovered domain: {}".format(domain))
        if click.confirm(click.style("[?]", fg='yellow') + " Add to asset data for enumeration?"):
            click.secho("[+] Adding {} to assets...".format(domain), fg='green')
            add_asset(orca_dbconn, domain, 'domain', source='shodan_search')
        else:
            click.echo(click.style("[-]", fg='yellow') + " Skipping {}...".format(domain))
