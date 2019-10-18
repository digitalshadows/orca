
import click
import requests
import socket
import time

from tqdm import tqdm

from modules import orca_helpers, orca_shodan, orca_dns
from modules.orca_dbconn import OrcaDbConnector
from modules.orca_crtsh import get_domains_from_crtsh
from modules.orca_amass_subprocess import get_subdomains_from_amass_subprocess

from settings import ORCA_PROJECTS, ORCA_CVESEARCH_IP, ORCA_CVESEARCH_PORT

from . import CONTEXT_SETTINGS


@click.group(context_settings=CONTEXT_SETTINGS, short_help='Enumerate the assets to get additional information.')
def enum():
    pass


@enum.command('all', short_help='Run all enumeration modules using data in the assets table.')
@click.pass_context
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def enum_all(ctx, project):

    click.secho("\n[1/5] Running Crt.sh Subdomain Enumeration", fg='green')
    ctx.invoke(enum_subdomains_crtsh, project=project)

    click.secho("\n[2/5] Running DNS Dumpster Subdomain Enumeration", fg='green')
    ctx.invoke(enum_subdomains_dumpster, project=project)

    click.secho("\n[3/5] Running Shodan Enumeration", fg='green')
    ctx.invoke(lookup_hosts_shodan, project=project, refresh_results=True)

    click.secho("\n[4/5] Running DNS Enumeration", fg='green')
    ctx.invoke(enum_dns_db, project=project)

    try:
        click.secho("\n[5/5] Running Exploit Enumeration", fg='green')
        ctx.invoke(enum_exploits_db, project=project)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        click.secho("[!] Error - Is your CVE-Search running? Check out the documentation for details.", fg='red')

    click.secho("\n[+] Complete", fg='green')



@enum.command('dns_db', short_help='Enumerate DNS records from the hosts in the db.')
@click.option('--all', '-a', 'all_', help='Enumerate both asset data and hosts table', is_flag=True)
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def enum_dns_db(project, all_):
    orca_dbconn = OrcaDbConnector(project)

    if all_:
        orca_dns.enumerate_domain_ad(orca_dbconn)
        orca_dns.enumerate_domain_hosts(orca_dbconn)
    else:
        orca_dns.enumerate_domain_ad(orca_dbconn)  # all domains in asset data


@enum.command('exploits_db', short_help='Get available exploits for CVEs in the DB.')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def enum_exploits_db(project):
    orca_dbconn = OrcaDbConnector(project)
    results = orca_dbconn.get_all_vuln_entries()

    with tqdm(total=len(results)) as pbar:
        for result in results:
            if 'CVE' in result['cve']:
                res = requests.get("http://{}:{}/api/cve/{}".format(ORCA_CVESEARCH_IP, ORCA_CVESEARCH_PORT, result['cve']))
                res_json = res.json()
                if 'references' in res_json:
                    for ref in res_json['references']:
                        if 'exploit-db' in ref:
                            tqdm.write("[+] Adding exploit: {} for {} to the database".format(ref, result['cve']))
                            orca_dbconn.update_vuln_table_exploit(result['host_id'], result['cve'], ref)
            pbar.update(1)
    
@enum.command('subdomains_crtsh',
              help='Get subdomains from crt.sh. Will run over all assets in the asset table unless --domain is specified.')
@click.option('--domain', '-d', callback=orca_helpers.validate_domain, help='Domain for scanning')
@click.option('--verbose', '-v', 'verbose', help='Enable verbose output', is_flag=True)
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def enum_subdomains_crtsh(project, domain,verbose):
    orca_dbconn = OrcaDbConnector(project)

    if domain:
        output = get_domains_from_crtsh(domain)
        asset_id = orca_dbconn.store_asset(domain, asset_type='domain', source='crtsh')
        for line in output:
            try:
                ipaddr = socket.gethostbyname(line)
                if orca_helpers.is_ipaddr(ipaddr):
                    click.echo(click.style("[+]", fg='green') + " Adding subdomain: {} - [{}]".format(line, ipaddr))
                    orca_dbconn.add_host_to_host_table(ipaddr, [line], asset_id, 'crtsh')
            except Exception as e:
                if verbose:
                    click.secho("[!] Error {}".format(e), fg='red')
                pass
    else:
        results = orca_dbconn.get_all_ad_entries_domains()
        for result in results:
            asset_id = result['asset_id']
            domain = result['asset_data_value']

            output = get_domains_from_crtsh(domain,verbose=verbose)

            for line in output:
                try:
                    ipaddr = socket.gethostbyname(line)
                    if orca_helpers.is_ipaddr(ipaddr):
                        click.echo(click.style("[+]", fg='green') + " Adding subdomain: {} - [{}]".format(line, ipaddr))

                        orca_dbconn.add_host_to_host_table(ipaddr, [line], asset_id, 'crtsh')
                except Exception as e:
                    if verbose:
                        click.echo(click.style("[-]", fg='red') + " Skipping: {}".format(e))
                    pass

            click.echo(
                click.style('\n[!]', fg='yellow') + " Sleeping for 10s")
            time.sleep(10)


@enum.command('subdomains_dumpster',
              help='Enumerate subdomains from DNS Dumpster. Will over all domains in the asset table unless --domain is specified')
@click.option('--domain', '-d', callback=orca_helpers.validate_domain, help='Domain for scanning')
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def enum_subdomains_dumpster(project, domain):
    orca_dbconn = OrcaDbConnector(project)

    if domain:
        output = orca_dns.get_domains_from_dnsdumpster(domain)
        asset_id = orca_dbconn.store_asset(domain, asset_type='domain', source='dnsdumpster')

        for line in output:
            orca_dbconn.add_host_to_host_table(line[1], [line[0]], asset_id, 'dnsdumpster')

    else:
        results = orca_dbconn.get_all_ad_entries_domains()
        for result in results:
                click.echo(click.style('\n[?]', fg='yellow') + " Searching for subdomains for: {}".format(result['asset_data_value']))
                asset_id = result['asset_id']
                domain = result['asset_data_value']

                output = orca_dns.get_domains_from_dnsdumpster(domain)

                for line in output:

                    click.echo(click.style("[+]", fg='green') + " Adding subdomain: {} - [{}]".format(line[0], line[1]))
                    orca_dbconn.add_host_to_host_table(line[1], [line[0]], asset_id, 'dnsdumpster')

        if len(results) > 1:
            time.sleep(10)

@enum.command('subdomains_amass',
              help='Enumerate subdomains via the OWASP Amass tool. Will over all domains in the asset table unless --domain is specified')
@click.option('--domain', '-d', callback=orca_helpers.validate_domain, help='Domain for scanning')
@click.option('--verbose', '-v', 'verbose', help='Enable verbose output', is_flag=True)
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def enum_subdomains_amass(project, domain, verbose):
    orca_dbconn = OrcaDbConnector(project)

    print("In enum_subdomains_amass")
    
    if domain:
        output = get_subdomains_from_amass_subprocess(domain)
        asset_id = orca_dbconn.store_asset(domain, asset_type='domain', source='amass')
        for line in output['subdomains']['results']:
            for ipaddr in line[1]: # Get unique

                try:
                    orca_helpers.validate_ip(None, None, ipaddr)
                except ValueError as e:
                    if verbose:
                        click.secho("[?] {}: {} - [{}]".format(e, line[0], ipaddr), fg='yellow')
                    pass
                else:
                    click.echo(click.style("[+]", fg='green') + " Adding subdomain: {} - [{}]".format(line[0], ipaddr))
                    orca_dbconn.add_host_to_host_table(ipaddr, [line[0]], asset_id, 'amass')

    else:
        results = orca_dbconn.get_all_ad_entries_domains()
        for result in results:
                click.echo(click.style('\n[?]', fg='yellow') + " Searching for subdomains for: {}".format(result['asset_data_value']))
                asset_id = result['asset_id']
                domain = result['asset_data_value']

                output = get_subdomains_from_amass_subprocess(domain)
                asset_id = orca_dbconn.store_asset(domain, asset_type='domain', source='amass')
                for line in output['subdomains']['results']:
                    print(line)
                    for ipaddr in line[1]: # Get unique
                        try:
                            print(ipaddr)
                            orca_helpers.validate_ip(None, None, ipaddr)
                        except ValueError as e:
                            if verbose:
                                click.secho("[?] {}: {} - [{}]".format(e, line[0], ipaddr), fg='yellow')
                            pass
                        else:
                            click.echo(click.style("[+]", fg='green') + " Adding subdomain: {} - [{}]".format(line[0], ipaddr))
                            orca_dbconn.add_host_to_host_table(ipaddr, [line[0]], asset_id, 'amass')

@enum.command('services_shodan', short_help='Enumerate service information from SHODAN.')
@click.option('--enumerate', '-e', 'enum', help='Which datasource would you like to use, the hosts or cidr table?',
              default='all', show_default='all', type=click.Choice(['all', 'hosts', 'cidr']))
@click.option('--refresh_results', '-r', help='Force a refresh of previously seen hosts', is_flag=True)
@click.argument('project', type=click.Choice(ORCA_PROJECTS))
def lookup_hosts_shodan(project, enum, refresh_results):
    orca_dbconn = OrcaDbConnector(project)

    # Check Shodan Key is initialized
    orca_helpers.get_shodan_key()

    if enum in ['hosts', 'all']:
        host_table = orca_dbconn.get_all_host_table_entries()

        with tqdm(total=len(host_table)) as pbar:
            for ipaddr in host_table:
                pbar.set_description(desc="Enumerating [{:16s}]".format(ipaddr['ipaddr']))

                orca_shodan.shodan_lookup_ipaddr(project, ipaddr['ipaddr'], ipaddr['asset_id'], ipaddr['host_id'],
                                                 refresh=refresh_results)
                pbar.update(1)

    if enum in ['cidr', 'all']:
        results = orca_dbconn.get_all_ad_entries_typed('cidr')

        for result in results:
            click.echo(click.style("[?]", fg='yellow') + " Enumerating CIDR {}".format(result['asset_data_value']))
            orca_shodan.shodan_lookup_netrange(project, result['asset_data_value'], result['asset_id'], 0)
