import json
import os
import textwrap
import time
from datetime import date
from datetime import datetime

import pyasn
import shodan
from blessed import Terminal
from netaddr import IPAddress
from netaddr.core import AddrFormatError
from retrying import retry
from settings import ORCA_CONFIG_DIR
from tqdm import tqdm

import orca_helpers
from orca_dbconn import OrcaDbConnector

blessed_t = Terminal()


def lookup_cidr_prefix(asndb, ipaddr):
    asndb_res = asndb.lookup(ipaddr)
    return asndb_res[1]


def retry_if_shodan_error(exception):
    """Return True if we should retry (in this case when it's an shodan.exception.APIError), False otherwise"""
    return isinstance(exception, shodan.exception.APIError)


@retry(wait_fixed=2000, stop_max_attempt_number=5, retry_on_exception=retry_if_shodan_error)
def get_shodan_data(shodan_api, ipaddr):
    json_result = {}
    try:
        json_result = shodan_api.host(ipaddr)
    except shodan.exception.APIError as e:

        if 'No information available for that IP' in str(e):
            return

        if 'Invalid IP' in str(e):
            return

        else:
            raise

    if json_result:
        return json_result


def shodan_lookup_ipaddr(title, ipaddr, asset_id, host_id=0, refresh=False):  # host_id is 0 when there is no parent
    shodan_api = shodan.Shodan(orca_helpers.get_shodan_key())

    orca_dbconn = OrcaDbConnector()

    orca_dbconn.init_host_table_name(title)
    orca_dbconn.init_shodan_table_name(title)
    orca_dbconn.init_vuln_table_name(title)

    orca_dir = os.path.expanduser(ORCA_CONFIG_DIR + "ipasn_db.dat")

    asndb = pyasn.pyasn(orca_dir)

    IPAddress(ipaddr)

    # Check IP is routable
    try:
        ip_valid = orca_helpers.ip_check_routable(ipaddr)
    except AddrFormatError as e:
        ip_valid = False

    if ip_valid:
        if (not orca_dbconn.is_ipaddr_in_db(ipaddr)) or refresh:
            shodan_response = get_shodan_data(shodan_api, ipaddr)
            if shodan_response is not None:
                hostname = []
                org = ''
                country = ''
                asn = ''
                last_update = ''
                ports = []
                banners = []
                cpes = {}
                modules = []

                if len(shodan_response['hostnames']) > 0:
                    hostname = shodan_response['hostnames']

                for port in shodan_response['ports']:
                    ports.append(int(port))

                for res in shodan_response['data']:
                    modules.append(res['_shodan']['module'])

                for banner in shodan_response['data']:
                    if 'data' in banner:
                        banners.append(banner['data'])

                for i in range(len(shodan_response['data']) - 1):
                    if 'cpe' in shodan_response['data'][i]:
                        if 'cpe' not in cpes:
                            cpes['cpe'] = [
                                {shodan_response['data'][i]['_shodan']['module']: shodan_response['data'][i]['cpe']}]
                        else:
                            cpes['cpe'].extend(
                                [{shodan_response['data'][i]['_shodan']['module']: shodan_response['data'][i]['cpe']}])

                if 'org' in shodan_response:
                    org =range(len(shodan_response['data']) - 1)

                if 'last_update' in shodan_response:
                    last_update = shodan_response['last_update']
                    if '.' in last_update:
                        last_update = last_update.rsplit('.')[0]

                if 'asn' in shodan_response:
                    asn = shodan_response['asn']

                if 'country_code3' in shodan_response:
                    country = shodan_response['country_code3']

                cidr = lookup_cidr_prefix(asndb, ipaddr)

                tqdm.write("[+] IP Address - {ipaddr} [{host_value}]"
                           "\n{ports_text:>12}: {ports_value}"
                           "\n{modules_text:>12}: {modules_value}"
                           "\n{asn_text:>12}: {asn_value}"
                           "\n{netblock_text:>12}: {netblock_value}"
                           "\n{org_text:>12}: {org_value}"
                           "\n{country_text:>12}: {country_value}"
                           "\n{cpe_text:>12}: {cpe_value}\n".format(
                    ipaddr=blessed_t.yellow(ipaddr),
                    host_text="Hostname", host_value=orca_helpers.list_to_string(hostname),
                    ports_text="Ports", ports_value=",".join("{0}".format(n) for n in ports),
                    modules_text="Modules", modules_value=','.join(modules),
                    asn_text="AS Number", asn_value=asn,
                    netblock_text="Netblock", netblock_value=cidr,
                    org_text="Organization", org_value=org,
                    country_text="Country", country_value=country,
                    cpe_text="CPE", cpe_value=orca_helpers.cpe_to_string(cpes)
                ))

                orca_dbconn.add_entry_to_db(ipaddr, date.fromtimestamp(time.time()),
                                            datetime.strptime(last_update, "%Y-%m-%dT%H:%M:%S"), modules, ports,
                                            banners, json.dumps(cpes), hostname, org, cidr, asn, country, asset_id,
                                            host_id)

                for i in range(len(shodan_response['data']) - 1):
                    if 'vulns' in shodan_response['data'][i]:
                        for cve, data in shodan_response['data'][i]['vulns'].items():
                            if 'cpe' in shodan_response['data'][i]:
                                # tqdm.write("Adding vuln {} IP address {} hostname {} module {} CPE {} CVSS {} Summary {}".format(blessed_t.red(cve), blessed_t.yellow(ipaddr), blessed_t.cyan(
                                #     orca_helpers.list_to_string(hostname)), blessed_t.cyan(shodan_response['data'][i]['_shodan']['module']), blessed_t.cyan(','.join(shodan_response['data'][i]['cpe'])), blessed_t.red(str(data['cvss'])), blessed_t.cyan(data['summary'])))

                                tqdm.write("\t{cve:>20} [CVSS: {cvss:3} - Module: {module}]: \"{summary}\"".format(
                                    cve=cve,
                                    cvss=str(data['cvss']),
                                    module=shodan_response['data'][i]['_shodan']['module'],
                                    summary=textwrap.shorten(data['summary'], width=128, placeholder="...")
                                ))

                                orca_dbconn.add_vuln_to_db(orca_dbconn.get_hostid_from_ipaddr(ipaddr), ipaddr, hostname,
                                                           shodan_response['data'][i]['_shodan']['module'],
                                                           shodan_response['data'][i]['cpe'], cve, data['cvss'],
                                                           data['verified'], data['summary'])
            else:
                # tqdm.write("{:16s} not found in SHODAN".format(ipaddr))
                pass
        else:
            tqdm.write("[!] {:16s}| IP addr in DB".format(ipaddr))
    else:
        tqdm.write("[!] {:16s}| Skipping non routable IP".format(ipaddr))


@retry(wait_fixed=2000, stop_max_attempt_number=5, retry_on_exception=retry_if_shodan_error)
def shodan_lookup_netrange(title, netrange, asset_id, refresh=False):
    orca_dbconn = OrcaDbConnector()

    orca_dbconn.init_ad_table_name(title)
    orca_dbconn.init_host_table_name(title)
    orca_dbconn.init_shodan_table_name(title)

    shodanapi = shodan.Shodan(orca_helpers.get_shodan_key())

    shodan_netrange = "net:" + netrange
    counter = shodanapi.count(shodan_netrange)['total']

    curr = shodanapi.search_cursor(shodan_netrange, minify=False)

    with tqdm(total=counter) as pbar:
        for json_result in curr:
            ipaddr = json_result['ip_str']

            if not orca_dbconn.is_ipaddr_in_db(ipaddr) or refresh:
                shodan_lookup_ipaddr(title, ipaddr, asset_id)
            else:
                tqdm.write("[!] {:16s}| IP addr in DB".format(json_result['ip_str']))
            pbar.update(1)

    orca_dbconn.update_ad_table(netrange)
