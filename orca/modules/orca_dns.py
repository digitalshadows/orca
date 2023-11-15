import logging
import sys

import dns.resolver
import requests
from blessed import Terminal
from tqdm import tqdm

blessed_t = Terminal()


def any_resolve(domain_name, any_resolver, max_tries, record_type):
    any_resolver.timeout = 1  # time to wait for any given server
    any_resolver.lifetime = 1  # total time to spend on this resolution

    result_list = []
    for _ in range(max_tries):
        try:
            any_answers = any_resolver.query(domain_name, record_type)
            for ans in any_answers:
                if "MX" in record_type:
                    result = str(ans).split()[1]
                    result = result.lower()[:-1]
                elif "NS" in record_type:
                    result = str(ans)[:-1]
                else:
                    result = str(ans)
                result_list.append(result)
            if result is not None:
                tqdm.write(blessed_t.green("[+] ") + "{dns_key:<32} - {dns_type:>5} - {dns_value}".format(
                    dns_type=blessed_t.magenta(record_type), dns_key=blessed_t.cyan(domain_name),
                    dns_value=blessed_t.yellow(result)))
            return result_list
        except dns.resolver.NoAnswer:
            # tqdm.write(blessed_t.red("[!] ") + "No Answer from DNS servers received")
            return None
        except dns.resolver.NoNameservers:
            tqdm.write(blessed_t.red("[!] {:<32} - No NS found".format(domain_name)))
            return None
        except dns.resolver.NXDOMAIN:
            tqdm.write(blessed_t.red(
                "[!] {dns_key:<32} - {dns_type:>5} - NXDOMAIN".format(dns_key=domain_name, dns_type=record_type)))
            return None
        except dns.exception.Timeout:
            tqdm.write(blessed_t.red("[!] {:<32} - DNS Timeout".format(domain_name)))
            return None


def enumerate_domain_ad(orca_dbconn, no_):
    domains = orca_dbconn.get_all_ad_entries_domains()

    with tqdm(total=len(domains)) as pbar:
        for domain in domains:
            pbar.set_description(desc="Enumerating [{:16s}]".format(domain['asset_data_value']))
            enumerate_domain(orca_dbconn, domain['asset_data_value'], no_)
        pbar.update(1)


def enumerate_domain_hosts(orca_dbconn, no_):
    domains = orca_dbconn.get_all_hosts()

    with tqdm(total=len(domains)) as pbar:
        for domain in domains:
            for hostname in domain['hostname']:
                pbar.set_description(desc="Enumerating [{:16s}]".format(hostname))
                enumerate_domain(orca_dbconn, hostname, no_)
            pbar.update(1)


def enumerate_domain_dmarc(orca_dbconn, no_):
    domains = orca_dbconn.get_all_ad_entries_domains()
    with tqdm(total=len(domains)) as pbar:
        for domain in domains:
            pbar.set_description(desc="Enumerating [{:16s}]".format(domain['asset_data_value']))
            dmarc_domain = f"_dmarc.{domain['asset_data_value']}"
            if res := enumerate_dmarc(orca_dbconn, dmarc_domain, no_):
                orca_dbconn.add_dns_entry(dmarc_domain, [], [], [], [], [], [], [res])

        pbar.update(1)


def enumerate_domain(orca_dbconn, domain_name, no_):
    max_tries = 3
    any_resolver = dns.resolver.Resolver()
    if not no_:
        any_resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '8.8.4.4']
    record_types = ["MX", "TXT", "SOA", "NS", "AAAA", "A", "CNAME"]
    temp_result = {"Domain": domain_name,
                   "results": {"MX": [], "TXT": [], "SOA": [], "NS": [], "AAAA": [], "A": [], "CNAME": []}}
    try:
        for record_type in record_types:
            tmp = any_resolve(domain_name, any_resolver, max_tries, record_type)
            if tmp is not None:
                temp_result['results'][record_type] = tmp

    except Exception as e:
        print(f"DNS servers no longer responding, exiting... {e}")
        sys.exit(2)
    print(temp_result)
    if any(result for _, result in temp_result['results'].items()):
        orca_dbconn.add_dns_entry(
            domain_name,
            temp_result['results']['MX'],
            temp_result['results']['A'],
            temp_result['results']['AAAA'],
            temp_result['results']['SOA'],
            temp_result['results']['NS'],
            temp_result['results']['CNAME'],
            temp_result['results']['TXT']
        )


def enumerate_dmarc(dbconn, domain_name, no_):
    max_tries = 3
    orca_resolver = dns.resolver.Resolver()
    if not no_:
        orca_resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9', '8.8.4.4']

    dmarc_results = ""

    try:
        print(f"Doing DMARC lookup for {domain_name}")
        if res := any_resolve(domain_name, orca_resolver, max_tries, "TXT"):
            dmarc_results = res[0]
    except dns.exception.Timeout:
        print("DNS servers no longer responding, exiting...")
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NoNameservers:
        pass
    except dns.resolver.NXDOMAIN:
        pass

    return dmarc_results


def get_domains_from_dnsdumpster(domain):
    url = 'http://api.hackertarget.com/hostsearch/'
    payload = {"q": domain}
    output = []

    try:
        response = requests.get(url, params=payload)
        if "502 Bad Gateway" in response.text:
            print("Bad Gateway - DNS Dumpster down")
            exit(2)

        splitoutput = response.text.split("\n")
        output.extend(
            result.split(",", 1)
            for result in splitoutput
            if result and len(result.split(",")) == 2
        )
    except requests.exceptions.HTTPError as e:
        logging.warning(f"Error connecting to DNS dumpster: {e}")
        return []
    except requests.exceptions.ConnectionError as e:
        logging.warning(f"Error connecting to DNS dumpster: {e}")
        return []

    return output
