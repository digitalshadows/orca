import sys
import dns.resolver
import requests
import logging

from blessed import Terminal
from tqdm import tqdm


blessed_t = Terminal()


def any_resolve(domain_name, any_resolver, max_tries, record_type):
    any_resolver.timeout = 1 # time to wait for any given server
    any_resolver.lifetime = 1 # total time to spend on this resolution

    result_list = []
    for n in range(max_tries):
        try:
            any_answers = any_resolver.query(domain_name,record_type)
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
                tqdm.write("[+] {dns_key:<32} - {dns_type:>5} - {dns_value}".format(dns_type=blessed_t.cyan(record_type), dns_key=blessed_t.green(domain_name), dns_value=blessed_t.yellow(result)))
            return result_list
        except dns.resolver.NoAnswer:
            #print "No Answer from DNS servers received" 
            return None
        except dns.resolver.NoNameservers:
            tqdm.write("No nameservers found for domain {}".format(domain_name))
            return None
        except dns.resolver.NXDOMAIN:
            tqdm.write("NXDOMAIN error for domain {} and record type {}".format(domain_name, record_type))
            return None
        except dns.exception.Timeout:
            return None


def enumerate_domain_ad(orca_dbconn):
    domains = orca_dbconn.get_all_ad_entries_domains()

    for domain in domains:
        enumerate_domain(orca_dbconn, domain['asset_data_value'])


def enumerate_domain_hosts(orca_dbconn):
    domains = orca_dbconn.get_all_hosts()
    
    with tqdm(total=len(domains)) as pbar:
        for domain in domains:
            for hostname in domain['hostname']:
                pbar.set_description(desc="Enumerating [{:16s}]".format(hostname))
                enumerate_domain(orca_dbconn, hostname)
            pbar.update(1)


def enumerate_domain(orca_dbconn, domain_name):
    max_tries = 3
    any_resolver = dns.resolver.Resolver()
    any_resolver.nameservers = ['1.1.1.1','8.8.8.8','9.9.9.9','8.8.4.4']
    record_types = ["MX", "TXT", "SOA", "NS", "AAAA", "A", "CNAME"]
    temp_result = {"Domain": domain_name, "results": {"MX": [], "TXT": [], "SOA": [], "NS": [], "AAAA": [], "A": [], "CNAME": []}}
    try:
        for record_type in record_types:
            tmp = any_resolve(domain_name, any_resolver, max_tries, record_type)
            if tmp is not None:
                temp_result['results'][record_type] = tmp
    except Exception as e: 
        print("DNS servers no longer responding, exiting... {}".format(e))
        sys.exit(2)

    if any([result for _, result in temp_result['results'].items()]):
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


def dmarc_resolve(dbconn, domain_name):
    max_tries = 3
    orca_resolver = dns.resolver.Resolver()
    orca_resolver.nameservers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']

    dmarc_results = {}
    
    try:
        print("Doing DMARC lookup for %s" % domain_name)
        dmarc_results.update(any_resolve(dbconn, domain_name, orca_resolver, max_tries, "TXT"))
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
        for result in splitoutput:
            if result and len(result.split(",")) == 2:
                output.append(result.split(",", 1))
    except requests.exceptions.HTTPError as e:
        logging.warning("Error connecting to DNS dumpster: {}".format(e))
        return []
    except requests.exceptions.ConnectionError as e:
        logging.warning("Error connecting to DNS dumpster: {}".format(e))
        return []

    return output
