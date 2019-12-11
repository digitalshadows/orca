import sys
import dns.resolver
import requests
import logging

from blessed import Terminal
from tqdm import tqdm
from modules import orca_helpers

blessed_t = Terminal()

def enumerate_bgp_domain(orca_dbconn, domain):
    url = "https://api.bgpview.io/search?query_term={}".format(domain.split('.')[0])
    source = "bgpview"
    asset_type = "cidr"
    res = requests.get(url)

    if res.status_code == 200:
        json_results = res.json()

        for result in json_results['data']['ipv4_prefixes']:
            email_addrs = []

            for email_addr in result['email_contacts']:
                if domain in email_addr:
                    email_addrs.append(email_addr)
                    asset = result['prefix']
                    print("Prefix: {}".format(asset))
                    print("Email addrs: {}".format(','.join(email_addrs)))
                    
                    if orca_helpers.is_cidr(asset):
                        orca_dbconn.store_asset(asset, asset_type=asset_type, source=source)
