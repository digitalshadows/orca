import requests

from blessed import Terminal
from modules import orca_helpers

blessed_t = Terminal()


def enumerate_bgp_domain(orca_dbconn, domain):
    url = f"https://api.bgpview.io/search?query_term={domain.split('.')[0]}"
    res = requests.get(url)

    if res.status_code == 200:
        json_results = res.json()

        source = "bgpview"
        asset_type = "cidr"
        for result in json_results['data']['ipv4_prefixes']:
            email_addrs = []

            for email_addr in result['email_contacts']:
                if domain in email_addr:
                    email_addrs.append(email_addr)
                    asset = result['prefix']
                    print(f"Prefix: {asset}")
                    print(f"Email addrs: {','.join(email_addrs)}")

                    if orca_helpers.is_cidr(asset):
                        orca_dbconn.store_asset(asset, asset_type=asset_type, source=source)
