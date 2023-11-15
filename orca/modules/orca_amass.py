import json


def get_subdomains_from_amass(amass_file):
    results = []
    domain = ''
    for line in amass_file:
        json_line = json.loads(line)
        if not domain:
            domain = json_line['domain']
        if json_line['name']:
            ip_addrs = [address['ip'] for address in json_line['addresses']]
            results.append([json_line['name'], list(set(ip_addrs))])
    return {'subdomains': {'results': results, 'domain': domain}}
