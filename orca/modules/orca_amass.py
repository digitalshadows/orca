import click
import json

from click import style, echo, secho

def get_subdomains_from_amass(amass_file):
    results = []
    domain = ''
    for line in amass_file:
        json_line = json.loads(line)
        if not domain:
            domain = json_line['domain']
        if json_line['name']:
            ip_addrs = []
            for address in json_line['addresses']:
                ip_addrs.append(address['ip'])
            results.append([json_line['name'],list(set(ip_addrs))])
    json_data = {'subdomains':{'results':results, 'domain': domain}}
    return json_data
