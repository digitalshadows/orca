import click
import json
import subprocess

from click import style, echo, secho

def get_subdomains_from_amass_subprocess(domain):
    results = []
    amass_file = "{}-amass.json".format(domain.split('.')[:1][0])
    print("About to run Amass for {}".format(domain))
    
    subprocess.run(["amass","enum","--json", amass_file,"-d","{}".format(domain)])
    
    with open(amass_file) as f:
        for line in f:
            json_line = json.loads(line)
            if json_line['name']:
                ip_addrs = []
                for address in json_line['addresses']:
                    ip_addrs.append(address['ip'])
                results.append([json_line['name'],list(set(ip_addrs))])
    json_data = {'subdomains':{'results':results, 'domain': domain}}

    subprocess.run(["rm", "-f", amass_file])
    
    return json_data
