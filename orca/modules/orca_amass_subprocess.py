import json
import subprocess


def get_subdomains_from_amass_subprocess(domain):
    results = []
    amass_file = f"{domain.split('.')[:1][0]}-amass.json"

    subprocess.run(["amass", "enum", "--json", amass_file, "-d", f"{domain}"])

    with open(amass_file) as f:
        for line in f:
            json_line = json.loads(line)
            if json_line['name']:
                ip_addrs = [address['ip'] for address in json_line['addresses']]
                results.append([json_line['name'], list(set(ip_addrs))])
    json_data = {'subdomains': {'results': results, 'domain': domain}}

    subprocess.run(["rm", "-f", amass_file])

    return json_data
