import requests
import click

from bs4 import BeautifulSoup
from click import style, echo, secho


def get_domains_from_crtsh(domain, verbose=False):
    payload = {'q': '%.{}'.format(domain)}
    url = 'https://crt.sh/'
    results = []

    response = requests.get(url, params=payload)

    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        try:
            table = soup.find_all('table')[2]

            rows = table.find_all('tr')
            for row in rows:
                cols = row.find_all('td')
                if len(cols) > 4:
                    hostname = cols[4].get_text()
                    if hostname[0] == '*':
                        if verbose:
                            click.echo(click.style('[-]', fg='yellow') + " Ignoring: {}".format(hostname))
                    else:
                        if hostname not in results:
                            results.append(hostname)
        except IndexError as e:
            secho("[!] crtsh returned an error: {} causing exception {}".format(response.text, e), bg='red')
            pass
    return results