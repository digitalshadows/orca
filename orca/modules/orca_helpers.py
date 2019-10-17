import json
import os
import click
import subprocess
import glob
import sys
import pathvalidate
import re
import validators

from stat import ST_MODE
from pathlib import PurePosixPath
from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError
from pygments import highlight, lexers, formatters

# CONSTANTS
from settings import ORCA_CONFIG_DIR


def list_to_string(input_list):
    if not input_list:
        return 'N/A'
    elif len(input_list) == 1:
        return str(input_list[0])
    elif len(input_list) > 1:
        return str(','.join([str(x) for x in input_list]))


def cpe_to_string(input_cpe):
    cpe_list = []
    if not input_cpe:
        return 'N/A'
    else:
        for result in input_cpe['cpe']:
            for k,v in result.items():
                if len(v) == 1:
                    cpe_list.append("{}:{}".format(k,v[0]))
                elif len(v) > 1:
                    cpe_list.append("{}:{}".format(k,','.join(v)))

    return ','.join(cpe_list)


def handle_json_output(json_input, raw):
    if raw:
        raw_json=json.dumps(json_input)
        print(raw_json)
    else:                        
        formatted_json = json.dumps(json_input, sort_keys=True, indent=4)
        colorful_json = highlight(formatted_json, lexers.JsonLexer(), formatters.TerminalFormatter())
        print(colorful_json)

def ip_check_routable(item):
    ip_addr = IPAddress(item)

    # This prevents netaddr allowing shortened ip addresses
    if not str(ip_addr) == item:
        raise AddrFormatError("IP Malformed")

    # Check for reserved IP addresses
    if any([ip_addr.is_multicast(), ip_addr.is_private(), ip_addr.is_loopback(), ip_addr.is_link_local(), ip_addr.is_reserved()]):
        raise AddrFormatError("IP is reserved")
    # Check to see if IP is IPv4
    elif ip_addr.version is not 4:
        raise AddrFormatError("IP is not IPv4")

    return True

def is_ipaddr(ip):
    tmp_ip = None
    try:
        tmp_ip = IPAddress(ip)
        ip_check_routable(ip)
    except:
        return False

    if tmp_ip:
        if tmp_ip.is_unicast():
            return True
        else:
            return False
    else:
        return False


def is_cidr(cidr):
    try:
        IPNetwork(cidr)
        return True
    except Exception as e:
        #click.echo("{} is not a valid IP Network range: {}".format(cidr, e))
        return False


def unique(results):
    uniq = []
    for x in results:
        if x not in uniq:
            uniq.append(x)
    return uniq


def print_table(rows):
    # GistID: 407b706d54619cb32588
    # find the maximum width of each columns
    wcolumns = None
    for columns in rows:
        if not wcolumns:
            wcolumns = [len(str(x)) for x in columns]
        else:
            wcolumns = [max(x, len(str(y))) for x, y in zip(wcolumns, columns)]
    # print columns with the maximum width
    for columns in rows:
        cols = [str(c).ljust(w) for w, c in zip(wcolumns, columns)]
        click.echo("| {} |".format(" | ".join(list(cols))))


def get_shodan_key():

    '''Returns the API key of the current logged-in user.'''

    shodan_dir = os.path.expanduser(ORCA_CONFIG_DIR)
    keyfile = shodan_dir + '/shodan_api_key'

    # If the file doesn't yet exist let the user know that they need to
    # initialize the shodan cli
    if not os.path.exists(keyfile):
        click.secho('[!] Please run "orca-recon init <shodan api key>" before using this command!', fg="red")
        sys.exit(1)

    perms = oct(os.stat(keyfile)[ST_MODE])[-3:]
    if perms != '600':
        if click.confirm('WARNING: permissions set incorrectly, do you want to reset?'):
            os.chmod(keyfile, 0o600)

    with open(keyfile, 'r') as fin:
        api_key = fin.read().strip()
        if len(api_key) != 32:
            click.secho("[!] Invalid SHODAN API key")
            sys.exit(1)
        else:
            return api_key
        
def setup_pyasn():

    # Create directory if required

    orca_dir = os.path.expanduser(ORCA_CONFIG_DIR)
    if not os.path.isdir(orca_dir):
        try:
            os.mkdir(orca_dir)
        except OSError:
            raise click.ClickException('Unable to create directory to store the PyASN DB: {}'.format(orca_dir))

    # Install PyASN
    if click.confirm("The Orca requires pyasn to be downloaded. Would you like to do that now?", default=True):

        # Clean up old files
        if os.path.exists(orca_dir + 'ipasn_db.dat'):
            os.remove(orca_dir + 'ipasn_db.dat')

        files = glob.glob(orca_dir + "rib.*")
        for file in files:
            print("Removing {}!".format(file))
            os.remove(file)

        # Download Data

        subprocess.call(["pyasn_util_download.py", "--latest"], cwd=orca_dir)
        click.echo(click.style('DB Downloaded', fg='green'))

        # Convert data

        files = glob.glob(orca_dir + "rib.*")

        subprocess.call(["pyasn_util_convert.py", "--single", files[0], "ipasn_db.dat"], cwd=orca_dir)
        click.echo(click.style('File formatted!', fg='green'))

        # Clean up
        files = glob.glob(orca_dir + "rib.*")
        for file in files:
            print("Removing {}!\n".format(file))
            os.remove(file)
    else:
        print("Exiting!")
        sys.exit()


def check_pyasn_ready():
    orca_dir = os.path.expanduser(ORCA_CONFIG_DIR)
    if os.path.exists(orca_dir + 'ipasn_db.dat'):
        return True
    else:
        return False

# Callbacks for Click validation


def validate_filename(ctx, param, value):

    p = PurePosixPath(value)

    file_name = str(p.name)
    file_path = str(p.parent)

    try:
        pathvalidate.validate_filepath(file_path, platform='Linux')
        pathvalidate.validate_filename(file_name, platform='Linux')
    except pathvalidate.ValidationError as e:
        click.secho("[!] Invalid filename provided: {}".format(value), bg='red')
        ctx.abort()
    return value


def validate_ip(ctx, param, value):

    if value:
        if not (validators.ipv4(value) and is_ipaddr(value)):

            if ctx:
                click.secho("[!] Invalid IPv4 provided: {}".format(value), bg='red')
                ctx.abort()
            else:
                raise ValueError('Invalid IPv4 provided')

    return value


def validate_cidr(ctx, param, value):

    if value:
        try:
            IPNetwork(value)

            if str(IPNetwork(value)) != value:
                click.secho("[!] Invalid CIDR provided: {} - did you mean {}?".format(value, str(IPNetwork(value))), bg='red')
                ctx.abort()
        except (AddrFormatError, ValueError):
            click.secho("[!] Invalid CIDR provided: {}".format(value), bg='red')
            ctx.abort()
    return value


def validate_domain(ctx, param, value):
    r = re.compile("^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$")

    if value and (not bool(r.match(value))):

        if ctx:
            click.secho("[!] Invalid domain name provided: {}".format(value), bg='red')
            ctx.abort()
        else:
            raise ValueError('Invalid domain provided')

    return value


def validate_orgname(ctx, param, value):
    r = re.compile("^[a-zA-Z0-9 \-!]*$")

    if value and (not bool(r.match(value))):
        click.secho("[!] Invalid organisation name provided: {}".format(value), bg='red')
        ctx.abort()

    return value


def validate_projectname(ctx, param, value):
    r = re.compile("^[a-zA-Z0-9]*$")

    if value and (not bool(r.match(value))):
        click.secho("[!] Invalid project name provided - special characters are not allowed: {}".format(value), bg='red')
        ctx.abort()

    return value
