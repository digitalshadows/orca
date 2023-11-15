import datetime
import sys
from contextlib import contextmanager

import psycopg2
import psycopg2.extras
from psycopg2.extras import RealDictCursor

psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
psycopg2.extensions.register_type(psycopg2.extensions.UNICODEARRAY)
psycopg2.extras.register_inet()

# CONSTANTS
from settings import ORCA_DB_DBNAME, ORCA_DB_PASSWORD, ORCA_DB_PORT, ORCA_DB_USERNAME, ORCA_DB_HOSTNAME


class OrcaDbConnector:
    conn = None
    log = None
    shodan_table_name = ""
    host_table_name = ""
    ad_table_name = ""
    dns_table_name = ""
    vuln_table_name = ""

    @contextmanager
    def get_real_dict_cursor(self):
        cursor = self.conn.cursor(cursor_factory=RealDictCursor)
        try:
            yield cursor
            self.conn.commit()
        finally:
            cursor.close()

    @contextmanager
    def get_cursor(self):
        cursor = self.conn.cursor()
        try:
            yield cursor
            self.conn.commit()
        finally:
            cursor.close()

    def __init__(self, title=None):
        if (self.conn is None):
            try:
                self.conn = psycopg2.connect(dbname=ORCA_DB_DBNAME, user=ORCA_DB_USERNAME, password=ORCA_DB_PASSWORD,
                                             host=ORCA_DB_HOSTNAME, port=ORCA_DB_PORT, connect_timeout=2)
            except (psycopg2.OperationalError, psycopg2.ProgrammingError) as e:
                print(
                    f"[!] Cannot access postgres DB with provided parameters. Ensure it is running and configured correctly. Got exception: {e}"
                )
                sys.exit(1)

        if title:
            self.init_ad_table_name(title)
            self.init_shodan_table_name(title)
            self.init_vuln_table_name(title)
            self.init_dns_table_name(title)
            self.init_host_table_name(title)

    def list_projects(self):
        projects = []

        try:
            with self.get_real_dict_cursor() as cur:
                query = "SELECT * FROM pg_catalog.pg_tables WHERE schemaname != 'pg_catalog' AND schemaname != 'information_schema'"
                cur.execute(query)
                if results := cur.fetchall():
                    projects.extend(
                        result['tablename'].split('_')[-1:][0]
                        for result in results
                        if 'asset_data' in result['tablename']
                    )
            return projects

        except psycopg2.OperationalError:
            raise

    def delete_all_entries(self, title):
        ad_statement = f"DROP TABLE IF EXISTS orca_asset_data_{title}"
        host_statement = f"DROP TABLE IF EXISTS orca_host_table_{title}"
        shodan_statement = f"DROP TABLE IF EXISTS orca_shodan_results_{title}"
        dns_statement = f"DROP TABLE IF EXISTS orca_dns_results_{title}"
        vuln_statement = f"DROP TABLE IF EXISTS orca_vuln_results_{title}"

        with self.get_cursor() as cur:
            cur.execute(ad_statement)
        with self.get_cursor() as cur:
            cur.execute(host_statement)
        with self.get_cursor() as cur:
            cur.execute(shodan_statement)
        with self.get_cursor() as cur:
            cur.execute(dns_statement)
        with self.get_cursor() as cur:
            cur.execute(vuln_statement)

    def add_vuln_to_db(self, host_id, ipaddr, shodan_hostname, module, cpe, cve, cvss, verified, summary):
        statement = f"INSERT INTO {self.vuln_table_name} (vuln_id, host_id, ipaddr, shodan_hostname, module, cpe, cve, cvss, verified, summary, exploit) VALUES (DEFAULT, %(host_id)s, %(ipaddr)s,%(shodan_hostname)s ,%(module)s,%(cpe)s,%(cve)s,%(cvss)s,%(verified)s,%(summary)s, False)ON CONFLICT (ipaddr, cve) DO UPDATE SET (shodan_hostname, module, cpe, cve, cvss, verified, summary, exploit) = (EXCLUDED.shodan_hostname, EXCLUDED.module, EXCLUDED.cpe, EXCLUDED.cve, EXCLUDED.cvss, EXCLUDED.verified, EXCLUDED.summary, EXCLUDED.exploit);"
        params = {"host_id": host_id, "ipaddr": ipaddr, "shodan_hostname": shodan_hostname, "module": module,
                  "cpe": cpe, "cve": cve, "cvss": cvss, "verified": verified, "summary": summary, }
        try:
            with self.get_cursor() as cur:
                cur.execute(statement, params)
        except Exception as e:
            print(f"add_vuln_to_db {e}")
            sys.exit(1)

    def add_entry_to_db(self, ipaddr, added, last_updated, modules, ports, banner_shodan, cpe, hostname, netname, cidr,
                        asn, country, asset_id, host_id):
        sanitized_banners = [
            banner_shodan[i].replace('\x00', '')
            for i in range(len(banner_shodan))
        ]
        statement = f"INSERT INTO {self.shodan_table_name} (shodan_id, ipaddr, asset_id, host_id, added, last_updated, cli, ports, banner_shodan, cpe, hostname, netname, cidr, asn, country) VALUES (DEFAULT, %(ipaddr)s,%(asset_id)s,%(host_id)s, %(added)s,%(last_updated)s,%(cli)s,%(ports)s,%(banner_shodan)s,%(cpe)s,%(hostname)s,%(netname)s,%(cidr)s,%(asn)s,%(country)s)ON CONFLICT (ipaddr) DO UPDATE SET (shodan_id, last_updated, cli, ports, banner_shodan, cpe, hostname, netname, cidr, asn, country) = (EXCLUDED.shodan_id, EXCLUDED.last_updated, EXCLUDED.cli, EXCLUDED.ports, EXCLUDED.banner_shodan, EXCLUDED.cpe, EXCLUDED.hostname, EXCLUDED.netname, EXCLUDED.cidr, EXCLUDED.asn, EXCLUDED.country);"
        params = {"ipaddr": ipaddr, "asset_id": asset_id, "host_id": host_id, "added": added,
                  "last_updated": last_updated, "cli": modules, "ports": ports, "banner_shodan": sanitized_banners,
                  "cpe": cpe, "hostname": hostname, "netname": netname, "cidr": cidr, "asn": asn, "country": country}

        try:
            with self.get_cursor() as cur:
                cur.execute(statement, params)
            self.add_host_to_host_table(ipaddr, hostname, asset_id, 'shodan')
            self.update_host_table_hostname_shodan(ipaddr, hostname)

        except Exception as e:
            print(f"Exception {e}")
            sys.exit(1)

    def get_all_entries(self):
        statement = f"SELECT * FROM {self.shodan_table_name}"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_hosts(self):
        statement = f"SELECT hostname FROM {self.host_table_name}"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_summary_counts(self, project):

        self.init_ad_table_name(project)
        self.init_dns_table_name(project)
        self.init_host_table_name(project)
        self.init_shodan_table_name(project)
        self.init_vuln_table_name(project)

        def get_count(cur, tablename):
            cur.execute("SELECT count(*) FROM {}".format(tablename))
            return cur.fetchone()["count"]

        with self.get_real_dict_cursor() as cur:
            return {
                "asset_count": get_count(cur, self.ad_table_name),
                "host_count": get_count(cur, self.host_table_name),
                "dns_count": get_count(cur, self.dns_table_name),
                "shodan_count": get_count(cur, self.shodan_table_name),
                "vuln_count": get_count(cur, self.vuln_table_name)
            }

    def get_hostname_from_hostid(self, host_id):
        statement = f"SELECT hostname FROM {self.host_table_name} WHERE host_id = %(host_id)s"
        params = {"host_id": host_id}
        results = ""

        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchone()
            if results:
                return results['hostname']
        return results

    def get_hostid_from_ipaddr(self, ipaddr):
        statement = (
            f"SELECT host_id FROM {self.host_table_name} WHERE ipaddr = %(ipaddr)s"
        )
        params = {"ipaddr": ipaddr}
        results = ""

        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchone()
            if results:
                return results['host_id']
        return results

    def get_shodan_hostname_from_hostid(self, host_id):
        statement = f"SELECT shodan_hostname FROM {self.host_table_name} WHERE host_id = %(host_id)s"
        params = {"host_id": host_id}
        results = ""

        with self.get_cursor() as cur:
            cur.execute(statement, params)
            return cur.fetchone()

    def get_shodan_entry(self, ipaddr):
        statement = f"SELECT * FROM {self.shodan_table_name} WHERE ipaddr = %(ipaddr)s"
        params = {"ipaddr": ipaddr}
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            result = cur.fetchone()
        return result

    def get_all_ad_entries(self):
        statement = f"SELECT * FROM {self.ad_table_name}"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_dns_entries(self):
        statement = f"SELECT * FROM {self.dns_table_name}"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_ad_entries_typed(self, data_type):
        statement = f"SELECT * FROM {self.ad_table_name} WHERE asset_data_type = %(data_type)s"
        params = {"data_type": data_type}
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchall()
        return results

    def get_all_ad_entries_domains(self):
        statement = (
            f"SELECT * FROM {self.ad_table_name} WHERE asset_data_type = 'domain'"
        )
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_host_table_entries(self):
        statement = f"SELECT * FROM {self.host_table_name}"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_shodan_entries(self):
        statement = f"SELECT * FROM {self.shodan_table_name}"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_shodan_cpes(self):
        statement = f"SELECT shodan_id, ipaddr, cpe, tags,country,host_id,netname FROM {self.shodan_table_name} WHERE (SELECT COUNT(*) FROM json_each(cpe) s) > 0"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_vuln_entries(self):
        statement = f"SELECT * FROM {self.vuln_table_name}"
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_entries_rules(self, k, v):
        statement = f"SELECT * FROM {self.shodan_table_name} WHERE {k} @> %(value)s"
        params = {"value": v}
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchall()
        return results

    def get_all_entries_tagged(self):
        statement = "SELECT * FROM %s WHERE tags != '{}'" % self.shodan_table_name
        with self.get_real_dict_cursor() as cur:
            cur.execute(statement)
            results = cur.fetchall()
        return results

    def get_all_entries_with_tag(self, tag):
        statement = (
            f"SELECT * FROM {self.shodan_table_name} WHERE %(tag)s = ANY (tags)"
        )
        params = {"tag": tag}
        results = {}

        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchall()
        return results

    def is_ipaddr_in_db(self, ipaddr):
        statement = f"SELECT EXISTS(SELECT 1 FROM {self.shodan_table_name} WHERE ipaddr = %(ipaddr)s)"
        params = {"ipaddr": ipaddr}
        results = False

        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchone()
            if results['exists']:
                return True
        return False

    def is_host_id_in_vuln_table(self, host_id):
        statement = f"SELECT EXISTS(SELECT 1 FROM {self.vuln_table_name} WHERE host_id = %(host_id)s AND exploit=True)"
        params = {"host_id": host_id}
        results = False

        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchone()
            if results['exists']:
                return True
        return False

    def update_entry_tags(self, ipaddr, tag):
        statement = f'UPDATE {self.shodan_table_name} SET tags = %(tag)s WHERE ipaddr = %(ipaddr)s'
        params = {"tag": tag, "ipaddr": ipaddr}

        with self.get_cursor() as cur:
            cur.execute(statement, params)

    def append_entry_tags(self, ipaddr, tag):
        statement = f'UPDATE {self.shodan_table_name} SET tags = tags || %(tag)s WHERE ipaddr = %(ipaddr)s'
        params = {"tag": tag, "ipaddr": ipaddr}

        with self.get_cursor() as cur:
            cur.execute(statement, params)

    def create_ipaddr_index(self):
        query = f"CREATE INDEX IF NOT EXISTS {self.shodan_table_name.replace('scan', 'ndx')} ON {self.shodan_table_name}(ipaddr);"
        with self.get_cursor() as cur:
            cur.execute(query)

    def create_cidr_index(self):
        query = f"CREATE INDEX IF NOT EXISTS {self.shodan_table_name.replace('scan', 'ndx')} ON {self.shodan_table_name} USING GIST (cidr inet_ops);"
        with self.get_cursor() as cur:
            cur.execute(query)

    def init_dns_table_name(self, name):
        self.dns_table_name = f"orca_dns_results_{name}"
        self.init_dns_table()

    def init_dns_table(self):
        table = f"CREATE TABLE IF NOT EXISTS {self.dns_table_name} (dns_id serial NOT NULL PRIMARY KEY, domain text UNIQUE, mx_record text[], a_record text[], aaaa_record text[], soa_record text[], ns_record text[], cname_record text[], txt_record text[], tags text[])"

        try:
            with self.get_cursor() as cur:
                cur.execute(table)
        except psycopg2.errors.SyntaxError as e:
            print(f"An error occurred creating table with name {self.dns_table_name}")

    def init_vuln_table_name(self, name):
        self.vuln_table_name = f"orca_vuln_results_{name}"
        self.init_vuln_table()

    def init_vuln_table(self):
        table = f"CREATE TABLE IF NOT EXISTS {self.vuln_table_name} (vuln_id serial NOT NULL PRIMARY KEY, host_id serial, ipaddr ipaddress, shodan_hostname text[], module text, cpe text[], cve text, cvss float, verified boolean, summary text, exploit boolean, exploit_ref text[], UNIQUE(ipaddr, cve))"

        try:
            with self.get_cursor() as cur:
                cur.execute(table)
        except psycopg2.errors.SyntaxError as e:
            print(f"An error occurred creating table with name {self.vuln_table_name}")

    def init_shodan_table_name(self, name):
        self.shodan_table_name = f"orca_shodan_results_{name}"
        self.init_shodan_table()
        self.create_ipaddr_index()
        self.create_cidr_index()

    def init_shodan_table(self):
        ip4r = "CREATE EXTENSION IF NOT EXISTS ip4r"
        with self.get_cursor() as cur:
            cur.execute(ip4r)

        table = f"CREATE TABLE IF NOT EXISTS {self.shodan_table_name} (shodan_id serial NOT NULL PRIMARY KEY, ipaddr ipaddress UNIQUE, asset_id serial, host_id serial, added timestamp, last_updated timestamp, cli text[], ports integer[], banner_shodan text[], cpe json, hostname text[], netname text, cidr inet, asn text, country text, tags text[])"
        try:
            with self.get_cursor() as cur:
                cur.execute(table)
        except psycopg2.errors.SyntaxError as e:
            print(f"An error occurred creating table with name {self.shodan_table_name}")

    def init_host_table_name(self, name):
        self.host_table_name = f"orca_host_table_{name}"
        self.init_host_table()

    def init_host_table(self):
        ip4r = "CREATE EXTENSION IF NOT EXISTS ip4r"
        with self.get_cursor() as cur:
            cur.execute(ip4r)

        query = f"CREATE TABLE IF NOT EXISTS {self.host_table_name} (host_id serial primary key not null, ipaddr ipaddress UNIQUE, hostname text[], asset_id serial, shodan_hostname text[], shodan boolean, host_data_origin text)"
        try:
            with self.get_cursor() as cur:
                cur.execute(query)
        except psycopg2.errors.SyntaxError as e:
            print(f"An error occurred creating table with name {self.host_table_name}")

    def init_ad_table(self):
        query = f"CREATE TABLE IF NOT EXISTS {self.ad_table_name} (asset_id serial primary key not null, asset_data_value text UNIQUE, asset_data_type text, asset_data_origin text, infra_check boolean, verified boolean, insert_time timestamp)"
        try:
            with self.get_cursor() as cur:
                cur.execute(query)
        except psycopg2.errors.SyntaxError as e:
            print(f"An error occurred creating table with name {self.ad_table_name}")

    def init_ad_table_name(self, name):
        self.ad_table_name = f"orca_asset_data_{name}"
        self.init_ad_table()

    def store_ad_whois(self, cidr, verified):
        query = f"INSERT INTO {self.ad_table_name} (asset_id, asset_data_value, asset_data_type, asset_data_origin, infra_check, verified) VALUES (DEFAULT, %(cidr)s, 'cidr','whois', false, %(verified)s) ON CONFLICT DO NOTHING RETURNING asset_id"
        params = {"cidr": cidr, "verified": verified}
        with self.get_cursor() as cur:
            cur.execute(query, params)
            res = cur.fetchone()
        return res[0] if res is not None else 0

    def add_dns_entry(self, domain, mx_record, a_record, aaaa_record, soa_record, ns_record, cname_record, txt_record):
        query = f"INSERT INTO {self.dns_table_name} (dns_id, domain, mx_record, a_record, aaaa_record, soa_record, ns_record, cname_record, txt_record) VALUES (DEFAULT, %(domain)s, %(mx_record)s, %(a_record)s, %(aaaa_record)s, %(soa_record)s, %(ns_record)s, %(cname_record)s, %(txt_record)s) ON CONFLICT DO NOTHING"
        params = {"domain": domain, "mx_record": mx_record, "a_record": a_record, "aaaa_record": aaaa_record,
                  "soa_record": soa_record, "ns_record": ns_record, "cname_record": cname_record,
                  "txt_record": txt_record}
        with self.get_cursor() as cur:
            cur.execute(query, params)

    def store_asset(self, asset, source, asset_type):
        res = ''
        # Tried initially to "DO NOTHING RETURNING" but that would result in no result being returned. Had to use the approach here:
        # https://stackoverflow.com/questions/34708509/how-to-use-returning-with-on-conflict-in-postgresql
        query = f"INSERT INTO {self.ad_table_name} (asset_id, asset_data_value, asset_data_type, asset_data_origin, infra_check, verified, insert_time) VALUES (DEFAULT, %(asset)s, %(asset_type)s, %(source)s, false, false, %(insert_time)s) ON CONFLICT(asset_data_value) DO UPDATE SET asset_data_origin=%(source)s RETURNING asset_id"
        params = {"asset": asset, "asset_type": asset_type, "source": source, "insert_time": datetime.datetime.now()}
        with self.get_cursor() as cur:
            cur.execute(query, params)
            res = cur.fetchone()

        return res[0] if res is not None else -1

    def add_host_to_host_table(self, ipaddr, hostname, asset_id, host_data_origin):
        statement = f"INSERT INTO {self.host_table_name} (host_id, ipaddr, hostname, asset_id, shodan, host_data_origin) VALUES (DEFAULT, %(ipaddr)s, %(hostname)s, %(asset_id)s, false, %(host_data_origin)s) ON CONFLICT (ipaddr) DO UPDATE SET shodan = True"

        params = {"ipaddr": ipaddr, "hostname": hostname, "asset_id": asset_id, "host_data_origin": host_data_origin}

        try:
            with self.get_cursor() as cur:
                cur.execute(statement, params)

        except Exception as e:
            print(f"Exception {e}")

    def add_host_to_host_table_netark(self, ipaddr, hostname, asset_id):
        shodan_array = []
        statement = f"INSERT INTO {self.host_table_name} (host_id, ipaddr, hostname, asset_id, shodan_hostname, shodan) VALUES (DEFAULT, %(ipaddr)s, %(hostname)s, %(asset_id)s,%(shodan_hostname)s, false) ON CONFLICT (ipaddr) DO UPDATE SET hostname = %(hostname)s"
        params = {"ipaddr": ipaddr, "hostname": hostname, "asset_id": asset_id, "shodan_hostname": shodan_array}
        with self.get_cursor() as cur:
            cur.execute(statement, params)

    def is_exploit_in_vuln_table(self, host_id, cve, exploit_ref):
        statement = f"SELECT EXISTS(SELECT * FROM {self.vuln_table_name} WHERE %(exploit_ref)s = ANY(exploit_ref) AND host_id = %(host_id)s AND cve = %(cve)s)"
        params = {"host_id": host_id, "exploit_ref": exploit_ref, "cve": cve}

        with self.get_real_dict_cursor() as cur:
            cur.execute(statement, params)
            results = cur.fetchone()
            if results['exists']:
                return True
        return False

    def update_vuln_table_exploit(self, host_id, cve, exploit_ref):
        statement = f"UPDATE {self.vuln_table_name} SET exploit = True, exploit_ref = exploit_ref || %(exploit_ref)s WHERE host_id = %(host_id)s AND cve = %(cve)s"
        params = {"host_id": host_id, "exploit_ref": [exploit_ref], "cve": cve}

        if not self.is_exploit_in_vuln_table(host_id, cve, exploit_ref):
            with self.get_cursor() as cur:
                cur.execute(statement, params)

    def update_ad_table(self, netrange):
        statement = f"UPDATE {self.ad_table_name} SET infra_check = True WHERE asset_data_value = %(netrange)s"
        params = {"netrange": netrange}
        with self.get_cursor() as cur:
            cur.execute(statement, params)

    def update_host_table_hostname(self, ipaddr, hostnames):
        statement = f"UPDATE {self.host_table_name} SET hostname = %(hostnames)s WHERE ipaddr = %(ipaddr)s"
        params = {"hostnames": hostnames, "ipaddr": ipaddr}
        with self.get_cursor() as cur:
            cur.execute(statement, params)

    def update_host_table_hostname_shodan(self, ipaddr, hostnames):
        statement = f"UPDATE {self.host_table_name} SET shodan_hostname = %(hostnames)s WHERE ipaddr = %(ipaddr)s"
        params = {}
        if hostnames is None or len(hostnames) <= 0 and len(hostnames) == 0:
            params = {"hostnames": None, "ipaddr": ipaddr}
        elif len(hostnames) > 0:
            params = {"hostnames": hostnames, "ipaddr": ipaddr}
        with self.get_cursor() as cur:
            cur.execute(statement, params)
