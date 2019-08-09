import re
import json
import pkg_resources


def tagging(orca_dbconn):
    with pkg_resources.resource_stream('rules', "rules.json") as json_data:
        rules = json.load(json_data)
        for rule in rules['rules']:
            for k, v in rule['keys'].items():
                for value in v:
                    results = orca_dbconn.get_all_entries_rules(k, v)
                    for result in results:
                        print('Match found for rule {} for host {}'.format(rule['tag'], result['ipaddr']))
                        if result['tags'] is not None:
                            if rule['tag'] not in result['tags']:
                                orca_dbconn.append_entry_tags(result['ipaddr'],[rule['tag']])
                        else:
                            orca_dbconn.update_entry_tags(result['ipaddr'],[rule['tag']])


def cpe_tagging(orca_dbconn):
    shodan_results = orca_dbconn.get_all_shodan_cpes()
    for shodan_result in shodan_results:
        for k,v in shodan_result['cpe']['cpe'][0].items():
            if 'cpe:/o' in v[0]:
                tag = v[0].split(':')[3]
                print('Match found for rule {} for host {}'.format([tag], shodan_result['ipaddr']))
                if shodan_result['tags'] is not None:
                    if tag not in shodan_result['tags']:
                        orca_dbconn.append_entry_tags(shodan_result['ipaddr'],[tag])
                else:
                    orca_dbconn.update_entry_tags(shodan_result['ipaddr'],[tag])

                
def banner_search(orca_dbconn):
    with pkg_resources.resource_stream('rules', "rules_fuzzy.json") as json_data:
        rules = json.load(json_data)
        for rule in rules['rules']:
            shodan_results = orca_dbconn.get_all_shodan_entries()
            for k, v in rule['keys'].items():
                for search_term in v:
                    for shodan_result in shodan_results:
                        for banner in shodan_result[k]:
                            if search_term in banner:
                                print('Match found for rule {} for host {}'.format(rule['tag'], shodan_result['ipaddr']))
                                if shodan_result['tags'] is not None:
                                    if rule['tag'] not in shodan_result['tags']:
                                        orca_dbconn.append_entry_tags(shodan_result['ipaddr'],[rule['tag']])
                                else:
                                    orca_dbconn.update_entry_tags(shodan_result['ipaddr'],[rule['tag']])


def regex_search(orca_dbconn):
    with pkg_resources.resource_stream('rules', "regexShodanRules.json") as json_data:
        rules = json.load(json_data)
        for rule in rules:
            shodan_results = orca_dbconn.get_all_shodan_entries()
            for shodan_result in shodan_results:
                if rule['type'] == 'regex':
                    rgex = re.compile(rule['match'])
                    for banner in shodan_result['banner_shodan']:
                        m = rgex.search(banner, re.I)
                        if m:
                            print('Match found for rule {} for host {}'.format(rule['title'], shodan_result['ipaddr']))
                            if shodan_result['tags'] is not None:
                                if rule['title'] not in shodan_result['tags']:
                                    orca_dbconn.append_entry_tags(shodan_result['ipaddr'],[rule['title']])
                            else:
                                orca_dbconn.update_entry_tags(shodan_result['ipaddr'],[rule['title']])

