from urllib.parse import urlparse

from googlesearch import search


def search_org_name(search_input, results_number=20):
    urls = []

    for url in search(search_input, stop=results_number):
        o = urlparse(url)
        urls.append(o.netloc)

    uniq_domain_list = []
    for domain in urls:

        if domain.startswith("www."):
            domain = domain[4:]

        if domain not in uniq_domain_list:
            uniq_domain_list.append(domain)
            yield domain
