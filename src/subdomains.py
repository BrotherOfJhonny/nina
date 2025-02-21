import dns.resolver
import logging
import requests
import re
import tldextract
from bs4 import BeautifulSoup as bs

def subDomain(domain, store, reportPath):
    """
    Enumera subdomínios utilizando o serviço crt.sh.
    Retorna uma lista de subdomínios encontrados.
    """
    url = "https://crt.sh/?q=%25." + domain + "&output=json"
    logging.info("Consultando crt.sh para subdomínios de %s", domain)
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
    except Exception as e:
        logging.error("Erro ao consultar crt.sh: %s", e)
        data = []
    subdomains = set()
    for entry in data:
        names = entry.get("name_value", "")
        # O campo pode conter vários subdomínios separados por nova linha
        for sub in names.split("\n"):
            if sub.endswith(domain):
                subdomains.add(sub.strip())
    return list(subdomains)

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "ns1", "ns2", "blog", "dev", "test", "api", "m", "mobile",
    "vpn", "admin", "portal", "secure", "static", "cdn", "docs", "beta", "intranet", "support"
]

def brute_force_subdomains(domain, common_subdomains=COMMON_SUBDOMAINS, timeout=3):
    """
    Realiza enumeração de subdomínios utilizando uma lista de subdomínios comuns e consultas DNS.
    Retorna uma lista de subdomínios que resolvem com sucesso.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    found_subdomains = set()

    for sub in common_subdomains:
        full_domain = "{}.{}".format(sub, domain)
        try:
            answers = resolver.resolve(full_domain, "A")
            if answers:
                logging.info("Subdomínio encontrado: %s", full_domain)
                found_subdomains.add(full_domain)
        except Exception:
            continue

    return list(found_subdomains)
