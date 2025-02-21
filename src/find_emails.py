from __future__ import print_function
import requests
import re
import math
import sys
from bs4 import BeautifulSoup as bs
from src.colors import YELLOW, GREEN, RED, BLUE, RESET
import urllib3
import warnings

urllib3.disable_warnings()
warnings.simplefilter("ignore")

# threading: para Python 2.7, use o pacote futures
try:
    import concurrent.futures
except ImportError:
    print("[{0}!{1}] Nina needs python 3.4 or a backport of concurrent.futures for legacy versions!".format(YELLOW, RESET))
    sys.exit()

def request_find_email(domain, url_search, token, page):
    """
    Faz a requisição para uma página de emails e extrai os endereços que contenham o domínio.
    """
    emails = []
    url = url_search + str(token) + str(page)
    try:
        r = requests.get(url, timeout=4, verify=False).text
    except Exception:
        return None
    soup = bs(r, 'html.parser')
    for link in soup.find_all('a'):
        href = link.get('href')
        if href and ("@{}".format(domain)) in href:
            # Remove o prefixo "mailto:" se presente
            if href.startswith("mailto:"):
                email = href[len("mailto:"):]
            else:
                email = href
            if email not in emails:
                emails.append(email)
    return emails if emails else None

def find_emails(domain, store, reportPath, MAX_EMAILS, THREADS):
    print("\n{0}[*] Searching for emails...\n".format(BLUE))
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/76.0.3809.100 Safari/537.36")
    }
    page = 1
    last_page = None
    emails = []
    url_skymem = "http://www.skymem.info/srch"
    url_search = "http://www.skymem.info/domain/"

    try:
        r = requests.get(url_skymem, headers=headers, params={"q": domain}, timeout=4, verify=False).text
        soup = bs(r, 'html.parser')
        token = ""
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and "domain" in href:
                token = href[8:35]
                break

        if token:
            url = url_search + str(token) + str(page)
            r = requests.get(url, timeout=4, verify=False).text
            soup = bs(r, 'html.parser')
            for small in soup.find_all('small'):
                if "emails)" in small.text:
                    numbers = re.findall("[0-9]+", small.text)
                    if numbers:
                        last_page = math.ceil(int(numbers[0]) / 5)
                    break

        if last_page is not None:
            # Se o total de páginas é menor que MAX_EMAILS/5, busque em todas elas
            if last_page < int(MAX_EMAILS / 5):
                pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
                futures = [pool.submit(request_find_email, domain, url_search, token, p)
                           for p in range(page, last_page + 1)]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result is not None:
                        for e in result:
                            if e not in emails:
                                emails.append(e)
            else:
                # Caso contrário, busque nas 10 primeiras páginas
                pool = concurrent.futures.ThreadPoolExecutor(max_workers=THREADS)
                futures = [pool.submit(request_find_email, domain, url_search, token, p)
                           for p in range(page, 11)]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result is not None:
                        for e in result:
                            if e not in emails:
                                emails.append(e)
                    if len(emails) >= MAX_EMAILS:
                        break

        if emails:
            print("[{0}+{1}] {2} Emails found:\n".format(GREEN, RESET, len(emails)))
            for e in emails:
                print("\t{0}-{1} {2}".format(GREEN, RESET, e))
            if store:
                with open(reportPath, "a", encoding="utf-8") as f:
                    f.write("\n\n## Emails found<br><br>\n")
                    f.write("**{0} Emails found:**<br><br>\n".format(len(emails)))
                    for e in emails:
                        f.write("\n- **{0}**<br>\n".format(e))
        else:
            print("[{0}!{1}] No emails found.".format(YELLOW, RESET))
    except KeyboardInterrupt:
        sys.exit("[{0}!{1}] Interrupt handler received, exiting...\n".format(YELLOW, RESET))
    except Exception as e:
        print("[{0}!{1}] No emails found. Error: {2}".format(YELLOW, RESET, e))
        pass

if __name__ == "__main__":
    # Exemplo de chamada
    # find_emails("example.com", False, "report.md", 50, 5)
    pass
