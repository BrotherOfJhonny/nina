import requests
import logging
from bs4 import BeautifulSoup
import urllib.parse

def dork_with_google(query: str, timeout: int = 10) -> list:
    """Realiza dorking usando o Google e retorna uma lista de URLs encontradas."""
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/90.0.4430.93 Safari/537.36")
    }
    search_url = "https://www.google.com/search?q=" + urllib.parse.quote(query)
    try:
        response = requests.get(search_url, headers=headers, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        logging.error("Timeout ao buscar no Google. Utilizando Bing como fallback.")
        return dork_with_bing(query, timeout=timeout)
    except Exception as e:
        logging.error("Erro na busca no Google: " + str(e))
        return []
    
    soup = BeautifulSoup(response.text, "html.parser")
    results = []
    # Google envolve links de resultados com "/url?q="
    for a in soup.find_all("a"):
        href = a.get("href")
        if href and href.startswith("/url?q="):
            url = href.split("/url?q=")[1].split("&")[0]
            results.append(url)
    return results

def dork_with_bing(query: str, timeout: int = 10) -> list:
    """Realiza dorking usando o Bing e retorna uma lista de URLs encontradas."""
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/90.0.4430.93 Safari/537.36")
    }
    search_url = "https://www.bing.com/search?q=" + urllib.parse.quote(query)
    try:
        response = requests.get(search_url, headers=headers, timeout=timeout)
        response.raise_for_status()
    except Exception as e:
        logging.error("Erro na busca no Bing: " + str(e))
        return []
    
    soup = BeautifulSoup(response.text, "html.parser")
    results = []
    # Os resultados do Bing geralmente estão em <li class="b_algo">
    for li in soup.find_all("li", class_="b_algo"):
        h2 = li.find("h2")
        if h2:
            a = h2.find("a")
            if a and a.get("href"):
                results.append(a.get("href"))
    return results

def dorks(domain: str, store: bool, reportPath: str):
    """
    Executa a técnica de dorking para encontrar diretórios e arquivos indexados pelo motor de busca.
    Tenta primeiro com o Google e, se houver timeout ou erro, utiliza o Bing.
    Os resultados são adicionados ao relatório.
    """
    query = f"site:{domain} intitle:\"index of\""
    logging.info(f"Iniciando dorking com Google para: {query}")
    results = dork_with_google(query, timeout=10)
    if not results:
        logging.info("Resultados do Google insuficientes, utilizando Bing...")
        results = dork_with_bing(query, timeout=10)
    
    if results:
        with open(reportPath, "a", encoding="utf-8") as f:
            f.write("\n\n## Dorking Results<br><br>\n")
            for url in results:
                f.write(f"- {url}<br>\n")
        logging.info(f"Resultados do dorking: {results}")
    else:
        logging.warning("Nenhum resultado de dorking encontrado.")
