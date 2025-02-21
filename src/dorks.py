import requests
import logging
import time
from bs4 import BeautifulSoup
import urllib.parse

def build_query(domain: str) -> str:
    """
    Constrói a query para buscar arquivos específicos no domínio.
    Tipos de arquivo: pdf, docx, xml, xmlx, bkp, zip, txt.
    """
    query = "site:{0} (filetype:pdf OR filetype:docx OR filetype:xml OR filetype:xmlx OR filetype:bkp OR filetype:zip OR filetype:txt)".format(domain)
    return query

def google_dork_paginated(query: str, max_pages: int = 3, timeout: int = 10, user_agent: str = None) -> list:
    """
    Realiza dorking usando o Google, percorrendo várias páginas de resultados.
    Retorna uma lista de URLs encontradas.
    """
    if not user_agent:
        user_agent = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/90.0.4430.93 Safari/537.36")
    headers = {"User-Agent": user_agent}
    all_results = []

    for page in range(max_pages):
        start = page * 10
        # Utiliza filter=0 para não omitir resultados e hl=en para idioma inglês.
        url = "https://www.google.com/search?filter=0&hl=en&start={start}&q={query}".format(
            start=start, query=urllib.parse.quote(query))
        logging.debug("Google URL: %s", url)
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
        except requests.exceptions.Timeout:
            logging.error("Timeout na página %d do Google. Interrompendo.", page)
            break
        except Exception as e:
            logging.error("Erro na página %d do Google: %s", page, e)
            break

        soup = BeautifulSoup(response.text, "html.parser")
        page_results = []

        # 1) Tentar extrair links com o seletor "div" de classe "yuRUbf"
        for div in soup.find_all("div", class_="yuRUbf"):
            a = div.find("a")
            if a and a.get("href"):
                page_results.append(a.get("href"))

        # 2) Fallback: se não encontrou nada, tenta extrair links que começam com "/url?q="
        if not page_results:
            logging.debug("Nenhum link encontrado no seletor 'yuRUbf' na página %d. Tentando fallback '/url?q='.", page)
            for a in soup.find_all("a"):
                href = a.get("href")
                if href and href.startswith("/url?q="):
                    real_url = href.split("/url?q=")[1].split("&")[0]
                    page_results.append(real_url)

        # Adiciona resultados da página, evitando duplicatas.
        for r in page_results:
            if r not in all_results:
                all_results.append(r)

        # Pausa para evitar bloqueios
        time.sleep(2)
        if not page_results:
            logging.debug("Nenhum resultado na página %d. Interrompendo busca Google.", page)
            break

    return all_results

def dork_with_google(domain: str, timeout: int = 10, max_pages: int = 3) -> list:
    """
    Tenta realizar dorking usando o Google.
    Caso não retorne resultados com o user-agent padrão, tenta com um user-agent alternativo.
    """
    query = build_query(domain)
    logging.info("Query Google: %s", query)
    results = google_dork_paginated(query, max_pages=max_pages, timeout=timeout)
    if results:
        return results

    logging.info("Nenhum resultado com user-agent padrão. Tentando user-agent alternativo.")
    alt_user_agent = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/91.0.4472.114 Safari/537.36")
    results_alt = google_dork_paginated(query, max_pages=max_pages, timeout=timeout, user_agent=alt_user_agent)
    return results_alt

def dork_with_bing(domain: str, timeout: int = 10, max_pages: int = 1) -> list:
    """
    Realiza dorking usando o Bing para buscar arquivos específicos no domínio.
    """
    query = build_query(domain)
    logging.info("Query Bing: %s", query)
    user_agent = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/90.0.4430.93 Safari/537.36")
    headers = {"User-Agent": user_agent}
    all_results = []

    for page in range(max_pages):
        first = page * 10 + 1
        search_url = "https://www.bing.com/search?q={}&first={}".format(
            urllib.parse.quote(query), first)
        logging.debug("Bing URL: %s", search_url)
        try:
            response = requests.get(search_url, headers=headers, timeout=timeout)
            response.raise_for_status()
        except Exception as e:
            logging.error("Erro na busca no Bing (página %d): %s", page, e)
            break

        soup = BeautifulSoup(response.text, "html.parser")
        page_results = []
        for li in soup.find_all("li", class_="b_algo"):
            h2 = li.find("h2")
            if h2:
                a = h2.find("a")
                if a and a.get("href"):
                    page_results.append(a.get("href"))
        for r in page_results:
            if r not in all_results:
                all_results.append(r)
        time.sleep(2)
        if not page_results:
            logging.debug("Nenhum resultado na página %d do Bing. Interrompendo.", page)
            break

    return all_results

def dork_with_openAI(domain: str):
    """
    Placeholder para uma 'busca' via OpenAI.
    Não há API oficial de busca do OpenAI; esta função é meramente ilustrativa.
    """
    logging.info("Tentando 'busca' no OpenAI (placeholder).")
    return []

def dorks(domain: str, store: bool, reportPath: str):
    """
    Executa a técnica de dorking para buscar arquivos específicos (.pdf, .docx, .xml, .xmlx, .bkp, .zip, .txt)
    no domínio.
    
    1. Tenta com o Google (com paginação e fallback de user-agent).
    2. Se não houver resultados, utiliza o Bing.
    3. Se ainda não encontrar, tenta a função placeholder para OpenAI.
    
    Os resultados são adicionados ao relatório.
    """
    logging.info("Executando dorking para arquivos no domínio: %s", domain)
    
    # Tentativa com Google
    results = dork_with_google(domain, timeout=10, max_pages=3)
    if not results:
        logging.info("Resultados do Google insuficientes, utilizando Bing...")
        results = dork_with_bing(domain, timeout=10, max_pages=2)
    
    # Se ainda não encontrou, tenta placeholder do OpenAI (sem implementação real)
    if not results:
        logging.info("Nenhum resultado com Bing. Tentando 'busca' no OpenAI (placeholder).")
        results = dork_with_openAI(domain)
    
    if results:
        with open(reportPath, "a", encoding="utf-8") as f:
            f.write("\n\n## Dorking Results<br><br>\n")
            for url in results:
                f.write("- {}<br>\n".format(url))
        logging.info("Resultados do dorking: %s", results)
    else:
        logging.warning("Nenhum resultado de dorking encontrado, mesmo após Google/Bing/OpenAI.")
