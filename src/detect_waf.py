import os
import json
import logging
import requests
import re

def detect_waf(domain: str, store: bool, reportPath: str, subs: list, srcPath: str, threads: int):
    logging.info(f"Iniciando detecção de WAF para {domain}")
    try:
        r = requests.get("http://" + domain, timeout=10, verify=False)
    except requests.RequestException as e:
        logging.error(f"Erro durante requisição HTTP para {domain}: {e}")
        return
    
    ref_path = os.path.join(srcPath, "references_recon.json")
    try:
        with open(ref_path, "r") as file:
            references = json.load(file)
    except FileNotFoundError:
        logging.error(f"Arquivo de referência não encontrado: {ref_path}")
        references = {}
    except json.JSONDecodeError as e:
        logging.error(f"Erro ao decodificar JSON do arquivo de referência: {e}")
        references = {}
    
    waf_references = references.get("WAF", {})
    detected_waf = []
    for waf_name, details in waf_references.items():
        code_pattern = details.get("code", "")
        page_pattern = details.get("page", "")
        headers_pattern = details.get("headers", "")
        cookie_pattern = details.get("cookie", "")
        match_found = False

        if code_pattern:
            try:
                if re.search(code_pattern, str(r.status_code)):
                    match_found = True
            except Exception:
                pass

        if page_pattern:
            if re.search(page_pattern, r.text, re.IGNORECASE):
                match_found = True

        if headers_pattern:
            headers_str = " ".join(r.headers.values())
            if re.search(headers_pattern, headers_str, re.IGNORECASE):
                match_found = True

        if cookie_pattern:
            cookies_str = " ".join(r.cookies.values())
            if re.search(cookie_pattern, cookies_str, re.IGNORECASE):
                match_found = True

        if match_found:
            logging.warning(f"WAF detectado: {waf_name}")
            detected_waf.append(waf_name)
    
    if detected_waf:
        logging.info(f"WAF detectados para {domain}: {', '.join(detected_waf)}")
    else:
        logging.info(f"Nenhum WAF detectado para {domain}")

