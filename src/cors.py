import os
import json
import logging
import requests

def cors_testing(srcPath: str) -> dict:
    ref_path = os.path.join(srcPath, "references_recon.json")
    try:
        with open(ref_path, "r") as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        logging.error(f"Arquivo não encontrado: {ref_path}")
    except json.JSONDecodeError as json_err:
        logging.error(f"Erro ao decodificar JSON em {ref_path}: {json_err}")
    return {}

def cors(domain: str, store: bool, reportPath: str, subs: list, srcPath: str, vulnerabilities: list, threads: int):
    references = cors_testing(srcPath)
    logging.info(f"Referências CORS carregadas: {references}")
    
    logging.info(f"Iniciando teste de CORS para o domínio: {domain}")
    try:
        r = requests.get("http://" + domain, timeout=10, verify=False)
        headers = r.headers
        logging.info(f"Cabeçalhos recebidos: {headers}")
    
        if "Access-Control-Allow-Origin" in headers:
            allowed_origin = headers["Access-Control-Allow-Origin"]
            if allowed_origin.strip() == "*":
                vulnerabilities.append(f"CORS Vulnerability, High, /, High - Valor: {allowed_origin}")
                logging.warning("Vulnerabilidade CORS: Wildcard '*' em Access-Control-Allow-Origin.")
            elif domain not in allowed_origin:
                vulnerabilities.append(f"CORS Vulnerability, Medium, /, Medium - Valor: {allowed_origin}")
                logging.warning(f"Vulnerabilidade CORS: o header ('{allowed_origin}') não restringe ao domínio.")
            else:
                logging.info("Configuração de CORS parece adequada.")
        else:
            logging.info("Header Access-Control-Allow-Origin não encontrado.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Erro durante requisição HTTP para testar CORS: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Erro ao decodificar JSON da resposta: {e}")
