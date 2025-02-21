#!/usr/bin/env python3
"""
NINA Recon Tool - Versão Aprimorada

Esta ferramenta realiza enumeração e recon de domínios utilizando diversos módulos.
Funcionalidades incluem:
  - Portscan interno (com SSL aplicado somente em portas comuns)
  - Opção para executar portscan via Nmap (--nmap-scan)
  - Teste de CORS e detecção de WAF utilizando referências do arquivo JSON
  - Enumeração de diretórios comuns e verificação dos cabeçalhos de segurança
  - Geração de relatório em Markdown e conversão para HTML com Bootstrap
  - Início de um servidor HTTP local na porta 4366 e abertura automática do relatório no navegador
"""

import argparse
import sys
import socket
import pathlib
import os
import tldextract
from colorama import init as colorama_init
import logging
import subprocess
import webbrowser
import http.server
import socketserver
import threading
import time
import markdown  # pip install markdown

# Importa os módulos da ferramenta (eles devem estar na pasta "src")
from src.email_spoof import spoof
from src.portscan import portscan
from src.dorks import dorks
from src.cors import cors
from src.vuln_vectors import hunt  # Atualmente comentado
from src.enum_tech import tech
from src.search_backups import search_backups
from src.detect_waf import detect_waf
from src.find_repos import find_repos
from src.subdomain_takeover import subtake
from src.zone_transfer import zone_transfer
from src.subdomains import subDomain
from src.dns_information import dns_information, whois_lookup
from src.find_emails import find_emails
from src.ssl_information import ssl_information
from src.js_links import js_links
from src.colors import YELLOW, GREEN, RED, BLUE, RESET

# Inicializa o Colorama e limpa a tela se necessário
colorama_init(autoreset=True)
if os.name == 'nt':
    os.system('cls')

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Nina Recon Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-d", "--domain", help="Domínio para iniciar o recon", required=True)
    parser.add_argument("-o", "--output", help="Salvar relatório em diretório (Markdown)", action='store_true')
    parser.add_argument("-A", "--all", help="Executa todas as opções de recon de uma só vez", action='store_true')
    parser.add_argument("--whois", help="Realizar lookup WHOIS", action='store_true')
    parser.add_argument("-D", "--dns", help="Coletar informações DNS", action='store_true')
    parser.add_argument("--spoof", help="Verificar se o domínio pode ser falsificado (SPF/DMARC)", action='store_true')
    parser.add_argument("-a", "--axfr", help="Tentar transferência de zona (AXFR)", action='store_true')
    parser.add_argument("--dork", help="Realizar buscas via dorks", action='store_true')
    parser.add_argument("-s", "--subdomains", help="Pesquisar subdomínios registrados", action='store_true')
    parser.add_argument("-p", "--portscan", help="Executa portscan interno (banner grabbing)", action='store_true')
    parser.add_argument("--nmap-scan", help="Executa portscan via Nmap (-sS -svvv)", action='store_true')
    parser.add_argument("--subtake", help="Verificar vulnerabilidade de takeover de subdomínio", action='store_true')
    parser.add_argument("--ssl", help="Extrair informações do certificado SSL", action='store_true')
    parser.add_argument("-jl", "--js-links", help="Encontrar endpoints em arquivos JavaScript", action='store_true')
    parser.add_argument("-t", "--tech", help="Descobrir tecnologias utilizadas na página", action='store_true')
    parser.add_argument("-c", "--cors", help="Testar configurações incorretas de CORS", action='store_true')
    parser.add_argument("-b", "--backups", help="Procurar por arquivos de backup comuns", action='store_true')
    parser.add_argument("-w", "--waf", help="Detectar WAF (Web Application Firewall)", action='store_true')
    parser.add_argument("-r", "--repos", help="Descobrir repositórios válidos do domínio", action='store_true')
    parser.add_argument("--email", help="Buscar emails (padrão: máximo 50)", nargs='?', const=50, type=int)
    parser.add_argument("--threads", help="Número de threads (padrão: 5)", type=int, default=5)
    parser.add_argument("-V", "--version", help="Exibir a versão da ferramenta", action='store_true')
    return parser.parse_args()

def nmap_scan(domain: str, port_range: str = "1-1024") -> None:
    """Executa portscan via Nmap e registra a saída."""
    command = ["nmap", "-sS", "-svvv", "-p", port_range, domain]
    logging.info("[*] Executando nmap: " + " ".join(command))
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        logging.info(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.error("Erro ao executar nmap: " + str(e))

def generate_html_report(report_md: pathlib.Path) -> pathlib.Path:
    """Converte o relatório Markdown para HTML utilizando Bootstrap e salva com a extensão .html."""
    md_content = report_md.read_text(encoding="utf-8")
    html_body = markdown.markdown(md_content, extensions=['extra', 'tables'])
    
    # ASCII art do cachorro, fonte reduzida e line-height menor
    ascii_art = r"""
                                               
                                        ##        
                                      ####        
                                      ####        
                                    ########      
                                  ############    
  ##                              ################
  ##                          ##    ##############
  ##                        ######    ##    ####  
  ####################################            
    ##################################            
  ######################################          
  ######################################          
  ####################################            
  ##############  ####################            
  ############        ################            
  ############              ##########            
    ########                  ########            
  ##########                  ##  ##              
  ####  ####                ####  ##              
  ####  ####                ####  ##              
  ####  ####                ####  ##              
  ####  ####                ####  ####            
  ####    ####              ############          
    ##                                            
"""

    html_template = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Relatório Nina Recon Tool - {report_md.stem}</title>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  <style>
    body {{
      padding: 20px;
    }}
    pre.ascii-art {{
      background-color: #f8f9fa;
      padding: 15px;
      border-radius: 5px;
      font-size: 8px;    /* Fonte menor para reduzir o tamanho do desenho */
      line-height: 1;    /* Reduzindo o espaçamento entre linhas */
      overflow-x: auto;  /* Rolagem horizontal caso necessário */
    }}
    h1, h2, h3, h4, h5, h6, p {{
      margin-bottom: 1rem;
    }}
    .header-span {{
      margin-bottom: 10px;
    }}
  </style>
</head>
<body>
  <div class="container">
    <span class="d-block p-2 bg-primary text-white header-span">Relatório Nina Recon Tool</span>
    <span class="d-block p-2 bg-dark text-white header-span">URL Testada: {report_md.stem}.report</span>
    <h1 class="mt-3">RELATÓRIO NINA RECON TOOL PARA {report_md.stem}</h1>
    <h2 class="mb-4">Detalhes do Recon</h2>
    
    <!-- Seção com ASCII Art em tamanho reduzido -->
    <pre class="ascii-art mb-4">
{ascii_art}
    </pre>
    
    <!-- Conteúdo do relatório -->
    <div class="report-content">
      {html_body}
    </div>
  </div>
  <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // Adiciona a classe "table" a todas as tabelas
    document.addEventListener("DOMContentLoaded", function() {{
      var tables = document.getElementsByTagName("table");
      for (var i = 0; i < tables.length; i++) {{
        tables[i].classList.add("table");
      }}
    }});
  </script>
</body>
</html>"""
    
    report_html = report_md.with_suffix(".html")
    report_html.write_text(html_template, encoding="utf-8")
    logging.info(f"Relatório HTML salvo em: {report_html}")
    return report_html

def start_http_server(directory: pathlib.Path, port: int = 4366):
    """Inicia um servidor HTTP local para servir o diretório e abre o relatório HTML no navegador."""
    os.chdir(directory)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        url = f"http://localhost:{port}/"
        logging.info(f"Servidor HTTP iniciado em {url}")
        webbrowser.open(url)
        httpd.serve_forever()

def directory_enumeration(domain: str, store: bool, report_file: pathlib.Path, common_dirs: list = None):
    """Realiza enumeração de diretórios comuns e adiciona os resultados ao relatório."""
    import requests
    if common_dirs is None:
        common_dirs = ["/admin", "/login", "/uploads", "/includes", "/backup", "/config"]
    results = []
    for d in common_dirs:
        url = f"http://{domain}{d}"
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200:
                results.append(url)
        except Exception:
            pass
    if results:
        with report_file.open("a", encoding="utf-8") as f:
            f.write("\n\n## Directory Enumeration<br><br>\n")
            for url in results:
                f.write(f"- {url}<br>\n")
        logging.info(f"Diretórios encontrados: {results}")

def header_security_scan(domain: str, store: bool, report_file: pathlib.Path):
    """Verifica os cabeçalhos de segurança HTTP e adiciona os resultados ao relatório."""
    import requests
    try:
        r = requests.get("http://" + domain, timeout=5, verify=False)
        headers = r.headers
        secure_headers = {
            "X-Frame-Options": headers.get("X-Frame-Options", "Not found"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "Not found"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Not found"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Not found")
        }
        with report_file.open("a", encoding="utf-8") as f:
            f.write("\n\n## Security Headers<br><br>\n")
            for header, value in secure_headers.items():
                f.write(f"- {header}: {value}<br>\n")
        logging.info(f"Cabeçalhos de segurança: {secure_headers}")
    except Exception as e:
        logging.error(f"Erro ao verificar cabeçalhos de segurança: {e}")

def print_banner() -> None:
    banner_text = f"""
{GREEN}NINA RECON TOOL{RESET}
{YELLOW}
              .--~~,__
 :-....,-------`~~'._.'  
  `-,,,  ,_      ;'~U'   
   _,-' ,'`-__; '--.    
  (_/'~~      ''''(;     
{RESET}
          by H41stur
"""
    print(banner_text)

def validate_domain(domain: str) -> None:
    try:
        socket.gethostbyname(domain)
    except socket.gaierror:
        logging.error(f"{YELLOW}O domínio '{domain}' não está respondendo!{RESET}")
        sys.exit(1)

def write_vulnerabilities(vulnerabilities: list, store: bool, report_dir: pathlib.Path, domain: str, report_file: pathlib.Path) -> None:
    if vulnerabilities and store:
        web_vulns = []
        infra_vulns = []
        with report_file.open("a", encoding="utf-8") as f:
            f.write("\n\n## Vulnerabilidades Encontradas<br><br>\n")
            for vuln in vulnerabilities:
                parts = vuln.split(",")
                if "WEB" in parts[0]:
                    web_vulns.append(parts)
                elif "Infra" in parts[0]:
                    infra_vulns.append(parts)
            if infra_vulns:
                f.write("\n\n### Infraestrutura<br><br>\n")
                f.write('<table class="table"><thead><tr><th>Vulnerabilidade</th><th>Confiança</th><th>Endpoint</th><th>Severidade</th></tr></thead><tbody>')
                for v in infra_vulns:
                    f.write(f"<tr><td>{v[1]}</td><td>{v[2]}</td><td>{v[4]}</td><td>{v[3]}</td></tr>")
                f.write("</tbody></table>")
            if web_vulns:
                f.write("\n\n### WEB<br><br>\n")
                f.write('<table class="table"><thead><tr><th>Vulnerabilidade</th><th>Confiança</th><th>Endpoint</th><th>Severidade</th></tr></thead><tbody>')
                for v in web_vulns:
                    f.write(f"<tr><td>{v[1]}</td><td>{v[2]}</td><td>{v[4]}</td><td>{v[3]}</td></tr>")
                f.write("</tbody></table>")
        logging.info(f"Relatório salvo em: {report_dir / f'{domain}.report.md'}")

def main() -> None:
    print_banner()
    args = parse_arguments()
    version = "2.1.0"

    if args.version:
        print(f"Nina Recon Tool versão: {version}")
        sys.exit(0)

    domain_input = args.domain
    if "." not in domain_input:
        logging.error("Formato de domínio inválido. Utilize, por exemplo: example.com")
        sys.exit(1)
    extracted = tldextract.extract(domain_input)
    domain = f"{extracted.domain}.{extracted.suffix}"
    validate_domain(domain)

    store = args.output
    report_dir = pathlib.Path.cwd() / domain if store else None
    report_file = None
    if store:
        try:
            report_dir.mkdir(exist_ok=True)
        except Exception as e:
            logging.error(f"Erro ao criar o diretório {report_dir}: {e}")
            sys.exit(1)
        report_file = report_dir / f"{domain}.report.md"
        if report_file.exists():
            report_file.unlink()
        # Início do relatório em Markdown
        report_file.write_text(f"# RELATÓRIO NINA RECON TOOL PARA {domain.upper()}<br><br>\n", encoding="utf-8")

    THREADS = args.threads
    MAX_EMAILS = args.email
    script_path = pathlib.Path(__file__).parent.resolve()
    src_path = str(script_path / "src")
    vulnerabilities = []
    subs = []

    try:
        if args.all:
            # Caso "all" seja escolhido, executa todos os módulos
            if args.subdomains:
                subs = subDomain(domain, store, str(report_file))
            whois_lookup(domain, store, str(report_file), vulnerabilities)
            dns_information(domain, store, str(report_dir), str(report_file), vulnerabilities)
            spoof(domain, vulnerabilities)
            zone_transfer(domain, store, str(report_file), vulnerabilities)
            if args.nmap_scan:
                nmap_scan(domain)
            elif args.portscan:
                portscan(domain, THREADS)
            if subs:
                subtake(domain, store, subs, str(report_file), THREADS)
            ssl_information(domain, store, str(src_path), str(report_file), subs, THREADS)
            js_links(domain, store, str(report_file), subs, THREADS)
            cors(domain, store, str(report_file), subs, src_path, vulnerabilities, THREADS)
            dorks(domain, store, str(report_file))
            find_emails(domain, store, str(report_file), MAX_EMAILS, THREADS)
            search_backups(domain, store, str(report_file), subs, THREADS)
            tech(domain, store, str(report_file), subs, THREADS)
            find_repos(domain, store, str(report_file), subs)
            detect_waf(domain, store, str(report_file), subs, str(src_path), THREADS)
            directory_enumeration(domain, store, report_file)
            header_security_scan(domain, store, report_file)
            write_vulnerabilities(vulnerabilities, store, report_dir, domain, report_file)
            
            # Converte o relatório MD para HTML com Bootstrap
            report_html = generate_html_report(report_file)
            # Inicia servidor HTTP local em uma thread separada
            server_thread = threading.Thread(target=start_http_server, args=(report_dir, 4366), daemon=True)
            server_thread.start()
            time.sleep(2)
            webbrowser.open(f"http://localhost:4366/{report_html.name}")
            server_thread.join()
            sys.exit(0)

        # Execução individual das opções selecionadas
        if args.dns:
            dns_information(domain, store, str(report_dir), str(report_file), vulnerabilities)
        if args.subdomains:
            subs = subDomain(domain, store, str(report_file))
        if args.subtake:
            if not subs:
                subs = subDomain(domain, store, str(report_file))
            subtake(domain, store, subs, str(report_file), THREADS)
        if args.axfr:
            zone_transfer(domain, store, str(report_file), vulnerabilities)
        if args.repos:
            find_repos(domain, store, str(report_file), subs)
        if args.waf:
            detect_waf(domain, store, str(report_file), subs, str(src_path), THREADS)
        if args.whois:
            whois_lookup(domain, store, str(report_file), vulnerabilities)
        if args.backups:
            search_backups(domain, store, str(report_file), subs, THREADS)
        if args.tech:
            tech(domain, store, str(report_file), subs, THREADS)
        if args.cors:
            cors(domain, store, str(report_file), subs, src_path, vulnerabilities, THREADS)
        if args.dork:
            dorks(domain, store, str(report_file))
        if args.nmap_scan:
            nmap_scan(domain)
        elif args.portscan:
            portscan(domain, THREADS)
        if args.spoof:
            spoof(domain, vulnerabilities)
        if args.email:
            find_emails(domain, store, str(report_file), MAX_EMAILS, THREADS)
        if args.ssl:
            ssl_information(domain, store, str(src_path), str(report_file), subs, THREADS)
        if args.js_links:
            js_links(domain, store, str(report_file), subs, THREADS)

        write_vulnerabilities(vulnerabilities, store, report_dir, domain, report_file)
    except KeyboardInterrupt:
        logging.warning(f"{YELLOW}Interrupção detectada, saindo...{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()
