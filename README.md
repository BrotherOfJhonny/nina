# Nina Recon Tool – Versão modificada

<p align="center">
  <img src="https://raw.githubusercontent.com/h41stur/nina/main/nina/data/nina.jpeg" alt="Nina" width="400">
</p>

Nina Recon Tool é uma ferramenta de reconhecimento para domínios e seus subdomínios, projetada para economizar tempo nas fases iniciais de testes de penetração e bug bounty.  
Esta nova versão foi totalmente reformulada e aprimorada para oferecer uma experiência mais rica e interativa, com relatórios em HTML baseados em Bootstrap, fallback de dorking, funcionalidades ampliadas e um servidor web local para visualização imediata do relatório.

---

## Instalação

Clone o repositório e instale as dependências:

```bash
git clone https://github.com/h41stur/nina.git
cd nina
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Caso não possua um arquivo requirements.txt, instale manualmente:
```bash
pip install requests colorama markdown beautifulsoup4
```
requirements.txt
```bash
# Requisitos para Nina Recon Tool

requests>=2.20.0
colorama>=0.4.0
markdown>=3.0
beautifulsoup4>=4.6.0
tldextract>=3.1.0

# Para compatibilidade com Python 2.7, se necessário (opcional)
futures>=3.0.5
```

Nota:
Para usuários de Python 2.7, instale o pacote futures para compatibilidade com concurrent.futures.

Uso
Exiba a ajuda do programa:

```bash
python3 nina_v2.py -h
```
Para executar todas as funcionalidades e gerar o relatório, use:

```bash
sudo python3 nina_v2.py -d xpto.com.br -A -o
-d: Domínio alvo.
-A: Executa todas as funções de reconhecimento.
-o: Salva o relatório em um diretório (o relatório é gerado inicialmente em Markdown e convertido para HTML).
Após a execução, o relatório HTML é gerado com um template Bootstrap interativo e um servidor HTTP local na porta 4366 é iniciado, abrindo automaticamente o relatório no seu navegador.
```

API Keys

As chaves de API (se necessário para alguns módulos) podem ser configuradas no arquivo:

```bash
nina/data/api-keys.yaml
```
```
Funcionalidades

## Discovery
- WHOIS Lookup
- Pesquisa informações WHOIS do domínio.
## DNS Information
- Coleta informações DNS, SPF/DMARC e servidores de email.
## Portscan
- Realiza varredura de portas (interno com suporte a SSL ou via Nmap).
## JavaScript Links Extraction
- Identifica endpoints e parâmetros em arquivos JavaScript.
## Technology Enumeration
- Descobre tecnologias utilizadas na página.
## Backup Files Search
- Procura por arquivos de backup comuns.
## WAF Detection
- Detecta a presença de firewalls de aplicação web.
## Git Repositories Search
- Verifica a existência de repositórios públicos.
## Subdomain Enumeration e Takeover
- Pesquisa subdomínios registrados e verifica possíveis takeover.
## OSINT
- Google Dorking com Fallback para Bing
- Realiza dorking com o Google; se houver timeout ou falha, utiliza o Bing.
## Email Discovery
- Busca por emails relacionados ao domínio alvo.
## Vulnerabilities
- Email Spoofing Check
- Verifica vulnerabilidades de spoofing de email (baseado em SPF e DMARC).
## Zone Transfer Attack (AXFR)
- Tenta realizar transferência de zona.
## CORS Misconfiguration Check
- Verifica configurações incorretas de CORS.

## Extras
Directory Enumeration
- Enumera diretórios comuns.
## Security Headers Scan
- Verifica cabeçalhos de segurança HTTP.
Relatório HTML
- O relatório gerado é convertido para HTML utilizando um template Bootstrap, que inclui:
```

As alterações foram feitas com ajuda de IA, este cara de infraestrutura que se meteu a programar gera este tipo de coisa.

💐💐💐 Tributo para a amiga do meu amigo 💐💐💐

Repositorio original:
https://github.com/h41stur/nina/blob/main/README.md
h41stur ->Baita cara gente boa, jeito de bravo coração de criança. 


