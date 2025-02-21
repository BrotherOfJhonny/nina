# Nina_V2 Recon Tool – Versão Alterada

<p align="center">
  <img src="https://github.com/BrotherOfJhonny/nina/blob/main/src/nina.png" alt="Nina" width="400">
</p>
Nina Recon Tool é uma ferramenta de reconhecimento para domínios e seus subdomínios, projetada para economizar tempo nas fases iniciais de testes de penetração e bug bounty.  
Esta nova versão foi totalmente reformulada e aprimorada para oferecer uma experiência mais rica e interativa, com relatórios em HTML baseados em Bootstrap, fallback de dorking, funcionalidades ampliadas e um servidor web local para visualização imediata do relatório.


## Instalação

Clone o repositório e instale as dependências:
```bash
git clone https://github.com/BrotherOfJhonny/nina.git
cd nina
python3 -m venv venv
source venv/bin/activate
```

requirements.txt que inclui todos os pacotes necessários para executar o projeto:
```

# Requisitos para Nina Recon Tool

requests>=2.25.0
colorama>=0.4.4
markdown>=3.3.4
beautifulsoup4>=4.9.3
tldextract>=3.1.0
PyYAML>=5.4.1
wget>=3.2
dnspython>=2.1.0
PrettyTable>=2.4.0
jsbeautifier>=1.14.0
python-whois>=0.7.3

# Para compatibilidade com Python 2.7 (caso necessário)
futures>=3.0.5; python_version < "3.0"
```

Para Instalar execute o comando:
```bash
pip install -r requirements.txt
```

Nota:
Para usuários de Python 2.7, instale o pacote futures para compatibilidade com concurrent.futures.

## Uso

Para executar todas as funcionalidades e gerar o relatório, use:

```bash
sudo python3 nina_v2.py -d dominio.com.br -A -o

-d: Domínio alvo.
-A: Executa todas as funções de reconhecimento.
-o: Salva o relatório em um diretório (o relatório é gerado inicialmente em Markdown e convertido para HTML).
-s: O script chama subDomain e, em seguida, chama brute_force_subdomains.

Após a execução, o relatório HTML é gerado com um template Bootstrap interativo
um servidor HTTP local na porta 4366 é iniciado, abrindo automaticamente o relatório no seu navegador.

```


  <img src="https://github.com/BrotherOfJhonny/nina/blob/main/src/report_nina.jpg" alt="Relatorio" width="400">



```
  
## Funcionalidades
|----------------------|-----------------------------------------|-----------------------------------------------------------------------------------------------------------|
| **Category**         | **Feature**                             | **Description**                                                                                           |
|----------------------|-----------------------------------------|-----------------------------------------------------------------------------------------------------------|
| **Discovery**        | WHOIS Lookup                            | Pesquisa informações WHOIS do domínio.                                                                    |
| **Discovery**        | DNS Information                         | Coleta informações DNS, SPF/DMARC e servidores de email.                                                  |
| **Discovery**        | Portscan                                | Realiza varredura de portas (interno com suporte a SSL ou via Nmap).                                      |
| **Discovery**        | JavaScript Links Extraction             | Identifica endpoints e parâmetros em arquivos de JavaScript.                                              |
| **Discovery**        | Technology Enumeration                  | Descobre tecnologias utilizadas na página.                                                                |
| **Discovery**        | Backup Files Search                     | Procura por arquivos de backup comuns.                                                                    |
| **Discovery**        | WAF Detection                           | Detecta a presença de firewalls de aplicação web.                                                         |
| **Discovery**        | Git Repositories Search                 | Verifica a existência de repositórios públicos.                                                           |
| **Discovery**        | Subdomain Enumeration e Takeover        | Pesquisa subdomínios registrados e verifica possíveis takeover.                                           |
| **OSINT**            | Google Dorking com Fallback para Bing   | Realiza dorking com o Google; se houver timeout ou falha, utiliza o Bing.                                 |
| **OSINT**            | Email Discovery                         | Busca por emails relacionados ao domínio alvo.                                                            |
| **Vulnerabilities**  | Email Spoofing Check                    | Verifica vulnerabilidades de spoofing de email (baseado em SPF e DMARC).                                  |
| **Vulnerabilities**  | Zone Transfer Attack (AXFR)             | Tenta realizar transferência de zona.                                                                     |
| **Vulnerabilities**  | CORS Misconfiguration Check             | Verifica configurações incorretas de CORS.                                                                |
| **Extras**           | Directory Enumeration                   | Enumera diretórios comuns.                                                                                |
| **Extras**           | Security Headers Scan                   | Verifica cabeçalhos de segurança HTTP.                                                                    |
|----------------------|-----------------------------------------|-----------------------------------------------------------------------------------------------------------|




# 💐💐💐 Este é um tributo para amiga do meu amigo 💐💐💐

Isso é uma versão sem vergonha de um trabalho bem feito, peço desculpas ao desenvolvedor original.

Licença
Este projeto está licenciado sob a MIT License.

Projeto original:
https://github.com/h41stur/nina


