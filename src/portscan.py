import socket
import ssl
import logging
import concurrent.futures

SSL_PORTS = {443, 8443, 465, 993, 995}

def portscan_request(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in SSL_PORTS:
                context = ssl.create_default_context()
                try:
                    s = context.wrap_socket(s, server_hostname=host)
                except Exception as e:
                    logging.warning(f"Erro ao aplicar SSL em {host}:{port}: {e}. Usando conexão sem SSL.")
            try:
                banner_bytes = s.recv(200)
                banner = banner_bytes.decode('utf-8', errors='replace')
            except Exception as recv_err:
                logging.debug(f"Erro ao ler banner em {host}:{port} - {recv_err}")
                banner = ""
            return banner
    except Exception as e:
        logging.debug(f"Erro ao conectar em {host}:{port} - {e}")
        return ""

def portscan(domain: str, threads: int) -> None:
    common_ports = [21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 111, 2000, 3306, 5060]
    host = domain
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {executor.submit(portscan_request, host, port): port for port in common_ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                banner = future.result()
                if banner:
                    logging.info(f"- Discovered open port: {host} {port} - Banner: {banner.strip()}")
                else:
                    logging.info(f"- Discovered open port: {host} {port} - Sem banner")
            except Exception as exc:
                logging.error(f"Erro na porta {port}: {exc}")
