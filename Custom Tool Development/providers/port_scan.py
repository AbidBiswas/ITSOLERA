import socket
import nmap
import logging

def scan(target_host, common_ports=None, full_scan=False, aggressive=False):
    logging.info(f"Starting Nmap scan on {target_host}...")

    open_ports = {}
    try:
        # Resolve domain to IP manually
        try:
            ip_addr = socket.gethostbyname(target_host)
            logging.debug(f"Resolved {target_host} to {ip_addr}")
        except socket.gaierror:
            logging.error(f"Failed to resolve host: {target_host}")
            return {}

        nm = nmap.PortScanner()

        if full_scan:
            ports_range = "1-65535"
        else:
            if not common_ports:
                common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 8080]
            ports_range = ",".join(map(str, common_ports))

        args = f"-p {ports_range} -sV -T4 -Pn"
        if aggressive:
            args += " -A"

        logging.debug(f"Nmap arguments: {args}")
        nm.scan(hosts=ip_addr, arguments=args)

        if ip_addr in nm.all_hosts():
            for proto in nm[ip_addr].all_protocols():
                ports = nm[ip_addr][proto].keys()
                for port in sorted(ports):
                    state = nm[ip_addr][proto][port].get("state")
                    service = nm[ip_addr][proto][port].get("name", "")
                    version = nm[ip_addr][proto][port].get("version", "")
                    if state == "open":
                        open_ports[port] = f"{service} {version}".strip()
                        logging.debug(f"Open port found: {port} ({service} {version})")
        else:
            logging.warning(f"Nmap did not return results for host {ip_addr}")

    except nmap.PortScannerError as e:
        logging.error(f"Nmap error: {e}. Ensure Nmap is installed and in your PATH.")
    except Exception as e:
        logging.error(f"Unexpected error during port scanning: {e}")

    return open_ports
	
