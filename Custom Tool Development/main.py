import argparse
import logging
import os
import yaml
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from providers import (
    whois_lookup, dns_enum, crtsh, hackertarget,
    active_recon, port_scan, dir_enum, vul_scan, virustotal
)


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def create_ascii_art(text):
    char_map = {
        'I': ["#####", "  #  ", "  #  ", "  #  ", "#####"],
        'T': ["#######", "   #   ", "   #   ", "   #   ", "   #   "],
        'S': ["########", "#       ", "########", "       #", "########"],
        'O': ["########", "#      #", "#      #", "#      #", "########"],
        'L': ["#       ", "#       ", "#       ", "#       ", "########"],
        'E': ["########", "#       ", "########", "#       ", "########"],
        'R': ["####### ", "#      #", "####### ", "#     # ", "#      #"],
        'A': ["   #   ", "  # #  ", " #   # ", "#######", "#     #"],
        ' ': ["       ", "       ", "       ", "       ", "       "]
    }
    banner_lines = [""] * 5
    for i in range(5):
        for char in text.upper():
            banner_lines[i] += char_map.get(char, char_map[' '])[i] + "  "
    return "\n".join(banner_lines)


def setup_logging(verbosity):
    levels = [logging.ERROR, logging.WARNING, logging.INFO, logging.DEBUG]
    level = levels[min(verbosity, 3)]
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def load_config():
    try:
        with open("config/sources.yaml", "r") as f:
            config = yaml.safe_load(f)
            logging.debug("Configuration loaded successfully.")
            return config
    except FileNotFoundError:
        logging.error("Configuration file not found: config/sources.yaml")
        return {}


def detect_technologies(domain):
    techs = set()
    try:
        url = f"http://{domain}"
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        html = resp.text.lower()
        soup = BeautifulSoup(html, "html.parser")

        server = headers.get("Server")
        if server:
            techs.add(f"Server: {server}")
        powered = headers.get("X-Powered-By")
        if powered:
            techs.add(f"X-Powered-By: {powered}")
        cookies = resp.cookies.get_dict()
        for cookie in cookies:
            if "wordpress" in cookie:
                techs.add("CMS: WordPress (cookie)")
            elif "php" in cookie:
                techs.add("Backend: PHP (cookie)")
            elif "laravel" in cookie:
                techs.add("Framework: Laravel (cookie)")
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator and generator.get("content"):
            techs.add(f"Meta Generator: {generator['content']}")
        comments = soup.find_all(string=lambda text: isinstance(text, str) and "generator" in text.lower())
        for comment in comments:
            if "joomla" in comment:
                techs.add("CMS: Joomla (HTML comment)")
            if "drupal" in comment:
                techs.add("CMS: Drupal (HTML comment)")
        libs = {
            "jquery": "JavaScript Library: jQuery",
            "react": "JavaScript Framework: React",
            "angular": "JavaScript Framework: Angular",
            "vue": "JavaScript Framework: Vue.js",
            "bootstrap": "CSS Framework: Bootstrap"
        }
        scripts = soup.find_all("script", src=True)
        links = soup.find_all("link", href=True)
        for tag in scripts + links:
            src = tag.get("src") or tag.get("href")
            for key, val in libs.items():
                if key in src.lower():
                    techs.add(val)
        if "/wp-content/" in html or "/wp-includes/" in html:
            techs.add("CMS: WordPress (path heuristic)")
        if "/sites/all/modules/" in html:
            techs.add("CMS: Drupal (path heuristic)")
        favicon_url = urljoin(url, "/favicon.ico")
        try:
            fav_resp = requests.get(favicon_url, timeout=3)
            if fav_resp.ok:
                fav_hash = hash(fav_resp.content)
                if fav_hash == 123456789:
                    techs.add("CMS: ExampleCMS (favicon hash)")
        except:
            pass
    except Exception as e:
        logging.error(f"Technology detection failed: {e}")
    return sorted(techs)


def main(domain, whois_flag, dns_flag, subdomains_flag, active_flag,
         ports_flag, dirs_flag, vulns_flag, vt_flag, tech_flag,
         full_scan, aggressive_scan):

    config = load_config()
    logging.info(f"Loaded configuration for tools.")

    if whois_flag:
        print("--- WHOIS Lookup ---")
        print(whois_lookup.lookup(domain), "\n")

    if dns_flag:
        print("--- DNS Enumeration ---")
        dns_data = dns_enum.enum(domain)
        for record_type, records in dns_data.items():
            print(f"{record_type} Records:")
            for r in records if isinstance(records, list) else [records]:
                print(f"  - {r}")
        print()

    if subdomains_flag:
        print("--- Subdomain Enumeration ---")
        all_subdomains = set()
        if config.get("crtsh", {}).get("enabled"):
            all_subdomains.update(crtsh.search(domain))
        if config.get("hackertarget", {}).get("enabled"):
            all_subdomains.update(hackertarget.search(domain))
        for sub in sorted(all_subdomains):
            print(sub)
        with open(f"{domain}_subdomains.txt", "w") as f:
            for sub in sorted(all_subdomains):
                f.write(f"{sub}\n")
        print()

    if active_flag:
        print("--- Active Recon ---")
        active_recon.run_active_recon(domain)
        print()

    if ports_flag:
        print("--- Port Scanning ---")
        open_ports = port_scan.scan(domain, full_scan=full_scan, aggressive=aggressive_scan)
        for port, service in open_ports.items():
            print(f"  - Port {port}: {service}")
        if not open_ports:
            print("No open ports found.")
        print()

    if dirs_flag:
        print("--- Directory and File Enumeration ---")
        for path in dir_enum.enumerate(domain):
            print(f"  - {path}")
        print()

    if vulns_flag:
        print("--- Basic Vulnerability Scan ---")
        for vuln in vul_scan.scan(domain):
            print(f"  - {vuln}")
        print()

    if vt_flag:
        print("--- VirusTotal Domain Report ---")
        vt_config = config.get("virustotal", {})
        api_key = vt_config.get("api_key")
        if not api_key:
            print("VirusTotal API key not configured.")
        else:
            vt_result = virustotal.domain_report(domain, api_key)
            if "error" in vt_result:
                print(vt_result["error"])
            else:
                print(f"Reputation Score: {vt_result['reputation']}")
                print(f"Categories: {vt_result['categories']}")
                for engine, count in vt_result["last_analysis"].items():
                    print(f"  - {engine}: {count}")
        print()

    if tech_flag:
        print("--- Technology Detection ---")
        techs = detect_technologies(domain)
        if techs:
            for tech in techs:
                print(f"- {tech}")
        else:
            print("No technologies detected.")
        print()


if __name__ == "__main__":
    clear_console()
    BRIGHT_RED = "\033[91m"
    RESET_COLOR = "\033[0m"
    print(BRIGHT_RED + create_ascii_art("ITSOLERA") + RESET_COLOR)
    print(f"\n{BRIGHT_RED}>> INITIALIZING SECURE CONNECTION...{RESET_COLOR}")
    print(f"{BRIGHT_RED}>> AUTHENTICATION PROTOCOL V2.0 ACTIVATED...{RESET_COLOR}")
    print(f"{BRIGHT_RED}>> ACCESS GRANTED. WELCOME, OPERATOR.{RESET_COLOR}\n")

    parser = argparse.ArgumentParser(description="A comprehensive reconnaissance tool.")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains via APIs")
    parser.add_argument("--active", action="store_true", help="Run active reconnaissance")
    parser.add_argument("--ports", action="store_true", help="Perform port scanning")
    parser.add_argument("--dirs", action="store_true", help="Directory and file enumeration")
    parser.add_argument("--vulns", action="store_true", help="Run a basic vulnerability scan")
    parser.add_argument("--vt", action="store_true", help="Query VirusTotal domain report")
    parser.add_argument("--tech", action="store_true", help="Detect technologies used by the target website")
    parser.add_argument("--full-port-scan", action="store_true", help="Scan all 65535 ports (very slow)")
    parser.add_argument("--aggressive-scan", action="store_true", help="Enable aggressive Nmap scan (-A)")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="Increase output verbosity (-v, -vv, -vvv)")

    args = parser.parse_args()
    setup_logging(args.verbose)

    main(
        domain=args.domain,
        whois_flag=args.whois,
        dns_flag=args.dns,
        subdomains_flag=args.subdomains,
        active_flag=args.active,
        ports_flag=args.ports,
        dirs_flag=args.dirs,
        vulns_flag=args.vulns,
        vt_flag=args.vt,
        tech_flag=args.tech,
        full_scan=args.full_port_scan,
        aggressive_scan=args.aggressive_scan
    )
