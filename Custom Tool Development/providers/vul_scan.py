import requests

COMMON_VULN_PATHS = [
    ("/.env", "APP_KEY", "Potentially exposed .env file"),
    ("/.git/config", "[core]", "Potentially exposed Git repository"),
    ("/config.php", "<?php", "Exposed PHP config file"),
    ("/.htaccess", "RewriteEngine", "Exposed Apache .htaccess file"),
    ("/phpinfo.php", "phpinfo()", "Exposed phpinfo() file"),
    ("/wp-config.php", "DB_NAME", "Exposed WordPress config file"),
    ("/server-status", "Apache Status", "Apache server-status exposed"),
    ("/.DS_Store", "Bud1", "Potential .DS_Store info leak"),
    ("/crossdomain.xml", "<cross-domain-policy>", "Exposed crossdomain.xml file"),
    ("/robots.txt", "Disallow:", "robots.txt available (may disclose sensitive paths)"),
]

HEADERS_TO_CHECK = [
    "Server",
    "X-Powered-By",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Content-Security-Policy"
]

def scan(target_url):
    print(f"[*] Running basic vulnerability scan for {target_url}...")
    vulnerabilities = []

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    # Check common exposed paths
    for path, keyword, description in COMMON_VULN_PATHS:
        try:
            response = requests.get(target_url + path, timeout=5)
            if response.status_code == 200 and keyword in response.text:
                vulnerabilities.append(f"{description} found at {target_url}{path}")
        except requests.RequestException:
            continue

    # Check HTTP headers for missing security features
    try:
        response = requests.get(target_url, timeout=5)
        headers = response.headers
        for header in HEADERS_TO_CHECK:
            if header not in headers:
                vulnerabilities.append(f"Missing security header: {header}")
    except requests.RequestException:
        vulnerabilities.append(f"Failed to connect to {target_url} for header analysis.")

    if not vulnerabilities:
        vulnerabilities.append("No obvious vulnerabilities found by this basic scan.")

    return vulnerabilities
