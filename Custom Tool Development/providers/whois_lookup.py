import whois

def lookup(domain):
    print(f"  [*] Performing WHOIS lookup for {domain} (Placeholder)...")
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Error during WHOIS lookup: {e}"
