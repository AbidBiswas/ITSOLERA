import os

def generate_sqli_payloads(obfuscate=False):
    path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'sql_payloads.txt')
    with open(path, encoding='utf-8', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip()]
    if obfuscate:
        payloads = [p.replace(" ", "/**/") for p in payloads]
    return payloads
