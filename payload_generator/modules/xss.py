# modules/xss.py

import os

def generate_xss_payloads(obfuscate=False):
    path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'xss_payload.txt')
    with open(path, encoding='utf-8', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip()]
    if obfuscate:
        payloads = [p.replace("alert", "a\\u006cert") for p in payloads]
    return payloads
