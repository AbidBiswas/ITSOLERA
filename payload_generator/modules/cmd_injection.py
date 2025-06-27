import os

def generate_cmd_payloads(obfuscate=False):
    path = os.path.join(os.path.dirname(__file__), '..', 'payloads', 'cmd_payloads.txt')
    with open(path, encoding='utf-8', errors='ignore') as f:
        payloads = [line.strip() for line in f if line.strip()]
    if obfuscate:
        # Example obfuscation: replace spaces with `${IFS}` (bash internal field separator)
        payloads = [p.replace(" ", "${IFS}") for p in payloads]
    return payloads
