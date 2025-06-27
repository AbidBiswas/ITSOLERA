import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Security Payload Generator Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--xss", action="store_true")
    group.add_argument("--sqli", action="store_true")
    group.add_argument("--cmd", action="store_true")

    parser.add_argument("--encode", choices=["base64", "url", "hex", "unicode"])
    parser.add_argument("--obfuscate", action="store_true")
    parser.add_argument("--output", choices=["cli", "json"], default="cli")
    parser.add_argument("--clipboard", action="store_true")

    return parser.parse_args()