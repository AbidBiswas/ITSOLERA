from cli import parse_args
from modules import xss, sqli, cmd_injection
from payload_encoder import encode_payload
import json
import pyperclip

def main():
    args = parse_args()
    payloads = []

    if args.xss:
        payloads = xss.generate_xss_payloads(args.obfuscate)
    elif args.sqli:
        payloads = sqli.generate_sqli_payloads(args.obfuscate)
    elif args.cmd:
        payloads = cmd_injection.generate_cmd_payloads(args.obfuscate)

    if args.encode:
        payloads = [encode_payload(p, args.encode) for p in payloads]

    if args.output == 'json':
        print(json.dumps(payloads, indent=2))
    else:
        for p in payloads:
            print(p)

    if args.clipboard:
        pyperclip.copy("\n".join(payloads))
        print("[+] Payloads copied to clipboard.")

if __name__ == "__main__":
    main()