import base64
import urllib.parse

def encode_payload(payload, encoding_type):
    if encoding_type == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif encoding_type == "url":
        return urllib.parse.quote(payload)
    elif encoding_type == "hex":
        return ''.join('\\x{:02x}'.format(ord(c)) for c in payload)
    elif encoding_type == "unicode":
        return ''.join('\\u{:04x}'.format(ord(c)) for c in payload)
    return payload