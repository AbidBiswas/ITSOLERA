import requests

def enumerate(target_url, wordlist_path="../wordlists/common.txt"):
    print(f"[*] Starting directory enumeration for {target_url}...")
    found_paths = []
    try:
        with open(wordlist_path, "r") as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found at {wordlist_path}. Skipping directory enumeration.")
        return []

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    for path in wordlist:
        test_url = f"{target_url}/{path}"
        try:
            response = requests.get(test_url, timeout=2)
            if response.status_code == 200:
                print(f"  [+] Found: {test_url} (Status: {response.status_code})")
                found_paths.append(test_url)
            elif response.status_code == 401 or response.status_code == 403:
                print(f"  [!] Restricted: {test_url} (Status: {response.status_code})")
                found_paths.append(f"{test_url} (Restricted)")
        except requests.exceptions.RequestException as e:
            pass
    return found_paths
