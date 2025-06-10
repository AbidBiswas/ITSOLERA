Installation
Clone the repository:

git clone https://github.com/yourusername/recon-tool.git
cd recon-tool
Install required Python dependencies:

pip install -r requirements.txt
(Optional) For enhanced tech detection, install Wappalyzer CLI globally using Node.js:

npm install -g wappalyzer
Configure API keys and tool settings in config/sources.yaml.

Usage
Run the tool from the command line:

python3 main.py example.com --whois --dns --subdomains --ports --tech --wappa -vv
Use the flags to specify which reconnaissance modules to run:

--whois — WHOIS lookup

--dns — DNS enumeration

--subdomains — Subdomain enumeration

--active — Active reconnaissance

--ports — Port scanning

--dirs — Directory enumeration

--vulns — Vulnerability scanning

--vt — VirusTotal domain report

--tech — Basic technology detection

--wappa — Enhanced technology detection with Wappalyzer CLI

-v, -vv, -vvv — Increase verbosity/debug output

Future Improvements
Asynchronous scanning for improved speed

Extended fingerprinting using additional APIs and ML models

Better error handling and retries

Graphical or web-based reporting interface

Integration with CI/CD pipelines for automated security checks

License
This project is licensed under the MIT License.

Acknowledgments
Wappalyzer for technology detection

crt.sh and HackerTarget for subdomain enumeration APIs
