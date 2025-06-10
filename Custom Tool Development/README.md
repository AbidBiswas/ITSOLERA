# Custom Reconnaissance Tool

A lightweight, modular command-line interface (CLI) tool designed for automated initial information gathering during penetration testing engagements. This tool provides core reconnaissance functionalities to aid security professionals and interns in real-world red team scenarios.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Configuration](#configuration)
* [Usage](#usage)
* [Available Flags](#available-flags)
* [Future Improvements](#future-improvements)
* [License](#license)
* [Acknowledgements](#acknowledgements)
* [Contact](#contact)

---

## Features

* **Passive Reconnaissance**:
    * WHOIS lookup
    * DNS enumeration (A, MX, TXT, NS records)
    * Subdomain enumeration using external APIs (e.g., crt.sh, AlienVault OTX)
* **Active Reconnaissance**:
    * Port scanning (via Nmap wrapper or sockets)
    * Banner grabbing
    * Detecting technologies (e.g., using Wappalyzer CLI)
* **Reporting**:
    * Generate summary reports in `.txt` or `.html` format.
    * Include timestamps and IP resolution details.
* **Modularity**:
    * Each reconnaissance module is independent and callable via command-line flags.
    * Implemented logging with verbosity levels for detailed output.

---

## Installation

To set up the reconnaissance tool, follow these steps:

### 1. Clone the Repository

First, clone this repository to your local machine:

```bash
git clone [https://github.com/your-username/recon-tool.git](https://github.com/your-username/recon-tool.git) # Replace with your actual repo URL
cd recon-tool
pip install -r requirements.txt
```
Markdown

# Custom Reconnaissance Tool

A lightweight, modular command-line interface (CLI) tool designed for automated initial information gathering during penetration testing engagements. This tool provides core reconnaissance functionalities to aid security professionals and interns in real-world red team scenarios.

---

## Table of Contents

* [Features](#features)
* [Installation](#installation)
* [Configuration](#configuration)
* [Usage](#usage)
* [Available Flags](#available-flags)
* [Future Improvements](#future-improvements)
* [License](#license)
* [Acknowledgements](#acknowledgements)
* [Contact](#contact)

---

## Features

* **Passive Reconnaissance**:
    * WHOIS lookup
    * DNS enumeration (A, MX, TXT, NS records)
    * Subdomain enumeration using external APIs (e.g., crt.sh, AlienVault OTX)
* **Active Reconnaissance**:
    * Port scanning (via Nmap wrapper or sockets)
    * Banner grabbing
    * Detecting technologies (e.g., using Wappalyzer CLI)
* **Reporting**:
    * Generate summary reports in `.txt` or `.html` format.
    * Include timestamps and IP resolution details.
* **Modularity**:
    * Each reconnaissance module is independent and callable via command-line flags.
    * Implemented logging with verbosity levels for detailed output.

---

## Installation

To set up the reconnaissance tool, follow these steps:

### 1. Clone the Repository

First, clone this repository to your local machine:

```bash
git clone [https://github.com/your-username/recon-tool.git](https://github.com/your-username/recon-tool.git) # Replace with your actual repo URL
cd recon-tool
2. Install Python Dependencies
Install all necessary Python packages listed in requirements.txt:

Bash

pip install -r requirements.txt
3. (Optional) Install Wappalyzer CLI
For enhanced and more accurate technology detection, it is highly recommended to install the Wappalyzer command-line interface globally. This requires Node.js and npm to be installed on your system.

Bash

npm install -g wappalyzer
Configuration
Before running the tool, you need to configure any external API keys or specific tool settings. This is done in the config/sources.yaml file (or config.py if using a .py based config).

Example config/sources.yaml (if used):

YAML

# config/sources.yaml
api_keys:
  alienvault_otx: "YOUR_ALIENVAULT_OTX_API_KEY"
  virustotal: "YOUR_VIRUSTOTAL_API_KEY"
  # Add other API keys here as needed
Usage
Run the tool from the main directory by specifying the target domain and the desired reconnaissance options using command-line flags.

Bash

python3 main.py example.com --whois --dns --subdomains --ports --tech --wappa -vv
Available Flags
Flag	Description
--whois	Perform WHOIS lookup for the target domain.
--dns	Perform DNS enumeration for A, MX, TXT, and NS records.
--subdomains	Discover subdomains using configured external APIs (e.g., crt.sh).
--active	Execute all active reconnaissance modules.
--ports	Perform port scanning on the target (requires Nmap installed).
--banner	Perform banner grabbing on open ports (requires --ports).
--tech	Perform basic technology detection on discovered web services.
--wappa	Perform enhanced technology detection using the Wappalyzer CLI.
--dirs	Perform directory enumeration.
--vulns	Perform vulnerability scanning.
--vt	Query VirusTotal for domain reputation.
--report	Generate a summary report with all gathered information.
--report-format	Specify report format: txt (default) or html.
-v, -vv	Increase verbosity level: -v for INFO, -vv for DEBUG.

Export to Sheets
Future Improvements
We plan to continuously improve this tool with the following enhancements:

Asynchronous Scanning: Implement asynchronous operations to significantly improve scanning performance and reduce overall runtime.
Advanced Fingerprinting: Integrate more sophisticated fingerprinting techniques and heuristic analysis for highly accurate technology detection.
User Interface: Develop a graphical user interface (GUI) or a web dashboard for a more intuitive user experience and enhanced reporting visualization.
Robust Error Handling: Enhance error handling mechanisms with automated retries and intelligent fallback strategies for network operations and API calls.
Continuous Monitoring: Automate periodic scanning and integrate the tool with CI/CD pipelines for continuous security monitoring capabilities.
Dockerization: Provide a Docker image for easy deployment across various environments.
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Acknowledgements
We extend our sincere gratitude to the following for their invaluable contributions and inspiration:

Wappalyzer: For its excellent technology detection capabilities.
crt.sh and HackerTarget: For providing robust subdomain enumeration services.
The Open-Source Community: For fostering an environment of collaboration and innovation that inspires modular and extensible security tooling.
Contact
For any questions, issues, or contributions, please feel free to open an issue or submit a pull request on the project's GitHub repository.

ITSOLERA Cyber Department
Muhammad Ahsan Ayaz - Cyber Team Lead
Abid Biswas - Lead Developer
