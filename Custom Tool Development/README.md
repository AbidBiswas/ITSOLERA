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
