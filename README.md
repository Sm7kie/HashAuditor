![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

**HashAuditor** is an advanced, interactive command-line tool for generating and auditing (cracking) password hashes. It features intelligent algorithm auto-detection, salt support, and dynamic loading of all OpenSSL algorithms available on the host system.

## Features

* **Dynamic Algorithm Loading:** Automatically detects and loads all hash algorithms supported by the system (SHA-2, SHA-3, BLAKE2, Whirlpool, etc.).
* **Smart Auto-Detect:** Analyzes hash length to determine the likely algorithm (e.g., distinguishing between MD5, SHA-256, etc.).
* **Salt Support:** robust generation and auditing of salted passwords to simulate real-world security scenarios.
* **Dual Modes:**
    * **Interactive Menu:** For easy, guided usage.
    * **CLI Mode:** For automation and scripting pipelines.
* **Output Management:** Save results to files automatically for reporting.

## Installation

```bash
git clone [https://github.com/Sm7kie/HashAuditor.git](https://github.com/Sm7kie/HashAuditor.git)
cd HashAuditor
pip install -r requirements.txt
