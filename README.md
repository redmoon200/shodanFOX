🦊 shodanFOX

shodanFOX is a powerful, flexible, and user‑friendly Shodan reconnaissance automation toolkit designed for security researchers, bug bounty hunters, and penetration testers.
It extends Shodan search capabilities with automation, filtering, and stability improvements while providing a clean hacker‑style CLI experience.

🚀 Overview

shodanFOX simplifies large‑scale Shodan reconnaissance by allowing users to:

Combine queries with domains

Perform favicon hash hunting

Run multiple searches efficiently

Handle Shodan API limitations gracefully

Built with stability and extensibility in mind, shodanFOX is ideal for both quick recon and large‑scale asset discovery.

✨ Key Features
🎨 Custom CLI Experience

Eye‑catching ASCII banner

Random color on every run

Clean and readable terminal output

🔍 Advanced Shodan Querying

Single query mode (-q)

Query file support (-qf)

Domain targeting (-d)

Multiple domain input (-f)

Multi‑hash favicon hunting (-m)

⚡ Performance & Automation

Concurrent search execution (-c)

Automatic retry mechanism for API failures

Graceful handling of Shodan search cursor timeouts

Prevents duplicate results automatically

📦 Output Options

Plain text output (default)

JSON output support (-j)

Clean, structured result saving

🛡 Stability & Error Handling

Handles Shodan API errors without crashing

Detects connection issues and timeouts

Skips failed queries safely and continues execution

🧰 Use Cases

🔎 Asset discovery

🐞 Bug bounty reconnaissance

🌐 Internet‑wide service enumeration

🔐 Favicon hash hunting

🧠 Threat intelligence research

🛠 Example Usage
# Basic search
python shodanfox.py -q "apache"

# Domain‑specific recon
python shodanfox.py -q "nginx" -d example.com

# Multi‑hash favicon hunting
python shodanfox.py -m hashes.txt

# Query file + domain file
python shodanfox.py -qf queries.txt -f domains.txt

# JSON output with concurrency
python shodanfox.py -q "ssh" -j -c 3

📋 Requirements

Python 3.10+

Shodan API key

Python modules:

shodan

colorama

requests

Install dependencies:

pip install -r requirements.txt

🔑 Shodan API Key Setup
export SHODAN_API_KEY="YOUR_API_KEY"

⚠️ Disclaimer

This tool is intended for educational and authorized security testing only.
The author is not responsible for any misuse or illegal activity.
