#!/usr/bin/env python3
import shodan
import argparse
import random
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

# ================= CONFIG =================
API_KEY = "PUT_YOUR_SHODAN_API_KEY_HERE"
# ==========================================

COLORS = [
    Fore.RED, Fore.GREEN, Fore.YELLOW,
    Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Fore.WHITE
]

def banner():
    color = random.choice(COLORS)
    print(color + r"""
 ███████╗██╗  ██╗ ██████╗ ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ██╗  ██╗
 ██╔════╝██║  ██║██╔═══██╗██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗╚██╗██╔╝
 ███████╗███████║██║   ██║██║  ██║███████║██╔██╗ ██║█████╗  ██║   ██║ ╚███╔╝
 ╚════██║██╔══██║██║   ██║██║  ██║██╔══██║██║╚██╗██║██╔══╝  ██║   ██║ ██╔██╗
 ███████║██║  ██║╚██████╔╝██████╔╝██║  ██║██║ ╚████║██║     ╚██████╔╝██╔╝ ██╗
 ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝

        shodanFOX – Recon Automation Toolkit
""" + Style.RESET_ALL)

# ---------------- SHODAN ----------------

def shodan_search(api, query, retries):
    for attempt in range(retries):
        try:
            return api.search_cursor(query)
        except shodan.APIError:
            time.sleep(2 ** attempt)
    return []

# ---------------- DOMAIN EXTRACTION ----------------

def extract_domains(item):
    domains = set()

    domains.update(item.get("hostnames", []))
    domains.update(item.get("domains", []))

    ssl = item.get("ssl", {})
    cert = ssl.get("cert", {})

    subject = cert.get("subject")
    if isinstance(subject, dict):
        cn = subject.get("CN")
        if cn:
            domains.add(cn)

    extensions = cert.get("extensions")

    if isinstance(extensions, dict):
        san = extensions.get("subjectAltName")
        if isinstance(san, dict):
            domains.update(san.get("dns_names", []))
        elif isinstance(san, list):
            for x in san:
                if isinstance(x, str) and x.startswith("DNS:"):
                    domains.add(x.replace("DNS:", "").strip())

    elif isinstance(extensions, list):
        for ext in extensions:
            if isinstance(ext, dict) and ext.get("name") == "subjectAltName":
                for v in ext.get("value", []):
                    if isinstance(v, str) and v.startswith("DNS:"):
                        domains.add(v.replace("DNS:", "").strip())

    return domains

# ---------------- QUERY BUILDER ----------------

def build_queries(args):
    base_queries = []

    if args.query:
        base_queries.append(args.query)

    if args.query_file:
        with open(args.query_file) as f:
            base_queries.extend(x.strip() for x in f if x.strip())

    if not base_queries:
        print(Fore.RED + "[!] No query provided")
        sys.exit(1)

    domains = []

    if args.hostname:
        domains.append(args.hostname)

    if args.file:
        with open(args.file) as f:
            domains.extend(x.strip() for x in f if x.strip())

    queries = []

    if domains:
        for q in base_queries:
            for d in domains:
                if args.wildcard:
                    queries.append(f"{q} hostname:*.{d}")
                else:
                    queries.append(f"{q} hostname:{d}")
        return queries

    return base_queries

# ---------------- MAIN ----------------

def main():
    banner()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-q", "--query")
    parser.add_argument("-qf", "--query-file")
    parser.add_argument("-d", "--hostname")
    parser.add_argument("-f", "--file")
    parser.add_argument("-o", "--output")
    parser.add_argument("-w", "--wildcard", action="store_true",
                        help="Use hostname wildcard search (hostname:*.domain)")
    parser.add_argument("-r", "--retries", type=int, default=3)
    parser.add_argument("-h", "--help", action="store_true")

    args = parser.parse_args()

    if args.help:
        print("Usage: shodanfox -q|-qf [-d|-f] [-w] [-o file]")
        return

    api = shodan.Shodan(API_KEY)
    queries = build_queries(args)

    print(Fore.BLUE + "[*] Loaded Queries:")
    for q in queries:
        print(Fore.BLUE + "    " + q)

    seen_hosts = set()
    seen_ip_port = set()

    with ThreadPoolExecutor(max_workers=1) as exe:
        future_map = {
            exe.submit(shodan_search, api, q, args.retries): q
            for q in queries
        }

        for future in as_completed(future_map):
            query = future_map[future]
            print(Fore.MAGENTA + f"\n[QUERY] {query}")

            for item in future.result():
                ip_port = f"{item['ip_str']}:{item['port']}"
                if ip_port in seen_ip_port:
                    continue
                seen_ip_port.add(ip_port)

                domains = extract_domains(item)

                for d in domains:
                    if d not in seen_hosts:
                        seen_hosts.add(d)
                        print(Fore.GREEN + f"  [FOUND] https://{d}:{item['port']}")

    if args.output:
        with open(args.output, "w") as f:
            for h in sorted(seen_hosts):
                f.write(f"https://{h}:443\n")

        print(Fore.GREEN + f"\n[+] Saved {len(seen_hosts)} URLs to {args.output}")

if __name__ == "__main__":
    main()
