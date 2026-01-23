#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import shodan
import argparse
import random
import time
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

# ================= CONFIG =================
API_KEY = os.getenv("SHODAN_API_KEY")
if not API_KEY:
    print("[!] Set SHODAN_API_KEY environment variable")
    sys.exit(1)
# =========================================

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

def shodan_search(api, query, retries, delay, output_file):
    for attempt in range(retries):
        try:
            # Make the Shodan API call
            results = api.search_cursor(query)
            for item in results:
                ip_port = f"{item.get('ip_str')}:{item.get('port')}"
                for d in extract_domains(item):
                    # If the domain is found, save it to the file in real-time
                    with open(output_file, "a") as f:
                        f.write(f"https://{d}:{item['port']}\n")
                    print(Fore.GREEN + f"  [FOUND] https://{d}:{item['port']}")
            time.sleep(delay)  # Throttle requests based on user-defined delay
            return results
        except shodan.APIError as e:
            # If rate-limited, back off exponentially
            print(Fore.YELLOW + f"[!] Rate limit exceeded. Retrying in {2 ** attempt} seconds.")
            time.sleep(2 ** attempt)  # Exponential backoff on API error
    return []

# ---------------- DOMAIN EXTRACTION ----------------

def extract_domains(item):
    domains = set()

    domains.update(item.get("hostnames", []))
    domains.update(item.get("domains", []))

    ssl = item.get("ssl", {})
    cert = ssl.get("cert", {})

    subject = cert.get("subject", {})
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

    if args.domain_file:
        with open(args.domain_file) as f:
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

    parser = argparse.ArgumentParser(
        description="shodanFOX - Shodan Recon Automation Tool"
    )

    parser.add_argument("-q", "--query", help="Single Shodan query")
    parser.add_argument("-qf", "--query-file", help="File with Shodan queries")
    parser.add_argument("-d", "--hostname", help="Single domain")
    parser.add_argument("-df", "--domain-file", help="File with domains")
    parser.add_argument("-w", "--wildcard", action="store_true",
                        help="Use wildcard hostname search")
    parser.add_argument("-o", "--output", help="Save output to file")
    parser.add_argument("-r", "--retries", type=int, default=3)
    parser.add_argument("--time", type=int, default=1, help="Time in seconds between requests")

    args = parser.parse_args()

    if not args.output:
        print(Fore.RED + "[!] Output file must be specified using -o <filename>")
        sys.exit(1)

    api = shodan.Shodan(API_KEY)
    queries = build_queries(args)

    print(Fore.BLUE + "[*] Loaded Queries:")
    for q in queries:
        print("   ", q)

    seen_hosts = set()

    # Open the output file for writing results in real-time
    with ThreadPoolExecutor(max_workers=1) as exe:
        futures = {exe.submit(shodan_search, api, q, args.retries, args.time, args.output): q for q in queries}

        for future in as_completed(futures):
            query = futures[future]
            print(Fore.MAGENTA + f"\n[QUERY] {query}")

            future.result()  # Just let the result be processed in real-time

    print(Fore.GREEN + f"\n[+] Results saved in {args.output}")

if __name__ == "__main__":
    main()
