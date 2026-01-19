#!/usr/bin/env python3
import shodan
import argparse
import json
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

def shodan_search(api, query, retries):
    for attempt in range(retries):
        try:
            return api.search_cursor(query)
        except shodan.APIError:
            time.sleep(2 ** attempt)
    return []

# ---------- QUERY BUILDER (NO WILDCARD) ----------
def build_queries(args):
    queries = []

    # favicon hash mode
    if args.multi_hash:
        with open(args.multi_hash) as f:
            return [f"http.favicon.hash:{x.strip()}" for x in f if x.strip()]

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

    # ---- SAFE QUERY BUILD ----
    if domains:
        for d in domains:
            for q in base_queries:
                queries.append(f"({q}) AND hostname:{d}")
    else:
        queries = base_queries

    return queries

def main():
    banner()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-q", "--query")
    parser.add_argument("-qf", "--query-file")
    parser.add_argument("-m", "--multi-hash")
    parser.add_argument("-d", "--hostname")
    parser.add_argument("-f", "--file")
    parser.add_argument("-o", "--output")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-c", "--concurrent", type=int, default=1)
    parser.add_argument("-r", "--retries", type=int, default=3)
    parser.add_argument("-h", "--help", action="store_true")

    args = parser.parse_args()

    if args.help:
        parser.print_help()
        return

    api = shodan.Shodan(API_KEY)
    queries = build_queries(args)

    print(Fore.BLUE + "[*] Running Queries:")
    for q in queries:
        print(Fore.BLUE + "    " + q)

    seen = set()
    results = []

    def worker(query):
        found = []
        for item in shodan_search(api, query, args.retries):
            key = f"{item['ip_str']}:{item['port']}"
            if key not in seen:
                seen.add(key)
                found.append(item)
        return found

    # ---- SEQUENTIAL FUTURES EXECUTION ----
    with ThreadPoolExecutor(max_workers=1) as exe:
        future_map = {exe.submit(worker, q): q for q in queries}

        for future in as_completed(future_map):
            query = future_map[future]
            found = future.result()

            print(Fore.MAGENTA + f"\n[QUERY] {query}")

            if not found:
                print(Fore.YELLOW + "  [-] No results")
                continue

            for r in found:
                print(Fore.CYAN + f"  [FOUND] {r['ip_str']}:{r['port']}")
                results.append(r)

    if args.output and results:
        with open(args.output, "w") as f:
            for r in results:
                if args.json:
                    json.dump(r, f)
                    f.write("\n")
                else:
                    f.write(f"{r['ip_str']}:{r['port']}\n")

        print(Fore.GREEN + f"\n[+] Saved {len(results)} results to {args.output}")

if __name__ == "__main__":
    main()
