#!/usr/bin/env python3
import shodan
import argparse
import json
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

# ================= CONFIG =================
API_KEY = "add your API_KEY"
DEFAULT_QUERY = "http.favicon.hash:116323821"
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

        shodanFOX – Recon Automation Toolkit By REDMOON
""" + Style.RESET_ALL)

def print_help():
    print("""
USAGE:
  shodanfox [OPTIONS]

TARGET OPTIONS:
  -q,  --query <query>          Single Shodan query
  -qf, --query-file <file>      File with queries
  -d,  --hostname <domain>      Single domain
  -f,  --file <file>            File with domains
  -m,  --multi-hash <file>      File with favicon hashes (one per line)

OUTPUT OPTIONS:
  -o,  --output <file>          Output file (default: results.txt)
  -j,  --json                   JSON output

PERFORMANCE:
  -c,  --concurrent <num>       Threads (default: 1)
  -r,  --retries <num>          Retry API errors (default: 3)

OTHER:
  -h,  --help                   Show this help menu

EXAMPLES:
  shodanfox -q "http.favicon.hash:12345"
  shodanfox -m hashes.txt -d example.com
  shodanfox -qf queries.txt -f domains.txt
""")

def shodan_search(api, query, retries):
    for attempt in range(retries):
        try:
            return api.search_cursor(query)
        except shodan.APIError:
            time.sleep(2 ** attempt)
    return []

def build_queries(args):
    queries = []

    # Multi-hash mode
    if args.multi_hash:
        with open(args.multi_hash) as f:
            hashes = [x.strip() for x in f if x.strip()]
        for h in hashes:
            queries.append(f"http.favicon.hash:{h}")
        return queries

    base_queries = []
    if args.query:
        base_queries.append(args.query)
    if args.query_file:
        with open(args.query_file) as f:
            base_queries.extend([x.strip() for x in f if x.strip()])
    if not base_queries:
        base_queries.append(DEFAULT_QUERY)

    domains = []
    if args.hostname:
        domains.append(args.hostname)
    if args.file:
        with open(args.file) as f:
            domains.extend([x.strip() for x in f if x.strip()])

    if domains:
        for d in domains:
            for q in base_queries:
                queries.append(f"{q} hostname:{d}")
    else:
        queries = base_queries

    return queries

def main():
    banner()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-q", "--query")
    parser.add_argument("-qf", "--query-file")
    parser.add_argument("-d", "--hostname")
    parser.add_argument("-f", "--file")
    parser.add_argument("-m", "--multi-hash")
    parser.add_argument("-o", "--output", default="results.txt")
    parser.add_argument("-j", "--json", action="store_true")
    parser.add_argument("-c", "--concurrent", type=int, default=1)
    parser.add_argument("-r", "--retries", type=int, default=3)
    parser.add_argument("-h", "--help", action="store_true")

    args = parser.parse_args()

    if args.help:
        print_help()
        return

    api = shodan.Shodan(API_KEY)
    queries = build_queries(args)
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

    with ThreadPoolExecutor(max_workers=args.concurrent) as exe:
        futures = [exe.submit(worker, q) for q in queries]
        for f in as_completed(futures):
            results.extend(f.result())

    with open(args.output, "w") as f:
        for r in results:
            if args.json:
                json.dump(r, f)
                f.write("\n")
            else:
                f.write(f"https://{r['ip_str']}:{r['port']}/\n")

    print(Fore.GREEN + f"\n[+] Saved {len(results)} results to {args.output}")

if __name__ == "__main__":
    main()