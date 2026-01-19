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
API_KEY = ""   # <-- PUT YOUR SHODAN API KEY HERE
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

def print_help():
    print("""
USAGE:
  shodanfox [OPTIONS]

TARGET OPTIONS:
  -q,  --query <query>
  -qf, --query-file <file>
  -d,  --hostname <domain>
  -f,  --file <file>
  -m,  --multi-hash <file>

OUTPUT OPTIONS:
  -o,  --output <file>          Save results to file (optional)
  -j,  --json                   JSON output (print / save)

PERFORMANCE:
  -c,  --concurrent <num>
  -r,  --retries <num>

OTHER:
  -h,  --help
""")

def shodan_search(api, query, retries):
    for attempt in range(retries):
        try:
            return api.search_cursor(query)
        except shodan.APIError:
            time.sleep(2 ** attempt)
    return []

def build_queries(args):
    if args.multi_hash:
        with open(args.multi_hash) as f:
            return [f"http.favicon.hash:{x.strip()}" for x in f if x.strip()]

    base = []
    if args.query:
        base.append(args.query)
    if args.query_file:
        with open(args.query_file) as f:
            base.extend(x.strip() for x in f if x.strip())

    if not base:
        base.append(DEFAULT_QUERY)

    domains = []
    if args.hostname:
        domains.append(args.hostname)
    if args.file:
        with open(args.file) as f:
            domains.extend(x.strip() for x in f if x.strip())

    if domains:
        return [f"{q} hostname:{d}" for d in domains for q in base]

    return base

def main():
    banner()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-q", "--query")
    parser.add_argument("-qf", "--query-file")
    parser.add_argument("-d", "--hostname")
    parser.add_argument("-f", "--file")
    parser.add_argument("-m", "--multi-hash")
    parser.add_argument("-o", "--output")   # <-- OPTIONAL
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

    print(Fore.BLUE + "[*] Running queries:")
    for q in queries:
        print(Fore.BLUE + "    " + q)

    seen, results = set(), []

    def worker(query):
        out = []
        for item in shodan_search(api, query, args.retries):
            key = f"{item['ip_str']}:{item['port']}"
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    with ThreadPoolExecutor(max_workers=args.concurrent) as exe:
        for f in as_completed(exe.submit(worker, q) for q in queries):
            results.extend(f.result())

    if not results:
        print(Fore.YELLOW + "\n[-] No results found.")
        return

    print()
    for r in results:
        line = f"{r['ip_str']}:{r['port']}"
        print(Fore.CYAN + "[FOUND] " + line)

    # ---- SAVE ONLY IF REQUESTED ----
    if args.output:
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

