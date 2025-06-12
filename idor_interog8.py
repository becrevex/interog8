#!/usr/bin/env python3
"""idor_scanner.py – Quick‑and‑dirty IDOR reconnaissance tool

Why IDOR?
~~~~~~~~~
Insecure Direct Object References occur when an application exposes a
reference (numeric ID, GUID, filename, etc.) that can be tampered with to
access another user’s object.  This script finds URLs & form parameters
containing **candidate IDs**, then automatically increments / decrements or
swaps them with values from a *wordlist* to gauge authorization leaks.

Key Features
============
* **Crawler** – discovers links & forms to chosen depth.
* **Heuristics** – detects parameters that *look* like IDs
  (integers, UUIDs, hex strings ≥8, Base64‑ish tokens).
* **Mutations** –
  • Sequential ±1/±10 for integers
  • Random UUID replacement
  • Wordlist substitutions (optional `--wordlist`)
* **Diff engine** – compares baseline response vs. tampered (status, length,
  and fuzzy ratio) to flag potential IDOR.
* **Concurrency** with ThreadPool + *tqdm* progress bar.
* **Argparse** (`--url`, `--depth`, `--threads`, `--timeout`, `--proxy`, …).

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama python-Levenshtein

Example
=======
    python idor_scanner.py --url https://target.local/profile?id=123 --depth 1 --threads 8
"""

import argparse, httpx, queue, threading, uuid, re, random, base64, time
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style
from Levenshtein import ratio as levenshtein_ratio

###############################################################################
# CLI
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="Lightweight IDOR scanner")
    p.add_argument("--url", required=True, help="Seed URL")
    p.add_argument("--depth", type=int, default=1, help="Crawl depth (default 1)")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy", help="Proxy (http://127.0.0.1:8080)")
    p.add_argument("--wordlist", help="File with test IDs (one per line)")
    return p.parse_args()

###############################################################################
# HTTP helpers
###############################################################################

def make_client(args):
    proxies = {"http://": args.proxy, "https://": args.proxy} if args.proxy else None
    return httpx.Client(headers={"User-Agent": "idor-scan/1.0"}, timeout=args.timeout, verify=False, proxies=proxies)

###############################################################################
# Crawling
###############################################################################

ID_REGEXES = [
    ("int", re.compile(r"^\d{2,}$")),                 # integers ≥2 digits
    ("uuid", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("hex", re.compile(r"^[0-9a-f]{8,}$", re.I)),       # long hex
    ("b64", re.compile(r"^[A-Za-z0-9+/]{12,}={0,2}$")), # rough base64
]


def crawl(client, seed, max_depth):
    seen, q = set(), queue.Queue()
    q.put((seed, 0))
    pages = []

    while not q.empty():
        url, depth = q.get()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        try:
            r = client.get(url, follow_redirects=True)
        except Exception:
            continue
        pages.append((url, r))
        if "text/html" not in r.headers.get("content-type", ""):
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            q.put((urljoin(url, tag["href"]), depth + 1))
        for form in soup.find_all("form"):
            pages.append((url, form))
    return pages

###############################################################################
# Mutation helpers
###############################################################################

def guess_id_type(value):
    for name, rx in ID_REGEXES:
        if rx.match(value):
            return name
    return None


def mutate(value, id_type, supplied_list):
    """Yield alternative values for a parameter."""
    if supplied_list:
        for w in supplied_list:
            if w != value:
                yield w
    if id_type == "int":
        try:
            iv = int(value)
            for delta in (-10, -1, 1, 2, 10):
                yield str(iv + delta)
        except ValueError:
            pass
    elif id_type == "uuid":
        yield str(uuid.uuid4())
    elif id_type == "hex":
        newhex = "%x" % random.randint(0x1000, 0xFFFFFFF)
        yield newhex
    elif id_type == "b64":
        try:
            raw = base64.b64decode(value + "==", validate=True)
            iv = int.from_bytes(raw[:4], "big", signed=False)
            newb = base64.b64encode((iv + 1).to_bytes(len(raw), "big")).decode()
            yield newb.strip("=")
        except Exception:
            pass

###############################################################################
# Worker thread
###############################################################################

findings = []
lock = threading.Lock()


def compare(baseline, mutated):
    # simple heuristics: status change OR >10% length diff OR Levenshtein ratio <0.9
    if baseline.status_code != mutated.status_code:
        return True, "status %d→%d" % (baseline.status_code, mutated.status_code)
    if abs(len(baseline.text) - len(mutated.text)) / (len(baseline.text) + 1) > 0.10:
        return True, "len %d→%d" % (len(baseline.text), len(mutated.text))
    if levenshtein_ratio(baseline.text[:1000], mutated.text[:1000]) < 0.9:
        return True, "content diff"
    return False, ""


def worker(client, q, wordlist, pbar):
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            return
        url, obj = item
        if isinstance(obj, httpx.Response):
            params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            for k, v in params.items():
                id_type = guess_id_type(v)
                if not id_type:
                    continue
                base_resp = obj
                for alt in mutate(v, id_type, wordlist):
                    tampered = inject_get(url, k, alt)
                    try:
                        r = client.get(tampered, follow_redirects=False)
                        diff, note = compare(base_resp, r)
                        if diff:
                            with lock:
                                findings.append((url, k, v, alt, note))
                            break  # stop after first positive for this param
                    except Exception:
                        pass
        # (Form POST fuzzing could be added similarly.)
        q.task_done()
        pbar.update(1)

###############################################################################
# Helpers
###############################################################################

def inject_get(url, key, new_val):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[key] = new_val
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    args = parse_args()
    wordlist = []
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            wordlist = [l.strip() for l in f if l.strip()]

    client = make_client(args)
    print(f"{Fore.CYAN}[+] Crawling…{Style.RESET_ALL}")
    pages = crawl(client, args.url, args.depth)

    q = queue.Queue()
    for p in pages:
        q.put(p)

    pbar = tqdm(total=q.qsize(), desc="IDOR fuzz")
    threads = [threading.Thread(target=worker, args=(client, q, wordlist, pbar), daemon=True) for _ in range(args.threads)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    pbar.close()

    if findings:
        for url, param, orig, new, note in findings:
            print(f"{Fore.RED}[IDOR] {url}  param={param}  {orig}->{new}  ({note}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No IDOR indicators found.{Style.RESET_ALL}")
