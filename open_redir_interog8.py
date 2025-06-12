#!/usr/bin/env python3
"""open_redirect_scanner.py – Detects open redirect vulnerabilities

Overview
========
* **Crawls** target site (links & forms) to configurable depth.
* Identifies parameters likely to hold URLs (`next`, `url`, `redirect`, `return`, `dest`, etc.).
* Replaces the parameter value with a **malicious external URL** (e.g., `https://evil.example/`) and checks:
  1. **302/301 Location** header pointing to the external URL.
  2. In‑page **meta refresh** or **JavaScript** `window.location` pointing outside.
* Handles **GET** parameters and **POST‑body** forms.
* Multithreaded with progress bar.
* CLI flags: `--url`, `--depth`, `--threads`, `--proxy`, `--timeout`, `--evil`.

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama

Example
=======
    python open_redirect_scanner.py --url https://target.local --depth 2 --threads 12 --evil https://evil.com
"""

import argparse, httpx, queue, threading, re
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl, quote
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style

###############################################################################
# CLI
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="Open redirect scanner")
    p.add_argument("--url", required=True, help="Seed URL")
    p.add_argument("--depth", type=int, default=1, help="Crawl depth")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy", help="http://127.0.0.1:8080 proxy")
    p.add_argument("--evil", default="https://evil.example/", help="External redirect destination")
    return p.parse_args()

###############################################################################
# HTTP client
###############################################################################

def make_client(args):
    proxies = {"http://": args.proxy, "https://": args.proxy} if args.proxy else None
    return httpx.Client(headers={"User-Agent": "openredir-scan/1.0"}, verify=False, timeout=args.timeout, proxies=proxies)

###############################################################################
# Crawl
###############################################################################

LIKELY_KEYS = re.compile(r"(redir|url|next|return|goto|dest|destination|to|out)\b", re.I)

def crawl(client, seed, max_depth):
    seen, q, pages = set(), queue.Queue(), []
    q.put((seed, 0))
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
        if "text/html" in r.headers.get("content-type", ""):
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                q.put((urljoin(url, a["href"]), depth + 1))
            for f in soup.find_all("form"):
                pages.append((url, f))
    return pages

###############################################################################
# Helpers
###############################################################################

def inject_qs(url, key, new_val):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[key] = new_val
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

META_REFRESH_RX = re.compile(r"<meta[^>]+http-equiv=['\"]?refresh['\"][^>]+content=['\"]?\d+;\s*url=([^'">]+)", re.I)
JS_LOC_RX = re.compile(r"window\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.I)

###############################################################################
# Worker
###############################################################################

findings, lock = [], threading.Lock()


def test_get(client, url, evil):
    params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
    for k, v in params.items():
        if not LIKELY_KEYS.search(k):
            continue
        crafted = inject_qs(url, k, evil)
        try:
            r = client.get(crafted, follow_redirects=False)
        except Exception:
            continue
        # Check Location header
        loc = r.headers.get("location", "")
        if loc.startswith(evil):
            with lock:
                findings.append(("GET", crafted, k, "302→" + loc))
            continue
        # Check meta refresh / JS in body
        if any(rx.search(r.text) and evil in rx.search(r.text).group(1) for rx in (META_REFRESH_RX, JS_LOC_RX)):
            with lock:
                findings.append(("GET", crafted, k, "meta/js redirect"))


def test_post(client, page_url, form, evil):
    if form.get("method", "GET").upper() != "POST":
        return
    action = urljoin(page_url, form.get("action", page_url))
    inputs = {i.get("name"): i.get("value", "") for i in form.find_all("input") if i.get("name")}
    for k in list(inputs.keys()):
        if not LIKELY_KEYS.search(k):
            continue
        data = inputs.copy(); data[k] = evil
        try:
            r = client.post(action, data=data, follow_redirects=False)
        except Exception:
            continue
        loc = r.headers.get("location", "")
        if loc.startswith(evil):
            with lock:
                findings.append(("POST", action, k, "302→" + loc))
            continue
        if any(rx.search(r.text) and evil in rx.search(r.text).group(1) for rx in (META_REFRESH_RX, JS_LOC_RX)):
            with lock:
                findings.append(("POST", action, k, "meta/js redirect"))


def worker(client, q, evil, pbar):
    while True:
        try:
            url, obj = q.get_nowait()
        except queue.Empty:
            break
        if isinstance(obj, httpx.Response):
            test_get(client, url, evil)
        else:
            test_post(client, url, obj, evil)
        q.task_done(); pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    args = parse_args()
    sess = make_client(args)
    pages = crawl(sess, args.url, args.depth)

    q = queue.Queue(); [q.put(p) for p in pages]
    pbar = tqdm(total=q.qsize(), desc="Open‑redirect fuzz")

    threads = [threading.Thread(target=worker, args=(sess, q, args.evil, pbar), daemon=True) for _ in range(args.threads)]
    [t.start() for t in threads]; [t.join() for t in threads]
    pbar.close()

    if findings:
        for typ, loc, param, note in findings:
            print(f"{Fore.RED}[OPEN REDIRECT] ({typ}) {loc} param={param} ({note}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No open‑redirect indicators found.{Style.RESET_ALL}")
