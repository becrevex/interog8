#!/usr/bin/env python3
"""verb_tampering_scanner.py – Broken Access Control / HTTP verb tampering scanner

What it detects
===============
1. Endpoints that respond differently (status, body length, keywords) when the
   HTTP verb is changed (e.g., GET → PUT / DELETE / PATCH / OPTIONS).
2. Endpoints that honour **method‑override headers** (`X-HTTP-Method-Override`,
   `X-HTTP-Method`, `X-Method-Override`).
3. Resources that become writable (2xx) or expose data with an unexpected
   verb (e.g., `DELETE /users/123` → 204 when GET/POST was 403).

Approach
========
* Crawl links up to `--depth` (only same‑origin).
* **Baseline**: send a normal GET (or form POST) and record `status`, `len`,
  and a short `sha1` of the first 2 kB.
* **Tamper**:
  - Resend with verbs: `HEAD`, `OPTIONS`, `PUT`, `PATCH`, `DELETE`, `TRACE`,
    `PROPFIND`.
  - Resend original verb but add override headers that claim another method.
* **Diff** baseline vs tampered:
  - Status category change (e.g., 2xx vs 4xx/5xx).
  - Body length diff > 20 % (where body exists).
  - Hash mismatch when baseline was 403/401 and tamper is 200.
* Multi‑threaded, colourised findings.

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama

Example
=======
    python verb_tampering_scanner.py --url https://target.local --depth 1 --threads 12
"""

import argparse, httpx, queue, threading, hashlib, re
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style

###############################################################################
# CLI
###############################################################################

def cli():
    p = argparse.ArgumentParser("HTTP verb tampering scanner")
    p.add_argument("--url", required=True)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=6.0)
    p.add_argument("--proxy")
    return p.parse_args()

###############################################################################
# HTTP client
###############################################################################

def client(a):
    proxies = {"http://": a.proxy, "https://": a.proxy} if a.proxy else None
    return httpx.Client(timeout=a.timeout, verify=False, headers={"User-Agent": "verb-scan/1.0"}, proxies=proxies)

###############################################################################
# Crawl (simple)
###############################################################################

def crawl(sess, seed, depth):
    seen, q, urls = set(), queue.Queue(), []
    q.put((seed, 0))
    origin = f"{urlsplit(seed).scheme}://{urlsplit(seed).netloc}"
    while not q.empty():
        u, d = q.get()
        if u in seen or d > depth or not u.startswith(origin):
            continue
        seen.add(u)
        try:
            r = sess.get(u, follow_redirects=True)
        except Exception:
            continue
        urls.append(u)
        if "text/html" in r.headers.get("content-type", ""):
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                q.put((urljoin(u, a["href"]), d + 1))
    return urls

###############################################################################
# Diff helpers
###############################################################################

def signature(resp):
    body = resp.text.encode(errors="ignore")[:2048]
    return (resp.status_code, len(resp.text), hashlib.sha1(body).hexdigest())

VERBS = ["HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "PROPFIND"]
OVERRIDE_HEADERS = [
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-HTTP-Method", "PUT"),
    ("X-Method-Override", "PATCH"),
]

finds, lock = [], threading.Lock()


def worker(sess, q, pbar):
    while True:
        try:
            url = q.get_nowait()
        except queue.Empty:
            break
        try:
            base = sess.get(url, follow_redirects=False)
        except Exception:
            q.task_done(); pbar.update(1); continue
        base_sig = signature(base)
        for verb in VERBS:
            if verb == "HEAD":
                r = sess.request(verb, url, follow_redirects=False)
            else:
                r = sess.request(verb, url, data="verbtest", follow_redirects=False)
            s = signature(r)
            if s[0]//100 != base_sig[0]//100 or (base_sig[0] in (401,403) and s[0]//100==2):
                with lock:
                    finds.append((url, verb, f"status {base_sig[0]}→{s[0]}"))
            elif abs(s[1]-base_sig[1])/(base_sig[1]+1) > 0.2:
                finds.append((url, verb, "size diff"))
        # header overrides
        for h, v in OVERRIDE_HEADERS:
            try:
                r = sess.post(url, headers={h: v}, data="override", follow_redirects=False)
                s = signature(r)
                if s[0]//100==2 and base_sig[0]//100!=2:
                    with lock:
                        finds.append((url, f"POST+{h}:{v}", f"status {base_sig[0]}→{s[0]}"))
            except Exception:
                pass
        q.task_done(); pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    a = cli()
    sess = client(a)
    targets = crawl(sess, a.url, a.depth)

    q = queue.Queue(); [q.put(u) for u in targets]
    pbar = tqdm(total=q.qsize(), desc="Verb tamper")
    ths = [threading.Thread(target=worker, args=(sess, q, pbar), daemon=True) for _ in range(a.threads)]
    [t.start() for t in ths]; [t.join() for t in ths]
    pbar.close()

    if finds:
        for url, meth, note in finds:
            print(f"{Fore.RED}[VERB] {url} :: {meth} ({note}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No verb‑tampering indicators found.{Style.RESET_ALL}")
