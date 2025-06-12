#!/usr/bin/env python3
"""weak_http_headers_scanner.py – Auditor for missing / weak security headers

Checks each unique origin/route for presence and strength of common
security‑related HTTP response headers.

Evaluated Headers
=================
* **Strict‑Transport‑Security**  (HSTS)
* **Content‑Security‑Policy**   (CSP)
* **X‑Frame‑Options**           (clickjacking)
* **X‑Content‑Type‑Options**    (MIME sniffing)
* **Referrer‑Policy**
* **Permissions‑Policy**
* **Cache‑Control** (looks for `no‑store` or `private`)
* **Cross‑Origin‑Resource‑Policy**  (CORP)

Flags:
* **Missing** – header not present.
* **Weak** – header present but lax (e.g., CSP `unsafe‑inline`, HSTS <6 months).

Features
========
* Crawls links (depth) and de‑duplicates by **scheme://host[:port]** and path.
* Multi‑threaded requests with timeouts.
* Outputs CSV‑style summary to stdout.

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama

Example
=======
    python weak_http_headers_scanner.py --url https://example.com --depth 1 --threads 20
"""

import argparse, httpx, queue, threading, re, csv, sys
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style

SEC_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
    "cross-origin-resource-policy",
]

WEAK_PATTERNS = {
    "content-security-policy": re.compile(r"unsafe-inline|unsafe-eval", re.I),
    "strict-transport-security": re.compile(r"max-age=(\d+)", re.I),  # check < 15768000 (6m)
    "x-frame-options": re.compile(r"allow", re.I),
    "cache-control": re.compile(r"public", re.I),
}

###############################################################################
# CLI
###############################################################################

def args():
    p = argparse.ArgumentParser("Weak HTTP headers scanner")
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
    return httpx.Client(timeout=a.timeout, verify=False, headers={"User-Agent": "header-audit/1.0"}, proxies=proxies)

###############################################################################
# Crawl
###############################################################################

def crawl(sess, seed, depth):
    seen, q, urls = set(), queue.Queue(), []
    q.put((seed, 0))
    while not q.empty():
        u, d = q.get()
        if u in seen or d > depth:
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
# Analyzer
###############################################################################

results_lock = threading.Lock()
records = []  # list of dicts per URL


def evaluate(url, resp):
    row = {"url": url}
    hdrs = resp.headers
    for h in SEC_HEADERS:
        v = hdrs.get(h, "")
        if not v:
            row[h] = "missing"
        else:
            low = v.lower()
            weak = False
            if h in WEAK_PATTERNS:
                m = WEAK_PATTERNS[h].search(v)
                if m:
                    if h == "strict-transport-security":
                        try:
                            age = int(m.group(1))
                            weak = age < 15768000  # < 180 days
                        except ValueError:
                            weak = True
                    else:
                        weak = True
            row[h] = "weak" if weak else "ok"
    return row


def worker(sess, q, pbar):
    while True:
        try:
            url = q.get_nowait()
        except queue.Empty:
            break
        try:
            r = sess.get(url, follow_redirects=False)
            row = evaluate(url, r)
            with results_lock:
                records.append(row)
        except Exception:
            pass
        q.task_done(); pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    a = args()
    sess = client(a)
    targets = crawl(sess, a.url, a.depth)

    q = queue.Queue(); [q.put(u) for u in targets]
    p = tqdm(total=q.qsize(), desc="Header audit")
    ths = [threading.Thread(target=worker, args=(sess, q, p), daemon=True) for _ in range(a.threads)]
    [t.start() for t in ths]; [t.join() for t in ths]
    p.close()

    # Print CSV
    writer = csv.DictWriter(sys.stdout, fieldnames=["url"] + SEC_HEADERS)
    writer.writeheader(); writer.writerows(records)

    # Simple console summary
    missing = sum(any(v == "missing" for v in r.values()) for r in records)
    weak = sum(any(v == "weak" for v in r.values()) for r in records)
    print(f"\n{Fore.RED if missing else Fore.GREEN}[!] URLs with missing headers: {missing}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW if weak else Fore.GREEN}[!] URLs with weak headers: {weak}{Style.RESET_ALL}")
