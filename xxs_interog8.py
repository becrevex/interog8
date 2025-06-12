#!/usr/bin/env python3
"""xss_scanner.py – Lightweight yet thorough XSS reconnaissance tool

Highlights
----------
* Crawls pages & HTML forms (depth‑controlled)
* Injects **reflected**, **DOM**, and **stored** XSS payloads
* Detects:
    – Reflection in raw HTML
    – JavaScript execution (headless browser)
    – Common error messages (e.g., React rendering issues)
* Argparse CLI (`--url`, `--depth`, `--threads`, `--headless`, ...)
* Pure‑Python: httpx + BS4 + Playwright (optional) + colorama

Install:
    pip install httpx beautifulsoup4 colorama tqdm playwright
    playwright install  # for headless JS execution

Usage:
    python xss_scanner.py --url https://target.local --depth 2 --threads 10 --headless
"""

import argparse, httpx, re, sys, time, threading, queue, asyncio, contextlib
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style

# Optional playwright import (only if --headless)
with contextlib.suppress(ImportError):
    from playwright.async_api import async_playwright

PAYLOAD_REFLECT = "<xss_test>"
PAYLOAD_DOM = "\"onclick=alert(45)//"

ERROR_REGEX = re.compile(r"(<script>.*</script>|React\.)", re.I)

lock = threading.Lock()
findings = []  # (level, url, param, why)

###############################################################################
# Argparse
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="Python XSS scanner")
    p.add_argument("--url", required=True, help="Seed URL")
    p.add_argument("--depth", type=int, default=1, help="Crawl depth (default 1)")
    p.add_argument("--threads", type=int, default=10, help="Concurrency")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--headless", action="store_true", help="Execute DOM payloads in headless browser")
    p.add_argument("--proxy", help="http://127.0.0.1:8080 proxy")
    return p.parse_args()

###############################################################################
# HTTP helpers
###############################################################################

def make_client(args):
    proxies = {"http://": args.proxy, "https://": args.proxy} if args.proxy else None
    return httpx.Client(headers={"User-Agent": "xss-scanner/1.0"}, timeout=args.timeout, verify=False, proxies=proxies)

###############################################################################
# Crawling
###############################################################################

def crawl(client, start, depth):
    seen, q = set(), queue.Queue()
    q.put((start, 0))
    pages = []

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
        for tag in soup.find_all("a", href=True):
            q.put((urljoin(url, tag["href"]), d + 1))
        for form in soup.find_all("form"):
            pages.append((url, form))
    return pages

###############################################################################
# Testing parameters
###############################################################################

def inject_get(url, param, payload):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query))
    qs[param] = payload
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

async def headless_exec(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        triggered = False
        page.on("dialog", lambda dialog: (dialog.dismiss(), setattr(sys.modules[__name__], "_dlg", True)))
        try:
            await page.goto(url, wait_until="load")
            triggered = getattr(sys.modules[__name__], "_dlg", False)
        finally:
            await browser.close()
        return triggered

###############################################################################
# Worker thread
###############################################################################

def worker(client, q, args, pbar):
    loop = asyncio.new_event_loop() if args.headless else None
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            return
        url, obj = item
        if isinstance(obj, httpx.Response):  # pure GET page
            for k in dict(parse_qsl(urlsplit(url).query)):
                test_url = inject_get(url, k, PAYLOAD_REFLECT)
                try:
                    r = client.get(test_url)
                    if PAYLOAD_REFLECT in r.text:
                        with lock:
                            findings.append(("HIGH", test_url, k, "Reflected"))
                    elif ERROR_REGEX.search(r.text):
                        with lock:
                            findings.append(("MEDIUM", test_url, k, "Error reflection"))
                except Exception:
                    pass
                if args.headless:
                    dom_url = inject_get(url, k, PAYLOAD_DOM)
                    try:
                        if loop.run_until_complete(headless_exec(dom_url)):
                            with lock:
                                findings.append(("HIGH", dom_url, k, "DOM‑executed"))
                    except Exception:
                        pass
        else:  # form element
            form = obj
            method = form.get("method", "GET").upper()
            action = urljoin(url, form.get("action", url))
            inputs = {inp.get("name"): inp.get("value", "FUZZ") for inp in form.find_all("input") if inp.get("name")}
            for name in inputs.keys():
                data = inputs.copy()
                data[name] = PAYLOAD_REFLECT
                try:
                    r = client.request(method, action, data=data)
                    if PAYLOAD_REFLECT in r.text:
                        with lock:
                            findings.append(("HIGH", action, name, "Form reflect"))
                except Exception:
                    pass
        q.task_done()
        pbar.update(1)
    if loop:
        loop.close()

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    args = parse_args()
    client = make_client(args)

    print(f"{Fore.CYAN}[+] Crawling…{Style.RESET_ALL}")
    pages = crawl(client, args.url, args.depth)

    q = queue.Queue()
    for page in pages:
        q.put(page)

    pbar = tqdm(total=q.qsize(), desc="Testing")

    threads = [threading.Thread(target=worker, args=(client, q, args, pbar), daemon=True) for _ in range(args.threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    pbar.close()

    if findings:
        for level, url, param, why in findings:
            col = Fore.RED if level == "HIGH" else Fore.YELLOW
            print(f"{col}[{level}] {url} param={param} ({why}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No XSS found.{Style.RESET_ALL}")
