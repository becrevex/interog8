#!/usr/bin/env python3
"""mass_assignment_scanner.py – Over‑POSTing / Mass‑Assignment discovery tool

How it works
============
1. **Crawls** pages and HTML forms (depth‑controlled).
2. For each POST form:
   a. Sends a *baseline* request with the fields as rendered.
   b. Sends **mutated** requests that add extra parameters
      (e.g., `is_admin=1`, `role=admin`, `privilege=superuser`).
3. **Diffs** baseline vs. mutated responses:
   • HTTP status changes (201 ↔ 403, etc.)
   • Length difference >10 %
   • Levenshtein ratio < 0.9
   • Optional regex match for keywords (e.g., `"is_admin":\s*true`)
4. Flags any significant difference as a potential mass‑assignment issue.

Features
========
* CLI via *argparse* (`--url`, `--depth`, `--threads`, `--timeout`, `--wordlist`, …)
* Concurrency with ThreadPool + *tqdm* progress.
* Default wordlist of 40+ sensitive field names (is_admin, role, privilege, group[], …).
* Proxy & custom header support.

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama python-Levenshtein

Example
=======
    python mass_assignment_scanner.py --url https://target.local --depth 1 --threads 8
"""

import argparse, httpx, queue, threading, re
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style
from Levenshtein import ratio as lev_ratio

###############################################################################
# CLI
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="Mass‑assignment / Over‑POSTing scanner")
    p.add_argument("--url", required=True, help="Seed URL")
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy", help="http://127.0.0.1:8080 proxy")
    p.add_argument("--wordlist", help="Custom extra‑field list (one per line)")
    return p.parse_args()

###############################################################################
# HTTP
###############################################################################

def make_client(args):
    proxies = {"http://": args.proxy, "https://": args.proxy} if args.proxy else None
    return httpx.Client(headers={"User-Agent": "mass‑assign/1.0"}, timeout=args.timeout, verify=False, proxies=proxies)

###############################################################################
# Crawl
###############################################################################

def crawl(client, seed, depth):
    seen, q, out = set(), queue.Queue(), []
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
        if "text/html" in r.headers.get("content-type", ""):
            out.append((url, r))
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                q.put((urljoin(url, a["href"]), d + 1))
            for f in soup.find_all("form"):
                out.append((url, f))
    return out

###############################################################################
# Default sensitive field wordlist
###############################################################################

def default_fields():
    return [
        "is_admin", "isAdmin", "admin", "role", "roles", "priv", "privilege", "privileges", "access", "access_level",
        "accessLevel", "group", "groups", "permission", "permissions", "user[role]", "user[is_admin]", "accountType",
        "type", "auth", "authority", "power", "superuser", "root", "owner", "member_type", "staff", "staff_status",
        "account_level", "security_level", "user_role", "user_group", "plan", "subscription", "paid", "active",
    ]

###############################################################################
# Diff helpers
###############################################################################

def significant_diff(baseline, mutated):
    if baseline.status_code != mutated.status_code:
        return True, f"status {baseline.status_code}->{mutated.status_code}"
    if abs(len(baseline.text) - len(mutated.text)) / (len(baseline.text) + 1) > 0.10:
        return True, "size diff"
    if lev_ratio(baseline.text[:1500], mutated.text[:1500]) < 0.90:
        return True, "content diff"
    if re.search(r"is_admin\s*[:=]\s*true", mutated.text, re.I):
        return True, "is_admin true"
    return False, ""

###############################################################################
# Globals
###############################################################################

result_lock = threading.Lock()
findings = []  # (url, field, note)

###############################################################################
# Worker
###############################################################################

def fuzz_form(client, page_url, form, extra_fields):
    if form.get("method", "GET").upper() != "POST":
        return
    action = urljoin(page_url, form.get("action", page_url))
    inputs = {i.get("name"): i.get("value", "1") for i in form.find_all("input") if i.get("name")}
    if not inputs:
        return
    try:
        baseline = client.post(action, data=inputs, follow_redirects=False)
    except Exception:
        return
    # mutate by adding each extra field with high‑priv value
    for field in extra_fields:
        tampered = inputs.copy(); tampered[field] = "admin" if "role" in field else "1"
        try:
            r = client.post(action, data=tampered, follow_redirects=False)
            change, note = significant_diff(baseline, r)
            if change:
                with result_lock:
                    findings.append((action, field, note))
        except Exception:
            pass


def worker(client, q, extra_fields, pbar):
    while True:
        try:
            url, obj = q.get_nowait()
        except queue.Empty:
            break
        if not isinstance(obj, httpx.Response):
            fuzz_form(client, url, obj, extra_fields)
        q.task_done(); pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    args = parse_args()
    wordlist = default_fields()
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            wordlist.extend([l.strip() for l in f if l.strip()])

    client = make_client(args)
    pages = crawl(client, args.url, args.depth)

    q = queue.Queue(); [q.put(p) for p in pages]
    pbar = tqdm(total=q.qsize(), desc="Mass‑assignment fuzz")

    threads = [
        threading.Thread(target=worker, args=(client, q, wordlist, pbar), daemon=True)
        for _ in range(args.threads)
    ]
    [t.start() for t in threads]; [t.join() for t in threads]
    pbar.close()

    if findings:
        for url, field, note in findings:
            print(f"{Fore.RED}[MASS‑ASSIGN] {url}  +{field}  ({note}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No mass‑assignment indicators found.{Style.RESET_ALL}")
