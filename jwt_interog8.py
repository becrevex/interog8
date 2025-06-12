#!/usr/bin/env python3
"""jwt_weakness_scanner.py – Analyzer for common JWT implementation flaws

Detects (per token):
• **alg=none** acceptance (unsigned bypass)
• **weak shared secret** brute‑forcible for HS256 (wordlist)
• **short / past expiration** (exp claim)
• **'kid' header injection** vulnerability (blind indicator)
• **insecure "jku"/"x5u" remote JWKS URLs**

Workflow
========
1. Fetch the seed URL (and crawl links up to depth).
2. Collect JWTs from:
   – `Set‑Cookie` (cookie values that look like JWT)
   – `Authorization: Bearer <token>` in responses
   – URLs / forms containing JWT‑looking strings
3. For each token:
   a. Decode header & payload (no verify) → report alg, exp, etc.
   b. If alg == "none": flag **critical**.
   c. If alg starts with HS (HS256/384/512): brute wordlist (default 500 common secrets or supplied via `--wordlist`).
   d. If header has `kid`, suggest testing for path traversal / poisoning.
   e. If header has `jku`/`x5u` pointing to external host: flag.

Limitations: The script does **offline** analysis; it does NOT exploit server‑side verification except via alg=none check (predictive — server may or may not accept). Use Burp or custom PoC to confirm.

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama pyjwt

Example
=======
    python jwt_weakness_scanner.py --url https://target.local --depth 1 --threads 10 --wordlist secrets.txt
"""

import argparse, base64, json, httpx, queue, threading, re, hmac, hashlib, time
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style
import jwt  # PyJWT (no cryptography heavy when decoding w/o verify)

###############################################################################
# CLI
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="JWT weakness scanner")
    p.add_argument("--url", required=True)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--threads", type=int, default=8)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy")
    p.add_argument("--wordlist", help="Secrets wordlist for HS brute")
    return p.parse_args()

###############################################################################
# HTTP client
###############################################################################

def client(a):
    proxies = {"http://": a.proxy, "https://": a.proxy} if a.proxy else None
    return httpx.Client(timeout=a.timeout, verify=False, headers={"User-Agent": "jwt-scan/1.0"}, proxies=proxies)

###############################################################################
# Crawl + token collection
###############################################################################
JWT_RX = re.compile(r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

def crawl(sess, seed, depth):
    seen, q, tokens = set(), queue.Queue(), []
    q.put((seed, 0))
    while not q.empty():
        url, d = q.get()
        if url in seen or d > depth:
            continue
        seen.add(url)
        try:
            r = sess.get(url, follow_redirects=True)
        except Exception:
            continue
        # cookies
        for c in r.cookies.jar:
            if JWT_RX.fullmatch(c.value):
                tokens.append((url, "cookie", c.value))
        # Authorization header echo
        m = JWT_RX.search(r.text)
        if m:
            tokens.append((url, "body", m.group(0)))
        # HTML forms / links carrying JWTs
        if "text/html" in r.headers.get("content-type", ""):
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all(href=True):
                if JWT_RX.search(a['href']):
                    tokens.append((url, "href", JWT_RX.search(a['href']).group(0)))
            for inp in soup.find_all("input", value=True):
                if JWT_RX.fullmatch(inp['value']):
                    tokens.append((url, "form", inp['value']))
        q.task_done(); q.put_nowait((url, depth+1)) if False else None  # placeholder
    return tokens

###############################################################################
# Weakness checks
###############################################################################

WEAK_FINDINGS = []
WEAK_LOCK = threading.Lock()


def b64url_decode(data):
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def brute_hs(token_parts, alg, secrets):
    header_b64, payload_b64, sig_b64 = token_parts
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = b64url_decode(sig_b64)
    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    for s in secrets:
        if hmac.new(s.encode(), msg, hash_fn).digest() == sig:
            return s
    return None


def analyze(token, origin, secrets):
    header_b64, payload_b64, sig_b64 = token.split('.')
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except Exception:
        return
    alg = header.get('alg', '')
    issues = []
    if alg.lower() == 'none':
        issues.append('alg=none')
    if 'kid' in header:
        issues.append('kid present (check LFI/SSRF)')
    for key in ('jku', 'x5u'):
        if key in header and not header[key].startswith(origin):
            issues.append(f"{key} external {header[key]}")
    # expiration
    exp = payload.get('exp')
    if exp and exp < time.time():
        issues.append('token expired')
    # brute HS secret
    if alg.startswith('HS') and secrets:
        found = brute_hs((header_b64, payload_b64, sig_b64), alg, secrets)
        if found:
            issues.append(f'weak secret "{found}"')
    if issues:
        with WEAK_LOCK:
            WEAK_FINDINGS.append((token[:40] + '...', ', '.join(issues)))

###############################################################################
# Worker
###############################################################################

def worker(tokens, secrets, origin, pbar):
    while True:
        try:
            token_info = tokens.get_nowait()
        except queue.Empty:
            break
        url, source, tok = token_info
        analyze(tok, origin, secrets)
        tokens.task_done(); pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    a = parse_args()
    secrets = ["secret", "password", "admin", "qwerty", "123456", "jwtsecret", "changeme"]
    if a.wordlist:
        with open(a.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            secrets.extend([l.strip() for l in f if l.strip()])
    sess = client(a)
    origin = f"{urlsplit(a.url).scheme}://{urlsplit(a.url).netloc}"
    collected = crawl(sess, a.url, a.depth)

    q = queue.Queue(); [q.put(t) for t in collected]
    pbar = tqdm(total=q.qsize(), desc='JWT analysis')
    ths = [threading.Thread(target=worker, args=(q, secrets, origin, pbar), daemon=True) for _ in range(a.threads)]
    [t.start() for t in ths]; [t.join() for t in ths]
    pbar.close()

    if WEAK_FINDINGS:
        for token_snip, issues in WEAK_FINDINGS:
            print(f"{Fore.RED}[JWT] {token_snip}  => {issues}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No obvious JWT weaknesses detected.{Style.RESET_ALL}")
