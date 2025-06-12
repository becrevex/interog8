#!/usr/bin/env python3
"""deserialization_scanner.py – Insecure deserialization reconnaissance tool

Goals
=====
1. **Discover** potential deserialization entry points:
   • Cookies, hidden/form fields, JSON bodies that look serialized
     (Java `ACED0005`, PHP `O:`, .NET `__VIEWSTATE`, Ruby `!ruby/object:`).
2. **Test** by sending crafted payloads and observing:
   • Server‑side error responses (HTTP 500, stack traces)
   • Time delays (sleep gadget)
3. **Report** findings per URL / parameter.

Supported Formats & Heuristics
------------------------------
* **Java** serialized object → magic bytes `\xAC\xED\x00\x05` (base64‑encoded)
* **PHP** serialized object → starts with `O:` followed by digits and `:"`
* **.NET ViewState** → `__VIEWSTATE` param (base64, may start with `/w`)  + optional MAC disabled indicator
* **Python pickle** → `\x80\x03` base64 or hex within params
* **Ruby** YAML → `!ruby/object:` marker

Test Payloads
-------------
* **Java**: base64 of `rO0ABXNyABpqYXZhLnV0aWwuQXJyYXlMaXN0xZ3Jm6kZE9gDAAFJAARzaXpleHAAAAABdwQAAAABdACB`
  (short harmless ArrayList)
* **PHP**: `O:8:"phpinfo":0:{}` triggers phpinfo() call on unserialize if magic method exists.
* **.NET**: Replace `__VIEWSTATE` with `AAAA` to check MAC validation error.
* **Generic corruption**: truncate last 10% of data.

Install
=======
    pip install httpx beautifulsoup4 tqdm colorama

Example
=======
    python deserialization_scanner.py --url https://target.local --depth 1 --threads 10
"""

import argparse, httpx, queue, threading, base64, re, time
from urllib.parse import urljoin, urlsplit, urlunsplit, urlencode, parse_qsl
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style

###############################################################################
# CLI
###############################################################################

def parse_args():
    p = argparse.ArgumentParser(description="Insecure deserialization scanner")
    p.add_argument("--url", required=True)
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--proxy")
    return p.parse_args()

###############################################################################
# HTTP client
###############################################################################

def client(a):
    proxies = {"http://": a.proxy, "https://": a.proxy} if a.proxy else None
    return httpx.Client(timeout=a.timeout, verify=False, headers={"User-Agent": "deserialize-scan/1.0"}, proxies=proxies)

###############################################################################
# Crawl
###############################################################################

SERIAL_REGEXES = {
    "java_b64": re.compile(r"rO0A[0-9A-Za-z+/]+={0,2}"),
    "php": re.compile(r"O:\d+:\"[A-Za-z0-9_]+\""),
    "pickle_b64": re.compile(r"gAS[0-9A-Za-z+/]{10,}={0,2}"),
    "ruby_yaml": re.compile(r"!ruby/object:"),
}

VIEWSTATE_NAME = "__VIEWSTATE"


def crawl(sess, seed, depth):
    seen, q, pages = set(), queue.Queue(), []
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
        pages.append((url, r))
        if "text/html" in r.headers.get("content-type", ""):
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.find_all("a", href=True):
                q.put((urljoin(url, a["href"]), d + 1))
            for f in soup.find_all("form"):
                pages.append((url, f))
    return pages

###############################################################################
# Payload generators
###############################################################################

JAVA_TEST = base64.b64encode(b"\xAC\xED\x00\x05sr\x00\x1Ajava.util.ArrayListx\81\xD2\x03\x4F\x4C\x80\x04I\x00sizexp\x00\x00\x00\x01w\x04\x00\x00\x00\x01t\x00\x08testterm").decode()
PHP_TEST = "O:8:\"stdClass\":0:{}"  # harmless object

###############################################################################
# Util
###############################################################################

def mutate(value):
    """Return list of crafted variants for testing."""
    out = []
    if SERIAL_REGEXES["java_b64"].fullmatch(value):
        out.append(JAVA_TEST)
        out.append(value[:-10])  # truncate
    elif VIEWSTATE_NAME.lower() in value.lower():
        out.append("AAAA")
    elif SERIAL_REGEXES["php"].match(value):
        out.append(PHP_TEST)
        out.append(value[:-5])
    else:
        out.append(value[:-5])
    return out

###############################################################################
# Worker
###############################################################################

findings = []
lock = threading.Lock()

TIME_THRESHOLD = 4.0


def inject_qs(url, k, v):
    parts = urlsplit(url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    qs[k] = v
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

ERROR_RX = re.compile(r"(Serialization|unserialize|java\.io\.Exception|ViewState|BinaryFormatter)", re.I)


def test_param(sess, method, target, base_resp, param_name, payload_val, is_get, form_inputs=None):
    try:
        if is_get:
            tampered_url = inject_qs(target, param_name, payload_val)
            start = time.perf_counter()
            r = sess.get(tampered_url, follow_redirects=False)
        else:
            form_inputs[param_name] = payload_val
            start = time.perf_counter()
            r = sess.post(target, data=form_inputs, follow_redirects=False)
        elapsed = time.perf_counter() - start
    except Exception:
        return
    diff_status = r.status_code >= 500 and base_resp.status_code < 500
    error_match = ERROR_RX.search(r.text)
    slow = elapsed - (base_resp.elapsed.total_seconds() if base_resp.elapsed else 0) > TIME_THRESHOLD
    if diff_status or error_match or slow:
        note = "status500" if diff_status else "slow" if slow else "error"
        with lock:
            findings.append((target, param_name, note))


def worker(sess, q, pbar):
    while True:
        try:
            url, obj = q.get_nowait()
        except queue.Empty:
            break
        if isinstance(obj, httpx.Response):
            # GET parameters
            params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            if params:
                base = obj
                for k, v in params.items():
                    if any(rx.search(v) for rx in SERIAL_REGEXES.values()) or k.upper() == VIEWSTATE_NAME:
                        for pay in mutate(v):
                            test_param(sess, "GET", url, base, k, pay, True)
        else:
            form = obj
            if form.get("method", "GET").upper() != "POST":
                q.task_done(); pbar.update(1); continue
            action = urljoin(url, form.get("action", url))
            inputs = {i.get("name"): i.get("value", "") for i in form.find_all("input") if i.get("name")}
            if not inputs:
                q.task_done(); pbar.update(1); continue
            try:
                base = sess.post(action, data=inputs, follow_redirects=False)
            except Exception:
                q.task_done(); pbar.update(1); continue
            for k, v in inputs.items():
                if any(rx.search(v) for rx in SERIAL_REGEXES.values()) or k.upper() == VIEWSTATE_NAME:
                    for pay in mutate(v):
                        test_param(sess, "POST", action, base, k, pay, False, inputs.copy())
        q.task_done(); pbar.update(1)

###############################################################################
# Main
###############################################################################

if __name__ == "__main__":
    a = parse_args()
    sess = client(a)
    pages = crawl(sess, a.url, a.depth)

    q = queue.Queue(); [q.put(p) for p in pages]
    pbar = tqdm(total=q.qsize(), desc="Deserialization fuzz")
    threads = [threading.Thread(target=worker, args=(sess, q, pbar), daemon=True) for _ in range(a.threads)]
    [t.start() for t in threads]; [t.join() for t in threads]
    pbar.close()

    if findings:
        for tgt, param, note in findings:
            print(f"{Fore.RED}[DESERIAL] {tgt} param={param} ({note}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[-] No obvious deserialization indicators found.{Style.RESET_ALL}")
