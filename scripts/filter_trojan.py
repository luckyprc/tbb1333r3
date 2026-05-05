#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ==================== 配置 ====================
SUB_URLS = [
    "https://ghproxy.net/https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
]

TIMEOUT = 5
MAX_LATENCY_MS = 300
MAX_KEEP = 50
WORKERS = 20
MIN_KEEP = 5
# =============================================

def fetch_sub():
    for url in SUB_URLS:
        try:
            print(f"Trying {url} ...")
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            text = resp.text.strip()
            print(f"  Fetched {len(text)} chars")
            return text
        except Exception as e:
            print(f"  Failed: {e}")
    raise RuntimeError("All subscription URLs failed")

def parse_trojan(url: str):
    m = re.match(
        r'trojan://([^@]+)@([^:]+):(\d+)(?:\?([^#]*))?(?:#(.*))?',
        url.strip()
    )
    if not m:
        return None
    password, host, port, query, remark = m.groups()
    password = urllib.parse.unquote(password)
    port = int(port)
    remark = urllib.parse.unquote(remark) if remark else ""

    params = urllib.parse.parse_qs(query) if query else {}
    sni = params.get('sni', [None])[0] or params.get('host', [None])[0] or host
    allow_insecure = params.get('allowInsecure', ['0'])[0] == '1' or params.get('insecure', ['0'])[0] == '1'

    return {
        'url': url.strip(),
        'host': host,
        'port': port,
        'sni': sni,
        'password': password,
        'remark': remark,
        'allow_insecure': allow_insecure,
    }

def node_fingerprint(node: dict) -> str:
    raw = f"{node['host']}:{node['port']}:{node['password']}"
    return hashlib.md5(raw.encode()).hexdigest()

def guess_region(host: str) -> str:
    h = host.lower()
    if any(x in h for x in ['.cn', 'xiaohouzi', 'abzoones']):
        return 'CN'
    if any(x in h for x in ['hk', 'hongkong', 'hkg']):
        return 'HK'
    if any(x in h for x in ['jp', 'japan', 'tokyo', 'tyo']):
        return 'JP'
    if any(x in h for x in ['kr', 'korea', 'seoul']):
        return 'KR'
    if any(x in h for x in ['sg', 'singapore']):
        return 'SG'
    if any(x in h for x in ['tw', 'taiwan', 'taipei']):
        return 'TW'
    if any(x in h for x in ['us', 'usa', 'america', 'newyork', 'lax']):
        return 'US'
    if any(x in h for x in ['de', 'germany', 'frankfurt', 'fra']):
        return 'DE'
    if any(x in h for x in ['nl', 'netherlands', 'amsterdam']):
        return 'NL'
    if any(x in h for x in ['uk', 'gb', 'britain', 'london']):
        return 'GB'
    if any(x in h for x in ['.ua', 'ukraine', 'kiev', 'odesa']):
        return 'UA'
    if any(x in h for x in ['.eu', 'eu.org']):
        return 'EU'
    return 'OT'

def test_node(node: dict):
    host = node['host']
    port = node['port']
    sni = node['sni'] or host

    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        tcp_ms = (time.time() - start) * 1000

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=sni) as ssock:
            tls_ms = (time.time() - start) * 1000

        http_ok = False
        if 'type=ws' in node['url'] or 'type=http' in node['url']:
            try:
                path = re.search(r'path=([^&]+)', node['url'])
                path = urllib.parse.unquote(path.group(1)) if path else '/'
                req = f"HEAD {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                ssock.send(req.encode())
                resp = ssock.recv(1024)
                http_ok = b'200' in resp or b'204' in resp or b'101' in resp or b'403' in resp
            except Exception:
                http_ok = True
        else:
            http_ok = True

        return {
            'node': node,
            'latency': tls_ms,
            'tcp': tcp_ms,
            'alive': True,
            'http_ok': http_ok,
        }
    except Exception as e:
        return {
            'node': node,
            'latency': float('inf'),
            'alive': False,
            'error': str(e),
        }

def main():
    os.makedirs('output', exist_ok=True)

    content = fetch_sub()

    try:
        decoded = base64.b64decode(content).decode('utf-8')
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]
        print("Format: Base64")
    except Exception:
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        print("Format: Plain text")

    nodes = [parse_trojan(l) for l in lines if l.startswith('trojan://')]
    nodes = [n for n in nodes if n]
    print(f"Total parsed: {len(nodes)}")

    if not nodes:
        print("WARNING: No nodes found from upstream.")
        if os.path.exists('output/trojan_filtered.txt'):
            print("Keeping existing files.")
        else:
            open('output/trojan_filtered.txt', 'w').write('')
            open('output/trojan_filtered_plain.txt', 'w').write('')
        return

    seen = set()
    unique_nodes = []
    for n in nodes:
        fp = node_fingerprint(n)
        if fp not in seen:
            seen.add(fp)
            unique_nodes.append(n)
    print(f"After dedup: {len(unique_nodes)}")

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(test_node, n): n for n in unique_nodes}
        for future in as_completed(futures):
            r = future.result()
            if r['alive'] and r['latency'] <= MAX_LATENCY_MS and r['http_ok']:
                results.append(r)
                print(f"  ✓ {r['node']['host']}:{r['node']['port']}  {r['latency']:.0f}ms")
            elif r['alive'] and not r['http_ok']:
                print(f"  ~ {r['node']['host']}:{r['node']['port']}  TLS ok but HTTP probe failed")
            elif r['alive']:
                print(f"  ~ {r['node']['host']}:{r['node']['port']}  {r['latency']:.0f}ms (slow)")
            else:
                print(f"  ✗ {r['node']['host']}:{r['node']['port']}  dead")

    results.sort(key=lambda x: x['latency'])
    top = results[:MAX_KEEP]

    for r in top:
        region = guess_region(r['node']['host'])
        r['region'] = region

    stats = {
        'total_source': len(nodes),
        'unique': len(unique_nodes),
        'alive': len(results),
        'kept': len(top),
        'regions': {},
    }
    for r in top:
        stats['regions'][r['region']] = stats['regions'].get(r['region'], 0) + 1

    print(f"\nKept {len(top)} nodes (latency ≤ {MAX_LATENCY_MS}ms)")
    print(f"Region distribution: {stats['regions']}")

    if len(top) < MIN_KEEP and os.path.exists('output/trojan_filtered.txt'):
        print(f"Only {len(top)} nodes found (< {MIN_KEEP}), keeping previous files.")
        return

    plain_lines = []
    for r in top:
        n = r['node']
        remark = n['remark']
        remark = re.sub(r'⚡?\s*b2n\.ir/v2ray-configs\s*\|\s*', '', remark)
        remark = re.sub(r'⚡?\s*b2n\.ir/v2ray-configs', '', remark)
        remark = remark.strip()
        if remark:
            tag = f"[{r['region']}] {r['latency']:.0f}ms | {remark}"
        else:
            tag = f"[{r['region']}] {r['latency']:.0f}ms"
        url = re.sub(r'#.*$', '', n['url'])
        url = f"{url}#{urllib.parse.quote(tag)}"
        plain_lines.append(url)

    plain = '\n'.join(plain_lines)
    b64 = base64.b64encode(plain.encode('utf-8')).decode()

    with open('output/trojan_filtered.txt', 'w', encoding='utf-8') as f:
        f.write(b64)

    with open('output/trojan_filtered_plain.txt', 'w', encoding='utf-8') as f:
        f.write(plain)

    with open('output/trojan_stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    print("Output updated.")

if __name__ == '__main__':
    main()
