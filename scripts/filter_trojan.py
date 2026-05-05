#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import os
import re
import socket
import ssl
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ========== 配置 ==========
# 主源：使用 ghproxy 镜像，避免 GitHub Actions 被墙
SUB_URLS = [
    "https://ghproxy.net/https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
]

TIMEOUT = 5
MAX_LATENCY_MS = 300
MAX_KEEP = 50
WORKERS = 30
# ==========================

def fetch_sub():
    """多源尝试下载，返回有效文本"""
    for url in SUB_URLS:
        try:
            print(f"Trying {url} ...")
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            text = resp.text.strip()
            print(f"  Fetched {len(text)} chars")
            print(f"  Preview: {text[:200]}")
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
    return {
        'url': url.strip(),
        'host': host,
        'port': port,
        'sni': sni,
        'remark': remark,
    }

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
        return {
            'node': node,
            'latency': tls_ms,
            'tcp': tcp_ms,
            'alive': True,
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

    # 1. 下载订阅
    content = fetch_sub()

    # 2. 解析（先 Base64，失败则明文）
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]
        print("Format detected: Base64")
    except Exception:
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        print("Format detected: Plain text")

    nodes = [parse_trojan(l) for l in lines if l.startswith('trojan://')]
    nodes = [n for n in nodes if n]
    print(f"Total Trojan nodes parsed: {len(nodes)}")

    if not nodes:
        print("WARNING: No trojan nodes found, aborting.")
        # 保留空文件占位，避免 git-auto-commit 报错
        open('output/trojan_filtered.txt', 'w').write('')
        open('output/trojan_filtered_plain.txt', 'w').write('')
        return

    # 3. 并发测速
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(test_node, n): n for n in nodes}
        for future in as_completed(futures):
            r = future.result()
            if r['alive'] and r['latency'] <= MAX_LATENCY_MS:
                results.append(r)
                print(f"  ✓ {r['node']['host']}:{r['node']['port']}  {r['latency']:.0f}ms")
            elif r['alive']:
                print(f"  ~ {r['node']['host']}:{r['node']['port']}  {r['latency']:.0f}ms (slow)")
            else:
                print(f"  ✗ {r['node']['host']}:{r['node']['port']}  dead")

    # 4. 排序截取
    results.sort(key=lambda x: x['latency'])
    top = results[:MAX_KEEP]

    # 5. 输出（Base64 + 明文双份）
    plain = '\n'.join(r['node']['url'] for r in top)
    b64 = base64.b64encode(plain.encode('utf-8')).decode()

    with open('output/trojan_filtered.txt', 'w', encoding='utf-8') as f:
        f.write(b64)

    with open('output/trojan_filtered_plain.txt', 'w', encoding='utf-8') as f:
        f.write(plain)

    print(f"\nKept {len(top)} nodes (latency ≤ {MAX_LATENCY_MS}ms)")

if __name__ == '__main__':
    main()
