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
SUB_URL = "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/trojan.txt"
TIMEOUT = 5                 # 单次测试超时（秒）
MAX_LATENCY_MS = 300        # 保留延迟低于此值的节点
MAX_KEEP = 50               # 最终保留节点数
WORKERS = 30                # 并发测试数
# ==========================

def parse_trojan(url: str):
    """解析 trojan:// 链接"""
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
    """TCP + TLS 握手延迟测试"""
    host = node['host']
    port = node['port']
    sni = node['sni'] or host

    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        tcp_ms = (time.time() - start) * 1000

        # TLS 握手（不验证证书，只看能否握手成功）
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
    print(f"Downloading {SUB_URL} ...")
    resp = requests.get(SUB_URL, timeout=30)
    content = resp.text.strip()

    # 2. 解析节点（先尝试 Base64 解码，失败则按明文处理）
    try:
        decoded = base64.b64decode(content).decode('utf-8')
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]
        print("Subscription format: Base64")
    except Exception:
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        print("Subscription format: Plain text")

    nodes = [parse_trojan(l) for l in lines if l.startswith('trojan://')]
    nodes = [n for n in nodes if n]
    print(f"Total Trojan nodes: {len(nodes)}")

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

    # 4. 排序并截取前 N 个
    results.sort(key=lambda x: x['latency'])
    top = results[:MAX_KEEP]

    # 5. 生成输出（Base64 编码，标准订阅格式，Hiddify 兼容）
    plain = '\n'.join(r['node']['url'] for r in top)
    b64 = base64.b64encode(plain.encode('utf-8')).decode()

    with open('output/trojan_filtered.txt', 'w', encoding='utf-8') as f:
        f.write(b64)

    with open('output/trojan_filtered_plain.txt', 'w', encoding='utf-8') as f:
        f.write(plain)

    print(f"\nKept {len(top)} nodes (latency ≤ {MAX_LATENCY_MS}ms)")
    print("Output: output/trojan_filtered.txt (Base64) | output/trojan_filtered_plain.txt (Plain)")

if __name__ == '__main__':
    main()
