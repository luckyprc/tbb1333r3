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
    # Trojan 专用源
    "https://ghproxy.net/https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/trojan.txt",
    # 混合协议源（SS/Vmess/Trojan）
    "https://proxy.v2gh.com/https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
]

TIMEOUT = 3                 # 单次测试超时（秒）
MAX_LATENCY_MS = 300        # 保留延迟低于此值的节点
MAX_KEEP = 50               # 最终保留节点数
WORKERS = 50                # 并发测试数
MIN_KEEP = 5                # 如果本次筛出少于5个，保留历史数据
# =============================================

def fetch_sub():
    """多源尝试下载，返回有效文本"""
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
    allow_insecure = params.get('allowInsecure', ['0'])[0] in ('1', 'true') or \
                     params.get('insecure', ['0'])[0] in ('1', 'true')

    return {
        'url': url.strip(),
        'type': 'trojan',
        'host': host,
        'port': port,
        'sni': sni,
        'password': password,
        'remark': remark,
        'allow_insecure': allow_insecure,
    }

def parse_ss(url: str):
    """解析 ss:// 链接，只保留 Hiddify 友好的加密方式"""
    url = url.strip()
    if not url.startswith('ss://'):
        return None

    # 去掉 ss:// 前缀
    body = url[5:]

    # 尝试分离 tag（#后面的备注）
    if '#' in body:
        b64_part, tag = body.split('#', 1)
        tag = urllib.parse.unquote(tag)
    else:
        b64_part = body
        tag = ""

    # 尝试分离插件参数（?后面的）
    if '?' in b64_part:
        b64_part = b64_part.split('?')[0]

    # 标准格式: base64(method:password)@host:port
    if '@' in b64_part:
        # 可能是 base64(method:password)@host:port
        creds_b64, server_part = b64_part.split('@', 1)
        try:
            creds = base64.b64decode(creds_b64 + '==').decode('utf-8')
        except Exception:
            return None
        if ':' not in creds:
            return None
        method, password = creds.split(':', 1)
        m = re.match(r'([^:]+):(\d+)', server_part)
        if not m:
            return None
        host, port = m.group(1), int(m.group(2))
    else:
        # 纯 base64 格式: base64(method:password@host:port)
        try:
            full = base64.b64decode(b64_part + '==').decode('utf-8')
        except Exception:
            return None
        m = re.match(r'([^:]+):([^@]+)@([^:]+):(\d+)', full)
        if not m:
            return None
        method, password, host, port = m.group(1), m.group(2), m.group(3), int(m.group(4))

    # Hiddify/sing-box 对 ss 加密的支持有限，只保留常见兼容的
    good_methods = ('chacha20-ietf-poly1305', 'aes-256-gcm', 'aes-128-gcm')
    if method.lower() not in good_methods:
        return None

    return {
        'url': url,
        'type': 'ss',
        'host': host,
        'port': port,
        'password': password,
        'method': method,
        'remark': tag,
        'allow_insecure': False,
    }

def parse_vmess(url: str):
    """解析 vmess:// 链接，只保留带 TLS 的（Hiddify 对无 TLS vmess 支持极差）"""
    url = url.strip()
    if not url.startswith('vmess://'):
        return None

    b64 = url[8:]
    try:
        cfg = json.loads(base64.b64decode(b64 + '==').decode('utf-8'))
    except Exception:
        return None

    # 只保留有 TLS 的 vmess（ws+tls 或 tcp+tls）
    tls = cfg.get('tls', '') or cfg.get('scy', '')
    if isinstance(tls, str):
        tls = tls.strip().lower()
    if tls not in ('tls', 'true', '1', True):
        return None

    host = cfg.get('add', '')
    port = int(cfg.get('port', 0))
    if not host or not port:
        return None

    return {
        'url': url,
        'type': 'vmess',
        'host': host,
        'port': port,
        'id': cfg.get('id', ''),
        'aid': int(cfg.get('aid', 0)),
        'net': cfg.get('net', 'tcp'),
        'path': cfg.get('path', '/'),
        'host_header': cfg.get('host', ''),
        'sni': cfg.get('sni', '') or cfg.get('host', '') or host,
        'remark': cfg.get('ps', ''),
        'allow_insecure': False,
    }

def parse_node(url: str):
    """通用解析入口"""
    if url.startswith('trojan://'):
        return parse_trojan(url)
    elif url.startswith('ss://'):
        return parse_ss(url)
    elif url.startswith('vmess://'):
        return parse_vmess(url)
    return None

def node_fingerprint(node: dict) -> str:
    """生成节点指纹，用于去重"""
    if node['type'] == 'ss':
        raw = f"{node['host']}:{node['port']}:{node['method']}:{node['password']}"
    elif node['type'] == 'vmess':
        raw = f"{node['host']}:{node['port']}:{node['id']}"
    else:
        raw = f"{node['host']}:{node['port']}:{node.get('password', '')}"
    return hashlib.md5(raw.encode()).hexdigest()

def guess_region(host: str) -> str:
    """基于域名后缀或关键词粗略判断地区"""
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
    """TCP + TLS 握手延迟测试"""
    host = node['host']
    port = node['port']
    sni = node.get('sni', '') or host

    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        tcp_ms = (time.time() - start) * 1000

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=sni) as ssock:
            tls_ms = (time.time() - start) * 1000

        # 对 WS/HTTP 伪装节点做额外 HTTP 探针
        http_ok = True
        if node.get('net') == 'ws' or 'type=ws' in node['url']:
            try:
                path = node.get('path', '/')
                req = f"HEAD {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n"
                ssock.send(req.encode())
                resp = ssock.recv(1024)
                http_ok = any(x in resp for x in [b'200', b'204', b'101', b'403', b'400'])
            except Exception:
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

def hiddify_score(node: dict) -> int:
    """Hiddify 兼容性评分，越高越好"""
    score = 100
    t = node['type']

    if t == 'trojan':
        score += 50
    elif t == 'ss':
        score += 30
    elif t == 'vmess':
        score -= 20  # vmess 在 sing-box 里兼容性不如 trojan/ss

    if node.get('allow_insecure'):
        score -= 20

    return score

def build_singbox_outbound(node: dict, tag: str):
    """构建 sing-box outbound 对象"""
    t = node['type']

    if t == 'trojan':
        out = {
            "type": "trojan",
            "server": node['host'],
            "server_port": node['port'],
            "password": node['password'],
            "tls": {
                "enabled": True,
                "server_name": node.get('sni', node['host']),
                "insecure": node.get('allow_insecure', False)
            },
            "tag": tag
        }
        return out

    elif t == 'ss':
        out = {
            "type": "shadowsocks",
            "server": node['host'],
            "server_port": node['port'],
            "method": node['method'],
            "password": node['password'],
            "tag": tag
        }
        return out

    elif t == 'vmess':
        out = {
            "type": "vmess",
            "server": node['host'],
            "server_port": node['port'],
            "uuid": node['id'],
            "security": "auto",
            "alter_id": node.get('aid', 0),
            "tag": tag
        }
        # transport
        net = node.get('net', 'tcp')
        if net == 'ws':
            out["transport"] = {
                "type": "ws",
                "path": node.get('path', '/'),
                "headers": {}
            }
            if node.get('host_header'):
                out["transport"]["headers"]["Host"] = node['host_header']
        # tls
        out["tls"] = {
            "enabled": True,
            "server_name": node.get('sni', node['host']),
            "insecure": False
        }
        return out

    return None

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

    # 3. 解析所有节点
    nodes = []
    for l in lines:
        n = parse_node(l)
        if n:
            nodes.append(n)

    print(f"Total nodes parsed: {len(nodes)}")
    if not nodes:
        print("WARNING: No nodes found from upstream.")
        if os.path.exists('output/trojan_filtered.txt'):
            print("Keeping existing files.")
        else:
            open('output/trojan_filtered.txt', 'w').write('')
            open('output/trojan_filtered_plain.txt', 'w').write('')
            open('output/singbox.json', 'w').write('{"outbounds":[]}')
        return

    # 4. 去重
    seen = set()
    unique_nodes = []
    for n in nodes:
        fp = node_fingerprint(n)
        if fp not in seen:
            seen.add(fp)
            unique_nodes.append(n)
    print(f"After dedup: {len(unique_nodes)}")

    # 5. 并发测速
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

    # 6. 排序：先按 Hiddify 兼容性降序，再按延迟升序
    for r in results:
        r['region'] = guess_region(r['node']['host'])
        r['score'] = hiddify_score(r['node'])

    results.sort(key=lambda x: (-x['score'], x['latency']))
    top = results[:MAX_KEEP]

    # 7. 统计
    stats = {
        'total_source': len(nodes),
        'unique': len(unique_nodes),
        'alive': len(results),
        'kept': len(top),
        'regions': {},
        'types': {},
    }
    for r in top:
        stats['regions'][r['region']] = stats['regions'].get(r['region'], 0) + 1
        stats['types'][r['node']['type']] = stats['types'].get(r['node']['type'], 0) + 1

    print(f"\nKept {len(top)} nodes (latency ≤ {MAX_LATENCY_MS}ms)")
    print(f"Region distribution: {stats['regions']}")
    print(f"Type distribution: {stats['types']}")

    # 8. 兜底：筛出太少时保留旧数据
    if len(top) < MIN_KEEP and os.path.exists('output/trojan_filtered.txt'):
        print(f"Only {len(top)} nodes found (< {MIN_KEEP}), keeping previous files.")
        return

    # 9. 生成标准订阅（Base64 + 明文）
    plain_lines = []
    for r in top:
        n = r['node']
        remark = n.get('remark', '')
        # 清理 b2n.ir/v2ray-configs 标记
        remark = re.sub(r'⚡?\s*b2n\.ir/v2ray-configs\s*\|\s*', '', remark)
        remark = re.sub(r'⚡?\s*b2n\.ir/v2ray-configs', '', remark)
        remark = remark.strip()

        tag = f"[{r['region']}] {r['latency']:.0f}ms | {remark}" if remark else f"[{r['region']}] {r['latency']:.0f}ms"

        # 对 trojan 链接注入新 tag
        if n['type'] == 'trojan':
            url_clean = re.sub(r'#.*$', '', n['url'])
            url = f"{url_clean}#{urllib.parse.quote(tag)}"
        else:
            # ss/vmess 直接保留原链接（它们的 tag 在链接内部）
            url = n['url']

        plain_lines.append(url)

    plain = '\n'.join(plain_lines)
    b64 = base64.b64encode(plain.encode('utf-8')).decode()

    with open('output/trojan_filtered.txt', 'w', encoding='utf-8') as f:
        f.write(b64)

    with open('output/trojan_filtered_plain.txt', 'w', encoding='utf-8') as f:
        f.write(plain)

    with open('output/trojan_stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)

    # 10. 生成 sing-box JSON（Hiddify iOS 直接导入）
    sing_outbounds = []
    for idx, r in enumerate(top, 1):
        tag = f"[{r['region']}] {r['latency']:.0f}ms | {r['node'].get('remark', f'node-{idx}')}"
        out = build_singbox_outbound(r['node'], tag)
        if out:
            sing_outbounds.append(out)

    sing_config = {
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": [o["tag"] for o in sing_outbounds],
                "default": sing_outbounds[0]["tag"] if sing_outbounds else ""
            },
            *sing_outbounds
        ]
    }

    with open('output/singbox.json', 'w', encoding='utf-8') as f:
        json.dump(sing_config, f, indent=2, ensure_ascii=False)

    print("Output updated: trojan_filtered.txt | trojan_filtered_plain.txt | singbox.json")

if __name__ == '__main__':
    main()
