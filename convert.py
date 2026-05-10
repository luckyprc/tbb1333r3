#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multi-source daily converter:
Sources: yoyapai, cczzuu, v2rayse
1. Fetch each source with date fallback (today -> yesterday -> day before)
2. Auto-decode base64 if needed
3. Parse Trojan / Vmess / VLESS / SS
4. Force scv=true (tls.insecure + utls.chrome)
5. HTTP probe: keep 200/204/301/302/400/404/101
6. Output: nodes.txt (base64), raw.txt (plain URI), singbox.json
"""
import base64, json, urllib.parse, urllib.request, socket, ssl, os, sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==================== 源配置 ====================
SOURCES = {
    "yoyapai": {
        "url_template": "https://freenode.yoyapai.com/{date}-yoyapai.com-ssr-v2rayvpn-mianfeijiedian.txt",
        "date_fmt": "%Y/%m/%d",
        "encoding": "plain",      # 明文 URI
        "fallback_days": 3,
    },
    "cczzuu": {
        "url_template": "http://comm.cczzuu.top/node/{date}-v2ray.txt",
        "date_fmt": "%Y%m%d",
        "encoding": "base64",     # 返回 base64 编码
        "fallback_days": 3,
    },
    "v2rayse": {
        "url_template": "https://v2rayse.com/fs/public/{date}/free-node-share-2000.txt",
        "date_fmt": "%Y%m%d",
        "encoding": "base64",     # 返回 base64 编码
        "fallback_days": 3,
    },
}

# ==================== 解析函数 ====================

def parse_trojan(uri):
    p = urllib.parse.urlparse(uri)
    pw = urllib.parse.unquote(p.username or '')
    host = p.hostname
    port = p.port or 443
    name = urllib.parse.unquote(p.fragment) if p.fragment else f"Trojan-{host}"
    qs = urllib.parse.parse_qs(p.query)
    node = {
        "type": "trojan", "tag": name, "server": host,
        "server_port": port, "password": pw,
        "_uri": uri, "_source": ""
    }
    net = qs.get('type', ['tcp'])[0]
    if net == 'ws':
        node["transport"] = {
            "type": "ws",
            "path": urllib.parse.unquote(qs.get('path', ['/'])[0]),
            "headers": {}
        }
        if 'host' in qs:
            node["transport"]["headers"]["Host"] = qs['host'][0]
    if qs.get('security', [''])[0] == 'tls':
        sni = qs.get('sni', [host])[0]
        node["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    return node

def parse_vless(uri):
    p = urllib.parse.urlparse(uri)
    uuid = p.username
    host = p.hostname
    port = p.port or 443
    name = urllib.parse.unquote(p.fragment) if p.fragment else f"VLESS-{host}"
    qs = urllib.parse.parse_qs(p.query)
    node = {
        "type": "vless", "tag": name, "server": host,
        "server_port": port, "uuid": uuid,
        "_uri": uri, "_source": ""
    }
    net = qs.get('type', ['tcp'])[0]
    if net == 'ws':
        node["transport"] = {
            "type": "ws",
            "path": urllib.parse.unquote(qs.get('path', ['/'])[0]),
            "headers": {}
        }
        if 'host' in qs:
            node["transport"]["headers"]["Host"] = qs['host'][0]
    if qs.get('security', [''])[0] == 'tls':
        sni = qs.get('sni', [host])[0]
        fp = qs.get('fp', ['chrome'])[0]
        node["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": fp}
        }
    return node

def parse_vmess(uri):
    b64 = uri.replace('vmess://', '').strip()
    b64 = b64.replace('-', '+').replace('_', '/')
    pad = 4 - len(b64) % 4
    if pad != 4:
        b64 += '=' * pad
    try:
        raw = base64.b64decode(b64).decode('utf-8', errors='ignore')
        obj = json.loads(raw)
    except Exception:
        return None
    host = obj.get('add', '')
    port = int(obj.get('port', 0))
    if not host or not port:
        return None
    name = obj.get('ps', f"Vmess-{host}").replace('\r', '').replace('\n', '').strip()
    node = {
        "type": "vmess", "tag": name, "server": host,
        "server_port": port, "uuid": obj.get('id', ''),
        "alter_id": int(obj.get('aid', 0)),
        "security": obj.get('scy', 'auto') or 'auto',
        "_uri": uri, "_source": ""
    }
    net = obj.get('net', 'tcp')
    if net == 'ws':
        node["transport"] = {"type": "ws"}
        path = obj.get('path', '/')
        if path:
            node["transport"]["path"] = path
        if obj.get('host'):
            node["transport"]["headers"] = {"Host": obj['host']}
    if obj.get('tls') == 'tls':
        sni = obj.get('sni') or obj.get('host') or host
        node["tls"] = {
            "enabled": True, "server_name": sni,
            "insecure": True,
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    return node

def parse_ss(uri):
    try:
        p = urllib.parse.urlparse(uri)
        name = urllib.parse.unquote(p.fragment) if p.fragment else f"SS-{p.hostname}"
        if p.username and p.password:
            method = urllib.parse.unquote(p.username)
            password = urllib.parse.unquote(p.password)
            host = p.hostname
            port = p.port
        else:
            b64 = p.path.replace('/', '')
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += '=' * pad
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' in decoded:
                method_pw, server_port = decoded.rsplit('@', 1)
                method, password = method_pw.split(':', 1)
                host, port_str = server_port.rsplit(':', 1)
                port = int(port_str)
            else:
                return None
        return {
            "type": "shadowsocks", "tag": name, "server": host,
            "server_port": port, "method": method, "password": password,
            "_uri": uri, "_source": ""
        }
    except Exception:
        return None

def parse_text(text, source_name=""):
    nodes = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        node = None
        if line.startswith('trojan://'):
            node = parse_trojan(line)
        elif line.startswith('vmess://'):
            node = parse_vmess(line)
        elif line.startswith('vless://'):
            node = parse_vless(line)
        elif line.startswith('ss://'):
            node = parse_ss(line)
        if node:
            node["_source"] = source_name
            nodes.append(node)
    return nodes

# ==================== 抓取（含回退） ====================

def fetch_source(name, cfg):
    for i in range(cfg["fallback_days"]):
        d = datetime.now() - timedelta(days=i)
        date_str = d.strftime(cfg["date_fmt"])
        url = cfg["url_template"].format(date=date_str)
        print(f"[{name}] Trying {url}")
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
                text = data.decode('utf-8', errors='ignore')
                if cfg["encoding"] == "base64":
                    try:
                        clean = text.strip().replace('\n', '').replace('\r', '')
                        decoded = base64.b64decode(clean).decode('utf-8', errors='ignore')
                        text = decoded
                        print(f"[{name}] Base64 decoded OK")
                    except Exception as e:
                        print(f"[{name}] Base64 decode failed: {e}, using raw")
                if len(text) > 50 and any(proto in text for proto in ('trojan://', 'vmess://', 'vless://', 'ss://')):
                    print(f"[{name}] Success using {d.strftime('%Y%m%d')}")
                    return text, d.strftime('%Y%m%d')
        except Exception as e:
            print(f"[{name}] Failed: {e}")
            continue
    cache_file = os.path.join(OUTPUT_DIR, f"raw_{name}.txt")
    if os.path.exists(cache_file):
        print(f"[{name}] Using cached {cache_file}")
        with open(cache_file, 'r', encoding='utf-8') as f:
            return f.read(), "cached"
    return "", "failed"

# ==================== 探活 ====================

def probe_tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=5)
        return True
    except Exception:
        return False

def probe_http(node):
    transport = node.get('transport', {})
    if transport.get('type') != 'ws':
        return 200
    path = transport.get('path', '/')
    host = node['server']
    port = node['server_port']
    sni = node.get('tls', {}).get('server_name', host)
    try:
        if node.get('tls', {}).get('enabled'):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            url = f"https://{host}:{port}{path}"
            req = urllib.request.Request(url, headers={'Host': sni, 'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                return resp.status
        else:
            url = f"http://{host}:{port}{path}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None

def probe_node(node):
    host = node['server']
    port = node['server_port']
    if not probe_tcp(host, port):
        return node, False, None
    status = probe_http(node)
    if status is None:
        return node, False, None
    if status in (200, 204, 301, 302, 400, 404, 101):
        return node, True, status
    return node, False, status

def filter_alive(nodes, max_workers=50):
    alive = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_node, n): n for n in nodes}
        for future in as_completed(futures):
            node, is_alive, status = future.result()
            tag = node.get('tag', '')
            src = node.get('_source', '')
            if is_alive:
                alive.append(node)
                print(f"  [Alive][{src}] {tag} (HTTP {status})")
            else:
                print(f"  [Dead ][{src}] {tag} (HTTP {status})")
    return alive

# ==================== 输出 ====================

def to_raw(nodes):
    lines = [n['_uri'] for n in nodes if '_uri' in n]
    return '\n'.join(lines)

def to_base64(nodes):
    raw = to_raw(nodes)
    if not raw:
        return ""
    return base64.b64encode(raw.encode('utf-8')).decode('utf-8')

def to_singbox(nodes):
    outbounds = [
        {"tag": "direct", "type": "direct"},
        {"tag": "block", "type": "block"},
        {"tag": "dns-out", "type": "dns"},
    ]
    for n in nodes:
        clean = {k: v for k, v in n.items() if not k.startswith('_')}
        outbounds.append(clean)
    node_tags = [n['tag'] for n in nodes]
    if node_tags:
        outbounds.append({
            "tag": "auto",
            "type": "urltest",
            "outbounds": node_tags,
            "url": "http://www.google.com/generate_204",
            "interval": "1m",
            "tolerance": 50
        })
    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {"tag": "local", "address": "local"},
                {"tag": "google", "address": "https://dns.google/dns-query", "address_resolver": "local"}
            ]
        },
        "inbounds": [],
        "outbounds": outbounds,
        "route": {
            "auto_detect_interface": True,
            "final": "direct",
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"}
            ]
        }
    }

def save_source_raw(source_name, text):
    path = os.path.join(OUTPUT_DIR, f"raw_{source_name}.txt")
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)

def main():
    print("=" * 60)
    print(f"Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    all_nodes = []
    source_stats = {}
    for src_name, cfg in SOURCES.items():
        text, src_date = fetch_source(src_name, cfg)
        if not text:
            print(f"[{src_name}] SKIPPED (no data)")
            continue
        nodes = parse_text(text, source_name=src_name)
        print(f"[{src_name}] Parsed: {len(nodes)} nodes (source: {src_date})")
        save_source_raw(src_name, text)
        all_nodes.extend(nodes)
        source_stats[src_name] = {"date": src_date, "count": len(nodes)}
    if not all_nodes:
        print("[Error] No nodes from any source.")
        sys.exit(1)
    print(f"\n[Total] {len(all_nodes)} nodes before probe")
    print(f"[Probe] Testing {len(all_nodes)} nodes (TCP + HTTP)...")
    alive = filter_alive(all_nodes)
    print(f"[Probe] Alive: {len(alive)} / {len(all_nodes)}")
    if not alive:
        print("[Warning] All nodes dead. Keeping previous cache.")
        sys.exit(0)
    raw_content = to_raw(alive)
    b64_content = to_base64(alive)
    sb_config = to_singbox(alive)
    with open(os.path.join(OUTPUT_DIR, "raw.txt"), 'w', encoding='utf-8') as f:
        f.write(raw_content)
    with open(os.path.join(OUTPUT_DIR, "nodes.txt"), 'w', encoding='utf-8') as f:
        f.write(b64_content)
    with open(os.path.join(OUTPUT_DIR, "singbox.json"), 'w', encoding='utf-8') as f:
        json.dump(sb_config, f, ensure_ascii=False, indent=2)
    type_stats = {}
    src_alive_stats = {}
    for n in alive:
        t = n['type']
        type_stats[t] = type_stats.get(t, 0) + 1
        s = n.get('_source', 'unknown')
        src_alive_stats[s] = src_alive_stats.get(s, 0) + 1
    print(f"\n[Output] {OUTPUT_DIR}/")
    print(f"  - nodes.txt   (base64, {len(alive)} nodes)")
    print(f"  - raw.txt     (plain URI)")
    print(f"  - singbox.json (scv=true enforced)")
    print(f"[Source Stats] {source_stats}")
    print(f"[Alive Stats]  {src_alive_stats}")
    print(f"[Type Stats]   {type_stats}")
    print("Done.")

if __name__ == "__main__":
    main()
