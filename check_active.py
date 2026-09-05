#!/usr/bin/env python3
"""Active node checker: Safe & Gentle (Anti-GitHub-Abuse) + Real Protocol Verification.

安全与防风控设计：
1. 本地离线预清洗：零网络开销剔除已知 GFW 黑洞段、失效域名与垃圾配置，大幅减少网络发包。
2. 平缓流量控制：并发限制为安全范围 (15)，杜绝突发性外网端口扫描被 GitHub/Azure 监控标记。
3. 零第三方个人 API 依赖：完全杜绝因调用外部接口导致的 IP 封禁或 Abuse 投诉。
4. 真实协议鉴权握手：发送合规的 VLESS / Trojan / WS 协议包，彻底终结客户端测速 -1。
"""

import sys
import os
import re
import json
import base64
import asyncio
import ssl
import time
import socket
import struct
import hashlib
import uuid
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, Dict, Any

assert sys.version_info >= (3, 11), "需要 Python 3.11 及以上版本"

try:
    import maxminddb
    GEO_DB = "geoip.mmdb"
    geo_reader = maxminddb.open_database(GEO_DB) if os.path.exists(GEO_DB) else None
except ImportError:
    geo_reader = None

INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes.txt"
SUB_FILE = "sub.txt"

# 安全风控参数：低并发、平缓发包
MAX_EXECUTION_TIME = 330.0
MAX_LATENCY_MS = 1400.0
CONCURRENCY = 15          # 严格限制并发，避免被识别为端口扫描 (Port Scanning)
CONNECT_TIMEOUT = 3.0
PROBE_TIMEOUT = 2.5

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
REMARK_CLEAN_RE = re.compile(r"(?:-[A-Za-z]{2,3}(?:\d+ms|UDP))+$")

# 私有/保留网段
RESERVED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
]

# Cloudflare 大陆高阻断网段（国内直连 100% 丢包/超时的假活 Anycast IP）
CLOUDFLARE_BLOCKED_NETS = [
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
]

# GFW 封锁/污染重点 IP
GFW_POLLUTED_IPS = {
    "127.0.0.1", "0.0.0.0", "1.1.1.1", "8.8.8.8",
    "37.61.54.158", "46.82.174.68", "59.24.3.173", "64.33.88.161",
    "64.66.163.251", "65.49.33.6", "69.63.184.130", "72.14.205.99",
    "78.16.49.15", "93.46.8.89", "128.121.126.139", "159.106.121.75",
    "169.232.46.12", "178.63.227.114", "202.106.1.2", "202.108.22.5",
    "203.98.7.65", "207.12.88.98", "208.56.31.43", "209.85.229.20",
    "209.132.183.181", "243.185.187.39"
}

# 大陆握手即被 GFW 发送 RST 的高危免费域名（客户端连必死）
BLOCKED_DOMAINS = (
    "pages.dev", "workers.dev", "github.io", "herokuapp.com",
    "vercel.app", "netlify.app", "onrender.com", "railway.app",
    "fly.dev", "glitch.me", "surfree.org", "cloudfront.net"
)

_dns_cache: Dict[str, Optional[str]] = {}
_geo_cache: Dict[str, str] = {}


def safe_b64decode(text: str) -> str:
    if not text:
        return ""
    text = text.strip().replace("-", "+").replace("_", "/")
    pad = len(text) % 4
    if pad:
        text += "=" * (4 - pad)
    try:
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_gfw_blocked_ip(ip_str: str) -> bool:
    if ip_str in GFW_POLLUTED_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        if any(ip in net for net in RESERVED_NETS):
            return True
        if any(ip in net for net in CLOUDFLARE_BLOCKED_NETS):
            return True
        return False
    except ValueError:
        return False


def get_country(ip: str) -> str:
    if not geo_reader or not ip:
        return "UNK"
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        res = geo_reader.get(ip)
        if res and "country" in res:
            code = res["country"]["iso_code"]
            _geo_cache[ip] = code
            return code
    except Exception:
        pass
    _geo_cache[ip] = "UNK"
    return "UNK"


class NodeInfo:
    def __init__(self):
        self.protocol: str = ""
        self.host: str = ""
        self.port: int = 0
        self.uuid: str = ""
        self.password: str = ""
        self.sni: Optional[str] = None
        self.is_tls: bool = False
        self.is_ws: bool = False
        self.ws_path: str = "/"
        self.ws_host: Optional[str] = None
        self.is_udp: bool = False


def parse_node(link: str) -> Optional[NodeInfo]:
    link = link.strip()
    node = NodeInfo()
    try:
        if link.startswith("vmess://"):
            node.protocol = "vmess"
            b64 = link[8:].split("#")[0]
            conf_str = safe_b64decode(b64)
            if not conf_str:
                return None
            conf = json.loads(conf_str)
            uid = str(conf.get("id", ""))
            if not UUID_RE.match(uid) or uid.startswith("00000000"):
                return None
            node.uuid = uid
            node.host = str(conf.get("add", "")).strip()
            node.port = int(conf.get("port", 0))
            node.is_tls = conf.get("tls") in ("tls", "xtls")
            node.sni = conf.get("sni") or conf.get("host") or node.host

            net = str(conf.get("net", "")).lower()
            if net == "ws":
                node.is_ws = True
                node.ws_path = conf.get("path") or "/"
                node.ws_host = conf.get("host") or node.sni

        elif link.startswith("ss://"):
            node.protocol = "ss"
            body = link[5:].split("#")[0]
            part = body.split("@", 1)[1] if "@" in body else safe_b64decode(body).split("@", 1)[1]
            part = part.split("/?")[0].split("?")[0]
            h, p = (part.rsplit(":", 1) if not part.startswith("[") else part.rsplit("]:", 1))
            node.host = h.strip("[]")
            node.port = int(p)

        else:
            parsed = urlparse(link)
            node.protocol = parsed.scheme.lower()
            node.host = parsed.hostname or ""
            node.port = parsed.port or 0
            qs = parse_qs(parsed.query)
            security = (qs.get("security") or [""])[0]

            if node.protocol == "vless":
                node.uuid = str(parsed.username or "")
                if not UUID_RE.match(node.uuid) or node.uuid.startswith("00000000"):
                    return None
                node.is_tls = security in ("tls", "reality", "auto")
            elif node.protocol == "trojan":
                node.password = str(parsed.username or "")
                if not node.password:
                    return None
                node.is_tls = security != "none"
            elif node.protocol in ("hysteria2", "hy2"):
                node.is_tls = True
                node.is_udp = True

            if (qs.get("type") or [""])[0].lower() == "ws":
                node.is_ws = True
                node.ws_path = (qs.get("path") or ["/"])[0]
                node.ws_host = (qs.get("host") or [None])[0]

            if node.is_tls:
                node.sni = (qs.get("sni") or qs.get("peer") or [node.host])[0]

        if not node.host or not (1 <= node.port <= 65535):
            return None

        # 零网络开销过滤：被 GFW 封锁的域名直接剔除
        check_domain = (node.sni or node.host or "").lower()
        if any(check_domain.endswith(bad) for bad in BLOCKED_DOMAINS):
            return None

        # 零网络开销过滤：直接填了 Cloudflare 被墙 IP 的节点直接剔除
        if is_ip(node.host) and is_gfw_blocked_ip(node.host):
            return None

        return node
    except Exception:
        return None


def clean_remark(name: str) -> str:
    return REMARK_CLEAN_RE.sub("", str(name or ""))


def rebuild_link(link: str, cc: str, latency_str: str) -> str:
    if link.startswith("vmess://"):
        try:
            b64 = link[8:].split("#")[0]
            conf_str = safe_b64decode(b64)
            if conf_str:
                conf = json.loads(conf_str)
                conf["ps"] = f"{clean_remark(conf.get('ps', ''))}-{cc}{latency_str}"
                json_bytes = json.dumps(conf, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                return "vmess://" + base64.b64encode(json_bytes).decode("utf-8")
        except Exception:
            pass
    parts = link.split("#", 1)
    original = unquote(parts[1]) if len(parts) > 1 else ""
    new_remark = f"{clean_remark(original)}-{cc}{latency_str}"
    return parts[0] + "#" + quote(new_remark)


async def resolve_host_safe(host: str) -> Optional[str]:
    """使用系统本地安全解析 + GFW 特征阻断库过滤"""
    if is_ip(host):
        return None if is_gfw_blocked_ip(host) else host
    if host in _dns_cache:
        return _dns_cache[host]

    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if not addr_info:
            _dns_cache[host] = None
            return None
        ip = addr_info[0][4][0]
        if is_gfw_blocked_ip(ip):
            _dns_cache[host] = None
            return None
        _dns_cache[host] = ip
        return ip
    except Exception:
        _dns_cache[host] = None
        return None


def build_vless_probe(uid_str: str) -> bytes:
    """标准 VLESS 握手认证头"""
    u = uuid.UUID(uid_str)
    # Version(0) + UUID(16B) + AddonsLen(0) + Cmd(1=TCP) + Port(2B) + AddrType(2=Domain) + Len(10) + google.com
    return b"\x00" + u.bytes + b"\x00\x01\x00\x50\x02\x0agoogle.com"


def build_trojan_probe(password: str) -> bytes:
    """标准 Trojan 握手认证头"""
    hex_hash = hashlib.sha224(password.encode("utf-8")).hexdigest().encode("latin1")
    return hex_hash + b"\r\n\x01\x03\x0agoogle.com\x00\x50\r\n"


async def check_one(link: str, sem: asyncio.Semaphore) -> Optional[Tuple[str, float]]:
    node = parse_node(link)
    if not node:
        return None

    async with sem:
        # 增加微小抖动，避免瞬时突发流量触发云防火墙风控
        await asyncio.sleep(0.05)

        # 1. 解析 IP 与已知封锁段过滤
        resolved_ip = await resolve_host_safe(node.host)
        if not resolved_ip:
            return None

        # 2. 建立基础 TCP 连接
        writer = None
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved_ip, node.port),
                timeout=CONNECT_TIMEOUT,
            )
            elapsed_ms = (time.time() - start) * 1000

            # 3. TLS 协商
            if node.is_tls:
                tls_sni = node.sni or node.host
                if is_ip(tls_sni):
                    tls_sni = None

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                ssl_start = time.time()
                await asyncio.wait_for(
                    writer.start_tls(ctx, server_hostname=tls_sni),
                    timeout=PROBE_TIMEOUT,
                )
                elapsed_ms += (time.time() - ssl_start) * 1000

            # 4. 关键：代理协议握手鉴权（消灭客户端 -1）
            if node.protocol == "vless":
                # 发送真实 VLESS 认证
                writer.write(build_vless_probe(node.uuid))
                await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT)
                # 监听响应：若 UUID 错误或非 VLESS 代理，服务端会断开连接或无合法响应
                resp = await asyncio.wait_for(reader.read(16), timeout=PROBE_TIMEOUT)
                if not resp or resp[0] != 0x00:
                    return None

            elif node.protocol == "trojan":
                # 发送真实 Trojan 认证
                writer.write(build_trojan_probe(node.password))
                await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT)
                await asyncio.sleep(0.08)
                if reader.at_eof():
                    return None

            elif node.is_ws:
                # 真实 WebSocket 升级握手探测
                ws_host = node.ws_host or node.sni or node.host
                ws_req = (
                    f"GET {node.ws_path} HTTP/1.1\r\n"
                    f"Host: {ws_host}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                writer.write(ws_req.encode("utf-8"))
                await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT)

                resp_header = await asyncio.wait_for(reader.read(256), timeout=PROBE_TIMEOUT)
                if not resp_header:
                    return None

                status_line = resp_header.decode("utf-8", errors="ignore").split("\r\n")[0]
                # 必须明确返回 HTTP 101 Switching Protocols
                if "101" not in status_line:
                    return None

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if elapsed_ms > MAX_LATENCY_MS:
                return None

            cc = await asyncio.to_thread(get_country, resolved_ip)
            new_link = rebuild_link(link, cc, f"{elapsed_ms:.0f}ms")
            return new_link, elapsed_ms

        except Exception:
            return None
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass


async def main() -> None:
    print("--- 启动安全合规深度测活 (真实协议认证 + GFW假活段清洗 + 防风控平缓发包) ---")
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 未找到输入文件 {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        raw_lines = [line.strip() for line in f if len(line.strip()) > 15 and "://" in line]

    # 预筛去重
    nodes = list(dict.fromkeys(raw_lines))
    print(f"原始候选节点数: {len(nodes)}")

    # 第一阶段：纯本地离线规则预过滤（零发包，直接剔除已知死域与无效格式）
    pre_filtered = [link for link in nodes if parse_node(link) is not None]
    print(f"离线规则清洗后进入深度测活节点数: {len(pre_filtered)} (安全减少了约 {len(nodes) - len(pre_filtered)} 次外部连接)")

    # 第二阶段：平缓可控发包探测
    sem = asyncio.Semaphore(CONCURRENCY)
    task_objs = [asyncio.create_task(check_one(n, sem)) for n in pre_filtered]

    start = time.time()
    valid = []
    done = 0
    total = len(task_objs)

    for coro in asyncio.as_completed(task_objs):
        if time.time() - start > MAX_EXECUTION_TIME:
            print(f"\n达到安全运行上限 ({MAX_EXECUTION_TIME}s)，温和停止剩余任务")
            for t in task_objs:
                if not t.done():
                    t.cancel()
            break

        try:
            res = await coro
            done += 1
            if res:
                valid.append(res)
        except asyncio.CancelledError:
            pass

        if done % 10 == 0 or done == total:
            elapsed = time.time() - start
            speed = done / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r进度: {done}/{total} | 真实可用: {len(valid)} | 速率: {speed:.1f}/s")
            sys.stdout.flush()

    print()
    valid.sort(key=lambda x: x[1])
    final_nodes = [x[0] for x in valid]

    plain_data = "\n".join(final_nodes)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(plain_data)
    with open(SUB_FILE, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain_data.encode("utf-8")).decode("utf-8"))

    print(f"检测完成！安全耗时: {time.time() - start:.1f}s | 纯净存活节点: {len(final_nodes)} 个")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户手动终止")
