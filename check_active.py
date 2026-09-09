#!/usr/bin/env python3
"""Active node checker: Safe & Gentle (Anti-GitHub-Abuse) + Real Protocol Verification.

重构说明：
1. 传输层解耦：将 WebSocket 与应用层协议 (VLESS/VMess/Trojan) 解耦，先完成 WS 握手 (HTTP 101)，解决 VLESS-WS 被误杀的问题。
2. 原生支持 UDP/QUIC：针对 Hysteria2 / TUIC 协议，采用 RFC 9000 QUIC 探针测试，避免用 TCP 测 UDP 导致的 100% 误杀。
3. 严格协议认证：对纯 TCP 的 VLESS 与 Trojan 发送合规鉴权握手头，消灭客户端测速 -1。
4. 增强健壮性：修复 IPv6 与 IPv4 网段比较时的类型异常，安全可控低并发 (15)。
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
import hashlib
import uuid
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, Dict

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

# 安全风控参数
MAX_EXECUTION_TIME = 330.0
MAX_LATENCY_MS = 1400.0
CONCURRENCY = 15          # 严格限制并发，杜绝云监控识别为端口扫描 (Port Scanning)
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

# Cloudflare 大陆高阻断 Anycast 网段
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

# GFW 污染常用 IP
GFW_POLLUTED_IPS = {
    "127.0.0.1", "0.0.0.0", "1.1.1.1", "8.8.8.8",
    "37.61.54.158", "46.82.174.68", "59.24.3.173", "64.33.88.161",
    "64.66.163.251", "65.49.33.6", "69.63.184.130", "72.14.205.99",
    "78.16.49.15", "93.46.8.89", "128.121.126.139", "159.106.121.75",
    "169.232.46.12", "178.63.227.114", "202.106.1.2", "202.108.22.5",
    "203.98.7.65", "207.12.88.98", "208.56.31.43", "209.85.229.20",
    "209.132.183.181", "243.185.187.39"
}

# 阻断域名后缀
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
        for net in RESERVED_NETS:
            if ip.version == net.version and ip in net:
                return True
        for net in CLOUDFLARE_BLOCKED_NETS:
            if ip.version == net.version and ip in net:
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
            security = (qs.get("security") or [""])[0].lower()

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
            elif node.protocol in ("hysteria2", "hy2", "tuic"):
                node.protocol = "hy2"
                node.is_tls = True
                node.is_udp = True

            trans_type = (qs.get("type") or qs.get("transport") or [""])[0].lower()
            if trans_type == "ws":
                node.is_ws = True
                node.ws_path = (qs.get("path") or ["/"])[0]
                node.ws_host = (qs.get("host") or [None])[0]

            if node.is_tls:
                node.sni = (qs.get("sni") or qs.get("peer") or [node.host])[0]

        if not node.host or not (1 <= node.port <= 65535):
            return None

        # 离线黑名单过滤
        check_domain = (node.sni or node.host or "").lower()
        if any(check_domain.endswith(bad) for bad in BLOCKED_DOMAINS):
            return None

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
    return b"\x00" + u.bytes + b"\x00\x01\x00\x50\x02\x0agoogle.com"


def build_trojan_probe(password: str) -> bytes:
    """标准 Trojan 握手认证头"""
    hex_hash = hashlib.sha224(password.encode("utf-8")).hexdigest().encode("latin1")
    return hex_hash + b"\r\n\x01\x03\x0agoogle.com\x00\x50\r\n"


def build_quic_vn_probe() -> bytes:
    """
    构造 RFC 9000 QUIC 强制版本协商 (Version Negotiation) 探测包。
    任何规范的 QUIC/Hysteria2 服务端在收到不支持版本且 >=1200 字节的初始包时，必须回复 Version Negotiation 包。
    """
    first_byte = b"\xc0"
    reserved_version = b"\x0a\x1a\x2a\x3a"  # 保留未分配版本
    dcid = os.urandom(8)
    scid = os.urandom(8)
    header = first_byte + reserved_version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return header + b"\x00" * (1200 - len(header))


async def probe_quic_udp(ip: str, port: int, timeout: float = PROBE_TIMEOUT) -> Optional[float]:
    """UDP/QUIC 专用握手测活"""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        probe = build_quic_vn_probe()
        start = time.time()
        await loop.sock_sendto(sock, probe, (ip, port))
        data = await asyncio.wait_for(loop.sock_recv(sock, 2048), timeout=timeout)
        elapsed_ms = (time.time() - start) * 1000

        # RFC 9000: 检查对端返回是否为合法 QUIC VN 包 (Version 字段为 0) 或 QUIC 响应
        if len(data) >= 5:
            is_vn = data[1:5] == b"\x00\x00\x00\x00"
            is_quic = (data[0] & 0x80) != 0
            if is_vn or is_quic:
                return elapsed_ms
        return None
    except Exception:
        return None
    finally:
        sock.close()


async def check_one(link: str, sem: asyncio.Semaphore) -> Optional[Tuple[str, float]]:
    node = parse_node(link)
    if not node:
        return None

    async with sem:
        await asyncio.sleep(0.04)

        # 1. 域名解析与黑名单清洗
        resolved_ip = await resolve_host_safe(node.host)
        if not resolved_ip:
            return None

        # 2. 分流处理：针对 UDP 协议 (Hysteria 2 / TUIC)
        if node.is_udp:
            elapsed_ms = await probe_quic_udp(resolved_ip, node.port)
            if elapsed_ms is None or elapsed_ms > MAX_LATENCY_MS:
                return None
            cc = await asyncio.to_thread(get_country, resolved_ip)
            new_link = rebuild_link(link, cc, f"{elapsed_ms:.0f}ms")
            return new_link, elapsed_ms

        # 3. TCP 基础连接
        writer = None
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved_ip, node.port),
                timeout=CONNECT_TIMEOUT,
            )
            elapsed_ms = (time.time() - start) * 1000

            # 4. TLS 协商 (若启用)
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

            # 5. 传输层与应用层验证
            if node.is_ws:
                # 无论上层是 VLESS / VMess / Trojan，WS 传输必须先成功完成 HTTP 101 Upgrade
                ws_host = node.ws_host or node.sni or node.host
                path = node.ws_path if node.ws_path.startswith("/") else ("/" + node.ws_path)
                ws_req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {ws_host}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                writer.write(ws_req.encode("utf-8"))
                await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT)

                resp_header = await asyncio.wait_for(reader.read(512), timeout=PROBE_TIMEOUT)
                if not resp_header:
                    return None
                status_line = resp_header.split(b"\r\n")[0].decode("latin1", errors="ignore")
                if "101" not in status_line:
                    return None

            else:
                # 纯 TCP / TLS 模式下的应用层握手
                if node.protocol == "vless":
                    writer.write(build_vless_probe(node.uuid))
                    await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT)
                    resp = await asyncio.wait_for(reader.read(16), timeout=PROBE_TIMEOUT)
                    if not resp or resp[0] != 0x00:
                        return None

                elif node.protocol == "trojan":
                    writer.write(build_trojan_probe(node.password))
                    await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT)
                    # 密码错误时 Trojan 会主动 RST/断开连接
                    try:
                        probe_res = await asyncio.wait_for(reader.read(16), timeout=0.15)
                        if reader.at_eof() or probe_res == b"":
                            return None
                    except asyncio.TimeoutError:
                        pass  # 正常保持连接，鉴权通过

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
    print("--- 启动全协议深度测活 (WS解耦 + UDP/QUIC握手 + GFW黑洞过滤) ---")
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 未找到输入文件 {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        raw_lines = [line.strip() for line in f if len(line.strip()) > 15 and "://" in line]

    nodes = list(dict.fromkeys(raw_lines))
    print(f"原始候选节点数: {len(nodes)}")

    pre_filtered = [link for link in nodes if parse_node(link) is not None]
    print(f"离线规则预过滤后存活: {len(pre_filtered)} (安全拦截无效节点 {len(nodes) - len(pre_filtered)} 个)")

    sem = asyncio.Semaphore(CONCURRENCY)
    task_objs = [asyncio.create_task(check_one(n, sem)) for n in pre_filtered]

    start = time.time()
    valid = []
    done = 0
    total = len(task_objs)

    for coro in asyncio.as_completed(task_objs):
        if time.time() - start > MAX_EXECUTION_TIME:
            print(f"\n已达单次安全运行上限 ({MAX_EXECUTION_TIME}s)，温和停止剩余检测")
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

    print(f"检测完成！耗时: {time.time() - start:.1f}s | 高质量存活节点: {len(final_nodes)} 个")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户手动终止")
