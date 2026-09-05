#!/usr/bin/env python3
"""Active node checker with Mainland China GFW filtering & deep protocol verification.

核心优化：
1. 严厉拦截国内被封锁的 SNI 域名（pages.dev, workers.dev 等握手即 RST 域名）。
2. 识别并拦截未优选的 Cloudflare CDN 假活 IP（海外畅通但大陆阻断）。
3. 弃用失效的第三方虚假测活接口，采用国内可用性权重过滤。
4. 真实 TCP + TLS + WebSocket/HTTP 握手，剔除无效与假活节点。
"""

import sys
import os
import re
import json
import base64
import asyncio
import ssl
import time
import logging
import socket
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, Dict, Any
import requests

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

MAX_EXECUTION_TIME = 350.0
MAX_LATENCY_MS = 1500.0
CONCURRENCY = 80
CONNECT_TIMEOUT = 3.0
PROBE_TIMEOUT = 2.5

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
REMARK_CLEAN_RE = re.compile(r"(?:-[A-Za-z]{2,3}(?:\d+ms|UDP))+$")

# 私有/保留 IP 网段
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

# Cloudflare 大陆高阻断默认 IP 段（非国内优化 IP，国内直连必超时的假活 IP）
CLOUDFLARE_BLOCKED_NETS = [
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
]

# GFW 封锁/污染重点 IP 黑名单
GFW_POLLUTED_IPS = {
    "127.0.0.1", "0.0.0.0", "1.1.1.1", "8.8.8.8",
    "37.61.54.158", "46.82.174.68", "59.24.3.173", "64.33.88.161",
    "64.66.163.251", "65.49.33.6", "69.63.184.130", "72.14.205.99",
    "78.16.49.15", "93.46.8.89", "128.121.126.139", "159.106.121.75",
    "169.232.46.12", "178.63.227.114", "202.106.1.2", "202.108.22.5",
    "203.98.7.65", "207.12.88.98", "208.56.31.43", "209.85.229.20",
    "209.132.183.181", "243.185.187.39"
}

# 国内发包即被 RST 的黑名单域名/后缀
BLOCKED_DOMAINS = (
    "pages.dev", "workers.dev", "github.io", "herokuapp.com",
    "vercel.app", "netlify.app", "onrender.com", "railway.app",
    "fly.dev", "glitch.me", "surfree.org", "cloudfront.net"
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("NodeChecker")

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


def is_gfw_blocked(ip_str: str) -> bool:
    if ip_str in GFW_POLLUTED_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        if any(ip in net for net in RESERVED_NETS):
            return True
        # 拦截 Cloudflare 未优化普通段（在国内全部断连）
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
            if node.protocol == "vless":
                uid = str(parsed.username or "")
                if not UUID_RE.match(uid) or uid.startswith("00000000"):
                    return None
            node.host = parsed.hostname or ""
            node.port = parsed.port or 0
            qs = parse_qs(parsed.query)
            security = (qs.get("security") or [""])[0]

            if node.protocol == "trojan":
                node.is_tls = security != "none"
            elif node.protocol in ("hysteria2", "hy2"):
                node.is_tls = True
                node.is_udp = True
            elif node.protocol == "vless":
                node.is_tls = security in ("tls", "reality", "auto")

            if (qs.get("type") or [""])[0].lower() == "ws":
                node.is_ws = True
                node.ws_path = (qs.get("path") or ["/"])[0]
                node.ws_host = (qs.get("host") or [None])[0]

            if node.is_tls:
                node.sni = (qs.get("sni") or qs.get("peer") or [node.host])[0]

        if not node.host or not (1 <= node.port <= 65535):
            return None

        # 核心过滤：若 SNI 或 Host 属于国内强阻断域名，直接剔除（防止在大陆发送 TLS ClientHello 即刻被 RST）
        domain_to_check = (node.sni or node.host or "").lower()
        if any(domain_to_check.endswith(blocked) for blocked in BLOCKED_DOMAINS):
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


def _query_doh_sync(host: str) -> Optional[str]:
    """通过阿里 DoH API 获取中国大陆视角的真实解析结果"""
    url = f"https://dns.alidns.com/resolve?name={host}&type=1"
    try:
        resp = requests.get(url, timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            # Status 0 代表正常解析，非 0 说明国内解析失败/被污染
            if data.get("Status") != 0:
                return None
            answers = data.get("Answer", [])
            for ans in answers:
                if ans.get("type") == 1:
                    ip = ans.get("data", "").strip()
                    if ip and not is_gfw_blocked(ip):
                        return ip
    except Exception:
        pass
    return None


async def resolve_host(host: str) -> Optional[str]:
    """通过阿里 DoH 模拟大陆视角的 DNS，过滤被墙 IP"""
    if is_ip(host):
        return None if is_gfw_blocked(host) else host
    if host in _dns_cache:
        return _dns_cache[host]

    loop = asyncio.get_running_loop()
    doh_ip = await loop.run_in_executor(None, _query_doh_sync, host)
    if doh_ip:
        _dns_cache[host] = doh_ip
        return doh_ip

    # 若阿里 DoH 解析失败，说明该域名在大陆已无法解析或被阻断
    _dns_cache[host] = None
    return None


async def probe_udp_hy2(resolved_ip: str, port: int) -> Optional[float]:
    start = time.time()
    loop = asyncio.get_running_loop()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        dummy_quic = b"\xc0\x00\x00\x00\x01\x08" + b"\x00" * 32
        await loop.sock_connect(sock, (resolved_ip, port))
        await loop.sock_sendall(sock, dummy_quic)
        await asyncio.sleep(0.3)
        await loop.sock_sendall(sock, b"\x00")
        sock.close()
        return (time.time() - start) * 1000
    except Exception:
        return None


async def check_one(link: str, sem: asyncio.Semaphore) -> Optional[Tuple[str, float]]:
    node = parse_node(link)
    if not node:
        return None

    async with sem:
        # 1. 解析 IP：强制使用阿里 DoH 解析，如果国内无法解析或解析出被墙 IP，直接过滤
        resolved_ip = await resolve_host(node.host)
        if not resolved_ip:
            return None

        # 2. UDP 协议 (Hysteria2)
        if node.is_udp:
            udp_latency = await probe_udp_hy2(resolved_ip, node.port)
            if udp_latency is None or udp_latency > MAX_LATENCY_MS:
                return None
            cc = await asyncio.to_thread(get_country, resolved_ip)
            return rebuild_link(link, cc, "-HY2"), udp_latency

        # 3. TCP 连通性测试
        writer = None
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved_ip, node.port),
                timeout=CONNECT_TIMEOUT,
            )
            tcp_ms = (time.time() - start) * 1000

            # 4. TLS 协商校验
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
                tcp_ms += (time.time() - ssl_start) * 1000

            # 5. WebSocket 协议握手探测（杜绝 CDN 假活）
            if node.is_ws:
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
                # 出现 CDN 报错或 403/502/521 等说明后端早就死亡
                if any(bad in status_line for bad in ("502", "503", "520", "521", "522", "523", "525", "530", "403", "404")):
                    return None

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            if tcp_ms > MAX_LATENCY_MS:
                return None

            cc = await asyncio.to_thread(get_country, resolved_ip)
            new_link = rebuild_link(link, cc, f"{tcp_ms:.0f}ms")
            return new_link, tcp_ms

        except Exception:
            return None
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass


async def main() -> None:
    print("--- 启动节点深度健康检测 (过滤GFW重点阻断段+阿里DoH大陆视角+深度握手) ---")
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 未找到输入文件 {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        nodes = list({line.strip() for line in f if len(line.strip()) > 15 and "://" in line})
    print(f"待检测唯一节点数: {len(nodes)}")

    sem = asyncio.Semaphore(CONCURRENCY)
    task_objs = [asyncio.create_task(check_one(n, sem)) for n in nodes]

    start = time.time()
    valid = []
    done = 0
    total = len(task_objs)

    for coro in asyncio.as_completed(task_objs):
        if time.time() - start > MAX_EXECUTION_TIME:
            print(f"\n达到运行上限 ({MAX_EXECUTION_TIME}s)，强行终止剩余任务")
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

        if done % 50 == 0 or done == total:
            elapsed = time.time() - start
            speed = done / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r进度: {done}/{total} | 真实有效: {len(valid)} | 速度: {speed:.1f}/s")
            sys.stdout.flush()

    print()
    valid.sort(key=lambda x: x[1])
    final_nodes = [x[0] for x in valid]

    plain_data = "\n".join(final_nodes)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(plain_data)
    with open(SUB_FILE, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain_data.encode("utf-8")).decode("utf-8"))

    print(f"检测完成！耗时: {time.time() - start:.1f}s | 纯净存活节点: {len(final_nodes)} 个")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户手动终止")
