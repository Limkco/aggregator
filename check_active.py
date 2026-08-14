#!/usr/bin/env python3
"""Active node checker: TCP + SSL latency test, GeoIP annotation, ranking."""

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

MAX_NODES = 600
MAX_LATENCY_MS = 1500.0
CONCURRENCY = 120
TCP_TIMEOUT = 3.5
SSL_TIMEOUT = 3.5

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
REMARK_CLEAN_RE = re.compile(r"(?:-[A-Za-z]{2,3}(?:\d+ms|UDP))+$")

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(message)s", datefmt="%H:%M:%S"
)
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


def get_country(host: str) -> str:
    if not geo_reader or not host:
        return "UNK"
    if host in _geo_cache:
        return _geo_cache[host]
    try:
        if host not in _dns_cache:
            infos = socket.getaddrinfo(host, None)
            _dns_cache[host] = infos[0][4][0] if infos else None
        ip = _dns_cache[host]
        if ip:
            res = geo_reader.get(ip)
            if res and "country" in res:
                code = res["country"]["iso_code"]
                _geo_cache[host] = code
                return code
    except Exception:
        pass
    _geo_cache[host] = "UNK"
    return "UNK"


def parse_node(link: str) -> Optional[Tuple[str, int, Optional[str], bool, bool]]:
    """返回 (host, port, sni, is_tls, is_udp) 或 None"""
    link = link.strip()
    host = port = sni = None
    is_tls = is_udp = False

    try:
        if link.startswith("vmess://"):
            b64 = link[8:].split("#")[0]
            conf_str = safe_b64decode(b64)
            if not conf_str:
                return None
            conf = json.loads(conf_str)
            if not UUID_RE.match(str(conf.get("id", ""))):
                return None
            host = conf.get("add")
            port = conf.get("port")
            if conf.get("tls") in ("tls", "xtls"):
                is_tls = True
                sni = conf.get("sni") or conf.get("host")

        elif link.startswith("ss://"):
            body = link[5:].split("#")[0]
            if "@" in body:
                part = body.split("@", 1)[1]
            else:
                decoded = safe_b64decode(body)
                part = decoded.split("@", 1)[1] if "@" in decoded else ""
            if part:
                part = part.split("/?")[0].split("?")[0]
                if part.startswith("["):
                    h, p = part.rsplit(":", 1)
                    host = h.strip("[]")
                    port = int(p)
                else:
                    h, p = part.rsplit(":", 1)
                    host, port = h, int(p)

        else:
            parsed = urlparse(link)
            scheme = parsed.scheme.lower()
            if scheme == "vless" and not UUID_RE.match(str(parsed.username or "")):
                return None
            host = parsed.hostname
            port = parsed.port
            qs = parse_qs(parsed.query)
            security = (qs.get("security") or [""])[0]

            if scheme == "trojan":
                is_tls = security != "none"
            elif scheme in ("hysteria2", "hy2"):
                is_tls = True
                is_udp = True
            elif scheme == "vless":
                is_tls = security in ("tls", "reality", "auto")

            if is_tls:
                sni = (qs.get("sni") or qs.get("peer") or [None])[0]

        if port:
            port = int(port)
        if not host or not port:
            return None
        return host, port, sni, is_tls, is_udp
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


async def check_one(link: str, sem: asyncio.Semaphore) -> Optional[Tuple[str, float]]:
    parsed = parse_node(link)
    if not parsed:
        return None
    host, port, sni, is_tls, is_udp = parsed

    async with sem:
        writer = None
        try:
            start = time.time()
            if is_udp:
                latency = 9999.0
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
                )
                tcp_ms = (time.time() - start) * 1000
                latency = tcp_ms

                if is_tls:
                    tls_sni = sni
                    if sni:
                        try:
                            ipaddress.ip_address(sni)
                            tls_sni = None
                        except ValueError:
                            pass

                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                    ssl_start = time.time()
                    await asyncio.wait_for(
                        writer.start_tls(ctx, server_hostname=tls_sni),
                        timeout=SSL_TIMEOUT,
                    )
                    latency = tcp_ms + (time.time() - ssl_start) * 1000

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            if not is_udp and latency > MAX_LATENCY_MS:
                return None

            cc = await asyncio.to_thread(get_country, host)
            latency_str = "UDP" if is_udp else f"{latency:.0f}ms"
            new_link = rebuild_link(link, cc, latency_str)
            return new_link, latency
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            return None
        except Exception:
            return None
        finally:
            if writer:
                try:
                    writer.close()
                except Exception:
                    pass


async def main() -> None:
    print("--- 节点快速检测 (TCP + SSL + 延迟筛选) ---")
    print(f"最大延迟上限={MAX_LATENCY_MS}ms  保留节点数={MAX_NODES}  并发数={CONCURRENCY}")

    if not os.path.exists(INPUT_FILE):
        print(f"错误: 未找到输入文件 {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        nodes = list({line.strip() for line in f if line.strip()})
    print(f"待检测唯一节点数: {len(nodes)}")

    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_one(n, sem) for n in nodes]

    print(f"开始检测 (TCP 超时 {TCP_TIMEOUT}s / SSL 超时 {SSL_TIMEOUT}s)...")
    start = time.time()
    valid = []
    done = 0
    total = len(tasks)

    for coro in asyncio.as_completed(tasks):
        res = await coro
        done += 1
        if res:
            valid.append(res)
        if done % 50 == 0 or done == total:
            elapsed = time.time() - start
            speed = done / elapsed if elapsed > 0 else 0
            sys.stdout.write(
                f"\r进度: {done}/{total} | 存活: {len(valid)} | 速度: {speed:.1f}个/s"
            )
            sys.stdout.flush()

    print()
    tcp_valid = [x for x in valid if x[1] < 9000.0]
    udp_valid = [x for x in valid if x[1] >= 9000.0]
    tcp_valid.sort(key=lambda x: x[1])

    if udp_valid:
        max_udp = min(50, len(udp_valid))
        max_tcp = MAX_NODES - max_udp
        final_valid = tcp_valid[:max_tcp] + udp_valid[:max_udp]
    else:
        final_valid = tcp_valid[:MAX_NODES]

    final = [x[0] for x in final_valid]

    try:
        plain_data = "\n".join(final)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(plain_data)
        b64_data = base64.b64encode(plain_data.encode("utf-8")).decode("utf-8")
        with open(SUB_FILE, "w", encoding="utf-8") as f:
            f.write(b64_data)
        print(f"检测完成，耗时 {time.time() - start:.1f} 秒")
        print(f"实际存活节点: {len(valid)} 个，保留 Top {len(final)}")
        if valid:
            best = tcp_valid[0][1] if tcp_valid else 9999.0
            if best < 9000:
                print(f"最优延迟: {best:.1f}ms")
            else:
                print("最优节点为 UDP 节点 (无 TCP 延迟记录)")
    except Exception as e:
        print(f"保存文件过程发生异常: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户手动停止测试")
