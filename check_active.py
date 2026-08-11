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

assert sys.version_info >= (3, 11), "Requires Python 3.11+"

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
    """Return (host, port, sni, is_tls, is_udp) or None."""
    link = link.strip()
    host = port = sni = None
    is_tls = is_udp = False

    try:
        if link.startswith("vmess://"):
            b64 = link[8:].split("#")[0]
            conf = json.loads(safe_b64decode(b64) or "{}")
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
            conf = json.loads(safe_b64decode(b64) or "{}")
            conf["ps"] = f"{clean_remark(conf.get('ps', ''))}-{cc}{latency_str}"
            return "vmess://" + base64.b64encode(
                json.dumps(conf, separators=(",", ":")).encode()
            ).decode()
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

            cc = get_country(host)
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
    print("--- Fast node checker (TCP + SSL + latency cut) ---")
    print(f"MAX_LATENCY_MS={MAX_LATENCY_MS}  MAX_NODES={MAX_NODES}  CONCURRENCY={CONCURRENCY}")

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        nodes = list({line.strip() for line in f if line.strip()})
    print(f"Initial unique nodes: {len(nodes)}")

    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_one(n, sem) for n in nodes]

    print(f"Checking (TCP {TCP_TIMEOUT}s / SSL {SSL_TIMEOUT}s)...")
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
                f"\rProgress: {done}/{total} | Alive: {len(valid)} | {speed:.1f}/s"
            )
            sys.stdout.flush()

    print()
    valid.sort(key=lambda x: x[1])
    final = [x[0] for x in valid[:MAX_NODES]]

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(final))
        b64 = base64.b64encode("\n".join(final).encode()).decode()
        with open(SUB_FILE, "w", encoding="utf-8") as f:
            f.write(b64)
        print(f"Done in {time.time() - start:.1f}s")
        print(f"Alive (after latency cut): {len(valid)}, kept top {len(final)}")
        if valid:
            best = valid[0][1]
            if best < 9000:
                print(f"Best latency: {best:.1f}ms")
            else:
                print("Best nodes are UDP (no TCP latency)")
    except Exception as e:
        print(f"Save failed: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped by user")
