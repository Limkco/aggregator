#!/usr/bin/env python3
"""Deep protocol check after light TCP+SSL.
Strict 10-minute global limit. Save partial results on timeout.
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
import hashlib
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, List, Dict

assert sys.version_info >= (3, 11), "Requires Python 3.11+"

INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes.txt"
SUB_FILE = "sub.txt"
MAX_RUNTIME = 600          # 严格 10 分钟
CONCURRENCY = 40           # 深度测试并发不宜过高
TCP_TIMEOUT = 1.8
SSL_TIMEOUT = 2.5
SAVE_INTERVAL = 30         # 每 30 秒强制落盘一次

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
REMARK_CLEAN_RE = re.compile(r"(?:-[A-Za-z]{2,3}(?:\d+ms|UDP|OK))+$")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("DeepChecker")

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
    # 轻量占位，保持与上游一致（如需精确可复用 maxminddb）
    return _geo_cache.get(host, "UNK")


def parse_node(link: str) -> Optional[Tuple[str, int, Optional[str], str, bool]]:
    """返回 (host, port, sni, protocol, is_udp)"""
    link = link.strip()
    try:
        if link.startswith("vmess://"):
            b64 = link[8:].split("#")[0]
            conf = json.loads(safe_b64decode(b64) or "{}")
            if not UUID_RE.match(str(conf.get("id", ""))):
                return None
            host = conf.get("add")
            port = int(conf.get("port", 0))
            sni = conf.get("sni") or conf.get("host")
            return host, port, sni, "vmess", False

        if link.startswith("ss://"):
            body = link[5:].split("#")[0]
            if "@" in body:
                part = body.split("@", 1)[1]
            else:
                decoded = safe_b64decode(body)
                part = decoded.split("@", 1)[1] if "@" in decoded else ""
            if not part:
                return None
            part = part.split("/?")[0].split("?")[0]
            if part.startswith("["):
                h, p = part.rsplit(":", 1)
                host = h.strip("[]")
            else:
                h, p = part.rsplit(":", 1)
                host = h
            return host, int(p), None, "ss", False

        parsed = urlparse(link)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        qs = parse_qs(parsed.query)
        sni = (qs.get("sni") or qs.get("peer") or [None])[0]

        if scheme == "trojan":
            return host, port, sni, "trojan", False
        if scheme in ("hysteria2", "hy2"):
            return host, port, sni, "hysteria2", True
        if scheme == "vless":
            if not UUID_RE.match(str(parsed.username or "")):
                return None
            return host, port, sni, "vless", False
        return None
    except Exception:
        return None


def clean_remark(name: str) -> str:
    return REMARK_CLEAN_RE.sub("", str(name or ""))


def rebuild_link(link: str, cc: str, tag: str) -> str:
    if link.startswith("vmess://"):
        try:
            b64 = link[8:].split("#")[0]
            conf = json.loads(safe_b64decode(b64) or "{}")
            conf["ps"] = f"{clean_remark(conf.get('ps', ''))}-{cc}{tag}"
            return "vmess://" + base64.b64encode(
                json.dumps(conf, separators=(",", ":")).encode()
            ).decode()
        except Exception:
            pass
    parts = link.split("#", 1)
    original = unquote(parts[1]) if len(parts) > 1 else ""
    return parts[0] + "#" + quote(f"{clean_remark(original)}-{cc}{tag}")


async def trojan_probe(host: str, port: int, password: str, sni: Optional[str]) -> bool:
    """Trojan 真实协议探测：TLS 后发送认证包"""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sni = sni
        if sni:
            try:
                ipaddress.ip_address(sni)
                tls_sni = None
            except ValueError:
                pass
        await asyncio.wait_for(
            writer.start_tls(ctx, server_hostname=tls_sni), timeout=SSL_TIMEOUT
        )
        # Trojan 认证：hex(sha224(password)) + CRLF
        h = hashlib.sha224(password.encode()).hexdigest()
        writer.write((h + "\r\n").encode())
        await writer.drain()
        # 简单读一点数据判断是否存活（不强制要求特定响应）
        try:
            await asyncio.wait_for(reader.read(64), timeout=1.5)
        except asyncio.TimeoutError:
            pass
        return True
    except Exception:
        return False
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def strict_tcp_ssl(host: str, port: int, sni: Optional[str]) -> bool:
    """更严格的 TCP + SSL"""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sni = sni
        if sni:
            try:
                ipaddress.ip_address(sni)
                tls_sni = None
            except ValueError:
                pass
        await asyncio.wait_for(
            writer.start_tls(ctx, server_hostname=tls_sni), timeout=SSL_TIMEOUT
        )
        return True
    except Exception:
        return False
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def check_one(link: str, sem: asyncio.Semaphore, deadline: float) -> Optional[str]:
    if time.monotonic() > deadline:
        return None
    parsed = parse_node(link)
    if not parsed:
        return None
    host, port, sni, proto, is_udp = parsed

    async with sem:
        if time.monotonic() > deadline:
            return None
        try:
            ok = False
            if proto == "trojan":
                # 从链接提取密码
                try:
                    password = urlparse(link).username or ""
                except Exception:
                    password = ""
                if password:
                    ok = await trojan_probe(host, port, password, sni)
                else:
                    ok = await strict_tcp_ssl(host, port, sni)
            elif is_udp:
                # Hysteria2 等 UDP 协议，深度测试成本高，直接通过（已在轻量阶段筛选）
                ok = True
            else:
                ok = await strict_tcp_ssl(host, port, sni)

            if ok:
                cc = get_country(host)
                return rebuild_link(link, cc, "OK")
        except Exception:
            pass
    return None


def save_results(links: List[str]) -> None:
    try:
        content = "\n".join(links)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(content)
        b64 = base64.b64encode(content.encode()).decode()
        with open(SUB_FILE, "w", encoding="utf-8") as f:
            f.write(b64)
    except Exception as e:
        logger.error(f"Save failed: {e}")


async def main() -> None:
    print("--- Deep protocol check (max 10 minutes) ---")
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        nodes = list({ln.strip() for ln in f if ln.strip()})
    print(f"Candidates after light check: {len(nodes)}")

    deadline = time.monotonic() + MAX_RUNTIME
    sem = asyncio.Semaphore(CONCURRENCY)
    results: List[str] = []
    lock = asyncio.Lock()
    last_save = time.monotonic()

    async def worker(link: str):
        nonlocal last_save
        res = await check_one(link, sem, deadline)
        if res:
            async with lock:
                results.append(res)
                now = time.monotonic()
                if now - last_save >= SAVE_INTERVAL:
                    save_results(results)
                    last_save = now
                    logger.info(f"Progress saved: {len(results)} passed")

    tasks = [asyncio.create_task(worker(n)) for n in nodes]

    try:
        # 等待所有任务或超时
        await asyncio.wait(tasks, timeout=MAX_RUNTIME)
    except Exception:
        pass
    finally:
        # 取消未完成任务
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # 最终保存
    save_results(results)
    elapsed = time.monotonic() - (deadline - MAX_RUNTIME)
    print(f"\nFinished in {elapsed:.1f}s (limit {MAX_RUNTIME}s)")
    print(f"Passed deep check: {len(results)}")
    print(f"Results saved to {OUTPUT_FILE} / {SUB_FILE}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted, saving partial results...")
        # 主流程已处理保存
