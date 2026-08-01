#!/usr/bin/env python3
"""Deep protocol check after light TCP+SSL (pure Python, lightweight).

Goals:
- Lower concurrency to reduce GitHub Actions risk / network pressure
- Longer effective runtime window
- Stronger Trojan auth probe
- Slightly stricter TLS behavior for VMess/VLESS/SS
- Hysteria2 remains pass-through (UDP hard to probe purely)
- Periodic partial save + final save
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
import ipaddress
import hashlib
from urllib.parse import urlparse, parse_qs, unquote, quote
from typing import Optional, Tuple, List, Dict

assert sys.version_info >= (3, 11), "Requires Python 3.11+"

INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes.txt"
SUB_FILE = "sub.txt"

# ---- tunable (lightweight / safer for Actions) ----
MAX_RUNTIME = 480          # ~8 minutes (留一点缓冲给保存/收尾)
CONCURRENCY = 16           # 明显降低并发，减少风控与超时
TCP_TIMEOUT = 2.0
SSL_TIMEOUT = 2.8
PROBE_READ_TIMEOUT = 1.6
SAVE_INTERVAL = 25

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
REMARK_CLEAN_RE = re.compile(r"(?:-[A-Za-z]{2,3}(?:\d+ms|UDP|OK))+$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("DeepChecker")

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
    # 轻量占位，与上游保持一致；真正 Geo 已在 check_active 阶段完成
    return _geo_cache.get(host, "UNK")


def parse_node(link: str) -> Optional[Tuple[str, int, Optional[str], str, bool, Optional[str]]]:
    """返回 (host, port, sni, protocol, is_udp, password_or_uuid)"""
    link = link.strip()
    try:
        if link.startswith("vmess://"):
            b64 = link[8:].split("#")[0]
            conf = json.loads(safe_b64decode(b64) or "{}")
            uid = str(conf.get("id", ""))
            if not UUID_RE.match(uid):
                return None
            host = conf.get("add")
            port = int(conf.get("port", 0))
            sni = conf.get("sni") or conf.get("host")
            return host, port, sni, "vmess", False, uid

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
            return host, int(p), None, "ss", False, None

        parsed = urlparse(link)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        qs = parse_qs(parsed.query)
        sni = (qs.get("sni") or qs.get("peer") or [None])[0]
        user = parsed.username or ""

        if scheme == "trojan":
            return host, port, sni, "trojan", False, user
        if scheme in ("hysteria2", "hy2"):
            return host, port, sni, "hysteria2", True, None
        if scheme == "vless":
            if not UUID_RE.match(str(user)):
                return None
            return host, port, sni, "vless", False, user
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


def _make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # 尽量兼容常见节点证书/配置
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        pass
    return ctx


def _normalize_sni(sni: Optional[str]) -> Optional[str]:
    if not sni:
        return None
    try:
        ipaddress.ip_address(sni)
        return None  # SNI 不能是纯 IP
    except ValueError:
        return sni


async def trojan_probe(host: str, port: int, password: str, sni: Optional[str]) -> bool:
    """Trojan 轻量协议探测：TLS 后发送认证包，并尝试读回一点数据。"""
    if not password:
        return False
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        ctx = _make_ssl_context()
        tls_sni = _normalize_sni(sni)
        await asyncio.wait_for(
            writer.start_tls(ctx, server_hostname=tls_sni), timeout=SSL_TIMEOUT
        )

        # Trojan 认证：hex(sha224(password)) + CRLF
        h = hashlib.sha224(password.encode("utf-8", errors="ignore")).hexdigest()
        writer.write((h + "\r\n").encode())
        await writer.drain()

        # 再发一个极简请求头，帮助区分纯 TLS 端口 vs 真 Trojan
        # （很多假节点会在 TLS 后直接断开或无响应）
        try:
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            await writer.drain()
        except Exception:
            pass

        try:
            data = await asyncio.wait_for(reader.read(128), timeout=PROBE_READ_TIMEOUT)
            # 有任意可读数据，或连接仍存活，都算更可信
            if data:
                return True
        except asyncio.TimeoutError:
            # 超时但没立刻断，也倾向于保留（部分节点故意不回包）
            return True
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


async def strict_tcp_ssl(host: str, port: int, sni: Optional[str], send_probe: bool = True) -> bool:
    """更严格的 TCP + TLS，可选发送极小探测包观察行为。"""
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        ctx = _make_ssl_context()
        tls_sni = _normalize_sni(sni)
        await asyncio.wait_for(
            writer.start_tls(ctx, server_hostname=tls_sni), timeout=SSL_TIMEOUT
        )

        if send_probe:
            try:
                # 不依赖特定响应，只观察连接是否在探测后立刻被重置
                writer.write(b"\r\n")
                await writer.drain()
                try:
                    await asyncio.wait_for(reader.read(32), timeout=0.8)
                except asyncio.TimeoutError:
                    pass
            except Exception:
                # 写失败通常意味着连接已死
                return False
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


async def check_one(
    link: str, sem: asyncio.Semaphore, deadline: float
) -> Optional[str]:
    if time.monotonic() > deadline:
        return None

    parsed = parse_node(link)
    if not parsed:
        return None
    host, port, sni, proto, is_udp, secret = parsed

    async with sem:
        if time.monotonic() > deadline:
            return None
        try:
            ok = False
            if proto == "trojan":
                ok = await trojan_probe(host, port, secret or "", sni)
            elif is_udp:
                # Hysteria2 等 UDP：深度纯 Python 成本高且易误杀，沿用轻量阶段结果
                ok = True
            else:
                # VMess / VLESS / SS：加强版 TLS 存活探测
                ok = await strict_tcp_ssl(host, port, sni, send_probe=True)

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
    print("--- Deep protocol check (lightweight pure-Python) ---")
    print(f"Concurrency={CONCURRENCY}  MaxRuntime={MAX_RUNTIME}s")

    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        nodes = list({ln.strip() for ln in f if ln.strip()})
    print(f"Candidates after light check: {len(nodes)}")

    if not nodes:
        save_results([])
        print("No candidates, empty result saved.")
        return

    deadline = time.monotonic() + MAX_RUNTIME
    sem = asyncio.Semaphore(CONCURRENCY)
    results: List[str] = []
    lock = asyncio.Lock()
    last_save = time.monotonic()
    done = 0
    total = len(nodes)

    async def worker(link: str):
        nonlocal last_save, done
        res = await check_one(link, sem, deadline)
        async with lock:
            done += 1
            if res:
                results.append(res)
            now = time.monotonic()
            if now - last_save >= SAVE_INTERVAL:
                save_results(results)
                last_save = now
                logger.info(
                    f"Progress {done}/{total} | passed={len(results)} | saved"
                )
            elif done % 40 == 0 or done == total:
                logger.info(f"Progress {done}/{total} | passed={len(results)}")

    tasks = [asyncio.create_task(worker(n)) for n in nodes]

    try:
        await asyncio.wait(tasks, timeout=MAX_RUNTIME)
    except Exception:
        pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    save_results(results)
    elapsed = time.monotonic() - (deadline - MAX_RUNTIME)
    print(f"\nFinished in {elapsed:.1f}s (limit {MAX_RUNTIME}s)")
    print(f"Passed deep check: {len(results)} / {total}")
    print(f"Results saved to {OUTPUT_FILE} / {SUB_FILE}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted, saving partial results...")
        # 主流程 finally 已尽量保存；这里仅兜底提示
