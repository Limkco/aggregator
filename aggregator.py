#!/usr/bin/env python3
"""
节点聚合器 (双引擎增强版):
1. 引擎一：直接从 GitHub 每日活跃更新的公共开源订阅源秒级抓取基础节点池（确保绝不为 0）。
2. 引擎二：通过 GitHub 搜索 API (sort=indexed) 嗅探挖掘最新的散装分享配置。
3. 具备完整的 Clash YAML / JSON / Base64 解析，并在入库前阻断内网和假数据。
"""

import os
import re
import base64
import json
import time
import random
import logging
import threading
import queue
import hashlib
import ipaddress
from urllib.parse import quote, urlparse, parse_qs, unquote
from typing import List, Set, Dict, Any, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import yaml
except ImportError:
    yaml = None

# ==================== 配置区 ====================
# 引擎一：高质量 GitHub 每日活跃开源订阅源（绝对兜底保障，杜绝 0 节点）
DIRECT_RAW_SOURCES = [
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/ssrsub/ssr/master/v2ray",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mianfeifq/share/main/data.txt",
]

# 引擎二：搜索关键词组
KEYWORDS_GROUPS: List[List[str]] = [
    ["vmess://", "vless://", "trojan://"],
    ["ss://", "hysteria2://", "hy2://"],
    ["proxies", "clash", "subscription"],
]
EXTENSIONS: List[str] = ["txt", "yaml"]
MAX_PAGES: int = 1
TIMEOUT: int = 10
DOWNLOAD_WORKERS: int = 16
RAW_OUTPUT_FILE: str = "nodes.txt"
OUTPUT_FILE: str = "sub.txt"

LINK_PATTERN = re.compile(
    r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s<>"\'`]+',
    re.IGNORECASE
)
UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

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
]

FAKE_DOMAINS = {
    "example.com", "yourdomain.com", "mydomain.com", "domain.com",
    "test.com", "sample.com", "localhost"
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)


def is_invalid_host(host: str) -> bool:
    if not host:
        return True
    host = host.strip().lower()
    if host in FAKE_DOMAINS or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in RESERVED_NETS)
    except ValueError:
        return False


class NodeAggregator:
    def __init__(self, token: Optional[str]):
        # Actions 自动提供的 ghs_ Token 不支持全局跨库搜索，避免负作用
        self.github_token = token if (token and not token.startswith("ghs_")) else None
        self.nodes: Set[str] = set()
        self.seen_hashes: Set[str] = set()
        self.content_hashes: Set[str] = set()
        self.nodes_lock = threading.Lock()
        self.session = self._init_session()
        self._setup_headers()
        self.url_queue: queue.Queue = queue.Queue()
        self.should_stop = False

    def _init_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504], allowed_methods=["GET"])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=DOWNLOAD_WORKERS, pool_maxsize=DOWNLOAD_WORKERS)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _setup_headers(self) -> None:
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (compatible; Aggregator/4.0)",
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("已装载用户 Personal Access Token")

    def safe_base64_decode(self, text: str) -> Optional[str]:
        if not text:
            return None
        text = text.strip().replace(" ", "").replace("\n", "").replace("\r", "")
        text = unquote(text).replace("-", "+").replace("_", "/")
        pad = len(text) % 4
        if pad:
            text += "=" * (4 - pad)
        try:
            return base64.b64decode(text).decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _get_node_hash(self, link: str) -> str:
        link = link.strip()
        if "://" not in link:
            return hashlib.md5(link.encode()).hexdigest()
        try:
            protocol, rest = link.split("://", 1)
            protocol = protocol.lower()
            core = rest.split("#")[0]
            if protocol == "vmess":
                decoded = self.safe_base64_decode(core)
                if decoded:
                    conf = json.loads(decoded)
                    conf.pop("ps", None)
                    core = json.dumps(conf, sort_keys=True)
            return hashlib.md5(f"{protocol}://{core}".encode()).hexdigest()
        except Exception:
            return hashlib.md5(link.encode()).hexdigest()

    def _clean_link(self, raw: str) -> str:
        m = raw.strip()
        while m and m[0] in ('"', "'", '<', '(', '['):
            m = m[1:]
        while m and m[-1] in ')]}>\"\',;':
            if '?' in m and m.rfind('?') > m.rfind('://'):
                if m[-1] in '\"\'':
                    m = m[:-1]
                    continue
                break
            m = m[:-1]
        return m

    def _validate_link(self, link: str) -> bool:
        if len(link) < 20 or "://" not in link:
            return False
        try:
            proto, rest = link.split("://", 1)
            proto = proto.lower()
            if proto == "vmess":
                conf_str = self.safe_base64_decode(rest.split("#")[0])
                if not conf_str:
                    return False
                c = json.loads(conf_str)
                host = str(c.get("add", "")).strip()
                port = int(c.get("port", 0))
                uid = str(c.get("id", "")).strip()
                if not (1 <= port <= 65535) or is_invalid_host(host):
                    return False
                if not UUID_PATTERN.match(uid) or uid.startswith("00000000"):
                    return False
            else:
                p = urlparse(link)
                if not p.hostname or not p.port or not (1 <= p.port <= 65535):
                    return False
                if is_invalid_host(p.hostname):
                    return False
            return True
        except Exception:
            return False

    def _build_vmess_link(self, config: Dict[str, Any]) -> Optional[str]:
        try:
            server = str(config.get("server", "")).strip()
            port = int(config.get("port", 0))
            uuid_val = str(config.get("uuid", "")).strip()
            if not (1 <= port <= 65535) or is_invalid_host(server):
                return None
            if not UUID_PATTERN.match(uuid_val) or uuid_val.startswith("00000000"):
                return None
            v = {
                "v": "2", "ps": str(config.get("name", "vmess")),
                "add": server, "port": str(port), "id": uuid_val,
                "aid": str(config.get("alterId", 0)), "scy": str(config.get("cipher", "auto")),
                "net": str(config.get("network", "tcp")), "type": str(config.get("type", "none")),
                "host": str(config.get("servername") or config.get("ws-opts", {}).get("headers", {}).get("Host", "")),
                "path": str(config.get("ws-path") or config.get("ws-opts", {}).get("path", "")),
                "tls": "tls" if config.get("tls") else "",
            }
            return "vmess://" + base64.b64encode(json.dumps(v).encode("utf-8")).decode("utf-8")
        except Exception:
            return None

    def _build_ss_link(self, config: Dict[str, Any]) -> Optional[str]:
        try:
            server = str(config.get("server", "")).strip()
            port = int(config.get("port", 0))
            password = str(config.get("password", "")).strip()
            method = str(config.get("cipher", "")).strip()
            if not (1 <= port <= 65535) or is_invalid_host(server) or not password or not method:
                return None
            user = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("utf-8").strip()
            return f"ss://{user}@{server}:{port}#{quote(str(config.get('name', 'ss')))}"
        except Exception:
            return None

    def _extract_from_structured(self, data: Any) -> List[str]:
        proxies = data.get("proxies", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
        res = []
        for item in proxies:
            if not isinstance(item, dict):
                continue
            proto = str(item.get("type", "")).lower()
            if proto == "vmess":
                if lnk := self._build_vmess_link(item): res.append(lnk)
            elif proto in ("ss", "shadowsocks"):
                if lnk := self._build_ss_link(item): res.append(lnk)
        return res

    def extract_nodes(self, text: str) -> List[str]:
        if not text:
            return []
        found: List[str] = []
        stripped = text.strip()

        # 尝试结构化解析 (Clash YAML / JSON)
        if stripped.startswith(('{', '[')):
            try:
                found.extend(self._extract_from_structured(json.loads(stripped)))
            except Exception:
                pass
        if not found and yaml and ("proxies:" in stripped):
            try:
                found.extend(self._extract_from_structured(yaml.safe_load(stripped)))
            except Exception:
                pass

        # 正则扫描明文
        clean_text = text.replace('&amp;', '&').replace('\\/', '/')
        for m in LINK_PATTERN.findall(clean_text):
            c = self._clean_link(m)
            if self._validate_link(c):
                found.append(c)

        # Base64 解码扫描
        decoded = self.safe_base64_decode(text)
        if decoded:
            for m in LINK_PATTERN.findall(decoded):
                c = self._clean_link(m)
                if self._validate_link(c):
                    found.append(c)

        return found

    def fetch_worker(self) -> None:
        while not self.should_stop:
            try:
                url = self.url_queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                resp = self.session.get(url, timeout=TIMEOUT)
                if resp.status_code == 200:
                    c_hash = hashlib.md5(resp.content).hexdigest()
                    with self.nodes_lock:
                        if c_hash in self.content_hashes:
                            continue
                        self.content_hashes.add(c_hash)

                    new_nodes = self.extract_nodes(resp.text)
                    with self.nodes_lock:
                        for n in new_nodes:
                            h = self._get_node_hash(n)
                            if h not in self.seen_hashes:
                                self.seen_hashes.add(h)
                                self.nodes.add(n)
            except Exception:
                pass
            finally:
                self.url_queue.task_done()

    def run(self) -> None:
        # 1. 启动工作线程池
        for _ in range(DOWNLOAD_WORKERS):
            threading.Thread(target=self.fetch_worker, daemon=True).start()

        # 2. 引擎一：首先装载直接订阅源（秒级抓取几千基础节点）
        logger.info(f"【引擎一】开始抓取 {len(DIRECT_RAW_SOURCES)} 个每日开源订阅源...")
        for direct_url in DIRECT_RAW_SOURCES:
            self.url_queue.put(direct_url)

        # 3. 引擎二：执行精准搜索（移除了错误的 pushed 参数）
        logger.info("【引擎二】执行 GitHub 全网最新代码文件检索...")
        for group in KEYWORDS_GROUPS:
            kw = " OR ".join(f'"{k}"' if "://" in k else k for k in group)
            for ext in EXTENSIONS:
                query = f"{kw} extension:{ext}"
                api = f"https://api.github.com/search/code?q={quote(query)}&per_page=30&page=1&sort=indexed&order=desc"
                try:
                    resp = self.session.get(api, timeout=12)
                    if resp.status_code == 200:
                        items = resp.json().get("items", [])
                        logger.info(f"[{query[:35]}...] -> 命中 {len(items)} 个文件")
                        for it in items:
                            html = it.get("html_url")
                            if html:
                                raw = html.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                                self.url_queue.put(raw)
                    elif resp.status_code in (403, 429):
                        logger.warning("搜索 API 触发速率限制，平滑跳过（已有引擎一兜底保证）")
                        break
                except Exception:
                    pass
                time.sleep(1.5)

        # 等待下载解析队列结算
        deadline = time.time() + 25
        while time.time() < deadline and self.url_queue.unfinished_tasks > 0:
            time.sleep(0.5)

        self.should_stop = True
        with self.nodes_lock:
            nodes_list = list(self.nodes)

        logger.info(f"=== 抓取汇总：成功获得规范节点 {len(nodes_list)} 个 ===")
        plain = "\n".join(nodes_list) if nodes_list else ""
        with open(RAW_OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(plain)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(plain.encode("utf-8")).decode("utf-8"))


if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    NodeAggregator(token).run()
