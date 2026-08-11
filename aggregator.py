#!/usr/bin/env python3
"""Node aggregator: search GitHub for proxy configs, extract & deduplicate nodes."""

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
from urllib.parse import quote, urlparse, parse_qs
from typing import List, Set, Dict, Any, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import yaml
except ImportError:
    yaml = None

# ---------- Config ----------
KEYWORDS_GROUPS: List[List[str]] = [
    ["vmess://", "vless://", "trojan://"],
    ["ss://", "shadowsocks", "hysteria2", "hy://"],
    ["proxies", "clash", "subscription", "sub"],
    ["v2ray", "config", "节点", "机场", "翻墙"],
]
EXTENSIONS: List[str] = ["yaml", "yml", "txt"]
MAX_PAGES: int = 2
SEARCH_INTERVAL: float = 2.8
MAX_EXECUTION_TIME: int = 1500
TIMEOUT: int = 8
DOWNLOAD_WORKERS: int = 12
TARGET_NODES: int = 8000
OUTPUT_FILE: str = "sub.txt"
RAW_OUTPUT_FILE: str = "nodes.txt"

LINK_PATTERN = re.compile(
    r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s<>"\'`]+',
    re.IGNORECASE
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


class NodeAggregator:
    def __init__(self, token: Optional[str]):
        self.github_token = token
        self.nodes: Set[str] = set()
        self.seen_hashes: Set[str] = set()
        self.content_hashes: Set[str] = set()
        self.nodes_lock = threading.Lock()
        self.session = self._init_session()
        self._setup_headers()
        self.start_time = time.time()
        self.should_stop = False
        self.url_queue: queue.Queue = queue.Queue()
        self.sleep_interval = SEARCH_INTERVAL if token else 12.0
        if not token:
            logger.warning("No GH_TOKEN, using slow mode (12s/req)")
        if not yaml:
            logger.warning("PyYAML missing, YAML parsing disabled")

    def _init_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.6, status_forcelist=[500, 502, 503, 504],
                      allowed_methods=["GET"])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=DOWNLOAD_WORKERS,
                              pool_maxsize=DOWNLOAD_WORKERS)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _setup_headers(self) -> None:
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (compatible; NodeAggregator/2.2)",
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("GitHub Token loaded")

    def check_timeout(self) -> bool:
        return time.time() - self.start_time > MAX_EXECUTION_TIME

    def safe_base64_decode(self, text: str) -> Optional[str]:
        if not text:
            return None
        text = text.strip().replace(" ", "").replace("\n", "").replace("\r", "")
        text = text.replace("-", "+").replace("_", "/")
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
            sni = None

            if protocol == "vmess":
                decoded = self.safe_base64_decode(core)
                if decoded:
                    conf = json.loads(decoded)
                    sni = conf.get("sni") or conf.get("host") or conf.get("add")
                    conf.pop("ps", None)
                    core = json.dumps(conf, sort_keys=True)
            else:
                parsed = urlparse(link)
                qs = parse_qs(parsed.query)
                sni = (qs.get("sni") or qs.get("peer") or [None])[0]
                if not sni:
                    sni = parsed.hostname
                if not sni and "@" in rest:
                    body = rest.split("#")[0]
                    part = body.split("@")[-1].split("/?")[0].split("?")[0]
                    if part.startswith("["):
                        sni = part.rsplit(":", 1)[0].strip("[]")
                    else:
                        sni = part.rsplit(":", 1)[0]

            feature_str = f"{protocol}://{core}"
            if sni:
                feature_str += f"?sni={sni}"
            return hashlib.md5(feature_str.encode()).hexdigest()
        except Exception:
            return hashlib.md5(link.encode()).hexdigest()

    def _build_vmess_link(self, config: Dict[str, Any]) -> Optional[str]:
        try:
            v = {
                "v": "2",
                "ps": str(config.get("name", "unnamed")),
                "add": str(config.get("server")),
                "port": str(config.get("port")),
                "id": str(config.get("uuid")),
                "aid": str(config.get("alterId", 0)),
                "scy": str(config.get("cipher", "auto")),
                "net": str(config.get("network", "tcp")),
                "type": str(config.get("type", "none")),
                "host": str(config.get("servername") or config.get("ws-opts", {}).get("headers", {}).get("Host", "")),
                "path": str(config.get("ws-path") or config.get("ws-opts", {}).get("path", "")),
                "tls": "tls" if config.get("tls") else "",
            }
            if not v["add"] or not v["id"]:
                return None
            return "vmess://" + base64.b64encode(
                json.dumps(v, separators=(",", ":")).encode()
            ).decode()
        except Exception:
            return None

    def _build_ss_link(self, config: Dict[str, Any]) -> Optional[str]:
        try:
            server, port, password, method = (
                config.get("server"), config.get("port"),
                config.get("password"), config.get("cipher")
            )
            if not all([server, port, password, method]):
                return None
            user = base64.b64encode(f"{method}:{password}".encode()).decode().strip()
            return f"ss://{user}@{server}:{port}#{quote(str(config.get('name', 'ss')))}"
        except Exception:
            return None

    def _build_trojan_link(self, config: Dict[str, Any]) -> Optional[str]:
        try:
            server, port, password = config.get("server"), config.get("port"), config.get("password")
            if not all([server, port, password]):
                return None
            sni = config.get("sni") or config.get("servername")
            q = f"?peer={sni}" if sni else ""
            return f"trojan://{password}@{server}:{port}{q}#{quote(str(config.get('name', 'trojan')))}"
        except Exception:
            return None

    def _parse_structured_node(self, item: Dict[str, Any]) -> Optional[str]:
        if not isinstance(item, dict):
            return None
        proto = str(item.get("type", "")).lower()
        if proto == "vmess":
            return self._build_vmess_link(item)
        if proto in ("ss", "shadowsocks"):
            return self._build_ss_link(item)
        if proto == "trojan":
            return self._build_trojan_link(item)
        return None

    def _extract_from_structured(self, data: Union[Dict, List]) -> List[str]:
        proxies = []
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            proxies = data["proxies"]
        elif isinstance(data, list):
            proxies = data
        return [n for item in proxies if (n := self._parse_structured_node(item))]

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
            if m[-1] == '}' and m.count('{') >= m.count('}'):
                break
            if m[-1] == ']' and m.count('[') >= m.count(']'):
                break
            if m[-1] == ')' and m.count('(') >= m.count(')'):
                break
            m = m[:-1]
        return m

    def extract_nodes(self, text: str) -> List[str]:
        if not text:
            return []

        found: List[str] = []
        stripped = text.strip()

        parsed = None
        if stripped.startswith(('{', '[')):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                pass
        if parsed is None and ("proxies:" in stripped or "name:" in stripped) and yaml:
            try:
                parsed = yaml.safe_load(stripped)
            except Exception:
                pass
        if parsed:
            found.extend(self._extract_from_structured(parsed))

        clean_text = (text
                      .replace('&amp;', '&')
                      .replace('\\u0026', '&')
                      .replace('\\/', '/')
                      .replace('\\"', '"')
                      .replace('\\\\', '\\'))

        for match in LINK_PATTERN.findall(clean_text):
            link = self._clean_link(match)
            if len(link) > 20:
                found.append(link)

        decoded = self.safe_base64_decode(text)
        if decoded:
            d_clean = (decoded
                       .replace('&amp;', '&')
                       .replace('\\u0026', '&')
                       .replace('\\/', '/')
                       .replace('\\"', '"')
                       .replace('\\\\', '\\'))
            for match in LINK_PATTERN.findall(d_clean):
                link = self._clean_link(match)
                if len(link) > 20:
                    found.append(link)

        return list({n for n in found if len(n) > 20 and "://" in n})

    def fetch_worker(self) -> None:
        while not self.should_stop:
            try:
                url = self.url_queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                resp = self.session.get(url, timeout=TIMEOUT)
                if resp.status_code != 200:
                    continue
                content = resp.content
                c_hash = hashlib.md5(content).hexdigest()
                with self.nodes_lock:
                    if c_hash in self.content_hashes:
                        continue
                    self.content_hashes.add(c_hash)
                nodes = self.extract_nodes(content.decode("utf-8", errors="ignore"))
                if not nodes:
                    continue
                with self.nodes_lock:
                    before = len(self.nodes)
                    for node in nodes:
                        if len(node) < 20 or "://" not in node:
                            continue
                        h = self._get_node_hash(node)
                        if h not in self.seen_hashes:
                            self.seen_hashes.add(h)
                            self.nodes.add(node)
                    if len(self.nodes) > before and len(self.nodes) % 100 == 0:
                        logger.info(f"Unique nodes: {len(self.nodes)}")
                    if len(self.nodes) >= TARGET_NODES:
                        self.should_stop = True
            except Exception:
                pass
            finally:
                self.url_queue.task_done()

    def search_producer(self) -> None:
        logger.info(f"Start search, {len(KEYWORDS_GROUPS)} groups")
        consecutive_limits = 0

        for group in KEYWORDS_GROUPS:
            if self.should_stop or self.check_timeout():
                break

            kw_part = " OR ".join(f'"{k}"' if "://" in k else k for k in group)

            for ext in EXTENSIONS:
                if self.should_stop or self.check_timeout():
                    break

                found_any = False
                for page in range(1, MAX_PAGES + 1):
                    if self.should_stop or self.check_timeout():
                        self.should_stop = True
                        logger.warning("Timeout or target reached, stop search")
                        return

                    query = f"{kw_part} extension:{ext}"
                    api = (f"https://api.github.com/search/code?q={query}"
                           f"&per_page=30&page={page}&sort=indexed&order=desc")

                    success = False
                    for attempt in range(2):
                        if self.should_stop or self.check_timeout():
                            return
                        try:
                            resp = self.session.get(api, timeout=12)

                            if resp.status_code in (403, 429):
                                consecutive_limits += 1
                                if consecutive_limits >= 3:
                                    logger.warning("Rate limit hit 3 times, stop search to avoid hanging")
                                    self.should_stop = True
                                    return
                                wait = 20 + attempt * 5
                                logger.warning(f"Rate limited, wait {wait}s then skip (try {attempt+1})")
                                time.sleep(wait)
                                break

                            if resp.status_code == 200:
                                consecutive_limits = 0
                                items = resp.json().get("items", [])
                                logger.info(f"[{query[:60]}...] P{page} -> {len(items)} files")
                                if items:
                                    found_any = True
                                    for it in items:
                                        html = it.get("html_url")
                                        if html:
                                            raw = (html.replace("github.com", "raw.githubusercontent.com")
                                                       .replace("/blob/", "/"))
                                            self.url_queue.put(raw)
                                success = True
                                break

                            logger.error(f"API {resp.status_code}")
                            break
                        except Exception as e:
                            logger.error(f"Search error: {e}")
                            time.sleep(2)

                    time.sleep(random.uniform(self.sleep_interval, self.sleep_interval + 0.6))

                    if success and not found_any:
                        break

        logger.info("Search finished")

    def run(self) -> None:
        logger.info(f"Start {DOWNLOAD_WORKERS} download workers")
        for _ in range(DOWNLOAD_WORKERS):
            t = threading.Thread(target=self.fetch_worker, daemon=True)
            t.start()

        try:
            self.search_producer()
        except KeyboardInterrupt:
            logger.warning("Interrupted")
            self.should_stop = True

        logger.info("Waiting remaining downloads (max 20s)...")
        deadline = time.time() + 20
        while not self.url_queue.empty() and time.time() < deadline:
            time.sleep(0.4)

        self.should_stop = True
        self._save_results()
        try:
            self.session.close()
        except Exception:
            pass

    def _save_results(self) -> None:
        logger.info(f"=== Final unique nodes: {len(self.nodes)} ===")
        plain = "\n".join(self.nodes) if self.nodes else ""
        try:
            with open(RAW_OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(plain)
        except Exception as e:
            logger.error(f"Save plain failed: {e}")
        if not self.nodes:
            logger.warning("Empty result")
            return
        try:
            b64 = base64.b64encode(plain.encode()).decode()
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(b64)
            logger.info(f"Saved {OUTPUT_FILE} and {RAW_OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"Save base64 failed: {e}")


if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    NodeAggregator(token).run()
