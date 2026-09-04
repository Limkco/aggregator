#!/usr/bin/env python3
"""
节点聚合器 (全动态自主发现版):
1. 零固定依赖：完全不硬编码任何第三方死链或静态订阅。
2. 动态仓库嗅探：利用 GitHub 仓库搜索原生支持的 pushed:> 语法，动态发现全网 7 天内活跃的项目。
3. 候选文件树探测：自动探测活跃仓库中的常见配置/订阅文件、README、YAML 及 TXT。
4. 纯净代码检索：使用官方合法语法，作为动态仓库探测的有力补充。
"""

import os
import re
import base64
import json
import time
import logging
import threading
import queue
import hashlib
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import quote, urlparse, parse_qs, unquote
from typing import List, Set, Dict, Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import yaml
except ImportError:
    yaml = None

# ==================== 顶部全局配置区 ====================
# 动态嗅探的时间窗口（天数）：自动搜索过去 7 天内有代码提交/推送的活跃仓库
SEARCH_DAYS: int = 7

# 搜索全网活跃仓库的关键词
REPO_SEARCH_KEYWORDS: List[str] = [
    "v2ray node",
    "clash subscription",
    "free vmess",
    "vless proxies",
    "hysteria2 share",
    "节点 订阅"
]

# 常见包含节点的目标文件名模式（全自动动态拼接探测）
CANDIDATE_FILENAMES: Set[str] = {
    "nodes.txt", "sub.txt", "subscribe.txt", "v2ray.txt", "v2ray",
    "clash.yaml", "config.yaml", "proxies.yaml", "data.txt", "share.txt", "README.md"
}

# 辅助纯代码检索关键词组（合法语法，杜绝非法参数）
CODE_SEARCH_GROUPS: List[str] = [
    'vmess:// extension:txt',
    'vless:// extension:txt',
    'trojan:// extension:txt',
    'proxies extension:yaml'
]

TIMEOUT: int = 10
DOWNLOAD_WORKERS: int = 16
RAW_OUTPUT_FILE: str = "nodes.txt"
OUTPUT_FILE: str = "sub.txt"

LINK_PATTERN = re.compile(r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s<>"\'`]+', re.IGNORECASE)
UUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

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
    """拦截内网保留地址与常见模板虚假域名"""
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


class DynamicNodeAggregator:
    def __init__(self, token: Optional[str]):
        self.github_token = token
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
            "User-Agent": "Mozilla/5.0 (NodeFinder/5.0)",
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"

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
        try:
            proto, rest = link.split("://", 1)
            core = rest.split("#")[0]
            if proto.lower() == "vmess":
                decoded = self.safe_base64_decode(core)
                if decoded:
                    conf = json.loads(decoded)
                    conf.pop("ps", None)
                    core = json.dumps(conf, sort_keys=True)
            return hashlib.md5(f"{proto.lower()}://{core}".encode()).hexdigest()
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

        # 正则扫描明文链接
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

    def discover_active_repositories(self) -> None:
        """核心策略 1：全网动态嗅探指定天数内有推送更新的开源仓库"""
        since_date = (datetime.utcnow() - timedelta(days=SEARCH_DAYS)).strftime("%Y-%m-%d")
        logger.info(f"【动态嗅探】开始扫描全网自 {since_date} (过去 {SEARCH_DAYS} 天) 以来更新的活跃代理仓库...")

        for keyword in REPO_SEARCH_KEYWORDS:
            if self.should_stop:
                break
            query = f"{keyword} pushed:>{since_date} fork:true"
            api = f"https://api.github.com/search/repositories?q={quote(query)}&sort=updated&order=desc&per_page=15"
            try:
                resp = self.session.get(api, timeout=10)
                if resp.status_code == 200:
                    repos = resp.json().get("items", [])
                    logger.info(f"关键词 [{keyword}] 命中 {len(repos)} 个活跃仓库")
                    for repo in repos:
                        default_branch = repo.get("default_branch", "main")
                        full_name = repo.get("full_name")
                        if not full_name:
                            continue

                        # 动态探测该仓库根目录下的候选文件
                        for fname in CANDIDATE_FILENAMES:
                            raw_url = f"https://raw.githubusercontent.com/{full_name}/{default_branch}/{fname}"
                            self.url_queue.put(raw_url)
                elif resp.status_code in (403, 429):
                    logger.warning("仓库 API 触发频率限制，暂停 5 秒...")
                    time.sleep(5)
            except Exception as e:
                logger.error(f"仓库扫描发生异常: {e}")
            time.sleep(1.5)

    def discover_via_code_search(self) -> None:
        """核心策略 2：纯净代码即时检索（作为动态仓库探测的辅助通道）"""
        logger.info("【代码即时检索】启动全网实时文件检索...")
        for query in CODE_SEARCH_GROUPS:
            if self.should_stop:
                break
            api = f"https://api.github.com/search/code?q={quote(query)}&sort=indexed&order=desc&per_page=20"
            try:
                resp = self.session.get(api, timeout=10)
                if resp.status_code == 200:
                    items = resp.json().get("items", [])
                    logger.info(f"代码搜索 [{query}] 命中 {len(items)} 个文件")
                    for it in items:
                        html = it.get("html_url")
                        if html:
                            raw = html.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                            self.url_queue.put(raw)
                elif resp.status_code in (403, 429):
                    logger.warning("代码搜索 API 触发速率限制，平滑跳过")
                    break
            except Exception:
                pass
            time.sleep(2)

    def run(self) -> None:
        logger.info(f"启动 {DOWNLOAD_WORKERS} 个并发解析工作线程...")
        for _ in range(DOWNLOAD_WORKERS):
            threading.Thread(target=self.fetch_worker, daemon=True).start()

        # 1. 执行动态活跃仓库探测（过去 SEARCH_DAYS 天）
        self.discover_active_repositories()

        # 2. 执行纯净代码即时检索
        self.discover_via_code_search()

        # 等待下载队列处理完成
        logger.info("等待所有动态探测到的资源下载与解析...")
        deadline = time.time() + 30
        while time.time() < deadline and self.url_queue.unfinished_tasks > 0:
            time.sleep(0.5)

        self.should_stop = True
        with self.nodes_lock:
            nodes_list = list(self.nodes)

        logger.info(f"=== 动态探测完成！共获取格式有效节点: {len(nodes_list)} 个 ===")
        plain = "\n".join(nodes_list) if nodes_list else ""
        with open(RAW_OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(plain)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(base64.b64encode(plain.encode("utf-8")).decode("utf-8"))


if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    DynamicNodeAggregator(token).run()
