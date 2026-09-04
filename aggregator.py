#!/usr/bin/env python3
"""
节点聚合器 (完整增强版):
1. 保留原版完整的 Clash YAML / JSON 结构化节点转换为链接的功能。
2. 继承原版完善的 GitHub 速率保护、配额控制、Base64 订阅生成。
3. 增加入库前深度清洗：自动拦截内网保留 IP、虚假域名、畸形 UUID、无效端口。
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
from datetime import datetime, timedelta
from urllib.parse import quote, urlparse, parse_qs, unquote
from typing import List, Set, Dict, Any, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import yaml
except ImportError:
    yaml = None

# ==================== 全局配置 ====================
KEYWORDS_GROUPS: List[List[str]] = [
    ["vmess://", "vless://", "trojan://"],
    ["ss://", "shadowsocks", "hysteria2", "hy2://"],
    ["proxies", "clash", "subscription", "sub"],
    ["v2ray share", "free nodes", "节点订阅"],
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

# 匹配常见代理协议链接的正则表达式
LINK_PATTERN = re.compile(
    r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s<>"\'`]+',
    re.IGNORECASE
)
UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)

# 拦截内网及本地保留 IP 网段
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

# 拦截常见测试、占位虚假域名
FAKE_DOMAINS = {
    "example.com", "yourdomain.com", "mydomain.com", "domain.com",
    "test.com", "sample.com", "localhost"
}

# 日志格式
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def is_invalid_host(host: str) -> bool:
    """检查域名或 IP 是否为无效/保留地址"""
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
    """节点收集与去重核心类"""

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
            logger.warning("未检测到 GH_TOKEN，开启低速安全模式 (12s/请求)")
        if not yaml:
            logger.warning("未检测到 PyYAML 库，Clash YAML 解析功能已受限")

    def _init_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=2,
            backoff_factor=0.6,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=DOWNLOAD_WORKERS,
            pool_maxsize=DOWNLOAD_WORKERS
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _setup_headers(self) -> None:
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (compatible; HighQualityNodeAggregator/3.0)",
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("已成功装载 GitHub Token")

    def check_timeout(self) -> bool:
        return time.time() - self.start_time > MAX_EXECUTION_TIME

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
        """提取节点核心特征生成哈希，避免别名变动造成重复"""
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
                    sni = part.rsplit(":", 1)[0].strip("[]")

            feature_str = f"{protocol}://{core}"
            if sni:
                feature_str += f"?sni={sni}"
            return hashlib.md5(feature_str.encode()).hexdigest()
        except Exception:
            return hashlib.md5(link.encode()).hexdigest()

    def _build_vmess_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将 Clash YAML 的 VMess 配置转换为 vmess:// 标准链接"""
        try:
            server = str(config.get("server", "")).strip()
            port = int(config.get("port", 0))
            uuid_val = str(config.get("uuid", "")).strip()
            if not (1 <= port <= 65535) or is_invalid_host(server):
                return None
            if not UUID_PATTERN.match(uuid_val) or uuid_val.startswith("00000000"):
                return None

            v = {
                "v": "2",
                "ps": str(config.get("name", "vmess")),
                "add": server,
                "port": str(port),
                "id": uuid_val,
                "aid": str(config.get("alterId", 0)),
                "scy": str(config.get("cipher", "auto")),
                "net": str(config.get("network", "tcp")),
                "type": str(config.get("type", "none")),
                "host": str(config.get("servername") or config.get("ws-opts", {}).get("headers", {}).get("Host", "")),
                "path": str(config.get("ws-path") or config.get("ws-opts", {}).get("path", "")),
                "tls": "tls" if config.get("tls") else "",
            }
            json_str = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
            return "vmess://" + base64.b64encode(json_str.encode("utf-8")).decode("utf-8")
        except Exception:
            return None

    def _build_ss_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将 Clash YAML 的 SS 配置转换为 ss:// 链接"""
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

    def _build_trojan_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将 Clash YAML 的 Trojan 配置转换为 trojan:// 链接"""
        try:
            server = str(config.get("server", "")).strip()
            port = int(config.get("port", 0))
            password = str(config.get("password", "")).strip()
            if not (1 <= port <= 65535) or is_invalid_host(server) or not password:
                return None
            sni = config.get("sni") or config.get("servername")
            q = f"?peer={sni}" if sni else ""
            return f"trojan://{password}@{server}:{port}{q}#{quote(str(config.get('name', 'trojan')))}"
        except Exception:
            return None

    def _parse_structured_node(self, item: Dict[str, Any]) -> Optional[str]:
        """解析 Clash/JSON 单条代理配置"""
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
        """从结构化数据（如 Clash 的 proxies 列表）提取节点"""
        proxies = []
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            proxies = data["proxies"]
        elif isinstance(data, list):
            proxies = data
        return [n for item in proxies if (n := self._parse_structured_node(item))]

    def _clean_link(self, raw: str) -> str:
        """剔除链接前后多余的闭合符号、HTML标记与逗号分号"""
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

    def _validate_link(self, link: str) -> bool:
        """严格校验提取出来的节点链接，杜绝假节点进入后续测试环节"""
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
                if proto == "vless":
                    uid = str(p.username or "")
                    if not UUID_PATTERN.match(uid) or uid.startswith("00000000"):
                        return False
            return True
        except Exception:
            return False

    def extract_nodes(self, text: str) -> List[str]:
        """综合提取节点：支持 Clash YAML、JSON、纯文本正则与 Base64"""
        if not text:
            return []

        found: List[str] = []
        stripped = text.strip()

        # 1. 尝试解析 Clash YAML / JSON 结构化数据
        parsed = None
        if stripped.startswith(('{', '[')):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                pass
        if parsed is None and ("proxies:" in stripped or "proxy-groups:" in stripped) and yaml:
            try:
                parsed = yaml.safe_load(stripped)
            except Exception:
                pass
        if parsed:
            found.extend(self._extract_from_structured(parsed))

        # 2. 文本清洗与反转义
        clean_text = (
            text.replace('&amp;', '&')
            .replace('\\u0026', '&')
            .replace('\\/', '/')
            .replace('\\"', '"')
            .replace('\\\\', '\\')
        )

        # 3. 正则扫描直接明文链接
        for match in LINK_PATTERN.findall(clean_text):
            cleaned = self._clean_link(match)
            if self._validate_link(cleaned):
                found.append(cleaned)

        # 4. 尝试 Base64 订阅全文解密再扫描
        decoded = self.safe_base64_decode(text)
        if decoded:
            d_clean = (
                decoded.replace('&amp;', '&')
                .replace('\\u0026', '&')
                .replace('\\/', '/')
                .replace('\\"', '"')
                .replace('\\\\', '\\')
            )
            for match in LINK_PATTERN.findall(d_clean):
                cleaned = self._clean_link(match)
                if self._validate_link(cleaned):
                    found.append(cleaned)

        return found

    def fetch_worker(self) -> None:
        """并发抓取工作线程"""
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

                nodes = self.extract_nodes(resp.text)
                if not nodes:
                    continue

                with self.nodes_lock:
                    before = len(self.nodes)
                    for node in nodes:
                        h = self._get_node_hash(node)
                        if h not in self.seen_hashes:
                            self.seen_hashes.add(h)
                            self.nodes.add(node)

                    if len(self.nodes) > before and len(self.nodes) % 100 == 0:
                        logger.info(f"已收集有效格式节点: {len(self.nodes)}")
                    if len(self.nodes) >= TARGET_NODES:
                        self.should_stop = True
            except Exception:
                pass
            finally:
                self.url_queue.task_done()

    def search_producer(self) -> None:
        """调用 GitHub Search API，结合时效性过滤提升质量"""
        logger.info(f"开始执行 GitHub 搜索任务，关键词组数: {len(KEYWORDS_GROUPS)}")
        consecutive_limits = 0
        # 仅搜索最近 14 天有更新的代码，大幅淘汰历史陈旧死库
        pushed_filter = (datetime.utcnow() - timedelta(days=14)).strftime("%Y-%m-%d")

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
                        return

                    query = f"{kw_part} extension:{ext} pushed:>{pushed_filter}"
                    api = (
                        f"https://api.github.com/search/code?q={quote(query)}"
                        f"&per_page=30&page={page}&sort=indexed&order=desc"
                    )

                    success = False
                    for attempt in range(2):
                        if self.should_stop or self.check_timeout():
                            return
                        try:
                            resp = self.session.get(api, timeout=12)
                            if resp.status_code in (403, 429):
                                consecutive_limits += 1
                                if consecutive_limits >= 3:
                                    logger.warning("连续触发 GitHub 速率限制，为保护 Token 停止搜索")
                                    self.should_stop = True
                                    return
                                wait = 20 + attempt * 10
                                logger.warning(f"触发速率限制，等待 {wait} 秒...")
                                time.sleep(wait)
                                break

                            if resp.status_code == 200:
                                consecutive_limits = 0
                                items = resp.json().get("items", [])
                                logger.info(f"[{query[:50]}...] 页码 {page} -> 命中 {len(items)} 个文件")
                                if items:
                                    found_any = True
                                    for it in items:
                                        html = it.get("html_url")
                                        if html:
                                            raw = (
                                                html.replace("github.com", "raw.githubusercontent.com")
                                                .replace("/blob/", "/")
                                            )
                                            self.url_queue.put(raw)
                                success = True
                                break

                            logger.error(f"API 响应错误: {resp.status_code}")
                            break
                        except Exception as e:
                            logger.error(f"搜索请求异常: {e}")
                            time.sleep(2)

                    time.sleep(random.uniform(self.sleep_interval, self.sleep_interval + 0.5))
                    if success and not found_any:
                        break

        logger.info("GitHub API 检索生产流程结束")

    def run(self) -> None:
        logger.info(f"启动 {DOWNLOAD_WORKERS} 个下载工作线程")
        for _ in range(DOWNLOAD_WORKERS):
            threading.Thread(target=self.fetch_worker, daemon=True).start()

        try:
            self.search_producer()
        except KeyboardInterrupt:
            self.should_stop = True

        logger.info("等待抓取队列剩余任务结算 (上限 25 秒)...")
        deadline = time.time() + 25
        while time.time() < deadline:
            if self.url_queue.unfinished_tasks == 0:
                break
            time.sleep(0.5)

        self.should_stop = True
        self._save_results()
        try:
            self.session.close()
        except Exception:
            pass

    def _save_results(self) -> None:
        with self.nodes_lock:
            nodes_list = list(self.nodes)
        logger.info(f"=== 最终入库唯一高阶格式节点总数: {len(nodes_list)} ===")

        plain = "\n".join(nodes_list) if nodes_list else ""
        try:
            with open(RAW_OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(plain)
        except Exception as e:
            logger.error(f"保存明文节点文件失败: {e}")

        if not nodes_list:
            logger.warning("本次未收集到有效节点")
            return

        try:
            b64 = base64.b64encode(plain.encode("utf-8")).decode("utf-8")
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(b64)
            logger.info(f"已同步输出明文 {RAW_OUTPUT_FILE} 与 Base64 订阅 {OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"保存 Base64 订阅失败: {e}")


if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    NodeAggregator(token).run()
