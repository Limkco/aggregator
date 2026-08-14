#!/usr/bin/env python3
"""节点聚合器: 搜索 GitHub 上的代理配置，提取并去重节点。"""

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

# 匹配常见代理协议链接的正则表达式
LINK_PATTERN = re.compile(
    r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[^\s<>"\'`]+',
    re.IGNORECASE
)

# 日志格式配置
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


class NodeAggregator:
    """节点收集与去重核心类"""

    def __init__(self, token: Optional[str]):
        self.github_token = token
        self.nodes: Set[str] = set()               # 最终有效节点集合
        self.seen_hashes: Set[str] = set()          # 节点特征 Hash 集合（用于去重）
        self.content_hashes: Set[str] = set()       # 文件内容 Hash 集合（避免重复解析相同文件）
        self.nodes_lock = threading.Lock()         # 线程安全锁
        self.session = self._init_session()
        self._setup_headers()
        self.start_time = time.time()
        self.should_stop = False
        self.url_queue: queue.Queue = queue.Queue() # 待下载 URL 队列
        self.sleep_interval = SEARCH_INTERVAL if token else 12.0
        
        if not token:
            logger.warning("未检测到 GH_TOKEN，开启低速模式 (12s/请求)")
        if not yaml:
            logger.warning("未安装 PyYAML，YAML 解析功能已禁用")

    def _init_session(self) -> requests.Session:
        """初始化带有自动重试与连接池的 Requests Session"""
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
        """设置 GitHub API 请求头"""
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (compatible; NodeAggregator/2.2)",
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("已加载 GitHub Token")

    def check_timeout(self) -> bool:
        """检查程序执行时间是否超出安全阈值"""
        return time.time() - self.start_time > MAX_EXECUTION_TIME

    def safe_base64_decode(self, text: str) -> Optional[str]:
        """安全解码 Base64 字符串，包含自动补全与 URL 安全字符替换"""
        if not text:
            return None
        text = text.strip().replace(" ", "").replace("\n", "").replace("\r", "")
        text = unquote(text)  # 容错处理 URL 编码字符
        text = text.replace("-", "+").replace("_", "/")
        
        pad = len(text) % 4
        if pad:
            text += "=" * (4 - pad)
        try:
            return base64.b64decode(text).decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _get_node_hash(self, link: str) -> str:
        """
        根据节点链接提取核心特征（协议、核心配置/地址、SNI/Host）并计算 MD5，
        忽略备注名（ps/remark）等无用变动，实现精准语义去重。
        """
        link = link.strip()
        if "://" not in link:
            return hashlib.md5(link.encode()).hexdigest()
        try:
            protocol, rest = link.split("://", 1)
            protocol = protocol.lower()
            core = rest.split("#")[0]  # 移除备注
            sni = None

            if protocol == "vmess":
                decoded = self.safe_base64_decode(core)
                if decoded:
                    conf = json.loads(decoded)
                    sni = conf.get("sni") or conf.get("host") or conf.get("add")
                    conf.pop("ps", None)  # 移除节点别名以进行纯净去重
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
        """将结构化字典构建为 VMess 节点链接"""
        try:
            server = config.get("server")
            port = config.get("port")
            uuid_val = config.get("uuid")
            if not server or not port or not uuid_val:
                return None

            v = {
                "v": "2",
                "ps": str(config.get("name", "unnamed")),
                "add": str(server),
                "port": str(port),
                "id": str(uuid_val),
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
        """将结构化字典构建为 Shadowsocks 节点链接"""
        try:
            server, port, password, method = (
                config.get("server"), config.get("port"),
                config.get("password"), config.get("cipher")
            )
            if not all([server, port, password, method]):
                return None
            user = base64.b64encode(f"{method}:{password}".encode("utf-8")).decode("utf-8").strip()
            return f"ss://{user}@{server}:{port}#{quote(str(config.get('name', 'ss')))}"
        except Exception:
            return None

    def _build_trojan_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将结构化字典构建为 Trojan 节点链接"""
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
        """解析单条结构化节点数据"""
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
        """从 JSON/YAML 结构化对象中提取节点"""
        proxies = []
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            proxies = data["proxies"]
        elif isinstance(data, list):
            proxies = data
        return [n for item in proxies if (n := self._parse_structured_node(item))]

    def _clean_link(self, raw: str) -> str:
        """清除提取出的链接末尾或首部的闭合符号与废字符"""
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
        """从文本中综合提取节点（支持 JSON/YAML/明文/Base64）"""
        if not text:
            return []

        found: List[str] = []
        stripped = text.strip()

        # 尝试结构化解析 (JSON / YAML)
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

        # 文本清理（还原转义字符）
        clean_text = (text
                      .replace('&amp;', '&')
                      .replace('\\u0026', '&')
                      .replace('\\/', '/')
                      .replace('\\"', '"')
                      .replace('\\\\', '\\'))

        # 正则直接提取
        for match in LINK_PATTERN.findall(clean_text):
            link = self._clean_link(match)
            if len(link) > 20:
                found.append(link)

        # Base64 解密后再尝试提取
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
        """消费者工作线程：从队列拉取 URL 并进行抓取、提取和去重"""
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
                        logger.info(f"去重节点数: {len(self.nodes)}")
                    if len(self.nodes) >= TARGET_NODES:
                        self.should_stop = True
            except Exception:
                pass
            finally:
                self.url_queue.task_done()

    def search_producer(self) -> None:
        """生产者线程：调用 GitHub Search API，生成 Raw 文件下载 URL 并入队"""
        logger.info(f"开始搜索，共 {len(KEYWORDS_GROUPS)} 组关键词")
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
                        logger.warning("达到超时上限或目标节点数，停止搜索")
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
                                    logger.warning("连续 3 次触发速率限制，停止搜索")
                                    self.should_stop = True
                                    return
                                wait = 20 + attempt * 5
                                logger.warning(f"触发速率限制，等待 {wait} 秒后重试")
                                time.sleep(wait)
                                break

                            if resp.status_code == 200:
                                consecutive_limits = 0
                                items = resp.json().get("items", [])
                                logger.info(f"[{query[:60]}...] 页码 {page} -> 发现 {len(items)} 个文件")
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

                            logger.error(f"API 响应状态码错误: {resp.status_code}")
                            break
                        except Exception as e:
                            logger.error(f"搜索发生异常: {e}")
                            time.sleep(2)

                    time.sleep(random.uniform(self.sleep_interval, self.sleep_interval + 0.6))

                    if success and not found_any:
                        break

        logger.info("搜索流程执行结束")

    def run(self) -> None:
        """程序入口方法：启动下载工作线程，执行搜索，等待结束并保存结果"""
        logger.info(f"启动 {DOWNLOAD_WORKERS} 个下载线程")
        for _ in range(DOWNLOAD_WORKERS):
            t = threading.Thread(target=self.fetch_worker, daemon=True)
            t.start()

        try:
            self.search_producer()
        except KeyboardInterrupt:
            logger.warning("收到手动终止指令")
            self.should_stop = True

        logger.info("等待剩余下载任务完成 (上限 20 秒)...")
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.url_queue.unfinished_tasks == 0:
                break
            time.sleep(0.4)

        self.should_stop = True
        self._save_results()
        try:
            self.session.close()
        except Exception:
            pass

    def _save_results(self) -> None:
        """保存明文及 Base64 加密的节点列表到文件"""
        with self.nodes_lock:
            nodes_list = list(self.nodes)
        logger.info(f"=== 最终有效去重节点总数: {len(nodes_list)} ===")
        plain = "\n".join(nodes_list) if nodes_list else ""
        try:
            with open(RAW_OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(plain)
        except Exception as e:
            logger.error(f"保存明文文件失败: {e}")
            
        if not nodes_list:
            logger.warning("节点列表为空")
            return
            
        try:
            b64 = base64.b64encode(plain.encode("utf-8")).decode("utf-8")
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(b64)
            logger.info(f"已成功写入 {OUTPUT_FILE} 与 {RAW_OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"保存 Base64 订阅文件失败: {e}")


if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    NodeAggregator(token).run()
