import os
import re
import base64
import json
import time
import random
import logging
import threading
import queue
from urllib.parse import quote
from typing import List, Set, Dict, Any, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 尝试导入 PyYAML，如果未安装则降级处理
try:
    import yaml
except ImportError:
    yaml = None

# --- 配置部分 ---

# 关键词列表：已优化，保留高价值关键词，移除冗余项以节省请求次数
KEYWORDS: List[str] = [
    "proxies", "clash", "subscription", "vmess", "vless", 
    "trojan", "shadowsocks", "hysteria2", "sub", "config", 
    "v2ray", "ss", "节点", "机场", "翻墙"
]

# 文件后缀：包含 yml 以覆盖更多 Clash 配置
EXTENSIONS: List[str] = ["yaml", "yml", "txt", "conf", "json"]

MAX_PAGES: int = 5            # 每个关键词搜索的页数
SEARCH_INTERVAL: float = 3.0  # 搜索请求的基础间隔(秒)，配合重试机制使用
MAX_EXECUTION_TIME: int = 3600 # 全局最大运行时间 (1小时)
TIMEOUT: int = 10             # 单个文件下载超时时间 (秒)
DOWNLOAD_WORKERS: int = 10    # 下载线程数 (设置为10以降低并发风控风险)

OUTPUT_FILE: str = "sub.txt"
RAW_OUTPUT_FILE: str = "nodes.txt"

# 增强型正则：支持标准协议头，以及 #备注 和 [] 包裹的 IPv6
LINK_PATTERN = re.compile(r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[a-zA-Z0-9+/=_@.:?&%#\[\]-]+')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class NodeAggregator:
    def __init__(self, token: Optional[str]):
        self.github_token = token
        self.nodes: Set[str] = set()
        self.nodes_lock = threading.Lock() # 线程锁，保护集合写入安全
        
        # 初始化 Session (包含连接池优化)
        self.session = self._init_session()
        self._setup_headers()
        
        self.start_time = time.time()
        self.should_stop = False # 全局停止标志
        
        # 任务队列 (生产者-消费者模型核心)
        self.url_queue = queue.Queue()
        
        # 策略调整
        if token:
            self.sleep_interval = SEARCH_INTERVAL
        else:
            self.sleep_interval = 15.0 # 无 Token 必须非常慢
            logger.warning("未检测到 Token，将使用极低速模式 (15s/req) 以免被封锁")

        if not yaml:
            logger.warning("未检测到 PyYAML 库，YAML 解析功能将不可用。建议安装 PyYAML。")

    def _init_session(self) -> requests.Session:
        """初始化 Session，显式设置连接池大小以消除 'Connection pool is full' 警告"""
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        # [关键优化] pool_connections = DOWNLOAD_WORKERS
        # 确保每个线程都有独立的连接可用，无需频繁建立/关闭 TCP 连接
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
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("GitHub Token 已加载")

    def check_timeout(self) -> bool:
        """检查是否达到最大执行时间"""
        if time.time() - self.start_time > MAX_EXECUTION_TIME:
            return True
        return False

    def safe_base64_decode(self, text: str) -> Optional[str]:
        """安全的 Base64 解码，处理 URL 安全字符和填充"""
        if not text:
            return None
        text = text.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        text = text.replace('-', '+').replace('_', '/')
        padding = len(text) % 4
        if padding > 0:
            text += '=' * (4 - padding)
        try:
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except Exception:
            return None

    # --- [完整保留] 节点构建逻辑 ---

    def _build_vmess_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将字典配置转换为 vmess:// 标准链接"""
        try:
            v2ray_json = {
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
                "tls": "tls" if config.get("tls") else ""
            }
            if not v2ray_json["add"] or not v2ray_json["id"]:
                return None
            json_str = json.dumps(v2ray_json, separators=(',', ':'))
            b64_str = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            return f"vmess://{b64_str}"
        except Exception:
            return None

    def _build_ss_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将字典配置转换为 ss:// 标准链接"""
        try:
            server = config.get("server")
            port = config.get("port")
            password = config.get("password")
            method = config.get("cipher")
            name = config.get("name", "ss_node")
            if not (server and port and password and method):
                return None
            user_info = f"{method}:{password}"
            b64_user_info = base64.b64encode(user_info.encode('utf-8')).decode('utf-8').strip()
            safe_name = quote(str(name))
            return f"ss://{b64_user_info}@{server}:{port}#{safe_name}"
        except Exception:
            return None

    def _build_trojan_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将字典配置转换为 trojan:// 标准链接"""
        try:
            server = config.get("server")
            port = config.get("port")
            password = config.get("password")
            name = config.get("name", "trojan_node")
            sni = config.get("sni") or config.get("servername")
            if not (server and port and password):
                return None
            query = f"?peer={sni}" if sni else ""
            safe_name = quote(str(name))
            return f"trojan://{password}@{server}:{port}{query}#{safe_name}"
        except Exception:
            return None

    def _parse_structured_node(self, proxy_item: Dict[str, Any]) -> Optional[str]:
        """根据协议类型分发处理"""
        if not isinstance(proxy_item, dict):
            return None
        protocol = str(proxy_item.get("type", "")).lower()
        if protocol == "vmess":
            return self._build_vmess_link(proxy_item)
        elif protocol in ["ss", "shadowsocks"]:
            return self._build_ss_link(proxy_item)
        elif protocol == "trojan":
            return self._build_trojan_link(proxy_item)
        return None

    def _extract_from_structured_data(self, data: Union[Dict, List]) -> List[str]:
        """从 JSON/YAML 数据结构中提取节点"""
        extracted = []
        proxy_list = []
        # 1. Clash 格式
        if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
            proxy_list = data["proxies"]
        # 2. 纯列表格式
        elif isinstance(data, list):
            proxy_list = data
        
        for item in proxy_list:
            link = self._parse_structured_node(item)
            if link:
                extracted.append(link)
        return extracted

    # --- [完整保留] 核心提取逻辑 ---

    def extract_nodes(self, text: str) -> List[str]:
        if not text:
            return []
        found_nodes = []
        
        # 策略 1: 正则直接提取
        regex_matches = LINK_PATTERN.findall(text)
        found_nodes.extend(regex_matches)
        
        # 策略 2: Base64 解码后正则提取
        decoded = self.safe_base64_decode(text)
        if decoded:
            decoded_matches = LINK_PATTERN.findall(decoded)
            found_nodes.extend(decoded_matches)

        # 策略 3: JSON/YAML 解析 (针对结构化订阅)
        text_stripped = text.strip()
        is_json_like = text_stripped.startswith('{') or text_stripped.startswith('[')
        is_yaml_like = "proxies:" in text_stripped or "name:" in text_stripped

        parsed_data = None
        # 3.1 尝试 JSON
        if is_json_like:
            try:
                parsed_data = json.loads(text_stripped)
            except json.JSONDecodeError:
                pass
        
        # 3.2 尝试 YAML
        if parsed_data is None and is_yaml_like and yaml:
            try:
                parsed_data = yaml.safe_load(text_stripped)
            except Exception:
                pass
        
        # 3.3 提取结构化数据
        if parsed_data:
            structured_nodes = self._extract_from_structured_data(parsed_data)
            if structured_nodes:
                found_nodes.extend(structured_nodes)
            
        return found_nodes

    # --- 生产者-消费者并发架构 (核心优化) ---

    def fetch_worker(self):
        """消费者线程：从队列获取URL并下载解析"""
        while not self.should_stop:
            try:
                # 阻塞等待，每秒检查一次停止标志
                url = self.url_queue.get(timeout=1) 
            except queue.Empty:
                continue
            
            try:
                # 使用全局 TIMEOUT 常量
                resp = self.session.get(url, timeout=TIMEOUT)
                if resp.status_code == 200:
                    # 调用完整的提取逻辑
                    nodes = self.extract_nodes(resp.text)
                    if nodes:
                        with self.nodes_lock:
                            count_before = len(self.nodes)
                            for node in nodes:
                                self.nodes.add(node)
                            # 简单的进度展示
                            if len(self.nodes) > count_before and len(self.nodes) % 50 == 0:
                                logger.info(f"当前库存: {len(self.nodes)} 个唯一节点")
            except Exception:
                pass
            finally:
                self.url_queue.task_done()

    def search_producer(self):
        """生产者线程：执行搜索并将结果推入队列"""
        logger.info(f"开始搜索 GitHub, 关键词队列: {len(KEYWORDS)} 个")
        random.shuffle(KEYWORDS) # 打乱顺序
        
        for keyword in KEYWORDS:
            if self.should_stop: break
            
            for ext in EXTENSIONS:
                if self.should_stop: break
                
                # 标记：当前关键词+后缀组合是否找到了结果
                found_items_in_this_combo = False
                
                for page in range(1, MAX_PAGES + 1):
                    if self.should_stop: break
                    if self.check_timeout():
                        logger.warning("达到最大执行时间，停止搜索")
                        self.should_stop = True
                        return

                    query = f"{keyword} extension:{ext}"
                    api_url = f"https://api.github.com/search/code?q={query}&per_page=20&page={page}&sort=indexed&order=desc"
                    
                    # === 智能重试循环 (防止丢失数据) ===
                    max_retries = 3
                    success = False
                    
                    for attempt in range(max_retries):
                        try:
                            resp = self.session.get(api_url)
                            
                            # 触发速率限制：原地等待并重试，绝不跳过
                            if resp.status_code in [403, 429]:
                                wait_time = 60 * (attempt + 1) # 第一次60s，第二次120s
                                logger.warning(f"触发 API 速率限制，暂停 {wait_time} 秒后重试 (第 {attempt+1} 次)...")
                                time.sleep(wait_time)
                                continue 
                            
                            if resp.status_code == 200:
                                items = resp.json().get("items", [])
                                logger.info(f"搜索 [{query} P{page}] -> 找到 {len(items)} 个文件")
                                
                                if items:
                                    found_items_in_this_combo = True
                                    for item in items:
                                        html_url = item.get("html_url")
                                        if html_url:
                                            # 转换为 raw 链接
                                            raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                                            self.url_queue.put(raw_url)
                                else:
                                    # 当前页无结果，通常后续页也无结果，跳出页码循环
                                    pass 
                                
                                success = True
                                break # 成功，退出重试循环
                            
                            else:
                                logger.error(f"API 错误 {resp.status_code}")
                                break # 其他错误（如404）不重试
                                
                        except Exception as e:
                            logger.error(f"搜索请求异常: {e}")
                            time.sleep(5)
                    
                    # 动态随机休眠
                    time.sleep(random.uniform(self.sleep_interval, self.sleep_interval + 1.0))
                    
                    # 如果这一页本来就没结果，不需要继续翻后面的页码
                    if success and not found_items_in_this_combo:
                         break
                
                # 处理下一个后缀
                pass 

        logger.info("所有搜索任务已遍历完成")

    def run(self):
        # 1. 启动下载消费者线程
        logger.info(f"启动 {DOWNLOAD_WORKERS} 个下载线程...")
        threads = []
        for _ in range(DOWNLOAD_WORKERS):
            t = threading.Thread(target=self.fetch_worker)
            t.daemon = True # 守护线程
            t.start()
            threads.append(t)
        
        # 2. 在主线程运行搜索生产者
        try:
            self.search_producer()
        except KeyboardInterrupt:
            logger.warning("用户中断")
            self.should_stop = True
        
        # 3. 等待队列清空
        logger.info("搜索结束，等待剩余下载任务完成(最多30秒)...")
        timeout_wait = time.time() + 30
        while not self.url_queue.empty() and time.time() < timeout_wait:
            time.sleep(1)
        
        self.should_stop = True # 通知所有线程退出
        
        # 4. 保存结果
        self._save_results()

    def _save_results(self):
        logger.info(f"=== 最终统计: 共获取 {len(self.nodes)} 个唯一节点 ===")
        if not self.nodes:
            logger.warning("结果为空，未生成文件")
            return

        plain_text = "\n".join(self.nodes)
        
        # 保存明文
        try:
            with open(RAW_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(plain_text)
        except Exception as e:
            logger.error(f"保存明文失败: {e}")

        # 保存 Base64
        try:
            b64_content = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(b64_content)
            logger.info(f"结果已保存至 {OUTPUT_FILE} 和 {RAW_OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"保存 Base64 失败: {e}")

if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    aggregator = NodeAggregator(token)
    aggregator.run()
