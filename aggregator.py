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

# [核心修改] 引入 curl_cffi 以模拟浏览器指纹，绕过 API 风控
try:
    from curl_cffi import requests
except ImportError:
    print("错误: 缺少必要依赖。请运行: pip install curl_cffi")
    exit(1)

# 尝试导入 PyYAML，如果未安装则降级处理
try:
    import yaml
except ImportError:
    yaml = None

# --- 配置部分 ---

# 关键词列表
KEYWORDS: List[str] = [
    "proxies", "clash", "subscription", "vmess", "vless", 
    "trojan", "shadowsocks", "hysteria2", "sub", "config", 
    "v2ray", "ss", "节点", "机场", "翻墙"
]

# 文件后缀
EXTENSIONS: List[str] = ["yaml", "yml", "txt", "conf", "json"]

MAX_PAGES: int = 3            # 每个关键词搜索的页数
SEARCH_INTERVAL: float = 3.0  # 搜索请求的基础间隔(秒)
MAX_EXECUTION_TIME: int = 600 # 全局最大运行时间 (1小时)
TIMEOUT: int = 15             # 单个请求超时时间 (秒)
DOWNLOAD_WORKERS: int = 10    # 下载线程数

OUTPUT_FILE: str = "sub.txt"
RAW_OUTPUT_FILE: str = "nodes.txt"

# 增强型正则
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
        self.nodes_lock = threading.Lock() 
        
        # [核心修改] 初始化 curl_cffi 会话
        self.session = self._init_session()
        self._setup_headers()
        
        self.start_time = time.time()
        self.should_stop = False 
        
        self.url_queue = queue.Queue()
        
        # 策略调整
        if token:
            self.sleep_interval = SEARCH_INTERVAL
        else:
            self.sleep_interval = 15.0 
            logger.warning("未检测到 Token，将使用极低速模式 (15s/req) 以免被封锁")

        if not yaml:
            logger.warning("未检测到 PyYAML 库，YAML 解析功能将不可用。建议安装 PyYAML。")

    def _init_session(self):
        """
        [核心修改] 初始化 Session，使用 impersonate 参数模拟 Chrome 120。
        这能生成真实的 TLS 指纹，极大降低被识别为爬虫的风险。
        """
        try:
            # impersonate="chrome120" 是解决风控的关键
            return requests.Session(impersonate="chrome120")
        except Exception as e:
            logger.error(f"初始化 curl_cffi 失败: {e}")
            # 降级回退（极少发生）
            return requests.Session()

    def _setup_headers(self) -> None:
        """设置请求头，curl_cffi 会自动处理部分浏览器指纹头"""
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            # 虽然模拟了指纹，但保持明确的 UA 也是一种好习惯，或者可以让 curl_cffi 自动管理
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("GitHub Token 已加载")

    def _request_get(self, url, params=None, retries=3) -> Optional[requests.Response]:
        """
        [新增] 自定义 GET 请求封装，替代原有的 HTTPAdapter。
        实现对 5xx 错误和网络异常的自动重试。
        """
        for i in range(retries):
            try:
                if self.should_stop: return None
                
                resp = self.session.get(url, params=params, timeout=TIMEOUT)
                
                # 遇到服务器端错误时重试
                if resp.status_code in [500, 502, 503, 504]:
                    time.sleep(1 * (i + 1))
                    continue
                
                return resp
            except Exception as e:
                # 捕获网络底层异常（如连接重置、超时）
                if i == retries - 1:
                    # 仅在最后一次重试失败时记录 debug 日志，减少噪音
                    logger.debug(f"请求异常 {url}: {e}")
                time.sleep(1 * (i + 1))
        return None

    def check_timeout(self) -> bool:
        if time.time() - self.start_time > MAX_EXECUTION_TIME:
            return True
        return False

    def safe_base64_decode(self, text: str) -> Optional[str]:
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

    # --- 节点构建逻辑 (保持不变) ---

    def _build_vmess_link(self, config: Dict[str, Any]) -> Optional[str]:
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
        extracted = []
        proxy_list = []
        if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
            proxy_list = data["proxies"]
        elif isinstance(data, list):
            proxy_list = data
        
        for item in proxy_list:
            link = self._parse_structured_node(item)
            if link:
                extracted.append(link)
        return extracted

    def extract_nodes(self, text: str) -> List[str]:
        if not text:
            return []
        found_nodes = []
        
        regex_matches = LINK_PATTERN.findall(text)
        found_nodes.extend(regex_matches)
        
        decoded = self.safe_base64_decode(text)
        if decoded:
            decoded_matches = LINK_PATTERN.findall(decoded)
            found_nodes.extend(decoded_matches)

        text_stripped = text.strip()
        is_json_like = text_stripped.startswith('{') or text_stripped.startswith('[')
        is_yaml_like = "proxies:" in text_stripped or "name:" in text_stripped

        parsed_data = None
        if is_json_like:
            try:
                parsed_data = json.loads(text_stripped)
            except json.JSONDecodeError:
                pass
        
        if parsed_data is None and is_yaml_like and yaml:
            try:
                parsed_data = yaml.safe_load(text_stripped)
            except Exception:
                pass
        
        if parsed_data:
            structured_nodes = self._extract_from_structured_data(parsed_data)
            if structured_nodes:
                found_nodes.extend(structured_nodes)
            
        return found_nodes

    # --- 生产者-消费者并发架构 ---

    def fetch_worker(self):
        """消费者线程：从队列获取URL并下载解析"""
        while not self.should_stop:
            try:
                url = self.url_queue.get(timeout=1) 
            except queue.Empty:
                continue
            
            try:
                # [核心修改] 使用 _request_get 替代 session.get
                resp = self._request_get(url)
                
                if resp and resp.status_code == 200:
                    nodes = self.extract_nodes(resp.text)
                    if nodes:
                        with self.nodes_lock:
                            count_before = len(self.nodes)
                            for node in nodes:
                                self.nodes.add(node)
                            if len(self.nodes) > count_before and len(self.nodes) % 50 == 0:
                                logger.info(f"当前库存: {len(self.nodes)} 个唯一节点")
            except Exception:
                pass
            finally:
                self.url_queue.task_done()

    def search_producer(self):
        """生产者线程：执行搜索并将结果推入队列"""
        logger.info(f"开始搜索 GitHub, 关键词队列: {len(KEYWORDS)} 个")
        random.shuffle(KEYWORDS) 
        
        for keyword in KEYWORDS:
            if self.should_stop: break
            
            for ext in EXTENSIONS:
                if self.should_stop: break
                
                found_items_in_this_combo = False
                
                for page in range(1, MAX_PAGES + 1):
                    if self.should_stop: break
                    if self.check_timeout():
                        logger.warning("达到最大执行时间，停止搜索")
                        self.should_stop = True
                        return

                    query = f"{keyword} extension:{ext}"
                    api_url = f"https://api.github.com/search/code?q={query}&per_page=20&page={page}&sort=indexed&order=desc"
                    
                    max_retries = 3
                    success = False
                    
                    for attempt in range(max_retries):
                        # [核心修改] 使用 _request_get 替代 session.get
                        # _request_get 会处理网络错误和 500 错误，返回 None 或 Response 对象
                        resp = self._request_get(api_url)
                        
                        if not resp:
                            # 网络层面严重失败
                            logger.error(f"网络请求失败，重试中... ({attempt+1}/{max_retries})")
                            continue

                        # 触发速率限制：原地等待并重试
                        if resp.status_code in [403, 429]:
                            wait_time = 60 * (attempt + 1)
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
                                        raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                                        self.url_queue.put(raw_url)
                            
                            success = True
                            break 
                        
                        else:
                            logger.error(f"API 错误 {resp.status_code}")
                            break 
                    
                    time.sleep(random.uniform(self.sleep_interval, self.sleep_interval + 1.0))
                    
                    if success and not found_items_in_this_combo:
                         break
                
                pass 

        logger.info("所有搜索任务已遍历完成")

    def run(self):
        logger.info(f"启动 {DOWNLOAD_WORKERS} 个下载线程...")
        threads = []
        for _ in range(DOWNLOAD_WORKERS):
            t = threading.Thread(target=self.fetch_worker)
            t.daemon = True 
            t.start()
            threads.append(t)
        
        try:
            self.search_producer()
        except KeyboardInterrupt:
            logger.warning("用户中断")
            self.should_stop = True
        
        logger.info("搜索结束，等待剩余下载任务完成(最多30秒)...")
        timeout_wait = time.time() + 30
        while not self.url_queue.empty() and time.time() < timeout_wait:
            time.sleep(1)
        
        self.should_stop = True 
        
        self._save_results()

    def _save_results(self):
        logger.info(f"=== 最终统计: 共获取 {len(self.nodes)} 个唯一节点 ===")
        if not self.nodes:
            logger.warning("结果为空，未生成文件")
            return

        plain_text = "\n".join(self.nodes)
        
        try:
            with open(RAW_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(plain_text)
        except Exception as e:
            logger.error(f"保存明文失败: {e}")

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
