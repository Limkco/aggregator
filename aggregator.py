import os
import re
import base64
import json
import time
import random
import logging
import threading
import queue
from urllib.parse import quote, urlencode
from typing import List, Set, Dict, Any, Optional, Union

# 依赖检查
try:
    from curl_cffi import requests
    from duckduckgo_search import DDGS
except ImportError:
    print("错误: 缺少必要依赖。请运行: pip install curl_cffi duckduckgo_search")
    exit(1)

try:
    import yaml
except ImportError:
    yaml = None

# --- 配置部分 ---

# 通用关键词
KEYWORDS: List[str] = [
    "clash subscription", "vmess", "vless", "ss", "trojan", 
    "hysteria2", "sub", "节点", "机场", "翻墙", "free proxies"
]

# 搜索深度
MAX_RESULTS: int = 20 
MAX_EXECUTION_TIME: int = 600
TIMEOUT: int = 15
DOWNLOAD_WORKERS: int = 10

OUTPUT_FILE: str = "sub.txt"
RAW_OUTPUT_FILE: str = "nodes.txt"

LINK_PATTERN = re.compile(r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[a-zA-Z0-9+/=_@.:?&%#\[\]-]+')

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NodeAggregator:
    def __init__(self):
        self.nodes: Set[str] = set()
        self.nodes_lock = threading.Lock()
        # 模拟 Chrome 120 指纹
        self.session = requests.Session(impersonate="chrome120")
        self.start_time = time.time()
        self.should_stop = False
        self.url_queue = queue.Queue()

    def check_timeout(self) -> bool:
        return time.time() - self.start_time > MAX_EXECUTION_TIME

    # --- 核心网络请求 (带重试) ---
    def _request_get(self, url, retries=2) -> Optional[requests.Response]:
        for i in range(retries):
            try:
                if self.should_stop: return None
                resp = self.session.get(url, timeout=TIMEOUT)
                if resp.status_code == 200: return resp
                if resp.status_code in [403, 429, 503]: 
                    time.sleep(2 * (i + 1)) # 遇到风控多睡一会
            except Exception:
                pass
            time.sleep(1)
        return None

    # --- 搜索模块 1: DuckDuckGo (HTML模式) ---
    def search_ddg(self):
        logger.info(">>> 启动 DuckDuckGo 搜索 (HTML模式)...")
        ddgs = DDGS()
        count = 0
        
        # 随机选取部分关键词，避免超时
        selected_keywords = random.sample(KEYWORDS, min(5, len(KEYWORDS)))
        
        for keyword in selected_keywords:
            if self.should_stop or self.check_timeout(): break
            
            query = f"site:github.com {keyword} extension:yaml"
            logger.info(f"DDG Search: {query}")
            
            try:
                # [关键抗风控点] backend="html" 模拟网页加载，而非 API 调用
                results = ddgs.text(query, max_results=10, backend="html")
                
                found_in_key = 0
                for r in results:
                    href = r.get("href")
                    if href and "github.com" in href and "/blob/" in href:
                        raw_url = href.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                        self.url_queue.put(raw_url)
                        found_in_key += 1
                
                count += found_in_key
                # 必须休眠，否则 Action IP 必死
                time.sleep(random.uniform(5, 10))
                
            except Exception as e:
                logger.warning(f"DDG 搜索遇到阻碍 (可能是风控): {e}")
                time.sleep(10) # 冷却一下
        
        logger.info(f"DDG 搜索结束，贡献 {count} 个链接")

    # --- 搜索模块 2: Sourcegraph (备用神器) ---
    def search_sourcegraph(self):
        """
        Sourcegraph 是专门的代码搜索引擎，对爬虫容忍度较高。
        它不需要登录即可搜索公开代码。
        """
        logger.info(">>> 启动 Sourcegraph 搜索 (备用方案)...")
        
        # Sourcegraph 的搜索语法
        # context:global 表示全网搜
        # repo:github.com 表示只搜 GitHub
        base_url = "https://sourcegraph.com/.api/search/stream"
        
        selected_keywords = random.sample(KEYWORDS, min(3, len(KEYWORDS)))
        
        for keyword in selected_keywords:
            if self.should_stop or self.check_timeout(): break
            
            # 构造 Sourcegraph 查询语法
            sg_query = f"context:global repo:github.com file:yaml {keyword} count:20"
            params = {
                "q": sg_query,
                "v": "V2",
                "t": "literal", 
                "display": -1
            }
            
            try:
                # Sourcegraph 流式 API
                resp = self.session.get(base_url, params=params, stream=True)
                
                found_in_key = 0
                for line in resp.iter_lines():
                    if not line: continue
                    line_str = line.decode('utf-8', errors='ignore')
                    if line_str.startswith("data:"):
                        try:
                            data = json.loads(line_str[5:])
                            # 解析 Sourcegraph 复杂的返回结构
                            if isinstance(data, list):
                                for event in data:
                                    if event.get("type") == "matches":
                                        for match in event.get("data", []):
                                            repo = match.get("repository", "")
                                            path = match.get("path", "")
                                            if repo and path:
                                                # 构造 GitHub Raw 链接
                                                # repo 格式通常是 "github.com/user/repo"
                                                repo_clean = repo.replace("github.com/", "")
                                                raw_url = f"https://raw.githubusercontent.com/{repo_clean}/master/{path}"
                                                # 尝试 main 分支
                                                self.url_queue.put(raw_url)
                                                # 尝试 master 分支 (简单粗暴放入队列，让下载器去试错)
                                                raw_url_main = f"https://raw.githubusercontent.com/{repo_clean}/main/{path}"
                                                self.url_queue.put(raw_url_main)
                                                found_in_key += 1
                        except:
                            pass
                
                logger.info(f"Sourcegraph Search [{keyword}] -> 发现潜在文件")
                time.sleep(3)
                
            except Exception as e:
                logger.warning(f"Sourcegraph 搜索异常: {e}")
                
    # --- 消费者与主逻辑 ---
    
    def fetch_worker(self):
        while not self.should_stop:
            try:
                url = self.url_queue.get(timeout=2)
            except queue.Empty:
                continue
            
            try:
                # 只有合法的 raw 链接才下载
                if "raw.githubusercontent.com" in url:
                    resp = self._request_get(url)
                    if resp:
                        nodes = self.extract_nodes(resp.text)
                        if nodes:
                            with self.nodes_lock:
                                for n in nodes: self.nodes.add(n)
                                if len(self.nodes) % 50 == 0:
                                    logger.info(f"当前库存: {len(self.nodes)} 个")
            except: pass
            finally:
                self.url_queue.task_done()

    # (保留原有的解析逻辑，为了节省篇幅，此处省略，请确保 extract_nodes 等方法存在)
    # ... [此处插入原有的 safe_base64_decode, _build_*, extract_nodes 方法] ...
    # 必须完整保留原有的 extract_nodes, _build_vmess_link 等函数代码！
    
    # 为了保证代码完整运行，我把关键的 extract_nodes 简写补全，请你替换时保留完整的解析逻辑
    def safe_base64_decode(self, text):
        if not text: return None
        text = text.strip().replace(' ','').replace('\n','').replace('\r','').replace('-','+').replace('_','/')
        padding = len(text) % 4
        if padding > 0: text += '=' * (4-padding)
        try: return base64.b64decode(text).decode('utf-8', errors='ignore')
        except: return None

    def extract_nodes(self, text):
        if not text: return []
        res = LINK_PATTERN.findall(text)
        decoded = self.safe_base64_decode(text)
        if decoded: res.extend(LINK_PATTERN.findall(decoded))
        # 简单处理 YAML (假设 yaml 库已导入)
        if yaml:
            try:
                data = yaml.safe_load(text)
                if isinstance(data, dict) and 'proxies' in data:
                     # 这里应该调用 _build_vmess_link 等，假设你已保留那些函数
                     pass 
            except: pass
        return res

    def run(self):
        logger.info(f"启动 {DOWNLOAD_WORKERS} 个下载线程...")
        threads = []
        for _ in range(DOWNLOAD_WORKERS):
            t = threading.Thread(target=self.fetch_worker)
            t.daemon = True; t.start(); threads.append(t)
        
        # 并行或串行执行搜索
        # 建议串行，减少瞬时网络压力
        self.search_ddg()
        
        # 如果 DDG 没搜到多少，或者为了更多结果，继续跑 Sourcegraph
        if len(self.nodes) < 100:
            self.search_sourcegraph()
        
        logger.info("搜索结束，等待下载完成...")
        timeout = time.time() + 60
        while not self.url_queue.empty() and time.time() < timeout:
            time.sleep(1)
        
        self.should_stop = True
        self._save_results()

    def _save_results(self):
        logger.info(f"=== 最终统计: {len(self.nodes)} 个节点 ===")
        if not self.nodes: return
        content = "\n".join(self.nodes)
        with open(RAW_OUTPUT_FILE, 'w', encoding='utf-8') as f: f.write(content)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(base64.b64encode(content.encode('utf-8')).decode('utf-8'))

if __name__ == "__main__":
    NodeAggregator().run()
