import os
import re
import base64
import json
import requests
import concurrent.futures
import time
import random
import logging
from urllib.parse import quote
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 尝试导入 PyYAML，如果未安装则降级处理
try:
    import yaml
except ImportError:
    yaml = None

# --- 配置部分 ---
KEYWORDS = ["vmess", "vless", "ss", "trojan", "hysteria2", "clash", "sub", "节点", "翻墙", "proxies", "v2ray", "hy", "shadowsocks"]
# [修复] 移除空字符串，保留有效扩展名
EXTENSIONS = ["yaml", "txt", "conf", "json"] 
MAX_PAGES = 1
CONCURRENCY = 5
TIMEOUT = 10 
MAX_EXECUTION_TIME = 600  # 10分钟

OUTPUT_FILE = "sub.txt"
RAW_OUTPUT_FILE = "nodes.txt"

# [修复] 增强型正则：支持 #备注 和 [] 包裹的 IPv6
LINK_PATTERN = re.compile(r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[a-zA-Z0-9+/=_@.:?&%#\[\]-]+')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class NodeAggregator:
    def __init__(self, token):
        self.github_token = token
        self.nodes = set()
        self.session = self._init_session()
        self._setup_headers()
        self.start_time = time.time()
        # 根据 Token 状态动态调整速率限制
        self.max_requests = 500 if token else 30
        
        if not yaml:
            logger.warning("未检测到 PyYAML 库，YAML 解析功能将不可用。请在 requirements.txt 中添加 PyYAML。")

    def _init_session(self):
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _setup_headers(self):
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("GitHub Token 已加载")
        else:
            logger.warning("未检测到 Token，速率限制受限")

    def check_timeout(self):
        elapsed = time.time() - self.start_time
        if elapsed > MAX_EXECUTION_TIME:
            return True, elapsed
        return False, elapsed

    def safe_base64_decode(self, text):
        if not text: return None
        text = text.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        text = text.replace('-', '+').replace('_', '/')
        padding = len(text) % 4
        if padding > 0: text += '=' * (4 - padding)
        try:
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except Exception:
            return None

    # --- [新增] 节点组装逻辑开始 ---

    def _build_vmess_link(self, config):
        """将字典配置转换为 vmess:// 标准链接"""
        try:
            # 映射 Clash/通用字段到 VMess 分享标准字段
            v2ray_json = {
                "v": "2",
                "ps": config.get("name", "unnamed"),
                "add": config.get("server"),
                "port": config.get("port"),
                "id": config.get("uuid"),
                "aid": config.get("alterId", 0),
                "scy": config.get("cipher", "auto"),
                "net": config.get("network", "tcp"),
                "type": config.get("type", "none"), # header type
                "host": config.get("servername") or config.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                "path": config.get("ws-path") or config.get("ws-opts", {}).get("path", ""),
                "tls": "tls" if config.get("tls") else ""
            }
            # 简单的验证
            if not v2ray_json["add"] or not v2ray_json["id"]:
                return None
            
            json_str = json.dumps(v2ray_json, separators=(',', ':'))
            b64_str = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            return f"vmess://{b64_str}"
        except Exception:
            return None

    def _build_ss_link(self, config):
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
            # 处理名称编码
            safe_name = quote(str(name))
            return f"ss://{b64_user_info}@{server}:{port}#{safe_name}"
        except Exception:
            return None

    def _build_trojan_link(self, config):
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

    def _parse_structured_node(self, proxy_item):
        """根据协议类型分发处理"""
        if not isinstance(proxy_item, dict):
            return None
        
        protocol = proxy_item.get("type", "").lower()
        
        if protocol == "vmess":
            return self._build_vmess_link(proxy_item)
        elif protocol == "ss" or protocol == "shadowsocks":
            return self._build_ss_link(proxy_item)
        elif protocol == "trojan":
            return self._build_trojan_link(proxy_item)
        # 可以在此扩展 vless 等其他协议
        return None

    def _extract_from_structured_data(self, data):
        """从 JSON/YAML 数据结构中提取节点"""
        extracted = []
        proxy_list = []

        # 1. 检查是否为 Clash 格式 (包含 'proxies' 列表)
        if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
            proxy_list = data["proxies"]
        # 2. 检查是否为纯列表结构
        elif isinstance(data, list):
            proxy_list = data
        
        for item in proxy_list:
            link = self._parse_structured_node(item)
            if link:
                extracted.append(link)
        
        return extracted

    # --- [重写] 核心提取方法 ---

    def extract_nodes(self, text):
        if not text: return []
        found_nodes = []
        
        # 策略 1: 正则直接提取 (针对纯文本链接或混合文本)
        # 即使是 JSON/YAML 文件，有时也可能混有 URL，先提取一遍
        regex_matches = LINK_PATTERN.findall(text)
        found_nodes.extend(regex_matches)
        
        # 策略 2: Base64 解码后正则提取 (针对 Base64 订阅内容)
        decoded = self.safe_base64_decode(text)
        if decoded:
            decoded_matches = LINK_PATTERN.findall(decoded)
            found_nodes.extend(decoded_matches)

        # 策略 3: 尝试解析为结构化数据 (JSON/YAML)
        # 注意: 只有当内容看起来像 JSON/YAML 时才尝试，避免对大文件进行无意义解析
        text = text.strip()
        is_json_like = text.startswith('{') or text.startswith('[')
        is_yaml_like = "proxies:" in text or "name:" in text # 简单特征识别

        parsed_data = None
        
        # 3.1 尝试 JSON 解析
        if is_json_like:
            try:
                parsed_data = json.loads(text)
            except json.JSONDecodeError:
                pass
        
        # 3.2 尝试 YAML 解析 (如果 JSON 失败且看起来像 YAML)
        if parsed_data is None and is_yaml_like and yaml:
            try:
                parsed_data = yaml.safe_load(text)
            except Exception:
                pass
        
        # 3.3 如果解析成功，提取节点
        if parsed_data:
            structured_nodes = self._extract_from_structured_data(parsed_data)
            if structured_nodes:
                logger.info(f"从结构化数据中解析出 {len(structured_nodes)} 个节点")
                found_nodes.extend(structured_nodes)
            
        return found_nodes

    # --- 节点组装逻辑结束 ---

    def fetch_url(self, url):
        try:
            resp = self.session.get(url, timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def search_github(self):
        logger.info(f"开始搜索 GitHub, 关键字: {len(KEYWORDS)} 个")
        download_queue = []
        random.shuffle(KEYWORDS)
        
        total_requests = 0
        
        for keyword in KEYWORDS:
            for ext in EXTENSIONS:
                for page in range(1, MAX_PAGES + 1):
                    is_timeout, elapsed = self.check_timeout()
                    if is_timeout:
                        logger.warning(f"已运行 {elapsed:.0f}秒，超时停止搜索。")
                        return download_queue

                    if total_requests >= self.max_requests: 
                        logger.info(f"达到单次运行 API 请求限制 ({self.max_requests})，停止搜索")
                        return download_queue

                    query = f"{keyword} extension:{ext}"
                    api_url = f"https://api.github.com/search/code?q={query}&per_page=15&page={page}&sort=indexed&order=desc"
                    
                    try:
                        logger.info(f"搜索: {query} (Page {page})")
                        resp = self.session.get(api_url)
                        total_requests += 1
                        
                        if resp.status_code in [403, 429]:
                            logger.warning("触发 API 速率限制，休眠 60 秒...")
                            if time.time() - self.start_time + 60 > MAX_EXECUTION_TIME:
                                return download_queue
                            time.sleep(60)
                            continue
                        
                        if resp.status_code != 200:
                            logger.error(f"API 错误: {resp.status_code}")
                            time.sleep(5)
                            continue

                        items = resp.json().get("items", [])
                        for item in items:
                            html_url = item.get("html_url")
                            if html_url:
                                raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                                download_queue.append(raw_url)
                        
                        sleep_time = random.uniform(5, 10)
                        time.sleep(sleep_time)

                    except Exception as e:
                        logger.error(f"搜索异常: {e}")
                        time.sleep(5)
        
        return download_queue

    def run(self):
        urls = self.search_github()
        unique_urls = list(set(urls))
        logger.info(f"搜索阶段结束，准备下载 {len(unique_urls)} 个文件")

        if unique_urls:
            with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
                future_to_url = {executor.submit(self.fetch_url, url): url for url in unique_urls}
                
                count = 0
                for future in concurrent.futures.as_completed(future_to_url):
                    is_timeout, elapsed = self.check_timeout()
                    if is_timeout:
                        logger.warning("下载阶段超时，保存现有结果...")
                        for f in future_to_url: f.cancel()
                        break

                    try:
                        content = future.result()
                        # [重要] extract_nodes 现在支持解析 JSON/YAML 字段
                        nodes = self.extract_nodes(content)
                        if nodes:
                            for node in nodes:
                                self.nodes.add(node)
                        count += 1
                        if count % 10 == 0:
                            logger.info(f"下载进度: {count}/{len(unique_urls)}")
                    except Exception:
                        pass

        logger.info(f"聚合完成，共获取 {len(self.nodes)} 个唯一节点")

        if self.nodes:
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
                logger.info(f"结果已保存至 {OUTPUT_FILE}")
            except Exception as e:
                logger.error(f"保存 Base64 失败: {e}")
        else:
            logger.warning("结果为空，未生成文件")

if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    aggregator = NodeAggregator(token)
    aggregator.run()
