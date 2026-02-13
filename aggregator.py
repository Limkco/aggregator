import os
import re
import base64
import json
import time
import random
import logging
import concurrent.futures
from urllib.parse import quote
from typing import List, Set, Dict, Any, Optional, Tuple, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 尝试导入 PyYAML
try:
    import yaml
except ImportError:
    yaml = None

# --- 配置常量 ---
KEYWORDS: List[str] = [
    "vmess", "vless", "sock", "trojan", "shadowsocks", 
    "hysteria", "hysteria2", "hy", "hy2", "clash", 
    "sub", "上网节点", "proxies", "v2ray", "翻墙节点", "机场节点"
]

EXTENSIONS: List[str] = ["yaml", "yml", "txt", "conf", "json"]
MAX_PAGES: int = 3
CONCURRENCY: int = 5
TIMEOUT: int = 10
MAX_EXECUTION_TIME: int = 600  # 10分钟

OUTPUT_FILE: str = "sub.txt"
RAW_OUTPUT_FILE: str = "nodes.txt"

# 正则表达式：支持标准协议头，支持 #备注 和 [] 包裹的 IPv6
LINK_PATTERN = re.compile(r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[a-zA-Z0-9+/=_@.:?&%#\[\]-]+')

# --- 日志配置 ---
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
        self.session = self._init_session()
        self.start_time = time.time()
        
        self._setup_headers()
        
        # 根据 Token 状态动态调整速率限制
        self.max_requests = 500 if token else 30
        
        if not yaml:
            logger.warning("未检测到 PyYAML 库，YAML 解析功能将不可用。建议在 requirements.txt 中添加 PyYAML。")

    def _init_session(self) -> requests.Session:
        """初始化带有重试机制的 Session"""
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

    def _setup_headers(self) -> None:
        """设置请求头"""
        self.session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })
        if self.github_token:
            self.session.headers["Authorization"] = f"token {self.github_token}"
            logger.info("GitHub Token 已加载")
        else:
            logger.warning("未检测到 Token，速率限制将受限")

    def check_timeout(self) -> Tuple[bool, float]:
        """检查是否达到最大执行时间"""
        elapsed = time.time() - self.start_time
        if elapsed > MAX_EXECUTION_TIME:
            return True, elapsed
        return False, elapsed

    def safe_base64_decode(self, text: str) -> Optional[str]:
        """安全的 Base64 解码，处理 URL 安全字符和填充"""
        if not text:
            return None
        # 清理非法字符
        text = text.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        # URL Safe 替换
        text = text.replace('-', '+').replace('_', '/')
        
        # 补全填充
        padding = len(text) % 4
        if padding > 0:
            text += '=' * (4 - padding)
            
        try:
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except Exception:
            return None

    # --- 节点组装逻辑 ---

    def _build_vmess_link(self, config: Dict[str, Any]) -> Optional[str]:
        """将字典配置转换为 vmess:// 标准链接"""
        try:
            # 映射 Clash/通用字段到 VMess 分享标准字段
            v2ray_json = {
                "v": "2",
                "ps": str(config.get("name", "unnamed")),
                "add": str(config.get("server")),
                "port": str(config.get("port")),
                "id": str(config.get("uuid")),
                "aid": str(config.get("alterId", 0)),
                "scy": str(config.get("cipher", "auto")),
                "net": str(config.get("network", "tcp")),
                "type": str(config.get("type", "none")), # header type
                "host": str(config.get("servername") or config.get("ws-opts", {}).get("headers", {}).get("Host", "")),
                "path": str(config.get("ws-path") or config.get("ws-opts", {}).get("path", "")),
                "tls": "tls" if config.get("tls") else ""
            }
            
            # 基础验证
            if not v2ray_json["add"] or not v2ray_json["id"]:
                return None
            
            # 生成紧凑的 JSON 字符串
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
        # 可以在此扩展 vless 等其他协议
        return None

    def _extract_from_structured_data(self, data: Union[Dict, List]) -> List[str]:
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

    # --- 核心提取方法 ---

    def extract_nodes(self, text: str) -> List[str]:
        if not text:
            return []
        found_nodes = []
        
        # 策略 1: 正则直接提取 (针对纯文本链接或混合文本)
        regex_matches = LINK_PATTERN.findall(text)
        found_nodes.extend(regex_matches)
        
        # 策略 2: Base64 解码后正则提取 (针对 Base64 订阅内容)
        decoded = self.safe_base64_decode(text)
        if decoded:
            decoded_matches = LINK_PATTERN.findall(decoded)
            found_nodes.extend(decoded_matches)

        # 策略 3: 尝试解析为结构化数据 (JSON/YAML)
        text_stripped = text.strip()
        is_json_like = text_stripped.startswith('{') or text_stripped.startswith('[')
        is_yaml_like = "proxies:" in text_stripped or "name:" in text_stripped

        parsed_data = None
        
        # 3.1 尝试 JSON 解析
        if is_json_like:
            try:
                parsed_data = json.loads(text_stripped)
            except json.JSONDecodeError:
                pass
        
        # 3.2 尝试 YAML 解析
        if parsed_data is None and is_yaml_like and yaml:
            try:
                parsed_data = yaml.safe_load(text_stripped)
            except Exception:
                pass
        
        # 3.3 如果解析成功，提取节点
        if parsed_data:
            structured_nodes = self._extract_from_structured_data(parsed_data)
            if structured_nodes:
                logger.info(f"从结构化数据中解析出 {len(structured_nodes)} 个节点")
                found_nodes.extend(structured_nodes)
            
        return found_nodes

    def fetch_url(self, url: str) -> Optional[str]:
        """下载单个 URL 内容"""
        try:
            resp = self.session.get(url, timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def search_github(self) -> List[str]:
        """执行 GitHub 代码搜索"""
        logger.info(f"开始搜索 GitHub, 关键字: {len(KEYWORDS)} 个")
        download_queue = []
        
        # 随机打乱关键字以优化搜索覆盖面
        search_keywords = list(KEYWORDS)
        random.shuffle(search_keywords)
        
        total_requests = 0
        
        for keyword in search_keywords:
            for ext in EXTENSIONS:
                for page in range(1, MAX_PAGES + 1):
                    # 超时检查
                    is_timeout, elapsed = self.check_timeout()
                    if is_timeout:
                        logger.warning(f"已运行 {elapsed:.0f}秒，超时停止搜索。")
                        return download_queue

                    # API 限制检查
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
                            # 预判休眠后是否超时
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
                                # 转换 blob URL 为 raw URL
                                raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                                download_queue.append(raw_url)
                        
                        # 随机延迟防止触发二级风控
                        sleep_time = random.uniform(5, 10)
                        time.sleep(sleep_time)

                    except Exception as e:
                        logger.error(f"搜索异常: {e}")
                        time.sleep(5)
        
        return download_queue

    def run(self):
        """主执行流程"""
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
                        for f in future_to_url:
                            f.cancel()
                        break

                    try:
                        content = future.result()
                        if content:
                            # 提取节点并去重
                            nodes = self.extract_nodes(content)
                            if nodes:
                                for node in nodes:
                                    self.nodes.add(node)
                        
                        count += 1
                        if count % 10 == 0:
                            logger.info(f"下载进度: {count}/{len(unique_urls)}")
                    except Exception as e:
                        logger.debug(f"处理文件时发生错误: {e}")

        logger.info(f"聚合完成，共获取 {len(self.nodes)} 个唯一节点")

        if self.nodes:
            self._save_results()
        else:
            logger.warning("结果为空，未生成文件")

    def _save_results(self):
        """保存结果到文件"""
        plain_text = "\n".join(self.nodes)
        
        # 保存明文
        try:
            with open(RAW_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(plain_text)
        except Exception as e:
            logger.error(f"保存明文失败: {e}")

        # 保存 Base64 编码
        try:
            b64_content = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write(b64_content)
            logger.info(f"结果已保存至 {OUTPUT_FILE}")
        except Exception as e:
            logger.error(f"保存 Base64 失败: {e}")

if __name__ == "__main__":
    # 获取环境变量中的 Token
    token = os.environ.get("GH_TOKEN")
    aggregator = NodeAggregator(token)
    aggregator.run()
