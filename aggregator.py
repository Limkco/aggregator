import os
import re
import base64
import requests
import concurrent.futures
import time
import random
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- 配置部分 ---
KEYWORDS = ["vmess", "vless", "ss", "trojan", "hysteria2", "clash", "sub", "节点", "翻墙", "proxies", "v2ray", "hy","shadowsocks"]
EXTENSIONS = ["yaml", "txt", "conf"]
MAX_PAGES = 1
CONCURRENCY = 5
TIMEOUT = 15  # 增加超时时间
OUTPUT_FILE = "sub.txt"
RAW_OUTPUT_FILE = "nodes.txt"

# 正则表达式：匹配常见的节点链接格式
# 允许链接出现在文本的任何位置，不再局限于行首
LINK_PATTERN = re.compile(r'(vmess|vless|ss|trojan|hysteria2|hy2)://[a-zA-Z0-9+/=_@.:?&%-]+')

# 日志配置
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

    def _init_session(self):
        """初始化带重试机制的 Session"""
        session = requests.Session()
        retry = Retry(
            total=3,  # 最多重试3次
            backoff_factor=1,  # 重试间隔 1s, 2s, 4s
            status_forcelist=[500, 502, 503, 504], # 遇到这些错误码才重试
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
            logger.warning("未检测到 Token，将受到严格的 API 速率限制")

    def safe_base64_decode(self, text):
        if not text: return None
        text = text.strip().replace('-', '+').replace('_', '/')
        padding = len(text) % 4
        if padding > 0: text += '=' * (4 - padding)
        try:
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except:
            return None

    def parse_clash_yaml(self, content):
        """
        简单粗暴地从 Clash YAML 中提取 proxies 部分的 server 和 port
        注意：这只是一个简易实现，完整的 YAML 解析需要 PyYAML 库
        但为了不增加依赖，这里使用文本处理。
        """
        # 这一步是为了让搜到的 clash 文件也能贡献一些节点
        # 仅提取看起来像节点的配置块（这是一个极其简化的逻辑）
        # 实际上 Clash 转 vmess 链接很复杂，这里仅作为“尽力而为”的补充
        # 如果你想精准解析，建议还是只依靠近标准链接
        pass 
        # 考虑到转换复杂性及准确度，本次优化暂不包含复杂的 YAML->Link 转换
        # 而是专注于从 YAML 中提取可能存在的原始链接

    def extract_nodes(self, text):
        """使用正则从文本中提取所有节点"""
        if not text: return []
        
        # 1. 直接正则匹配
        found = LINK_PATTERN.findall(text)
        
        # 2. 尝试 Base64 解码后再匹配
        # 很多订阅链接返回的是 Base64 编码后的内容
        decoded = self.safe_base64_decode(text)
        if decoded:
            found_in_decoded = LINK_PATTERN.findall(decoded)
            found.extend(found_in_decoded)
            
        return found

    def fetch_url(self, url):
        try:
            resp = self.session.get(url, timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass # 忽略网络错误，由 Session 重试或跳过
        return None

    def search_github(self):
        logger.info(f"开始搜索 GitHub, 关键字: {len(KEYWORDS)} 个")
        download_queue = []
        random.shuffle(KEYWORDS) # 打乱顺序
        
        total_requests = 0
        
        for keyword in KEYWORDS:
            for ext in EXTENSIONS:
                for page in range(1, MAX_PAGES + 1):
                    if total_requests >= 25: # 安全阈值
                        logger.info("达到单次运行安全请求限制，停止搜索")
                        return download_queue

                    query = f"{keyword} extension:{ext}"
                    # 使用 text_match 获取上下文（可选，目前主要用 download_url）
                    api_url = f"https://api.github.com/search/code?q={query}&per_page=15&page={page}&sort=indexed&order=desc"
                    
                    try:
                        logger.info(f"搜索: {query} (Page {page})")
                        resp = self.session.get(api_url) # 使用带重试的 session
                        total_requests += 1
                        
                        if resp.status_code in [403, 429]:
                            logger.warning("触发 API 速率限制，休眠 60 秒...")
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
                        
                        # 随机休眠
                        sleep_time = random.uniform(5, 10)
                        time.sleep(sleep_time)

                    except Exception as e:
                        logger.error(f"搜索异常: {e}")
                        time.sleep(5)
        
        return download_queue

    def run(self):
        urls = self.search_github()
        unique_urls = list(set(urls))
        logger.info(f"搜索完成，准备下载 {len(unique_urls)} 个文件")

        if not unique_urls:
            logger.warning("未找到文件")
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            future_to_url = {executor.submit(self.fetch_url, url): url for url in unique_urls}
            
            count = 0
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    content = future.result()
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
            # 结果输出
            plain_text = "\n".join(self.nodes)
            
            # 1. 保存明文
            try:
                with open(RAW_OUTPUT_FILE, 'w', encoding='utf-8') as f:
                    f.write(plain_text)
            except Exception as e:
                logger.error(f"保存明文失败: {e}")

            # 2. 保存 Base64
            try:
                b64_content = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
                with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                    f.write(b64_content)
                logger.info("结果保存成功")
            except Exception as e:
                logger.error(f"保存 Base64 失败: {e}")
        else:
            logger.warning("结果为空，未生成文件")

if __name__ == "__main__":
    token = os.environ.get("GH_TOKEN")
    aggregator = NodeAggregator(token)
    aggregator.run()
