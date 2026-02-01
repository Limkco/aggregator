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
TIMEOUT = 10 
MAX_EXECUTION_TIME = 600  # 最大执行时间 600秒 (10分钟)

OUTPUT_FILE = "sub.txt"
RAW_OUTPUT_FILE = "nodes.txt"

# [关键修复] 使用 (?:...) 非捕获组，确保 findall 返回完整的链接
LINK_PATTERN = re.compile(r'(?:vmess|vless|ss|trojan|hysteria2|hy2)://[a-zA-Z0-9+/=_@.:?&%-]+')

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
            logger.warning("未检测到 Token，将受到严格的 API 速率限制")

    def check_timeout(self):
        elapsed = time.time() - self.start_time
        if elapsed > MAX_EXECUTION_TIME:
            return True, elapsed
        return False, elapsed

    def safe_base64_decode(self, text):
        if not text: return None
        # 简单的预处理，去除可能干扰解码的空白字符
        text = text.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        text = text.replace('-', '+').replace('_', '/')
        padding = len(text) % 4
        if padding > 0: text += '=' * (4 - padding)
        try:
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except:
            return None

    def extract_nodes(self, text):
        if not text: return []
        
        # 1. 直接匹配明文链接
        found = LINK_PATTERN.findall(text)
        
        # 2. 尝试 Base64 解码后匹配
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

                    if total_requests >= 30: 
                        logger.info("达到单次运行 API 请求限制，停止搜索")
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
