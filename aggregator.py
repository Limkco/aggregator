import os
import re
import json
import base64
import requests
import concurrent.futures
from urllib.parse import urlparse

# --- 配置部分 ---
# 对应 C 代码中的关键字
KEYWORDS = [
    "vmess", "vless", "ss", "trojan", "hysteria2", "hy2", 
    "clash", "config", "proxies"
]
EXTENSIONS = ["yaml", "txt", "conf"]
MAX_PAGES = 2  # 搜索页数限制
CONCURRENCY = 10  # 并发下载数
TIMEOUT = 10  # 超时时间 (秒)
OUTPUT_FILE = "sub.txt" # 最终生成的订阅文件（Base64编码后）
RAW_OUTPUT_FILE = "nodes.txt" # 明文节点文件（可选，方便调试）

# 对应 src/parser_nodes.c 中的协议头判断
PROTOCOLS = ["vmess://", "vless://", "ss://", "trojan://", "hysteria2://", "hy2://"]

class NodeAggregator:
    def __init__(self, token):
        self.github_token = token
        self.nodes = set()
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {self.github_token}" if self.github_token else None
        }
        # 移除 None header
        if not self.headers["Authorization"]:
            del self.headers["Authorization"]

    def safe_base64_decode(self, text):
        """
        对应 src/utils_base64.c 的功能
        尝试对字符串进行 URL-Safe Base64 解码
        """
        if not text:
            return None
        
        # 清理非 Base64 字符 (简化版，保留关键字符)
        text = text.strip()
        text = text.replace('-', '+').replace('_', '/')
        
        # 补全 padding
        padding = len(text) % 4
        if padding > 0:
            text += '=' * (4 - padding)
            
        try:
            decoded_bytes = base64.b64decode(text)
            return decoded_bytes.decode('utf-8', errors='ignore')
        except:
            return None

    def extract_nodes_from_text(self, text):
        """
        对应 src/aggregator_search.c -> ExtractNodesFromText
        从文本中提取节点链接
        """
        found_nodes = []
        if not text:
            return found_nodes

        # 1. 尝试按行读取直接匹配
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            for proto in PROTOCOLS:
                if line.startswith(proto):
                    found_nodes.append(line)
                    break
        
        # 2. 如果没找到，尝试 Base64 解码后再找
        if not found_nodes:
            decoded = self.safe_base64_decode(text)
            if decoded:
                lines = decoded.split('\n')
                for line in lines:
                    line = line.strip()
                    for proto in PROTOCOLS:
                        if line.startswith(proto):
                            found_nodes.append(line)
                            break
                            
        return found_nodes

    def fetch_github_file(self, url):
        """
        对应 src/aggregator_search.c -> SearchDownloadWorker
        下载 GitHub 原始文件内容
        """
        try:
            # 将 html_url 转换为 raw_url (简易处理，API返回通常有 download_url)
            # 但这里我们直接用 requests 请求 API 返回的 download_url 或者构造 raw
            resp = requests.get(url, timeout=TIMEOUT)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return None

    def search_github(self):
        """
        对应 src/aggregator_search.c -> SearchGitHubKeywords
        """
        print(f"[*] 开始搜索 GitHub, 关键字数量: {len(KEYWORDS)}")
        download_queue = []

        # 搜索阶段
        for keyword in KEYWORDS:
            for ext in EXTENSIONS:
                for page in range(1, MAX_PAGES + 1):
                    query = f"{keyword} extension:{ext}"
                    api_url = f"https://api.github.com/search/code?q={query}&per_page=20&page={page}&sort=indexed&order=desc"
                    
                    try:
                        print(f"  -> 搜索: {query} (Page {page})")
                        resp = requests.get(api_url, headers=self.headers, timeout=TIMEOUT)
                        
                        if resp.status_code == 403:
                            print("  [!] API 速率限制或未授权")
                            break
                        
                        if resp.status_code != 200:
                            continue

                        data = resp.json()
                        items = data.get("items", [])
                        if not items:
                            break
                            
                        for item in items:
                            # 优先使用 html_url 转换为 raw url
                            html_url = item.get("html_url")
                            if html_url:
                                raw_url = html_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                                download_queue.append(raw_url)
                                
                    except Exception as e:
                        print(f"  [!] 搜索请求错误: {e}")
        
        print(f"[*] 搜索完成，共找到 {len(download_queue)} 个潜在文件，准备下载...")
        return download_queue

    def process_downloads(self, urls):
        """
        多线程下载并处理
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            future_to_url = {executor.submit(self.fetch_github_file, url): url for url in urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    content = future.result()
                    if content:
                        extracted = self.extract_nodes_from_text(content)
                        if extracted:
                            # print(f"  [+] {url} 提取到 {len(extracted)} 个节点")
                            for node in extracted:
                                self.nodes.add(node) # Set 自动去重
                except Exception:
                    pass

    def run(self):
        # 1. 搜索
        urls = self.search_github()
        
        # 2. 下载并聚合
        self.process_downloads(urls)
        
        print(f"[*] 聚合完成，共获取 {len(self.nodes)} 个唯一节点")
        
        if not self.nodes:
            print("[!] 未找到有效节点，脚本结束")
            return

        # 3. 输出处理 (对应 src/aggregator_core.c 的最终输出)
        # 将所有节点拼接，并进行 Base64 编码
        plain_text = "\n".join(self.nodes)
        
        # 保存明文 (可选)
        with open(RAW_OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(plain_text)
            
        # 保存 Base64 订阅格式
        b64_content = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(b64_content)
            
        print(f"[*] 结果已保存至: {OUTPUT_FILE} (及 {RAW_OUTPUT_FILE})")

if __name__ == "__main__":
    # 从环境变量获取 Token，确保安全
    token = os.environ.get("GH_TOKEN")
    if not token:
        print("[!] 警告: 未检测到 GH_TOKEN，GitHub API 请求可能会受到严格限制")
    
    aggregator = NodeAggregator(token)
    aggregator.run()
