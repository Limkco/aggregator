import sys
import os
import re
import json
import base64
import asyncio
import ssl
import time
import logging
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置部分 ---
INPUT_FILE = "nodes.txt"       # 聚合生成的原始节点文件
OUTPUT_FILE = "nodes.txt"      # 清洗后的明文节点文件
SUB_FILE = "sub.txt"           # Base64 订阅文件

# 并发数 (根据网络情况调整)
CONCURRENCY = 200              
# 超时设置 (秒)
TCP_TIMEOUT = 2    # TCP 连接超时 (快速筛选)
SSL_TIMEOUT = 3    # SSL 握手超时 (验证可用性)

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("NodeChecker")

class NodeParser:
    """节点解析工具类"""
    
    @staticmethod
    def safe_base64_decode(text):
        if not text: return ""
        text = text.strip().replace('-', '+').replace('_', '/')
        padding = len(text) % 4
        if padding > 0:
            text += '=' * (4 - padding)
        try:
            return base64.b64decode(text).decode('utf-8', errors='ignore')
        except Exception:
            return ""

    @staticmethod
    def parse(link):
        """
        解析各类节点链接
        返回: (host, port, sni, is_tls)
        """
        link = link.strip()
        host, port, sni, is_tls = None, None, None, False
        
        try:
            # --- 1. VMess ---
            if link.startswith("vmess://"):
                try:
                    b64_str = link[8:]
                    json_str = NodeParser.safe_base64_decode(b64_str)
                    conf = json.loads(json_str)
                    host = conf.get("add")
                    port = conf.get("port")
                    # 严格筛选 TLS
                    if conf.get("tls") in ["tls", "xtls"]:
                        is_tls = True
                        sni = conf.get("sni") or conf.get("host")
                except: pass

            # --- 2. Shadowsocks (SS) ---
            elif link.startswith("ss://"):
                try:
                    body = link[5:].split('#')[0]
                    if '@' in body:
                        part_host = body.split('@')[1]
                    else:
                        decoded = NodeParser.safe_base64_decode(body)
                        part_host = decoded.split('@')[1] if '@' in decoded else ""
                    
                    if part_host:
                        h, p = part_host.split(':')
                        host = h
                        port = int(p)
                    # 普通 SS 默认无 TLS，除非你有特定识别 plugin 的逻辑，否则这里 is_tls 为 False
                except: pass

            # --- 3. URL Schema (Trojan, VLESS, Hysteria2) ---
            else:
                try:
                    parsed = urlparse(link)
                    host = parsed.hostname
                    port = parsed.port
                    qs = parse_qs(parsed.query)
                    security = qs.get("security", [""])[0]
                    scheme = parsed.scheme.lower()
                    
                    # Trojan
                    if scheme == "trojan":
                        if security != "none": is_tls = True
                    
                    # VLESS / Hysteria2
                    elif scheme in ["vless", "hysteria2", "hy2"]:
                        if security in ["tls", "reality", "auto"]: is_tls = True
                    
                    if is_tls:
                        if "sni" in qs: sni = qs["sni"][0]
                        elif "peer" in qs: sni = qs["peer"][0]
                except: pass
            
            if port: port = int(port)
                
        except Exception:
            return None, None, None, False

        return host, port, sni, is_tls

async def check_connectivity(link, semaphore):
    """
    分阶段检测：
    1. 静态过滤非 TLS
    2. TCP Ping (连接端口)
    3. SSL Handshake (验证协议)
    """
    # [阶段1] 解析并静态过滤
    host, port, sni, is_tls = NodeParser.parse(link)
    
    # 如果不是 TLS 节点，直接抛弃 (符合"先执行过滤非 TLS 节点")
    if not is_tls:
        return None
    if not host or not port:
        return None

    async with semaphore:
        writer = None
        try:
            # [阶段2] TCP Ping (去掉不在线节点)
            start_time = time.time()
            # 建立纯 TCP 连接
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), 
                timeout=TCP_TIMEOUT
            )
            tcp_latency = (time.time() - start_time) * 1000
            
            # 如果能走到这里，说明 TCP 是通的 (在线)
            
            # [阶段3] SSL 握手 (去掉无效/伪TLS节点)
            # 准备 SSL 上下文
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            
            # 在现有 TCP 连接上升级 SSL (start_tls)
            # 这比关闭再重连更高效，且能验证该端口确实支持 SSL
            start_ssl = time.time()
            await asyncio.wait_for(
                writer.start_tls(ssl_ctx, server_hostname=sni),
                timeout=SSL_TIMEOUT
            )
            ssl_handshake_latency = (time.time() - start_ssl) * 1000
            
            # 计算总延迟 (TCP建连 + SSL握手)
            total_latency = tcp_latency + ssl_handshake_latency
            
            # 安全关闭
            writer.close()
            try: await writer.wait_closed()
            except: pass
            
            # 返回结果
            return (link, total_latency, f"{host}:{port}")

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            # 任何阶段失败 (TCP连不上 或 SSL握手失败) 都视为无效
            if writer:
                try:
                    writer.close()
                    # 避免等待太久
                    # await writer.wait_closed() 
                except: pass
            return None
        except Exception:
            if writer:
                try: writer.close()
                except: pass
            return None

async def main():
    print(f"--- 极速节点清洗 (TLS + TCP + SSL Pipeline) ---")
    
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 找不到 {INPUT_FILE}")
        return

    # 1. 读取节点
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        raw_lines = [line.strip() for line in f if line.strip()]
    unique_nodes = list(set(raw_lines))
    print(f"初始节点数: {len(unique_nodes)}")
    
    # 2. 启动异步检测
    # 注意：这里的 check_connectivity 内部已经包含了三个阶段的逻辑
    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_connectivity(node, semaphore) for node in unique_nodes]
    
    print(f"开始三级筛选 (TCP超时: {TCP_TIMEOUT}s, SSL超时: {SSL_TIMEOUT}s)...")
    start_time = time.time()
    
    valid_nodes = []
    checked_count = 0
    total = len(tasks)
    
    # 实时处理结果
    for future in asyncio.as_completed(tasks):
        result = await future
        checked_count += 1
        
        if result:
            valid_nodes.append(result)
            
        # 进度条
        if checked_count % 20 == 0 or checked_count == total:
            elapsed = time.time() - start_time
            speed = checked_count / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r进度: {checked_count}/{total} | 存活(TLS): {len(valid_nodes)} | 速度: {speed:.1f}/s")
            sys.stdout.flush()

    print("\n")
    
    # 3. 排序 (延迟低优先)
    valid_nodes.sort(key=lambda x: x[1])
    
    # 4. 保存
    final_links = [x[0] for x in valid_nodes]
    
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(final_links))
            
        b64_content = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8')
        with open(SUB_FILE, 'w', encoding='utf-8') as f:
            f.write(b64_content)
            
        print(f"筛选完成，耗时 {time.time() - start_time:.2f}s")
        print(f"最终可用 TLS 节点: {len(final_links)}/{len(unique_nodes)}")
        if valid_nodes:
            print(f"最优节点延迟: {valid_nodes[0][1]:.2f}ms")
        print(f"结果已保存至 {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"保存失败: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户停止检测")
