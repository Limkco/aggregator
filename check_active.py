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

# 并发控制：AsyncIO 可以轻松支持更高并发
CONCURRENCY = 200              
# 超时设置：连接超时时间 (秒)
TIMEOUT = 3                    

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
        """兼容性 Base64 解码"""
        if not text: return ""
        # 移除可能存在的空白符
        text = text.strip()
        # URL Safe 替换
        text = text.replace('-', '+').replace('_', '/')
        # 补全 Padding
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
            # --- 1. VMess (JSON inside Base64) ---
            if link.startswith("vmess://"):
                try:
                    b64_str = link[8:]
                    json_str = NodeParser.safe_base64_decode(b64_str)
                    conf = json.loads(json_str)
                    
                    host = conf.get("add")
                    port = conf.get("port")
                    
                    if conf.get("tls") == "tls":
                        is_tls = True
                        sni = conf.get("sni") or conf.get("host")
                except:
                    pass

            # --- 2. Shadowsocks (SS) ---
            elif link.startswith("ss://"):
                try:
                    # 移除 ss:// 前缀
                    body = link[5:]
                    if '#' in body:
                        body = body.split('#')[0]
                    
                    # 格式 A: ss://base64_user_info@host:port
                    if '@' in body:
                        # 这种情况 host:port 是明文，user_info 是 base64
                        part_host = body.split('@')[1]
                        h, p = part_host.split(':')
                        host = h
                        port = int(p)
                    else:
                        # 格式 B: ss://base64_full
                        decoded = NodeParser.safe_base64_decode(body)
                        # 解码后通常是 method:password@host:port
                        if '@' in decoded:
                            part_host = decoded.split('@')[1]
                            h, p = part_host.split(':')
                            host = h
                            port = int(p)
                    
                    # SS 通常通过插件支持 TLS，这里简化处理，默认为 TCP
                    # 如果需要检测插件(obfs/v2ray-plugin)的 TLS，需更复杂解析
                except:
                    pass

            # --- 3. 标准 URL 格式 (Trojan, VLESS, Hysteria, etc.) ---
            else:
                try:
                    parsed = urlparse(link)
                    host = parsed.hostname
                    port = parsed.port
                    
                    # 处理 URL 参数
                    qs = parse_qs(parsed.query)
                    security = qs.get("security", [""])[0]
                    
                    # 判断 TLS
                    scheme = parsed.scheme.lower()
                    if scheme == "trojan":
                        if security != "none": is_tls = True
                    elif scheme in ["vless", "hysteria2", "hy2"]:
                        if security in ["tls", "reality", "auto"]: is_tls = True
                    
                    # 提取 SNI
                    if is_tls:
                        if "sni" in qs: sni = qs["sni"][0]
                        elif "peer" in qs: sni = qs["peer"][0]
                except:
                    pass
            
            # 端口转整数
            if port:
                port = int(port)
                
        except Exception:
            return None, None, None, False

        return host, port, sni, is_tls

async def check_connectivity(link, semaphore):
    """
    异步检测连接性
    """
    host, port, sni, is_tls = NodeParser.parse(link)
    
    if not host or not port:
        return None

    # 使用信号量限制并发
    async with semaphore:
        start_time = time.time()
        try:
            # 1. 准备 SSL 上下文 (如果需要)
            ssl_ctx = None
            if is_tls:
                # 创建一个不验证证书的 SSL 上下文，仅用于验证握手能否完成
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            
            # 2. 建立连接
            # asyncio.open_connection 同时支持 TCP 和 SSL 握手
            # server_hostname 用于发送 SNI
            future = asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=sni if is_tls else None)
            
            reader, writer = await asyncio.wait_for(future, timeout=TIMEOUT)
            
            # 3. 计算延迟
            latency = (time.time() - start_time) * 1000
            
            # 4. 关闭连接
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
                
            return (link, latency, f"{host}:{port}")

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            return None
        except Exception:
            return None

async def main():
    print(f"--- 极速节点检测器 (AsyncIO版) ---")
    
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 找不到 {INPUT_FILE}")
        return

    # 1. 读取去重
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        raw_lines = [line.strip() for line in f if line.strip()]
    
    unique_nodes = list(set(raw_lines))
    print(f"加载节点: {len(unique_nodes)} 个 (原始: {len(raw_lines)})")
    
    # 2. 异步检测任务
    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [check_connectivity(node, semaphore) for node in unique_nodes]
    
    print(f"开始检测 (并发: {CONCURRENCY}, 超时: {TIMEOUT}s)...")
    start_time = time.time()
    
    # 使用 as_completed 显示进度
    valid_nodes = []
    checked_count = 0
    total = len(tasks)
    
    for future in asyncio.as_completed(tasks):
        result = await future
        checked_count += 1
        
        if result:
            valid_nodes.append(result)
            
        # 动态进度条
        if checked_count % 10 == 0 or checked_count == total:
            elapsed = time.time() - start_time
            speed = checked_count / elapsed if elapsed > 0 else 0
            sys.stdout.write(f"\r进度: {checked_count}/{total} | 存活: {len(valid_nodes)} | 速度: {speed:.1f}/s")
            sys.stdout.flush()

    print("\n") # 换行
    
    # 3. 排序 (按延迟低到高)
    valid_nodes.sort(key=lambda x: x[1])
    
    # 4. 保存结果
    final_links = [x[0] for x in valid_nodes]
    
    try:
        # 保存明文
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(final_links))
            
        # 保存 Base64
        b64_content = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8')
        with open(SUB_FILE, 'w', encoding='utf-8') as f:
            f.write(b64_content)
            
        print(f"检测完成，耗时 {time.time() - start_time:.2f}s")
        print(f"存活节点: {len(final_links)}/{len(unique_nodes)}")
        if valid_nodes:
            print(f"最优延迟: {valid_nodes[0][1]:.2f}ms")
        print(f"结果已保存至: {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"保存文件失败: {e}")

if __name__ == "__main__":
    # Windows 下 ProactorEventLoop 性能更好，但通常默认即可
    # 如果遇到 'Event loop is closed' 错误，可尝试取消注释下面两行
    # if sys.platform == 'win32':
    #     asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户停止检测")
