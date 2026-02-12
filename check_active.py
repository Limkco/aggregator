import os
import json
import base64
import socket
import ssl
import concurrent.futures
import time
from urllib.parse import urlparse, parse_qs

# --- 配置 ---
INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes.txt"
SUB_FILE = "sub.txt"
TIMEOUT = 2          # 每次 Socket 连接的超时时间
MAX_WORKERS = 40     # 并发数
MAX_TOTAL_TIME = 180 # 全局最大运行时间（秒）

def safe_base64_decode(text):
    """辅助解码函数"""
    if not text: return ""
    text = text.strip().replace('-', '+').replace('_', '/')
    padding = len(text) % 4
    if padding > 0: text += '=' * (4 - padding)
    try:
        return base64.b64decode(text).decode('utf-8')
    except:
        return ""

def parse_node_info(node_link):
    """
    解析节点链接，提取 (host, port, sni, is_tls)。
    返回: (host, port, sni, is_tls)
    """
    node_link = node_link.strip()
    host, port, sni, is_tls = None, None, None, False

    try:
        # --- 1. VMess ---
        if node_link.startswith("vmess://"):
            try:
                b64_str = node_link[8:]
                conf_str = safe_base64_decode(b64_str)
                conf = json.loads(conf_str)
                
                host = conf.get("add")
                port = conf.get("port")
                
                # 判断 TLS
                if conf.get("tls") == "tls":
                    is_tls = True
                    # 提取 SNI：优先取 sni 字段，其次取 host 字段（ws header）
                    sni = conf.get("sni")
                    if not sni:
                        sni = conf.get("host")
            except:
                pass

        # --- 2. SS (Shadowsocks) ---
        elif node_link.startswith("ss://"):
            # SS 原生通常无 TLS，除非插件。此处为简化，默认 SS 视为 TCP 节点
            try:
                parsed = urlparse(node_link)
                host = parsed.hostname
                port = parsed.port
                
                # 处理旧版 SS Base64
                if not host:
                    decoded = safe_base64_decode(node_link[5:].split('#')[0])
                    if '@' in decoded:
                        part = decoded.split('@')[1]
                        h, p = part.split(':')
                        host = h
                        port = int(p)
            except:
                pass

        # --- 3. 通用 (Trojan, VLESS, Hysteria) ---
        else:
            try:
                parsed = urlparse(node_link)
                host = parsed.hostname
                port = parsed.port
                qs = parse_qs(parsed.query)

                # 判断 TLS
                security = qs.get("security", [""])[0]
                if node_link.startswith("trojan://"):
                    # Trojan 默认是 TLS，除非 security=none
                    if security != "none":
                        is_tls = True
                elif security in ["tls", "reality", "auto"]:
                    is_tls = True
                
                # 提取 SNI
                if is_tls:
                    # 优先看 sni 参数，其次看 peer 参数
                    if "sni" in qs:
                        sni = qs["sni"][0]
                    elif "peer" in qs:
                        sni = qs["peer"][0]
                    # 如果都没有，有时 host 本身就是 SNI（对于非 CDN 节点），暂不强行赋值
            except:
                pass
                
        if port is not None:
            port = int(port)
            
    except Exception:
        pass

    return host, port, sni, is_tls

def check_tcp_ping(host, port):
    """
    第一步：TCP 握手测速
    返回: (is_success, latency_ms)
    """
    if not host or not port:
        return False, 0
        
    start_time = time.time()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            latency = (time.time() - start_time) * 1000
            return True, latency
    except:
        return False, 0

def check_tls_handshake(host, port, sni):
    """
    第二步：TLS/SSL 握手测试 (验证 SNI)
    返回: True/False
    """
    try:
        # 创建 SSL 上下文
        context = ssl.create_default_context()
        #以此避开自签名证书错误，只验证连接和握手是否完成
        context.check_hostname = False 
        context.verify_mode = ssl.CERT_NONE 
        
        # 建立基础 TCP 连接
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            # 包装 SSL
            with context.wrap_socket(sock, server_hostname=sni if sni else host) as ssock:
                # 获取协议版本，如果能获取到说明握手成功
                version = ssock.version()
                return True
    except Exception:
        # 握手失败（包括 SNI 被阻断、超时等）
        return False

def check_node_task(node_link):
    """
    综合测试任务：TCP Ping -> (如果是TLS) -> TLS Handshake
    """
    host, port, sni, is_tls = parse_node_info(node_link)
    
    if not host or not port:
        return None

    # 1. 阶段一：TCP Ping
    tcp_success, latency = check_tcp_ping(host, port)
    if not tcp_success:
        return None # 连 TCP 都不通，直接丢弃

    # 2. 阶段二：如果是 TLS 节点，进行 SNI 检测
    if is_tls:
        # 如果没有提取到 SNI，通常用 host 作为 sni 尝试
        target_sni = sni if sni else host
        tls_success = check_tls_handshake(host, port, target_sni)
        
        if not tls_success:
            # TCP 通但 TLS 握手失败（可能是 SNI 阻断或伪装失效）
            return None 

    # 全部通过
    # 构造返回信息：(原始链接, 延迟, 调试信息)
    info = f"{host}:{port}"
    if is_tls:
        info += f" (SNI:{sni if sni else 'Host'})"
    
    return (node_link, latency, info)

def main():
    start_time = time.time()
    
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 找不到 {INPUT_FILE}")
        return

    print(f"读取 {INPUT_FILE}...")
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        nodes = [line.strip() for line in f if line.strip()]

    total = len(nodes)
    print(f"加载节点: {total} 个")
    print(f"策略: TCP Ping (全部) -> TLS Handshake (仅 TLS 节点)")
    print(f"参数: 超时 {TIMEOUT}s | 并发 {MAX_WORKERS}")

    valid_results = []
    checked_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(check_node_task, node): node for node in nodes}
        
        try:
            for future in concurrent.futures.as_completed(future_to_node):
                # 防风控：超时保护
                if time.time() - start_time > MAX_TOTAL_TIME:
                    print(f"\n[警告] 达到最大运行时间 {MAX_TOTAL_TIME}s，停止检测！")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                result = future.result()
                if result:
                    node_link, latency, info = result
                    valid_results.append((node_link, latency))
                    # 打印日志（可选，为了不刷屏可以注释掉 print）
                    # print(f"[可用] {latency:5.1f}ms | {info}")
                
                checked_count += 1
                if checked_count % 20 == 0:
                    print(f"进度: {checked_count}/{total} | 当前可用: {len(valid_results)}")

        except KeyboardInterrupt:
            print("\n用户中断")

    # 排序
    print(f"\n检测结束，进行延迟排序...")
    valid_results.sort(key=lambda x: x[1])
    
    final_nodes = [x[0] for x in valid_results]
    
    print("-" * 30)
    print(f"原始数量: {total}")
    print(f"存活数量: {len(final_nodes)}")
    if final_nodes:
        print(f"最优延迟: {valid_results[0][1]:.1f}ms")
    print("-" * 30)

    # 保存
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("\n".join(final_nodes))
    
    b64_content = base64.b64encode("\n".join(final_nodes).encode('utf-8')).decode('utf-8')
    with open(SUB_FILE, 'w', encoding='utf-8') as f:
        f.write(b64_content)
        
    print(f"结果已保存至 {OUTPUT_FILE} 和 {SUB_FILE}")

if __name__ == "__main__":
    main()
