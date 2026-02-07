import os
import json
import base64
import socket
import concurrent.futures
from urllib.parse import urlparse, unquote

# --- 配置 ---
INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes.txt"
SUB_FILE = "sub.txt"
TIMEOUT = 3          # TCP 连接超时时间（秒）
MAX_WORKERS = 50     # 并发线程数

def parse_node_info(node_link):
    """
    解析节点链接，提取 (host, port)。
    支持 vmess, ss, trojan, vless, hysteria2 等常用格式。
    """
    node_link = node_link.strip()
    host, port = None, None

    try:
        if node_link.startswith("vmess://"):
            # VMess 协议：Base64 解码 -> JSON 解析
            b64_str = node_link[8:]
            # 补全 Base64 填充
            padding = len(b64_str) % 4
            if padding > 0:
                b64_str += "=" * (4 - padding)
            
            try:
                conf_str = base64.b64decode(b64_str).decode("utf-8")
                conf = json.loads(conf_str)
                host = conf.get("add")
                port = conf.get("port")
            except Exception:
                pass

        elif node_link.startswith("ss://"):
            # Shadowsocks 协议
            # 格式 1: ss://method:pass@host:port
            # 格式 2 (Aggregator 生成): ss://base64_user_info@host:port#name
            try:
                parsed = urlparse(node_link)
                host = parsed.hostname
                port = parsed.port
                
                # 如果 urlparse 没解析出 host (可能是旧版纯 Base64 格式 ss://Base64)
                if not host and '#' not in node_link and '@' not in node_link:
                    # 尝试解码 ss:// 后面的部分
                    body = node_link[5:]
                    padding = len(body) % 4
                    if padding > 0: body += "=" * (4 - padding)
                    decoded = base64.b64decode(body).decode("utf-8")
                    # 解码后通常是 method:pass@host:port
                    if '@' in decoded:
                        part = decoded.split('@')[1]
                        host, port_str = part.split(':')
                        port = int(port_str)
            except Exception:
                pass

        else:
            # 通用格式 (trojan://, vless://, hysteria2:// 等)
            # 结构通常为 protocol://user@host:port...
            try:
                parsed = urlparse(node_link)
                host = parsed.hostname
                port = parsed.port
            except Exception:
                pass
                
        # 确保端口是整数
        if port is not None:
            port = int(port)
            
    except Exception as e:
        # print(f"解析错误: {e}")
        pass

    return host, port

def is_port_open(host, port):
    """
    测试 TCP 端口连通性
    """
    if not host or not port:
        return False
        
    try:
        # 创建 socket 连接
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return True
    except (socket.timeout, socket.error):
        return False
    except Exception:
        return False

def check_node(node):
    """
    工作线程函数：解析并测试单个节点
    """
    host, port = parse_node_info(node)
    
    if host and port:
        if is_port_open(host, port):
            print(f"[在线] {host}:{port}")
            return node
        else:
            # print(f"[离线] {host}:{port}")
            return None
    else:
        # 如果无法解析出地址端口，保守起见保留或丢弃？这里选择丢弃非法格式
        # print(f"[跳过] 格式无法解析")
        return None

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 找不到文件 {INPUT_FILE}")
        return

    print(f"正在读取 {INPUT_FILE} ...")
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        # 过滤空行
        nodes = [line.strip() for line in f if line.strip()]

    total = len(nodes)
    print(f"共加载 {total} 个节点，开始 TCP 连通性测试 (超时: {TIMEOUT}秒)...")

    valid_nodes = []
    
    # 使用线程池并发测试
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(check_node, node): node for node in nodes}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_node)):
            result = future.result()
            if result:
                valid_nodes.append(result)
            
            # 简单的进度显示
            if (i + 1) % 10 == 0:
                print(f"进度: {i + 1}/{total}")

    print("-" * 30)
    print(f"检测完成！")
    print(f"原始节点数: {total}")
    print(f"有效节点数: {len(valid_nodes)}")
    print("-" * 30)

    # 1. 保存到 nodes.txt (明文)
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(valid_nodes))
        print(f"已更新: {OUTPUT_FILE}")
    except Exception as e:
        print(f"保存 {OUTPUT_FILE} 失败: {e}")

    # 2. 同步保存到 sub.txt (Base64 订阅)
    # Aggregator 也会生成这个文件，为了保持一致性，这里也顺便更新
    try:
        plain_text = "\n".join(valid_nodes)
        b64_content = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
        with open(SUB_FILE, 'w', encoding='utf-8') as f:
            f.write(b64_content)
        print(f"已同步更新订阅文件: {SUB_FILE}")
    except Exception as e:
        print(f"保存 {SUB_FILE} 失败: {e}")

if __name__ == "__main__":
    main()
