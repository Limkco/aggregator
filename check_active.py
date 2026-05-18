import sys
import os
import re
import json
import base64
import asyncio
import ssl
import time
import logging
import socket # 用于 DNS 解析
import ipaddress # [深度修复 4] 用于校验 SNI 是否为纯 IP
from urllib.parse import urlparse, parse_qs, unquote, quote 

# --- 优化项: 严格版本兼容性断言 ---
assert sys.version_info >= (3, 11), "SSL 检测要求 Python 3.11+"

# --- 附加功能: GeoIP 数据库初始化 ---
try:
    import maxminddb
    GEO_DB_PATH = "geoip.mmdb"
    geo_reader = maxminddb.open_database(GEO_DB_PATH) if os.path.exists(GEO_DB_PATH) else None
except ImportError:
    geo_reader = None

async def get_country_code_async(host: str) -> str:
    """[深度修复] 异步包装并支持 IPv4/IPv6 双栈解析，彻底释放并发性能"""
    if not geo_reader: return "UNK"
    try:
        loop = asyncio.get_running_loop()
        # [修复] 使用 getaddrinfo 替代 gethostbyname 以支持 IPv6
        addr_info = await loop.run_in_executor(None, socket.getaddrinfo, host, None)
        if addr_info:
            # 提取解析到的第一个 IP 地址 (兼容 v4 和 v6)
            ip = addr_info[0][4][0]
            res = geo_reader.get(ip)
            if res and 'country' in res:
                return res['country']['iso_code']
    except Exception:
        pass
    return "UNK"

# --- 配置部分 ---
INPUT_FILE = "nodes.txt"       # 聚合生成的原始节点文件
OUTPUT_FILE = "nodes.txt"      # 清洗后的明文节点文件
SUB_FILE = "sub.txt"           # Base64 订阅文件

# 最大保留节点数量 (防止长期运行导致文件无限膨胀)
MAX_NODES = 10000

# 并发数 (根据网络情况调整)
CONCURRENCY = 200              
# 超时设置 (秒)
TCP_TIMEOUT = 2    # TCP 连接超时 (快速筛选)
SSL_TIMEOUT = 3    # SSL 握手超时 (验证可用性)

# [防毒化修复] 预编译标准 UUID 正则，用于拦截非法格式的 VLESS/VMess 节点
UUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

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
        返回: (host, port, sni, is_tls, is_udp)
        """
        link = link.strip()
        host, port, sni, is_tls, is_udp = None, None, None, False, False
        
        try:
            # --- 1. VMess ---
            if link.startswith("vmess://"):
                try:
                    # [深度修复 1] 强制剥离尾随的 #备注，防止 Base64 解码雪崩
                    b64_str = link[8:].split('#')[0]
                    json_str = NodeParser.safe_base64_decode(b64_str)
                    conf = json.loads(json_str)
                    
                    # 拦截格式非法的伪造 UUID
                    if not UUID_PATTERN.match(str(conf.get("id", ""))):
                        return None, None, None, False, False
                        
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
                        # [深度修复 2] 剥离尾随的 /?plugin= 混淆插件参数
                        part_host = part_host.split('/?')[0].split('?')[0]
                        
                        # [深度修复 2] 安全处理 IPv6 和 IPv4 的端口切分
                        if part_host.startswith('['):
                            # 处理 IPv6 格式，例如 [2001:db8::1]:8388
                            h, p = part_host.rsplit(':', 1)
                            host = h.strip('[]')
                            port = int(p)
                        else:
                            h, p = part_host.rsplit(':', 1)
                            host = h
                            port = int(p)
                except: pass

            # --- 3. URL Schema (Trojan, VLESS, Hysteria2) ---
            else:
                try:
                    parsed = urlparse(link)
                    scheme = parsed.scheme.lower()
                    
                    if scheme == "vless":
                        if not UUID_PATTERN.match(str(parsed.username or "")):
                            return None, None, None, False, False
                            
                    host = parsed.hostname
                    port = parsed.port
                    qs = parse_qs(parsed.query)
                    security = qs.get("security", [""])[0]
                    
                    # Trojan
                    if scheme == "trojan":
                        if security != "none": is_tls = True
                    
                    # Hysteria2 / hy2 (基于 QUIC 纯 UDP 协议)
                    elif scheme in ["hysteria2", "hy2"]:
                        is_tls = True
                        is_udp = True # [深度修复 3] 标记为 UDP 协议，跳过 TCP 测速
                        
                    # VLESS
                    elif scheme == "vless":
                        if security in ["tls", "reality", "auto"]: is_tls = True
                    
                    if is_tls:
                        if "sni" in qs: sni = qs["sni"][0]
                        elif "peer" in qs: sni = qs["peer"][0]
                except: pass
            
            if port: port = int(port)
                
        except Exception:
            return None, None, None, False, False

        return host, port, sni, is_tls, is_udp

async def check_connectivity(link, semaphore):
    """
    分阶段检测：
    1. 静态过滤非 TLS
    2. TCP Ping (连接端口)
    3. SSL Handshake (验证协议)
    """
    host, port, sni, is_tls, is_udp = NodeParser.parse(link)
    
    # 过滤掉非 TLS，但保留被标记为 is_udp 的协议 (Hysteria2)
    if not is_tls and not is_udp:
        return None
    if not host or not port:
        return None

    async with semaphore:
        writer = None
        try:
            start_time = time.time()
            
            if is_udp:
                # [深度修复 3] Hysteria2 协议直接放行，虚拟一个极低的延迟使其排在前面
                total_latency = 0 
            else:
                # 建立纯 TCP 连接
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), 
                    timeout=TCP_TIMEOUT
                )
                tcp_latency = (time.time() - start_time) * 1000
                
                # [深度修复 4] 校验 SNI 是否为纯 IP，如果是则置为 None，防止 OpenSSL 崩溃
                tls_sni = sni
                if sni:
                    try:
                        ipaddress.ip_address(sni)
                        tls_sni = None 
                    except ValueError:
                        pass
                
                # 准备 SSL 上下文
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                
                start_ssl = time.time()
                await asyncio.wait_for(
                    writer.start_tls(ssl_ctx, server_hostname=tls_sni),
                    timeout=SSL_TIMEOUT
                )
                ssl_handshake_latency = (time.time() - start_ssl) * 1000
                total_latency = tcp_latency + ssl_handshake_latency
                
                # 安全关闭
                writer.close()
                try: await writer.wait_closed()
                except: pass
            
            # 查询地理位置
            cc = await get_country_code_async(host)
            
            # 正则清除旧的测速和地区后缀
            def clean_remark(name):
                return re.sub(r'(?:-[A-Za-z]{2,3}(?:\d+ms|UDP))+$', '', str(name))
            
            # UDP 节点打上特殊标签，TCP 节点显示实际延迟
            latency_str = "UDP" if is_udp else f"{total_latency:.0f}ms"
            
            new_link = link
            if link.startswith("vmess://"):
                try:
                    # [深度修复 1] 重组写入时，依然要先剥离可能的尾巴
                    b64_core = link[8:].split('#')[0]
                    conf = json.loads(NodeParser.safe_base64_decode(b64_core))
                    clean_ps = clean_remark(conf.get("ps", ""))
                    conf["ps"] = f"{clean_ps}-{cc}{latency_str}"
                    new_link = "vmess://" + base64.b64encode(json.dumps(conf, separators=(',', ':')).encode('utf-8')).decode('utf-8')
                except Exception:
                    parts = link.split("#", 1)
                    original_name = unquote(parts[1]) if len(parts) > 1 else ""
                    clean_name = clean_remark(original_name)
                    new_remark = f"{clean_name}-{cc}{latency_str}"
                    new_link = parts[0] + "#" + quote(new_remark)
            else:
                parts = link.split("#", 1)
                original_name = unquote(parts[1]) if len(parts) > 1 else ""
                clean_name = clean_remark(original_name)
                new_remark = f"{clean_name}-{cc}{latency_str}"
                new_link = parts[0] + "#" + quote(new_remark)

            return (new_link, total_latency, f"{host}:{port}")

        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
            if writer:
                try:
                    writer.close()
                except: pass
            return None
        except Exception as e:
            logger.debug(f"节点检测发生内部异常 {host}:{port} - {type(e).__name__}: {str(e)}")
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
    with open(INPUT_FILE, 'r', encoding='utf-8-sig') as f:
        raw_lines = [line.strip() for line in f if line.strip()]
    unique_nodes = list(set(raw_lines))
    print(f"初始节点数: {len(unique_nodes)}")
    
    # 2. 启动异步检测
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
            sys.stdout.write(f"\r进度: {checked_count}/{total} | 存活(TLS/UDP): {len(valid_nodes)} | 速度: {speed:.1f}/s")
            sys.stdout.flush()

    print("\n")
    
    # 3. 排序 (延迟低优先，Hysteria2 的 0 延迟会排在最优质档位)
    valid_nodes.sort(key=lambda x: x[1])
    
    # 截取前 MAX_NODES 个最优节点
    final_links = [x[0] for x in valid_nodes][:MAX_NODES]
    
    # 4. 保存
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(final_links))
            
        b64_content = base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8')
        with open(SUB_FILE, 'w', encoding='utf-8') as f:
            f.write(b64_content)
            
        print(f"筛选完成，耗时 {time.time() - start_time:.2f}s")
        print(f"检测存活节点: {len(valid_nodes)} 个，根据策略保留最优的 {len(final_links)} 个")
        if valid_nodes:
            print(f"最优节点延迟: {valid_nodes[0][1]:.2f}ms (UDP 显示 0ms)")
        print(f"结果已保存至 {OUTPUT_FILE}")
        
    except Exception as e:
        print(f"保存失败: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n用户停止检测")
