import os
import json
import base64
import hashlib
from urllib.parse import urlparse, parse_qs

# --- 配置部分 ---
INPUT_RAW = "nodes.txt"               # 本轮新聚合的节点
INPUT_PREV = "previous_nodes.txt"     # 上一轮（release分支）的节点
OUTPUT_FILE = "nodes.txt"             # 合并去重后的输出文件（覆盖原文件给下游使用）

def safe_base64_decode(text):
    """安全的 Base64 解码"""
    if not text:
        return None
    text = text.strip().replace(' ', '').replace('\n', '').replace('\r', '')
    text = text.replace('-', '+').replace('_', '/')
    padding = len(text) % 4
    if padding > 0:
        text += '=' * (4 - padding)
    try:
        return base64.b64decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def get_node_hash(link):
    """核心特征提取：优先按 SNI/Host 进行哈希去重，无 SNI 时回退到核心参数"""
    link = link.strip()
    if "://" not in link:
        return hashlib.md5(link.encode('utf-8')).hexdigest()
    
    # --- 提取 SNI/Host 作为唯一标识 ---
    try:
        protocol, rest = link.split("://", 1)
        protocol = protocol.lower()
        
        sni = None
        if protocol == "vmess":
            # [深度修复 1] 强制剥离尾随的畸形备注，防止 Base64 解码雪崩导致去重失效
            b64_core = rest.split('#')[0]
            decoded = safe_base64_decode(b64_core)
            if decoded:
                conf = json.loads(decoded)
                sni = conf.get("sni") or conf.get("host") or conf.get("add")
        else:
            parsed = urlparse(link)
            qs = parse_qs(parsed.query)
            sni = qs.get("sni", [None])[0] or qs.get("peer", [None])[0]
            if not sni:
                sni = parsed.hostname
            # 兼容未带标准认证头（@）的特殊情况（如部分旧版 ss）
            if not sni and '@' in rest:
                body = rest.split('#')[0]
                part_host = body.split('@')[-1]
                
                # [深度修复 2] 剥离混淆插件参数并安全处理 IPv6 的特征提取
                part_host = part_host.split('/?')[0].split('?')[0]
                if part_host.startswith('['):
                    sni = part_host.rsplit(':', 1)[0].strip('[]')
                else:
                    sni = part_host.rsplit(':', 1)[0]
                
        if sni:
            return hashlib.md5(f"sni_{sni}".encode('utf-8')).hexdigest()
    except Exception:
        pass

    # --- 回退：无视节点备注/延迟后缀进行哈希对比 ---
    try:
        protocol, rest = link.split("://", 1)
        protocol = protocol.lower()
        
        if protocol == "vmess":
            # [深度修复 1] 同步在回退逻辑中剥离尾巴
            b64_core = rest.split('#')[0]
            decoded = safe_base64_decode(b64_core)
            if decoded:
                conf = json.loads(decoded)
                conf.pop("ps", None) 
                conf_str = json.dumps(conf, sort_keys=True)
                return hashlib.md5(f"vmess://{conf_str}".encode('utf-8')).hexdigest()
        
        core = rest.split("#")[0]
        return hashlib.md5(f"{protocol}://{core}".encode('utf-8')).hexdigest()
    except Exception:
        return hashlib.md5(link.encode('utf-8')).hexdigest()

def main():
    print("--- 历史节点与新节点合并去重 ---")
    seen_hashes = set()
    unique_nodes = []

    # 按顺序读取：先读取本轮新聚合的节点，再读取历史节点
    files_to_read = [INPUT_RAW]
    if os.path.exists(INPUT_PREV):
        files_to_read.append(INPUT_PREV)

    for filepath in files_to_read:
        if not os.path.exists(filepath):
            continue
            
        # 使用 utf-8-sig 安全读取，剥离可能的 Windows BOM 头 (\ufeff)
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        for link in lines:
            # 增加基础的有效性与长度校验，防止无效脏数据引发的无意义哈希和空间浪费
            if len(link) < 15 or "://" not in link:
                continue
                
            nhash = get_node_hash(link)
            if nhash not in seen_hashes:
                seen_hashes.add(nhash)
                unique_nodes.append(link)

    print(f"合并并去重后，即将送入测速环节的总节点数: {len(unique_nodes)}")
    
    # 覆盖原 nodes.txt 供下游（关键字过滤和测速）读取，输出依然采用标准 utf-8
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_nodes))

if __name__ == "__main__":
    main()
