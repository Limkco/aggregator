import os
import json
import base64
import hashlib

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
    """核心特征提取：无视节点备注/延迟后缀进行哈希对比"""
    link = link.strip()
    if "://" not in link:
        return hashlib.md5(link.encode('utf-8')).hexdigest()
    
    try:
        protocol, rest = link.split("://", 1)
        protocol = protocol.lower()
        
        # vmess 需要解密 base64 后剔除 'ps' (备注) 字段
        if protocol == "vmess":
            decoded = safe_base64_decode(rest)
            if decoded:
                conf = json.loads(decoded)
                conf.pop("ps", None) 
                conf_str = json.dumps(conf, sort_keys=True)
                return hashlib.md5(f"vmess://{conf_str}".encode('utf-8')).hexdigest()
        
        # 其他协议直接去除 # 后面的备注信息
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
            
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        for link in lines:
            nhash = get_node_hash(link)
            if nhash not in seen_hashes:
                seen_hashes.add(nhash)
                unique_nodes.append(link)

    print(f"合并并去重后，即将送入测速环节的总节点数: {len(unique_nodes)}")
    
    # 覆盖原 nodes.txt 供下游（关键字过滤和测速）读取
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("\n".join(unique_nodes))

if __name__ == "__main__":
    main()
