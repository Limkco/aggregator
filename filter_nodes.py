import os
import json
import base64
from urllib.parse import unquote

# --- 配置部分 ---
INPUT_FILE = "nodes.txt"           # 输入的节点文件
OUTPUT_FILE = "nodes_filtered.txt" # 过滤后输出的节点文件
SUB_FILE = "sub_filtered.txt"      # 过滤后生成的 Base64 订阅文件

# 在这里设置你需要过滤的关键字（黑名单）
# 例如过滤掉名字中带有"官网"、"剩余流量"、"到期"等说明性节点
BLACKLIST_KEYWORDS = [
    "官网", 
    "剩余", 
    "到期", 
    "流量", 
    "过期",
    "套餐",
    "hy",
    "pages",
    "Workers"
]

def safe_base64_decode(text):
    """安全的 Base64 解码，兼容现有的处理逻辑"""
    if not text:
        return ""
    text = text.strip().replace('-', '+').replace('_', '/')
    padding = len(text) % 4
    if padding > 0:
        text += '=' * (4 - padding)
    try:
        return base64.b64decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def get_node_name(link):
    """
    提取节点名称(备注)
    支持 vmess 的 JSON 'ps' 字段解析
    支持 ss/trojan/vless 等协议的 URL # 后缀解析
    """
    link = link.strip()
    
    # 1. 处理 VMess 协议
    if link.startswith("vmess://"):
        try:
            b64_str = link[8:]
            json_str = safe_base64_decode(b64_str)
            conf = json.loads(json_str)
            return conf.get("ps", "")
        except Exception:
            return ""
            
    # 2. 处理包含 '#' 的通用 URI 协议 (ss, trojan, vless, hysteria2 等)
    elif "#" in link:
        try:
            name_part = link.split("#", 1)[1]
            # URL 解码，将 %20 等恢复为正常字符以便匹配
            return unquote(name_part)
        except Exception:
            return ""
            
    return ""

def main():
    print("--- 节点关键字过滤脚本 ---")
    
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 找不到输入文件 {INPUT_FILE}")
        return

    # 读取原始节点
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        raw_lines = [line.strip() for line in f if line.strip()]
        
    print(f"初始读取节点数: {len(raw_lines)}")
    
    valid_nodes = []
    filtered_count = 0

    # 执行过滤逻辑
    for link in raw_lines:
        node_name = get_node_name(link)
        
        is_banned = False
        # 遍历黑名单关键字
        for keyword in BLACKLIST_KEYWORDS:
            # 同时检查节点名称和原始链接中是否包含关键字
            if keyword in node_name or keyword in unquote(link):
                is_banned = True
                break
                
        if not is_banned:
            valid_nodes.append(link)
        else:
            filtered_count += 1
            # 开启调试时可打印被过滤的节点名称
            # print(f"已过滤: {node_name or '未知名称'}")

    # 保存明文节点结果
    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(valid_nodes))
            
        # 同时生成 Base64 订阅文件，保持与你的项目生态一致
        b64_content = base64.b64encode("\n".join(valid_nodes).encode('utf-8')).decode('utf-8')
        with open(SUB_FILE, 'w', encoding='utf-8') as f:
            f.write(b64_content)
            
        print(f"过滤完成！")
        print(f"命中关键字被剔除的节点数: {filtered_count}")
        print(f"最终保留的有效节点数: {len(valid_nodes)}")
        print(f"明文结果已保存至: {OUTPUT_FILE}")
        print(f"订阅结果已保存至: {SUB_FILE}")
        
    except Exception as e:
        print(f"保存文件时发生错误: {e}")

if __name__ == "__main__":
    main()
