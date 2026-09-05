#!/usr/bin/env python3
"""强化特征过滤器：过滤广告名、伪造域名、内网IP和空模板，支持通用动态黑名单列表。"""

import base64
import json
import os

INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes.txt"

# 1. 基础广告、通知及虚假模板黑名单
BLACKLIST = [
    # 商业广告/引流/过期状态词
    "官网",
    "剩余",
    "到期",
    "流量",
    "过期",
    "套餐",
    "续费",
    "充值",
    "邀请",
    "返利",
    "优惠",
    "折扣",
    "限时",
    "活动",
    "群组",
    "频道",
    "电报",
    "telegram",
    "t.me/",
    "客服",
    "购买",
    "订阅",
    "试用",
    "联系",
    "防失联",
    "发布页",
    "关注",
    "禁止",
    "通知",
    # 模板/无效地址占位符
    "example.com",
    "yourdomain",
    "mydomain",
    "sample.com",
    "test.com",
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
]

# 2. 动态过滤规则列表：可任意添加协议名(如 "trojan")、特征词(如 "reality")或条件表达式(如 "tls=0")
FILTER_RULES = ["vmess", "reality", "tls=0", "trojan"]


def safe_b64decode(text: str) -> str:
    if not text:
        return ""
    text = text.strip().replace("-", "+").replace("_", "/")
    pad = len(text) % 4
    if pad:
        text += "=" * (4 - pad)
    try:
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_searchable_text(link: str) -> str:
    """提取链接所有可显文本（包括 Base64 内部）用于敏感词拦截"""
    text = link.lower()
    if link.startswith("vmess://"):
        conf = safe_b64decode(link[8:].split("#")[0])
        return text + " " + conf.lower()
    return text


def should_filter_node(link: str, rules: list) -> bool:
    """通用动态过滤匹配器，无需为新协议编写独立 if 分支"""
    link_lower = link.lower()

    # 预解析 VMess 内部配置
    vmess_json_str = ""
    vmess_conf = {}
    if link_lower.startswith("vmess://"):
        try:
            conf_str = safe_b64decode(link[8:].split("#")[0])
            if conf_str:
                vmess_json_str = conf_str.lower()
                vmess_conf = json.loads(conf_str)
        except Exception:
            pass

    for rule in rules:
        rule_clean = rule.lower().strip()
        if not rule_clean:
            continue

        # 逻辑 A: 条件判断规则（如 "tls=0" 过滤无 TLS 节点）
        if rule_clean == "tls=0":
            if link_lower.startswith("vmess://"):
                tls_val = str(vmess_conf.get("tls", "")).lower()
                if tls_val in ["", "none", "0", "false"]:
                    return True
            else:
                has_tls = (
                    "security=tls" in link_lower
                    or "security=reality" in link_lower
                    or "tls=1" in link_lower
                )
                if not has_tls:
                    return True
            continue

        # 逻辑 B: 通用协议头匹配（如 "trojan" -> 匹配 "trojan://"）
        if link_lower.startswith(f"{rule_clean}://"):
            return True

        # 逻辑 C: 通用字符串/特征匹配（如 "reality" -> 匹配 URL 或 VMess 配置中的对应文本）
        if rule_clean in link_lower or rule_clean in vmess_json_str:
            return True

    return False


def main() -> None:
    if not os.path.exists(INPUT_FILE):
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        lines = [ln.strip() for ln in f if len(ln.strip()) > 15]

    kept = []
    filtered = 0

    for link in lines:
        # 基础广告文本黑名单匹配
        search_blob = extract_searchable_text(link)
        if any(bad in search_blob for bad in BLACKLIST):
            filtered += 1
            continue

        # 通用节点规则过滤匹配
        if should_filter_node(link, FILTER_RULES):
            filtered += 1
            continue

        kept.append(link)

    print(f"清洗完成：过滤 {filtered} 条，保留 {len(kept)} 条")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(kept))


if __name__ == "__main__":
    main()
