#!/usr/bin/env python3
"""强化特征过滤器：过滤广告名、伪造域名、内网IP和空模板。"""

import os
import json
import base64
from urllib.parse import unquote

INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes.txt"

# 广告、通知及虚假模板黑名单
BLACKLIST = [
    # 商业广告/引流/过期状态词
    "官网", "剩余", "到期", "流量", "过期", "套餐", "续费", "充值",
    "邀请", "返利", "优惠", "折扣", "限时", "活动", "群组", "频道",
    "电报", "telegram", "t.me/", "客服", "购买", "订阅", "试用", "联系",
    "防失联", "发布页", "关注", "禁止", "通知",
    # 模板/无效地址占位符
    "example.com", "yourdomain", "mydomain", "sample.com", "test.com",
    "127.0.0.1", "localhost", "0.0.0.0",
]


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


def main() -> None:
    if not os.path.exists(INPUT_FILE):
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        lines = [ln.strip() for ln in f if len(ln.strip()) > 15]

    kept = []
    filtered = 0

    for link in lines:
        search_blob = extract_searchable_text(link)
        if any(bad in search_blob for bad in BLACKLIST):
            filtered += 1
            continue
        kept.append(link)

    print(f"清洗黑名单/模板词：过滤 {filtered} 条，保留 {len(kept)} 条")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(kept))


if __name__ == "__main__":
    main()
