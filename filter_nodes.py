#!/usr/bin/env python3
"""Filter nodes by blacklist keywords (name + deep payload).

Stronger blacklist to remove ads, expired promo, workers pages, etc.
"""

import os
import json
import base64
from urllib.parse import unquote

INPUT_FILE = "nodes.txt"
OUTPUT_FILE = "nodes_filtered.txt"
SUB_FILE = "sub_filtered.txt"

# 更强黑名单：广告 / 过期提示 / 常见无效来源 (已剔除协议关键字 hy2/hysteria 避免误杀正常节点)
BLACKLIST = [
    # 中文广告与过期提示
    "官网", "剩余", "到期", "流量", "过期", "套餐", "续费", "充值",
    "邀请", "返利", "优惠", "折扣", "限时", "活动", "群组", "频道",
    "电报", "tg", "telegram", "客服", "购买", "订阅", "试用",
    # 技术噪音 / 常见无效
    "pages.dev", "workers.dev", "cloudflare", "cf-workers",
    "localhost", "127.0.0.1", "0.0.0.0",
    "example.com", "test.com",
    # 常见垃圾备注
    "免费", "白嫖", "稳定", "高速", "推荐", "最新",
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


def get_name(link: str) -> str:
    link = link.strip()
    if link.startswith("vmess://"):
        try:
            b64 = link[8:].split("#")[0]
            conf = json.loads(safe_b64decode(b64) or "{}")
            return str(conf.get("ps", ""))
        except Exception:
            return ""
    if "#" in link:
        try:
            return unquote(link.split("#", 1)[1])
        except Exception:
            return ""
    return ""


def get_payload(link: str) -> str:
    """Extract deep content for blacklist matching."""
    link = link.strip()
    if link.startswith("vmess://"):
        b64 = link[8:].split("#")[0]
        return safe_b64decode(b64).lower()
    if link.startswith("ss://"):
        try:
            body = link[5:].split("#")[0]
            if "@" not in body:
                return safe_b64decode(body).lower()
            user = body.split("@", 1)[0]
            return safe_b64decode(user).lower()
        except Exception:
            return ""
    return ""


def main() -> None:
    print("--- Keyword filter (stronger) ---")
    if not os.path.exists(INPUT_FILE):
        print(f"Error: {INPUT_FILE} not found")
        return

    with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
        lines = [ln.strip() for ln in f if ln.strip()]
    print(f"Input nodes: {len(lines)}")

    blacklist = [kw.lower() for kw in BLACKLIST]
    kept = []
    filtered = 0

    for link in lines:
        name = get_name(link).lower()
        full = unquote(link).lower()
        payload = get_payload(link)

        banned = any(kw in name or kw in full or kw in payload for kw in blacklist)
        if banned:
            filtered += 1
        else:
            kept.append(link)

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(kept))
        b64 = base64.b64encode("\n".join(kept).encode()).decode()
        with open(SUB_FILE, "w", encoding="utf-8") as f:
            f.write(b64)
        print(f"Filtered out: {filtered}")
        print(f"Kept: {len(kept)}")
        print(f"Saved {OUTPUT_FILE} / {SUB_FILE}")
    except Exception as e:
        print(f"Save failed: {e}")


if __name__ == "__main__":
    main()
