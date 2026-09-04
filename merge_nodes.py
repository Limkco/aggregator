#!/usr/bin/env python3
"""节点指纹合并器：规范化节点，防止重复并剔除畸形链接。"""

import os
import json
import base64
import hashlib
from urllib.parse import urlparse, parse_qs

INPUT_RAW = "nodes.txt"
INPUT_PREV = "previous_nodes.txt"
OUTPUT_FILE = "nodes.txt"


def safe_b64decode(text: str) -> str | None:
    if not text:
        return None
    text = text.strip().replace("-", "+").replace("_", "/")
    pad = len(text) % 4
    if pad:
        text += "=" * (4 - pad)
    try:
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return None


def get_node_hash(link: str) -> str:
    link = link.strip()
    if "://" not in link:
        return hashlib.md5(link.encode()).hexdigest()

    try:
        protocol, rest = link.split("://", 1)
        protocol = protocol.lower()
        core = rest.split("#")[0]
        sni = None

        if protocol == "vmess":
            decoded = safe_b64decode(core)
            if decoded:
                conf = json.loads(decoded)
                sni = conf.get("sni") or conf.get("host") or conf.get("add")
                conf.pop("ps", None)
                core = json.dumps(conf, sort_keys=True)
        else:
            parsed = urlparse(link)
            qs = parse_qs(parsed.query)
            sni = (qs.get("sni") or qs.get("peer") or [parsed.hostname])[0]

        feature_str = f"{protocol}://{core}" + (f"?sni={sni}" if sni else "")
        return hashlib.md5(feature_str.encode()).hexdigest()
    except Exception:
        return hashlib.md5(link.encode()).hexdigest()


def main() -> None:
    seen: set[str] = set()
    unique: list[str] = []

    # 优先合并当前新检测存活的节点，再补充旧节点
    files = [INPUT_RAW]
    if os.path.exists(INPUT_PREV):
        files.append(INPUT_PREV)

    for path in files:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8-sig") as f:
            for line in f:
                link = line.strip()
                if len(link) < 15 or "://" not in link:
                    continue
                h = get_node_hash(link)
                if h not in seen:
                    seen.add(h)
                    unique.append(link)

    print(f"合并去重后保留核心节点: {len(unique)}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(unique))


if __name__ == "__main__":
    main()
