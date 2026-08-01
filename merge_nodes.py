#!/usr/bin/env python3
"""Merge new nodes with previous release nodes and deduplicate by feature hash."""

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
    text = text.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    text = text.replace("-", "+").replace("_", "/")
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
        sni = None

        if protocol == "vmess":
            b64 = rest.split("#")[0]
            decoded = safe_b64decode(b64)
            if decoded:
                conf = json.loads(decoded)
                sni = conf.get("sni") or conf.get("host") or conf.get("add")
        else:
            parsed = urlparse(link)
            qs = parse_qs(parsed.query)
            sni = (qs.get("sni") or qs.get("peer") or [None])[0]
            if not sni:
                sni = parsed.hostname
            if not sni and "@" in rest:
                body = rest.split("#")[0]
                part = body.split("@")[-1].split("/?")[0].split("?")[0]
                if part.startswith("["):
                    sni = part.rsplit(":", 1)[0].strip("[]")
                else:
                    sni = part.rsplit(":", 1)[0]

        if sni:
            return hashlib.md5(f"sni_{sni}".encode()).hexdigest()
    except Exception:
        pass

    try:
        protocol, rest = link.split("://", 1)
        protocol = protocol.lower()
        if protocol == "vmess":
            b64 = rest.split("#")[0]
            decoded = safe_b64decode(b64)
            if decoded:
                conf = json.loads(decoded)
                conf.pop("ps", None)
                return hashlib.md5(
                    f"vmess://{json.dumps(conf, sort_keys=True)}".encode()
                ).hexdigest()
        core = rest.split("#")[0]
        return hashlib.md5(f"{protocol}://{core}".encode()).hexdigest()
    except Exception:
        return hashlib.md5(link.encode()).hexdigest()


def main() -> None:
    print("--- Merge & deduplicate nodes ---")
    seen: set[str] = set()
    unique: list[str] = []

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

    print(f"Unique nodes after merge: {len(unique)}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(unique))


if __name__ == "__main__":
    main()
