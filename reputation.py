"""Threat-intel lookups: Google Safe Browsing (needs GSB_API_KEY) and the OpenPhish community feed (keyless)."""
import json
import os
import random
import socket
import struct
import time
import urllib.request
from urllib.parse import urlparse

OPENPHISH_FEED = "https://openphish.com/feed.txt"
_feed = {"at": 0.0, "urls": set(), "hosts": set()}
FEED_TTL = 3600


def status() -> dict:
    return {"safe_browsing": bool(os.getenv("GSB_API_KEY")), "openphish": True, "dns": True}


def _load_feed():
    if time.time() - _feed["at"] < FEED_TTL:
        return
    try:
        req = urllib.request.Request(OPENPHISH_FEED, headers={"User-Agent": "PhishGuard/1.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            lines = r.read().decode("utf-8", "ignore").splitlines()
        urls = {l.strip().lower() for l in lines if l.strip()}
        _feed.update(at=time.time(), urls=urls, hosts={(urlparse(u).hostname or "") for u in urls})
    except Exception:
        _feed["at"] = time.time() - FEED_TTL + 300  # retry in 5 min, keep stale data


def _dns_a(host: str, server: str, timeout=3):
    """Minimal DNS A-record lookup against a specific resolver. Returns list of IPs, [] if none, None on failure."""
    try:
        qid = random.randrange(65536)
        q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        q += b"".join(bytes([len(l)]) + l.encode() for l in host.split(".")) + bytes([0]) + struct.pack(">HH", 1, 1)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(q, (server, 53))
            data, _ = s.recvfrom(1024)
        if struct.unpack(">H", data[:2])[0] != qid:
            return None
        an = struct.unpack(">H", data[6:8])[0]
        i = 12
        while data[i]:  # skip question name
            i += data[i] + 1
        i += 5
        ips = []
        for _ in range(an):
            i += 2 if data[i] & 0xC0 == 0xC0 else 0
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            if rtype == 1 and rdlen == 4:
                ips.append(".".join(map(str, data[i:i + 4])))
            i += rdlen
        return ips
    except Exception:
        return None


def check_dns_block(host: str):
    """Cloudflare 1.1.1.2 (free, keyless) answers 0.0.0.0 for known malware/phishing domains."""
    if not host or host.replace(".", "").isdigit():
        return None
    blocked = _dns_a(host, "1.1.1.2")
    if blocked and all(ip == "0.0.0.0" for ip in blocked):
        normal = _dns_a(host, "1.1.1.1")
        if normal and any(ip != "0.0.0.0" for ip in normal):  # resolves normally elsewhere => filtered, not dead
            return "Cloudflare’s security DNS blocks this domain as malware/phishing."
    return None


def check_openphish(url: str, host: str):
    _load_feed()
    if url.lower() in _feed["urls"] or (host and host in _feed["hosts"]):
        return "Listed in the OpenPhish live phishing feed."
    return None


def check_safe_browsing(urls: list[str]) -> dict:
    """Returns {url: threat_type} for URLs Google flags."""
    key = os.getenv("GSB_API_KEY")
    if not key or not urls:
        return {}
    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        req = urllib.request.Request(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.load(r)
        return {m["threat"]["url"]: m["threatType"] for m in data.get("matches", [])}
    except Exception:
        return {}


def enrich_url_result(r: dict, sb_hits: dict) -> None:
    """Add reputation findings to a single URL result (in place)."""
    from analyzer import normalize_url, verdict
    url = normalize_url(r["input"])
    for u, threat in sb_hits.items():
        if u.rstrip("/") == url.rstrip("/"):
            r["findings"].insert(0, {"level": "high", "title": "Flagged by Google Safe Browsing",
                                     "detail": f"Google lists this address as {threat.replace('_', ' ').lower()}.", "points": 60})
            r["score"] = min(100, max(r["score"], 90))
    msg = check_openphish(url, r.get("host", ""))
    if msg:
        r["findings"].insert(0, {"level": "high", "title": "Known phishing site", "detail": msg, "points": 60})
        r["score"] = min(100, max(r["score"], 90))
    dns = check_dns_block(r.get("host", ""))
    if dns:
        r["findings"].insert(0, {"level": "high", "title": "Blocked by Cloudflare security DNS", "detail": dns, "points": 55})
        r["score"] = min(100, max(r["score"], 85))
    r["verdict"] = verdict(r["score"])


def enrich(result: dict) -> dict:
    urls = [result] if result["type"] == "url" else result.get("urls", [])
    if not urls:
        return result
    from analyzer import normalize_url, verdict
    sb_hits = check_safe_browsing([normalize_url(u["input"]) for u in urls])
    for u in urls:
        enrich_url_result(u, sb_hits)
    if result["type"] == "message":
        worst = max(u["score"] for u in urls)
        if worst >= 90:
            result["score"] = max(result["score"], 90)
            result["verdict"] = verdict(result["score"])
    return result
