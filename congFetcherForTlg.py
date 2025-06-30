#!/usr/bin/env python3
# glarabot – TCP-connect probe – 2025-06-30

import asyncio, base64, html, json, re, socket, sys, time, uuid
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import requests
from telegram import Bot, InputFile
from telegram.request import HTTPXRequest

# ────────── USER SETTINGS ──────────
MODE              = "op"   # "test" or "op" to upload to Telegram
PROBES_PER_NODE   = 4
TCP_TIMEOUT       = 4        # seconds
MAX_PARALLEL_PROB = 400

MAX_AVG_MS        = 500
MAX_WORST_MS      = 1000

TOKEN   = "YOUR TOKEN"
CHAT_ID = "Your ChatID"
# ──────────────────────────────────

URLS = [
    # — your subscription feeds —
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vmess",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/trojan",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/ss",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/vless",
    "https://raw.githubusercontent.com/74647/proxify/main/v2ray_configs/seperated_by_protocol/vmess.txt",
    "https://raw.githubusercontent.com/74647/proxify/main/v2ray_configs/seperated_by_protocol/vless.txt",
    "https://raw.githubusercontent.com/74647/proxify/main/v2ray_configs/seperated_by_protocol/trojan.txt",
    "https://raw.githubusercontent.com/74647/proxify/main/v2ray_configs/seperated_by_protocol/shadowsocks.txt",
    "https://raw.githubusercontent.com/74647/proxify/main/v2ray_configs/seperated_by_protocol/other.txt",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/vless",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/reality",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/trojan",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/tuic",
    "https://raw.githubusercontent.com/sinavm/SVM/main/subscriptions/xray/normal/hy2",
]

LINK_RE = re.compile(r"(?:ss|vmess|vless|trojan|hysteria2)://[^\s<>\"']+", re.I)

# —──────── fetch —────────
def fetch(url: str, tries=3):
    hdr = {"User-Agent": "glarabot/1.1"}
    for k in range(tries):
        try:
            r = requests.get(url, timeout=10, headers=hdr); r.raise_for_status()
            txt   = html.unescape(r.text)
            links = [l for l in LINK_RE.findall(txt) if "…" not in l]
            print(f"🛈 {url} → {len(links)} links")
            return links
        except Exception as e:
            print(f"❌ ({k+1}/{tries}) {url}: {e}")
            time.sleep(1)
    return []

# —──────── parsing helpers —────────
def _pad64(s): return s + "=" * (-len(s) % 4)

def safe_host_port(netloc):
    if "@" in netloc: netloc = netloc.split("@",1)[1]
    if netloc.startswith("[") and "]" in netloc:
        h, rest = netloc[1:].split("]",1)
        p = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
        return h, p
    if ":" in netloc:
        h, last = netloc.rsplit(":",1)
        if last.isdigit(): return h, int(last)
    return netloc, None

def hp_vmess(link):
    try:
        j = json.loads(base64.urlsafe_b64decode(_pad64(link.split("://",1)[1])))
        return j.get("add"), int(j.get("port")), None
    except Exception:
        return None, None, None

def hp_vless(link):
    try: p = urlparse(link)
    except Exception: return None, None, None
    try: host, port = p.hostname, p.port
    except ValueError: host, port = safe_host_port(p.netloc)

    uid = None
    if p.username:
        try: uid = uuid.UUID(p.username)
        except ValueError: pass
    if uid is None:
        q = parse_qs(p.query)
        if "id" in q:
            try: uid = uuid.UUID(q["id"][0])
            except ValueError: pass
    return host, port, uid

def hp_ss(link):
    body = link.split("://",1)[1]
    if "@" in body:
        p = urlparse(link)
        return p.hostname, p.port, None
    try:
        dec = base64.urlsafe_b64decode(_pad64(body.split("#")[0])).decode()
        _, addr = dec.rsplit("@",1)
        host, port = addr.split(":")
        return host, int(port), None
    except Exception:
        return None, None, None

def hp_generic(link):
    p = urlparse(link); return p.hostname, p.port, None

def parse_link(link):
    sc = link.split("://",1)[0].lower()
    if sc == "vmess": return hp_vmess(link)
    if sc == "vless": return hp_vless(link)
    if sc == "ss":    return hp_ss(link)
    return hp_generic(link)

# —──────── TCP-connect probe —────────
async def tcp_once(host, port):
    st = time.monotonic()
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=TCP_TIMEOUT)
        w.close()
        return (time.monotonic() - st) * 1000
    except Exception:
        return None

async def one_node(link, host, port, sem):
    async with sem:
        samples = []
        worst   = 0
        for _ in range(PROBES_PER_NODE):
            d = await tcp_once(host, port)
            if d is None: d = TCP_TIMEOUT * 1000
            samples.append(d)
            worst = max(worst, d)
            avg   = sum(samples)/len(samples)
            if avg > MAX_AVG_MS or worst > MAX_WORST_MS:
                return None          # hopeless – stop early
        return avg, worst, link

async def probe_all(uniq):
    sem   = asyncio.Semaphore(MAX_PARALLEL_PROB)
    todo  = [one_node(l,h,p,sem) for (l,h,p) in uniq]
    total = len(todo); done = 0

    async def progress():
        while done < total:
            print(f"\r⌛ {done}/{total} probed…", end="")
            await asyncio.sleep(1)
    asyncio.create_task(progress())

    good = []
    for coro in asyncio.as_completed(todo):
        r = await coro; done += 1
        if r: good.append(r)
    print()
    return sorted(good, key=lambda x: x[0])

# —──────── output —────────
def save(pairs):
    fn = f"configs_{datetime.now():%Y-%m-%d_%H-%M}.txt"
    with open(fn,"w",encoding="utf-8") as f:
        for avg, worst, l in pairs:
            f.write(f"{l}\n")
    return fn

async def upload(fn):
    if MODE != "op":
        print(f"🛈 [TEST] would upload {fn}"); return
    bot = Bot(token=TOKEN, request=HTTPXRequest())
    try:
        with open(fn,"rb") as f:
            await bot.send_document(chat_id=CHAT_ID,
                                    document=InputFile(f),
                                    filename=fn)
            await bot.send_message(chat_id=CHAT_ID,
                                   text="✅ latency-filtered list uploaded.")
    except Exception as e:
        print("❌ Telegram:", e)

# —──────── main —────────
async def main():
    socket.setdefaulttimeout(TCP_TIMEOUT+1)

    links = [l for u in URLS for l in fetch(u)]
    if not links: print("⚠️  no links"); return
    print(f"📦 total raw links: {len(links)}")

    uniq_map = {}
    for l in links:
        h, p, _ = parse_link(l)
        if h and p is not None:
            uniq_map.setdefault((h,p), l)
    uniq = [(l,h,p) for (h,p), l in uniq_map.items()]
    print(f"🔍 unique endpoints: {len(uniq)} (probing {PROBES_PER_NODE}× each)")

    good = await probe_all(uniq)
    if not good: print("⚠️  nothing passed"); return

    print(f"✅ {len(good)} nodes kept · best avg {good[0][0]:.0f} ms")
    fn = save(good); print("📄 saved →", fn)
    await upload(fn)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit()
