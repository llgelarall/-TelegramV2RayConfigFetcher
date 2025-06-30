#!/usr/bin/env python3
# glarabot – Advanced Proxy Tester (Ping & Speed Test) – 2025-06-30

"""
This script fetches proxy links (VLESS, VMess, Trojan, SS) from various sources,
then performs a comprehensive performance evaluation on each unique proxy.
It uses the xray-core engine to conduct real-world tests:
1. Ping Test: Measures latency to a reliable host.
2. Speed Test: Measures download speed using a test file.
Proxies that pass the defined latency and speed thresholds are saved to a file,
sorted by download speed, and optionally uploaded to a Telegram channel.

🔴 PREREQUISITES:
1. Download xray-core: https://github.com/XTLS/Xray-core/releases
2. Set the `XRAY_PATH` variable below to your xray executable's location.
3. Install httpx: pip install "httpx[socks]"
"""

import asyncio, base64, html, json, re, socket, sys, time, uuid, os
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import httpx
from telegram import Bot, InputFile
from telegram.request import HTTPXRequest

# ────────── USER SETTINGS ──────────

# --- Operation Mode ---
MODE              = "op"          # "test" or "op" (op = upload to Telegram)

# --- Xray-core Path (MANDATORY) ---
# 🔴 SET THIS TO THE PATH OF YOUR XRAY EXECUTABLE
XRAY_PATH         = "..\\2rayN-windows-64\\bin\\xray\\xray.exe" # e.g., "C:\\Users\\user\\Desktop\\xray.exe" on Windows or "/home/user/xray/xray" on Linux

# --- Performance & Filtering ---
PROBES_PER_NODE   = 1             # Number of tests per proxy (1 is usually enough for speed testing)
PING_TIMEOUT      = 8             # seconds for latency test
SPEED_TEST_TIMEOUT= 20            # seconds for download speed test
MAX_PARALLEL_PROB = 50            # Max concurrent xray processes. Adjust based on your system's RAM and CPU.

# --- Filtering Thresholds ---
MAX_LATENCY_MS    = 1500          # Proxies with ping above this are discarded (in milliseconds)
MIN_SPEED_MBPS    = 2.0           # Proxies with download speed below this are discarded

# --- Test URLs ---
PING_TEST_URL     = "https://www.google.com/generate_204" # A small, fast URL for latency check
SPEED_TEST_URL    = "http://cachefly.cachefly.net/10mb.test" # A 10MB file for speed testing

# --- Telegram Settings ---
TOKEN   = "YOUR TOKEN"
CHAT_ID = "YOUR CHATID"

# --- Source URLs ---
URLS = [
"..",
] # Reduced for brevity, user can add the full list back

LINK_RE = re.compile(r"(?:ss|vmess|vless|trojan)://[^\s<>\"']+", re.I)

# ───────── UTILITY HELPERS ─────────
def _pad64(s: str) -> str:
    return s + "=" * (-len(s) % 4)

def parse_int_port(port) -> int | None:
    if port is None: return None
    if isinstance(port, int): return port if 0 < port < 65536 else None
    if isinstance(port, str) and port.isascii() and port.isdecimal():
        try:
            p = int(port)
            return p if 0 < p < 65536 else None
        except ValueError: pass
    return None

# ───────── XRAY CONFIG GENERATION ─────────
def create_xray_config(link: str, local_port: int) -> str | None:
    """Parses a proxy link and builds a complete Xray client configuration."""
    try:
        protocol = link.split("://")[0].lower()
        if protocol == "vmess":
            outbound = parse_vmess(link)
        elif protocol == "vless":
            outbound = parse_vless(link)
        elif protocol == "trojan":
            outbound = parse_trojan(link)
        elif protocol == "ss":
            outbound = parse_ss(link)
        else:
            return None

        if not outbound:
            return None

        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [outbound]
        }
        return json.dumps(config)
    except Exception:
        return None

def parse_vmess(link: str) -> dict | None:
    try:
        data = json.loads(base64.b64decode(_pad64(link.split("://")[1])))
        if not all(k in data for k in ["add", "port", "id"]): return None
        
        stream_settings = {
            "network": data.get("net", "tcp"),
            "security": data.get("tls", "none")
        }
        if stream_settings["security"] == "tls":
            stream_settings["tlsSettings"] = {"serverName": data.get("sni", data.get("host", data["add"]))}
        if stream_settings["network"] == "ws":
            stream_settings["wsSettings"] = {"path": data.get("path", "/")}
            if "host" in data and data["host"]:
                 stream_settings["wsSettings"]["headers"] = {"Host": data["host"]}

        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": data["add"],
                    "port": int(data["port"]),
                    "users": [{"id": data["id"], "alterId": int(data.get("aid", 0)), "security": data.get("scy", "auto")}]
                }]
            },
            "streamSettings": stream_settings
        }
    except Exception:
        return None

def parse_vless(link: str) -> dict | None:
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        
        if not p.hostname or not p.port or not p.username: return None

        stream_settings = {
            "network": q.get("type", ["tcp"])[0],
            "security": q.get("security", ["none"])[0]
        }
        sec = stream_settings["security"]
        if sec == "tls":
            stream_settings["tlsSettings"] = {"serverName": q.get("sni", [p.hostname])[0]}
            if "fp" in q: stream_settings["tlsSettings"]["fingerprint"] = q["fp"][0]
        elif sec == "reality":
            stream_settings["realitySettings"] = {
                "serverName": q.get("sni", [p.hostname])[0],
                "publicKey": q.get("pbk", [""])[0],
                "fingerprint": q.get("fp", ["chrome"])[0]
            }
            if "sid" in q: stream_settings["realitySettings"]["shortId"] = q["sid"][0]
        
        net = stream_settings["network"]
        if net == "ws":
            stream_settings["wsSettings"] = {"path": q.get("path", ["/"])[0], "headers": {"Host": q.get("host", [p.hostname])[0]}}
        elif net == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": q.get("serviceName", [""])[0]}

        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": p.hostname,
                    "port": p.port,
                    "users": [{"id": p.username, "flow": q.get("flow", [""])[0]}]
                }]
            },
            "streamSettings": stream_settings
        }
    except Exception:
        return None

def parse_trojan(link: str) -> dict | None:
    try:
        p = urlparse(link)
        q = parse_qs(p.query)
        if not p.hostname or not p.port or not p.username: return None

        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": p.hostname, "port": p.port, "password": p.username}]
            },
            "streamSettings": {
                "network": q.get("type", ["tcp"])[0],
                "security": q.get("security", ["tls"])[0],
                "tlsSettings": {"serverName": q.get("sni", [p.hostname])[0]}
            }
        }
    except Exception:
        return None

def parse_ss(link: str) -> dict | None:
    try:
        p = urlparse(link)
        if p.username and p.password: # ss://method:pass@host:port
            method, password = p.username, p.password
            host, port = p.hostname, p.port
        else: # ss://base64(method:pass)@host:port
            user_info, host_port = link.split("://")[1].split("@")
            decoded = base64.urlsafe_b64decode(_pad64(user_info)).decode()
            method, password = decoded.split(":", 1)
            host, port_str = host_port.split(":", 1)
            port = int(port_str.split("#")[0].split("/")[0])

        if not all([method, password, host, port]): return None

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{"method": method, "password": password, "address": host, "port": port}]}
        }
    except Exception:
        return None

# ───────── NETWORK-LEVEL PROBE HELPERS ─────────
async def probe_node(link: str, local_port: int, sem: asyncio.Semaphore):
    """The main probing function. Creates a config, runs xray, and tests ping/speed."""
    async with sem:
        config_json = create_xray_config(link, local_port)
        if not config_json:
            return None

        config_path = f"temp_config_{local_port}.json"
        with open(config_path, "w") as f:
            f.write(config_json)

        process = None
        try:
            cmd = [XRAY_PATH, "run", "-c", config_path]
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await asyncio.sleep(2.0)  # Wait for xray to initialize

            proxies = f"socks5://127.0.0.1:{local_port}"
            async with httpx.AsyncClient(proxies=proxies, timeout=30, verify=False) as client:
                # 1. Ping Test
                ping_start = time.monotonic()
                try:
                    response = await client.head(PING_TEST_URL, timeout=PING_TIMEOUT)
                    response.raise_for_status()
                    ping_ms = (time.monotonic() - ping_start) * 1000
                except Exception:
                    return None  # Ping failed

                if ping_ms > MAX_LATENCY_MS:
                    return None  # Ping too high

                # 2. Speed Test
                dl_start = time.monotonic()
                bytes_downloaded = 0
                try:
                    async with client.stream("GET", SPEED_TEST_URL, timeout=SPEED_TEST_TIMEOUT) as response:
                        response.raise_for_status()
                        async for chunk in response.aiter_bytes():
                            bytes_downloaded += len(chunk)
                except Exception:
                    return None # Speed test failed

                duration = time.monotonic() - dl_start
                if duration < 0.1: return None # Unreliable measurement

                speed_mbps = (bytes_downloaded * 8) / (duration * 1_000_000)

                if speed_mbps < MIN_SPEED_MBPS:
                    return None # Speed too low

                # Success
                return speed_mbps, ping_ms, link

        except Exception:
            return None
        finally:
            if process and process.returncode is None:
                try:
                    process.terminate()
                    await process.wait()
                except ProcessLookupError:
                    pass # Process already finished
            if os.path.exists(config_path):
                try:
                    os.remove(config_path)
                except OSError:
                    pass # File might be in use, but will be overwritten

async def probe_all(links: list[str]):
    sem = asyncio.Semaphore(MAX_PARALLEL_PROB)
    # Assign a unique port from a pool to each concurrent task
    port_pool = range(20000, 20000 + len(links))
    tasks = [probe_node(link, port, sem) for link, port in zip(links, port_pool)]
    total, done = len(tasks), 0

    progress_task = asyncio.create_task(progress_bar(lambda: done, total))

    good_results = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        done += 1
        if res:
            good_results.append(res)

    progress_task.cancel()
    # Ensure final progress is shown
    await asyncio.sleep(0.1)
    print(f"\r✅ Probe finished. {done}/{total} completed.                    ")
    
    # Sort by speed (high to low), then ping (low to high)
    return sorted(good_results, key=lambda x: (-x[0], x[1]))

async def progress_bar(done_func, total):
    """Displays a dynamic progress bar."""
    while True:
        done = done_func()
        if total > 0:
            percent = (done / total) * 100
            bar = "█" * int(percent / 2) + "-" * (50 - int(percent / 2))
            print(f"\rTesting Proxies: |{bar}| {done}/{total} ({percent:.1f}%)", end="")
        await asyncio.sleep(0.5)

# ───────── OUTPUT HELPERS ─────────
def save_to_file(results: list):
    """Saves results to a detailed file and a subscription file."""
    now_str = f"{datetime.now():%Y-%m-%d_%H-%M}"
    report_fn = f"Glarabot_Report_{now_str}.txt"
    sub_fn = f"Glarabot_Sub_{now_str}.txt"

    with open(report_fn, "w", encoding="utf-8") as f_report, \
         open(sub_fn, "w", encoding="utf-8") as f_sub:
        
        report_header = (
            f"# Glarabot Speed Test Report\n"
            f"# Generated on: {datetime.now().isoformat()}\n"
            f"# Found {len(results)} working proxies.\n"
            f"# Sorted by Speed (desc) then Ping (asc).\n"
            f"# --------------------------------------------------\n\n"
        )
        f_report.write(report_header)

        sub_links = []
        for speed_mbps, ping_ms, link in results:
            line = f"🚀 SPEED: {speed_mbps:5.2f} MB/s | 🛰 PING: {int(ping_ms):4d} ms | {link.strip()}\n"
            f_report.write(line)
            sub_links.append(link)
        
        f_sub.write("\n".join(sub_links))
        
    print(f"📄 Detailed report saved to: {report_fn}")
    print(f"📋 Subscription file saved to: {sub_fn}")
    return sub_fn # Return the subscription file for upload

async def upload_to_telegram(fn):
    if MODE != "op":
        print(f"🛈 [TEST MODE] Would upload {fn} to Telegram.")
        return
    
    if not os.path.exists(fn):
        print(f"❌ File not found for upload: {fn}")
        return
    
    bot = Bot(token=TOKEN, request=HTTPXRequest(connection_pool_size=10))
    try:
        caption_text = (
            f"✅ **Glarabot Proxy List**\n\n"
            f"Generated: `{datetime.now():%Y-%m-%d %H:%M}` UTC\n"
            f"A list of high-speed proxies has been generated. Use the file below in your client."
        )
        with open(fn, "rb") as f:
            await bot.send_document(
                chat_id=CHAT_ID,
                document=InputFile(f, filename=os.path.basename(fn)),
                caption=caption_text,
                parse_mode="Markdown"
            )
        print("✅ Successfully uploaded to Telegram.")
    except Exception as e:
        print(f"❌ Telegram Upload Error: {e}")
    finally:
        await bot.shutdown()

# ───────── MAIN WORKFLOW ─────────
def fetch_from_url(url: str, session: httpx.Client, tries: int = 3):
    """Fetches and extracts proxy links from a single URL."""
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"}
    for k in range(tries):
        try:
            r = session.get(url, timeout=15, headers=headers, follow_redirects=True)
            r.raise_for_status()
            text = html.unescape(r.text)
            links = [link.strip() for link in LINK_RE.findall(text) if "…" not in link]
            print(f"🛈 Fetched {len(links):>4} links from: {url.split('//')[1][:70]}")
            return links
        except httpx.HTTPError as e:
            print(f"❌ ({k+1}/{tries}) HTTP Error for {url}: {e}")
        except Exception as e:
            print(f"❌ ({k+1}/{tries}) Failed {url}: {e}")
        time.sleep(1)
    return []

async def main():
    start_time = time.monotonic()
    
    if not os.path.exists(XRAY_PATH):
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! FATAL ERROR: Xray executable not found.")
        print(f"!!! Please set the correct path in `XRAY_PATH`.")
        print(f"!!! Current path: '{XRAY_PATH}'")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return

    print("─── Phase 1: Fetching Links ───")
    with httpx.Client() as session:
        all_links = [link for url in URLS for link in fetch_from_url(url, session)]
    
    if not all_links:
        print("⚠️ No links fetched. Exiting.")
        return
        
    print(f"\n📦 Total raw links fetched: {len(all_links)}")

    # Using a dictionary to get unique links, keeping the first occurrence
    unique_links = list(dict.fromkeys(all_links))
    print(f"🔍 Unique links to test: {len(unique_links)}")

    print("\n─── Phase 2: Probing Proxies (Ping & Speed Test) ───")
    good_proxies = await probe_all(unique_links)
    
    if not good_proxies:
        print("⚠️ No proxies passed the filtering criteria.")
        return

    print(f"\n─── Phase 3: Saving & Uploading Results ───")
    best = good_proxies[0]
    print(f"🏆 Found {len(good_proxies)} working proxies. Best speed: {best[0]:.2f} MB/s, Ping: {int(best[1])} ms")
    
    sub_file_to_upload = save_to_file(good_proxies)
    
    await upload_to_telegram(sub_file_to_upload)

    print(f"\n✨ Done in {time.monotonic() - start_time:.2f} seconds.")

# ───────── RUN ─────────
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Process interrupted by user.")
        sys.exit()
