# 📡 Telegram V2Ray Config Fetcher

> **Providing global internet access for Iranian users and beyond**  
> This tool automates delivery of free proxy configuration links—ensuring unrestricted connectivity regardless of location.


A Python script that fetches proxy configuration links from public GitHub sources and sends them to a Telegram user or channel using a bot. It supports popular protocols such as `vmess://`, `vless://`, `ss://`, `trojan://`, and `hysteria2://`. You can send the results as a `.txt` file or as multiple Telegram messages split into safe-sized chunks.

---

## ✅ Features

- Extracts `ss`, `vmess`, `vless`, `trojan`, and `hysteria2` links
- Sends results to Telegram as a document or text message chunks
- Supports multiple URL sources
- Saves configs locally as a timestamped `.txt` file
- Fully asynchronous and built on `python-telegram-bot` v20+
- Robust error handling and console feedback

---

## ⚙️ Requirements

- Python 3.7+
- Telegram bot token (generated via [@BotFather](https://t.me/BotFather))
- Telegram chat ID or channel username (e.g., `@yourchannel`)
- Dependencies:

## bash
pip install requests python-telegram-bot==20.7 httpx
## 🛠 Configuration
Open the Python script and set:
URLS = [
    'https://raw.githubusercontent.com/Aclashv2rayfree/clashfree/main/README.md',
    # Add more if needed
]

TOKEN = 'YOUR_BOT_TOKEN'
CHAT_ID = '@yourchannel_or_user_id'
ℹ️ Make sure your bot is an admin in the target channel if you're sending files or messages there.

## 🚀 Usage
After setting up the script:

python congFetcherForTlgpy.py

By default:

It fetches config links from the URLs

Saves them to a local file named like configs_{date}.txt

Sends that file to your Telegram bot/channel

## ✂️ Send as Messages Instead of File (Optional)
If you'd rather send the results in chunks (each under 4096 characters):

In the main() function of the script, comment out the send_file() line and uncomment send_chunks():
await send_file(all_configs, bot)

## 🔁 Automation Options

Linux/macOS (Cron):
Edit your crontab:
crontab -e

To run every 6 hours:
0 */6 * * * /usr/bin/python3 /path/to/telegram_config_bot.py

Windows:
Use Task Scheduler to set up a recurring task that runs:
python telegram_config_bot.py

GitHub Actions (Optional):
You can automate daily execution via GitHub Actions. Ask if you need a template.


## 📎 Notes
Works well with free daily proxy list repos
Can be used to automate Telegram bot updates for VPN configs
Logs results and failures to the terminal for debugging
