import os
import re
import requests
from concurrent.futures import ThreadPoolExecutor

SAVE_PATH = "/root/methods/proxy.txt"
URLS_FILE = "/root/methods/proxyUrls.txt"

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

PROXY_REGEX = re.compile(
    r"(?:https?:\/\/|socks4:\/\/|socks5:\/\/)?"
    r"((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})"
)

def load_urls():
    urls = []
    if os.path.exists(URLS_FILE):
        with open(URLS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)
        print(f"[INFO] Loaded {len(urls)} URLs from {URLS_FILE}")
    else:
        print(f"[WARNING] {URLS_FILE} not found!")
    return urls

def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            print(f"[OK] {url[:80]}...")
            return r.text
    except:
        pass
    return ""

def clean(content):
    proxies = set()
    matches = PROXY_REGEX.findall(content)
    for proxy in matches:
        try:
            ip, port = proxy.split(":")
            port = int(port)
            if not (1 <= port <= 65535):
                continue
            octets = ip.split(".")
            if len(octets) != 4:
                continue
            if all(0 <= int(o) <= 255 for o in octets):
                proxies.add(f"{ip}:{port}")
        except:
            continue
    return proxies

def main():
    raw_urls = load_urls()
    if not raw_urls:
        print("[ERROR] No URLs found!")
        return
    
    all_proxies = set()
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(fetch, raw_urls)
    
    for content in results:
        all_proxies.update(clean(content))
    
    final = sorted(all_proxies)
    os.makedirs("/root/methods", exist_ok=True)
    
    with open(SAVE_PATH, "w") as f:
        f.write("\n".join(final))
    
    print(f"\n[SUCCESS] Saved {len(final)} proxies -> {SAVE_PATH}")

if __name__ == "__main__":
    main()