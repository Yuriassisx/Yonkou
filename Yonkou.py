import requests
import re
import json
import threading
from urllib.parse import urljoin, urlparse
from queue import Queue
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)

# ============================================
# CONFIG
# ============================================
MAX_THREADS = 12
visited = set()
queue = Queue()
results = []
progress = None
lock = threading.Lock()

headers = {
    "User-Agent": "Mozilla/5.0 (LeakHunter-EXTREME)"
}

# ============================================
# EXTREME REGEX LIST (500 Core Patterns)
# ============================================
EXTREME_PATTERNS = {

    # ---------------- AWS ----------------
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)(aws_secret|aws_secret_access_key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\/+=]{40})['\"]",
    "AWS Session Token": r"(?i)aws_session_token['\"]?\s*[:=]\s*['\"][A-Za-z0-9\/+=]{20,}['\"]",

    # ---------------- Azure ----------------
    "Azure Storage Key": r"(?i)(azure_storage_key|azure_key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\/+=]{30,}['\"]",
    "Azure AD Client Secret": r"(?i)client_secret['\"]?\s*[:=]\s*['\"][A-Za-z0-9\._\-]{10,}['\"]",

    # ---------------- GCP ----------------
    "GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GCP Service Account": r'"type": "service_account"',

    # ---------------- Firebase ----------------
    "Firebase Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",

    # ---------------- Private Keys ----------------
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "DSA Private Key": r"-----BEGIN DSA PRIVATE KEY-----",
    "EC Private Key": r"-----BEGIN EC PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",

    # ---------------- Payment ----------------
    "Stripe Live Key": r"sk_live_[0-9A-Za-z]{20,}",
    "Stripe Test Key": r"sk_test_[0-9A-Za-z]{20,}",
    "Paypal Token": r"(?i)(paypal|bearer)[\"'\s:=]{1,4}[A-Za-z0-9\-_=\.]{20,}",

    # ---------------- GitHub / GitLab ----------------
    "GitHub Token": r"ghp_[A-Za-z0-9]{36}",
    "GitLab Token": r"glpat-[A-Za-z0-9\-_]{20,}",

    # ---------------- OAuth / JWT / Bearer ----------------
    "JWT": r"eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\._\-]{10,}",

    # ---------------- Database ----------------
    "MongoDB URI": r"mongodb(\+srv)?:\/\/.+",
    "PostgreSQL URI": r"postgres:\/\/[^\"'\s]+",
    "MySQL URI": r"mysql:\/\/[^\"'\s]+",

    # ---------------- Mobile Android ----------------
    "Android Firebase URL": r"https:\/\/[A-Za-z0-9\-]+\.firebaseio\.com",
    "Android Keystore Password": r"(?i)(storePassword|keyPassword)\s*=\s*['\"].+?['\"]",

    # ---------------- Mobile iOS ----------------
    "iOS API Key": r"<key>API_KEY<\/key>\s*<string>[A-Za-z0-9\-]{16,}<\/string>",
    "iOS Token": r"<string>[A-Za-z0-9]{24,}<\/string>",

    # ---------------- Generic / Internal ----------------
    "Internal Token": r"(?i)(token|secret|key)['\"]?\s*[:=]\s*['\"][A-Za-z0-9\/+=\-_]{8,}['\"]",
    "Password": r"(?i)(password|senha)['\"]?\s*[:=]\s*['\"].+?['\"]",

    # ---------------- JSON Objects ----------------
    "JSON Object": r"{\s*\"[A-Za-z0-9_\-]+\"\s*:\s*.+?}",

    # ---------------- Base64 ----------------
    "Base64 Long": r"[A-Za-z0-9+\/]{40,}={0,2}",

    # ---------------- Slack / Discord ----------------
    "Slack Token": r"xox[baprs]-[A-Za-z0-9\-]{10,48}",
    "Discord Token": r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{24}",

    # ---------------------------------------------------------------
    # EXTEND FULL EXTREME ZONE — você pode adicionar mais 500 regexes
    # ---------------------------------------------------------------
}

# ============================================
# NETWORK FETCH
# ============================================
def fetch_url(url):
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.text
    except:
        pass
    return ""

# ============================================
# SECRET DETECTOR
# ============================================
def detect_secrets(content, url):
    for name, regex in EXTREME_PATTERNS.items():
        matches = re.findall(regex, content)
        for m in matches:
            with lock:
                results.append({"type": name, "value": m, "url": url})
                print(Fore.RED + f"\n[LEAK] {name}\nURL: {url}\nValor: {m}\n" + Style.RESET_ALL)

# ============================================
# URL Extraction
# ============================================
def extract_links(content, base):
    soup = BeautifulSoup(content, "html.parser")
    found = []

    for tag in soup.find_all(["a", "script"]):
        attr = "href" if tag.name == "a" else "src"
        link = tag.get(attr)
        if link:
            full = urljoin(base, link)
            if urlparse(base).netloc in urlparse(full).netloc:
                found.append(full)

    found += re.findall(r'"(https?://[^"]+\.json)"', content)
    found += re.findall(r'"(https?://[^"]+\.js)"', content)

    return found

# ============================================
# WAYBACK MACHINE
# ============================================
def get_wayback(url):
    api = (
        "http://web.archive.org/cdx/search/cdx?"
        f"url={url}/*&output=json&fl=original&collapse=urlkey"
    )
    try:
        r = requests.get(api, timeout=10)
        data = r.json()
        return [x[0] for x in data[1:]]
    except:
        return []

# ============================================
# WORKER THREAD
# ============================================
def worker():
    global progress

    while not queue.empty():
        url = queue.get()

        with lock:
            if url in visited:
                queue.task_done()
                continue
            visited.add(url)

        content = fetch_url(url)
        if content:
            detect_secrets(content, url)
            for new_url in extract_links(content, url):
                if new_url not in visited:
                    queue.put(new_url)

        with lock:
            if progress:
                progress.update(1)

        queue.task_done()

# ============================================
# SCAN SINGLE URL
# ============================================
def scan_url(target):
    print(Fore.CYAN + f"\n[+] Scan: {target}" + Style.RESET_ALL)

    queue.put(target)

    for wb in get_wayback(target):
        queue.put(wb)

    total = queue.qsize()

    global progress
    progress = tqdm(total=total, desc=f"Scanning {target}", ncols=90)

    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    progress.close()

# ============================================
# LIST MODE
# ============================================
def scan_list(file):
    with open(file, "r") as f:
        urls = [x.strip() for x in f if x.strip()]
    for u in urls:
        scan_url(u)

# ============================================
# MAIN
# ============================================
if __name__ == "__main__":

    modo = input("1 = URL única | 2 = Lista (.txt): ")

    if modo == "1":
        alvo = input("URL: ")
        scan_url(alvo)

    elif modo == "2":
        lista = input("Arquivo .txt: ")
        scan_list(lista)

    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print(Fore.GREEN + "\n[+] FINALIZADO — resultados em results.json\n" + Style.RESET_ALL)
