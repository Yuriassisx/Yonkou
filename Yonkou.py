#!/usr/bin/env python3
import requests
import re
import json
import threading
from urllib.parse import urljoin, urlparse
from queue import Queue
from bs4 import BeautifulSoup
from tqdm import tqdm
from colorama import Fore, Style, init
import time

init(autoreset=True)

# ============================================
# CONFIG
# ============================================
MAX_THREADS = 20               # Aumentado - controla paralelismo
REQUEST_TIMEOUT = 12
MAX_CONTENT_LENGTH = 2 * 1024 * 1024   # 2 MB - pula respostas maiores
WAYBACK_LIMIT = 25            # limita snapshots por alvo
PROBE_COMMON_PATHS = True     # ativa sondagem de paths comuns
COMMON_PATHS = [
    "/.env", "/.env.example", "/config.js", "/config.json", "/.git/config",
    "/.git/HEAD", "/backup", "/backup.zip", "/.htpasswd", "/robots.txt",
    "/sitemap.xml", "/admin", "/.well-known/security.txt"
]

visited = set()
queue = Queue()
results = []
results_set = set()  # para evitar duplicados
progress = None
lock = threading.Lock()

headers = {
    "User-Agent": "Mozilla/5.0 (LeakHunter-EXTREME)"
}

session = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=100, pool_maxsize=100)
session.mount("http://", adapter)
session.mount("https://", adapter)

# ============================================
# EXTREME REGEX LIST — REMOVIDO FALSOS POSITIVOS + EXTENSO
# (mantive e refinei os padrões que você já tinha)
# ============================================
EXTREME_PATTERNS = {
    # AWS
    "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
    "AWS Secret Key": r"(?i)(?:aws_secret_access_key|aws_secret)['\"\s:=]{1,6}([A-Za-z0-9\/+=]{40})",
    "AWS Session Token": r"(?i)aws_session_token['\"\s:=]{1,6}([A-Za-z0-9\/+=]{20,})",

    # Azure
    "Azure Storage Key": r"(?i)(?:azure_storage_key|azure_key)['\"\s:=]{1,6}([A-Za-z0-9\/+=]{30,})",
    "Azure AD Client Secret": r"(?i)client_secret['\"\s:=]{1,6}([A-Za-z0-9\._\-]{16,})",

    # GCP / Firebase
    "GCP API Key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "GCP Service Account (JSON)": r'"type"\s*:\s*"service_account"',
    "Firebase Legacy Key": r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",

    # Cloudflare / DigitalOcean
    "Cloudflare API Key": r"(?i)cloudflare.*['\"]([A-Za-z0-9]{37})['\"]",
    "Cloudflare Token": r"\bcf-[A-Za-z0-9\-_]{30,}\b",
    "DigitalOcean Token": r"\bdo_[A-Za-z0-9]{60}\b",

    # Git tokens
    "GitHub Token": r"\bgh[pous]_[A-Za-z0-9]{36}\b",
    "GitLab Token": r"\bglpat-[A-Za-z0-9\-_]{20,}\b",
    "Bitbucket Token": r"\bbb[t]t?_[A-Za-z0-9]{20,}\b",  # aceita algumas variantes

    # Payment
    "Stripe Live Key": r"\bsk_live_[A-Za-z0-9]{20,}\b",
    "Stripe Test Key": r"\bsk_test_[A-Za-z0-9]{20,}\b",
    "Paypal Token": r"(?i)\b(?:paypal|bearer)['\"\s:=]{1,6}([A-Za-z0-9\-_=\.]{25,})\b",
    "MercadoPago Access Token": r"\bAPP_USR-[A-Za-z0-9\-_]{30,}\b",

    # Messaging / Email keys
    "Twilio API Key": r"\bSK[0-9a-fA-F]{32}\b",
    "SendGrid API Key": r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b",
    "Mailgun Private Key": r"\bkey-[A-Za-z0-9]{32}\b",

    # Bearer / OAuth / JWT
    "Bearer Token": r"\bBearer\s+[A-Za-z0-9\._\-]{25,}\b",
    # JWT com limites para reduzir falsos positivos
    "JWT": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    "JWT (Long)": r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,}\b",

    # DB URIs (com usuário:senha)
    "MongoDB URI": r"\bmongodb(\+srv)?:\/\/[^\s\"']+\b",
    "PostgreSQL URI": r"\bpostgres:\/\/[^\s\"']+:[^\s\"']+@[^\s\"']+\b",
    "MySQL URI": r"\bmysql:\/\/[^\s\"']+:[^\s\"']+@[^\s\"']+\b",

    # Mobile / Android / iOS
    "Android Keystore Password": r"(?i)(?:storePassword|keyPassword)\s*=\s*['\"].{4,}['\"]",
    "Android Firebase URL": r"https:\/\/[A-Za-z0-9\-]+\.firebaseio\.com",
    "iOS API Key": r"<key>API_KEY<\/key>\s*<string>[A-Za-z0-9\-]{16,}<\/string>",

    # ENV / Generic / Internal
    "Hardcoded Secret": r"(?i)\b(?:secret|token|api_key|apikey|auth|key)['\"\s:=]{1,6}([A-Za-z0-9\/+=\-_]{15,})",
    "Password Assignment": r"(?i)\b(?:password|senha)['\"\s:=]{1,6}([^\s\"']{4,})",
    "OAuth Client Secret": r"(?i)\bclient_secret['\"\s:=]{1,6}([A-Za-z0-9\-_\.]{10,})",

    "Environment Vars Sensitive": r"(?i)\b(?:SECRET_KEY|API_KEY|DB_PASS|TOKEN|ACCESS_KEY)=['\"]?([A-Za-z0-9\-_\/\+=]{8,})",

    # Slack / Discord
    "Slack Token": r"\bxox[baprs]-[A-Za-z0-9\-]{10,48}\b",
    "Discord Token": r"\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{24}\b",

    # Base64 long (min 60 chars) - reduz falsos positivos
    "Base64 Long": r"\b[A-Za-z0-9+\/]{60,}={0,2}\b",
}

# Map de risco simples (maior = mais crítico)
RISK_SCORES = {
    "AWS Access Key": 9,
    "AWS Secret Key": 9,
    "AWS Session Token": 8,
    "Azure Storage Key": 8,
    "GCP API Key": 8,
    "Stripe Live Key": 10,
    "GitHub Token": 9,
    "JWT": 9,
    "JWT (Long)": 9,
    "Hardcoded Secret": 7,
    "Password Assignment": 9,
    "Base64 Long": 4,
    # default: 5
}


# ============================================
# HELPERS
# ============================================
def safe_get_text(resp):
    """Retorna o texto se não for binário e estiver dentro do limite"""
    ctype = resp.headers.get("Content-Type", "")
    clen = resp.headers.get("Content-Length")
    try:
        if clen and int(clen) > MAX_CONTENT_LENGTH:
            return ""
    except:
        pass
    # ignora binários e imagens
    if any(x in ctype for x in ["application/octet-stream", "image/", "video/", "audio/", "application/pdf"]):
        return ""
    try:
        return resp.text
    except:
        return ""


def normalize_match(m):
    """Normaliza o resultado do re.findall para extrair string útil"""
    if isinstance(m, tuple):
        # pega o primeiro grupo não vazio
        for x in m:
            if isinstance(x, str) and x.strip():
                return x.strip()
        return m[0] if m else ""
    return str(m)


def snippet_from_content(content, match_str, context=60):
    idx = content.find(match_str)
    if idx == -1:
        return match_str[:120]
    start = max(0, idx - context)
    end = min(len(content), idx + len(match_str) + context)
    return content[start:end].replace("\n", " ").replace("\r", " ")


def risk_of(name):
    return RISK_SCORES.get(name, 5)


# ============================================
# NETWORK FETCH (otimizado)
# ============================================
def fetch_url(url):
    try:
        resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if resp.status_code == 200:
            text = safe_get_text(resp)
            return text
    except Exception:
        pass
    return ""


# ============================================
# SECRET DETECTOR
# ============================================
def detect_secrets(content, url):
    # evita conteúdo muito curto
    if not content or len(content) < 16:
        return

    for name, regex in EXTREME_PATTERNS.items():
        try:
            matches = re.findall(regex, content)
        except re.error:
            continue
        for m in matches:
            val = normalize_match(m)
            if not val:
                continue

            # heurística extra para reduzir falsos positivos
            # - ignora matches que estejam dentro de HTML tags triviais (ex: <title>AKIA...)</title> pode ser ok but keep)
            # - ignora se contém espaços
            if " " in val or "\n" in val:
                continue
            # evita pegar longas repetições de hex sem relação (hashes públicos)
            if re.match(r"^[0-9a-fA-F]{64,}$", val) and len(val) > 64:
                continue

            key = (name, val, url)
            with lock:
                if key in results_set:
                    continue
                results_set.add(key)

                snippet = snippet_from_content(content, val)
                score = risk_of(name)
                findings = {
                    "type": name,
                    "value": val,
                    "url": url,
                    "snippet": snippet,
                    "risk": score,
                    "timestamp": int(time.time())
                }
                results.append(findings)
                print(Fore.RED + f"\n[LEAK] {name} (risk={score})\nURL: {url}\nValor: {val}\nSnippet: {snippet}\n" + Style.RESET_ALL)


# ============================================
# URL Extraction (mais completo)
# ============================================
def extract_links(content, base):
    soup = BeautifulSoup(content, "html.parser")
    found = set()

    # a, link, script, img, form, iframe
    for tag in soup.find_all(True):
        attrs = {}
        for a in tag.attrs:
            try:
                attrs[a] = tag.get(a)
            except Exception:
                continue
        # atributos que podem conter URLs
        for attr in ("href", "src", "data-src", "data-href", "action", "srcset"):
            val = attrs.get(attr)
            if not val:
                continue
            # srcset contém múltiplos urls
            if attr == "srcset":
                parts = [p.split()[0] for p in val.split(",") if p.strip()]
                for p in parts:
                    full = urljoin(base, p)
                    if urlparse(base).netloc in urlparse(full).netloc:
                        found.add(full)
                continue
            full = urljoin(base, val)
            if urlparse(base).netloc in urlparse(full).netloc:
                found.add(full)

    # regex-based for json/js endpoints
    found.update(re.findall(r'"(https?://[^"]+\.json)"', content))
    found.update(re.findall(r'"(https?://[^"]+\.js)"', content))
    found.update(re.findall(r"(https?://[^\s'\"<>]+)", content))

    # normalize to list and return
    return list(found)


# ============================================
# WAYBACK MACHINE (limitado)
# ============================================
def get_wayback(url):
    api = (
        "http://web.archive.org/cdx/search/cdx?"
        f"url={url}/*&output=json&fl=original&collapse=urlkey"
    )
    try:
        r = session.get(api, timeout=REQUEST_TIMEOUT)
        data = r.json()
        # limita a WAYBACK_LIMIT e filtra duplicatas de domínio
        urls = []
        for x in data[1:WAYBACK_LIMIT+1]:
            if x and x[0] and urlparse(x[0]).netloc == urlparse(url).netloc:
                urls.append(x[0])
        return urls
    except Exception:
        return []


# ============================================
# PROBE COMMON PATHS (para encontrar arquivos expostos)
# ============================================
def probe_common_paths(target):
    base = target.rstrip("/")
    candidates = []
    for p in COMMON_PATHS:
        candidates.append(base + p)
    return candidates


# ============================================
# WORKER THREAD
# ============================================
def worker():
    global progress

    while True:
        try:
            url = queue.get(timeout=3)
        except Exception:
            break

        with lock:
            if url in visited:
                queue.task_done()
                continue
            visited.add(url)

        content = fetch_url(url)
        if content:
            detect_secrets(content, url)
            for new_url in extract_links(content, url):
                with lock:
                    if new_url not in visited:
                        queue.put(new_url)

        with lock:
            if progress:
                progress.update(1)

        queue.task_done()


# ============================================
# SCAN SINGLE URL (com melhorias)
# ============================================
def scan_url(target):
    print(Fore.CYAN + f"\n[+] Scan: {target}" + Style.RESET_ALL)

    # normalize target (ensure scheme)
    if not urlparse(target).scheme:
        target = "http://" + target

    # enqueue main target
    queue.put(target)

    # probe common paths optionally
    if PROBE_COMMON_PATHS:
        for p in probe_common_paths(target):
            queue.put(p)

    # wayback snapshots (limitado)
    for wb in get_wayback(target):
        queue.put(wb)

    # estima total inicial (filtramos na execução)
    total = max(1, queue.qsize())

    # start progress
    global progress
    progress = tqdm(total=total, desc=f"Scanning {target}", ncols=90)

    # spawn threads (min entre MAX_THREADS e queue size)
    nthreads = min(MAX_THREADS, max(4, queue.qsize()))
    threads = []
    for _ in range(nthreads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    # wait until queue empty
    queue.join()

    # give workers a chance to exit
    time.sleep(0.2)
    progress.close()


# ============================================
# LIST MODE
# ============================================
def scan_list(file):
    with open(file, "r", encoding="utf-8") as f:
        urls = [x.strip() for x in f if x.strip()]
    for u in urls:
        scan_url(u)


# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    try:
        modo = input("1 = URL única | 2 = Lista (.txt): ").strip()
    except KeyboardInterrupt:
        print("\nAbortado.")
        raise SystemExit

    if modo == "1":
        alvo = input("URL: ").strip()
        scan_url(alvo)

    elif modo == "2":
        lista = input("Arquivo .txt: ").strip()
        scan_list(lista)
    else:
        print("Modo inválido. Saindo.")
        raise SystemExit

    # salvar resultados finais (ordenados por risco decrescente)
    results_sorted = sorted(results, key=lambda x: x.get("risk", 5), reverse=True)
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results_sorted, f, indent=4, ensure_ascii=False)

    print(Fore.GREEN + "\n[+] FINALIZADO — resultados em results.json\n" + Style.RESET_ALL)
