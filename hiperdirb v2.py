Python 3.13.7 (tags/v3.13.7:bcee1c3, Aug 14 2025, 14:15:11) [MSC v.1944 64 bit (AMD64)] on win32
Enter "help" below or click "Help" above for more information.
#!/usr/bin/env python3
"""
HyperDirb v2 - Async Content Discovery Scanner
Author: Mahesh (with Claude's help)
For authorized pentesting / CTF / lab use only (TryHackMe, HackTheBox, etc.)

v2 changes over v1 (addressing full code-review checklist):
  - Rewritten on asyncio + aiohttp (connection pooling, real concurrency, no GIL/thread overhead)
  - Retry logic with exponential backoff on connection errors / 5xx / 429
  - Adaptive rate limiting: backs off automatically when the target starts 429'ing
  - Duplicate detection (visited set, path normalization)
  - Smarter soft-404 detection: status + length + <title> + body hash + similarity ratio
  - Redirect classification (login / admin / dashboard / unknown)
  - Response fingerprinting: Server, X-Powered-By, Via, CF-Ray, ETag
  - Basic CDN detection (Cloudflare, Akamai, Fastly, AWS, Azure)
  - Basic WAF detection (Cloudflare, Sucuri, Imperva, ModSecurity signatures)
  - Basic technology detection (WordPress, Laravel, Django, Flask, ASP.NET, Node, PHP)
  - Automatic backup-file probing (.bak, .old, .save, .orig, .swp, ~) when a file is found
  - Extension expansion (deep mode adds php~, php.bak, php.old, php1, phps, etc.)
  - robots.txt parsing -> auto-queues Disallow paths
  - sitemap.xml parsing -> auto-queues <loc> paths
  - Priority queue for recursion (admin/api/backup/config directories scanned first)
  - Resume support via checkpoint.json
  - JSON / CSV / HTML report export
  - Live progress bar (tqdm)
  - Structured logging (INFO/WARNING/ERROR to console + optional log file)

Known limitation kept intentionally: no HTTP/2 support (would require httpx + h2,
adding a heavy dependency for marginal benefit against most lab/bug-bounty targets).
"""

import argparse
import asyncio
import csv
import hashlib
import heapq
import json
import logging
import random
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

try:
    import aiohttp
except ImportError:
    print("[-] Missing dependency. Install with: pip install aiohttp --break-system-packages")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[-] Missing dependency. Install with: pip install colorama --break-system-packages")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("[-] Missing dependency. Install with: pip install tqdm --break-system-packages")
    sys.exit(1)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

BACKUP_SUFFIXES = ["~", ".bak", ".old", ".save", ".orig", ".swp", ".1"]
DEEP_EXT_SUFFIXES = ["~", ".bak", ".old", "1", "s"]  # appended to base extension, e.g. php -> phps

PRIORITY_KEYWORDS = {  # lower number = scanned first
    "admin": 0, "api": 0, "backup": 0, "config": 0, "db": 0,
    "upload": 1, "uploads": 1, "dashboard": 1, "manage": 1, "internal": 1,
}
DEFAULT_PRIORITY = 5

REDIRECT_CLASSIFY = {
    "login": ["login", "signin", "auth"],
    "admin": ["admin", "wp-admin", "cpanel"],
    "dashboard": ["dashboard", "panel", "console"],
    "error": ["404", "error", "notfound"],
}
... 
... CDN_SIGNATURES = {
...     "Cloudflare": ["cf-ray", "cloudflare"],
...     "Akamai": ["akamai", "x-akamai"],
...     "Fastly": ["fastly", "x-fastly"],
...     "AWS CloudFront": ["x-amz-cf-id", "cloudfront"],
...     "Azure": ["x-azure-ref", "azure"],
... }
... WAF_SIGNATURES = {
...     "Cloudflare WAF": ["cf-ray", "__cfduid", "cloudflare"],
...     "Sucuri": ["x-sucuri-id", "sucuri"],
...     "Imperva/Incapsula": ["x-iinfo", "incap_ses"],
...     "ModSecurity": ["mod_security", "modsecurity"],
... }
... TECH_SIGNATURES = {
...     "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
...     "Laravel": ["laravel_session", "x-powered-by: laravel"],
...     "Django": ["csrftoken", "django"],
...     "Flask": ["werkzeug"],
...     "ASP.NET": ["x-aspnet-version", "asp.net", ".aspx"],
...     "Node.js/Express": ["x-powered-by: express"],
...     "PHP": ["x-powered-by: php", ".php"],
... }
... 
... 
... def banner():
...     print(Fore.CYAN + Style.BRIGHT + r"""
...   _   _                        ____  _      _         ____
...  | | | |_   _ _ __   ___ _ __ |  _ \(_)_ __| |__     |___ \
...  | |_| | | | | '_ \ / _ \ '__|| | | | | '__| '_ \      __) |
...  |  _  | |_| | |_) |  __/ |   | |_| | | |  | |_) |    / __/
...  |_| |_|\__, | .__/ \___|_|   |____/|_|_|  |_.__/    |_____|
...         |___/|_|      Async Content Discovery Scanner
...     """ + Style.RESET_ALL)
... 
... 
... def setup_logging(logfile):
...     logger = logging.getLogger("hyperdirb")
...     logger.setLevel(logging.DEBUG)
...     fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S")
... 
...     console = logging.StreamHandler()
...     console.setLevel(logging.WARNING)  # keep console clean; findings are printed separately
...     console.setFormatter(fmt)
...     logger.addHandler(console)
... 
...     if logfile:
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


def normalize_path(path):
    return path.strip("/")


def priority_for(path):
    lower = path.lower()
    for kw, prio in PRIORITY_KEYWORDS.items():
        if kw in lower:
            return prio
    return DEFAULT_PRIORITY


def extract_title(body_text):
    m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


def body_hash(body_bytes):
    return hashlib.md5(body_bytes).hexdigest()


def similarity(a, b):
    # cheap similarity check without importing difflib's heavier SequenceMatcher on huge bodies
    import difflib
    if not a or not b:
        return 0.0
    sample_a, sample_b = a[:2000], b[:2000]
    return difflib.SequenceMatcher(None, sample_a, sample_b).ratio()


def detect_signatures(headers_lower_str, body_lower, signature_map):
    hits = []
    haystack = headers_lower_str + " " + body_lower[:3000]
    for name, sigs in signature_map.items():
        if any(sig in haystack for sig in sigs):
            hits.append(name)
    return hits


def classify_redirect(location):
    if not location:
        return "unknown"
    loc_lower = location.lower()
    for label, keywords in REDIRECT_CLASSIFY.items():
        if any(k in loc_lower for k in keywords):
            return label
    return "unknown"


def load_wordlist(path, extensions, deep_ext):
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if not w or w.startswith("#"):
                    continue
                words.append(w)
                if extensions:
                    for ext in extensions:
                        ext = ext.strip().lstrip(".")
                        words.append(f"{w}.{ext}")
                        if deep_ext:
                            for suf in DEEP_EXT_SUFFIXES:
                                words.append(f"{w}.{ext}{suf}")
    except FileNotFoundError:
        print(Fore.RED + f"[-] Wordlist not found: {path}")
        sys.exit(1)
    return words


@dataclass
class ScanState:
    target: str
    baseline_status: int = None
    baseline_len: int = None
    baseline_title: str = ""
    baseline_hash: str = ""
    baseline_body: str = ""
    visited: set = field(default_factory=set)
    results: list = field(default_factory=list)
    scanned: int = 0
    found: int = 0
    consecutive_429: int = 0
    current_delay: float = 0.0
    fingerprint: dict = field(default_factory=dict)
    tech: list = field(default_factory=list)
    cdn: list = field(default_factory=list)
    waf: list = field(default_factory=list)


async def fetch(session, url, method, timeout, retries, state, logger):
    """Fetch with retry + exponential backoff + adaptive 429 handling."""
    backoff = 0.5
    for attempt in range(retries + 1):
        try:
            if state.current_delay:
                await asyncio.sleep(state.current_delay + random.uniform(0, 0.1))

            async with session.request(method, url, timeout=timeout, allow_redirects=False, ssl=False) as resp:
                body = b""
                if method != "HEAD":
                    body = await resp.read()

                if resp.status == 429:
                    state.consecutive_429 += 1
                    state.current_delay = min(state.current_delay + 0.25, 3.0)
                    logger.warning(f"429 Too Many Requests at {url} - backing off (delay={state.current_delay:.2f}s)")
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue

                if resp.status >= 500 and attempt < retries:
                    logger.warning(f"{resp.status} server error at {url}, retrying ({attempt+1}/{retries})")
                    await asyncio.sleep(backoff)
                    backoff *= 2
                    continue

                # success path: slowly relax the adaptive delay if things are healthy
                if state.consecutive_429 > 0:
                    state.consecutive_429 = 0
                    state.current_delay = max(0.0, state.current_delay - 0.1)

                return resp.status, dict(resp.headers), body

        except (aiohttp.ClientConnectionError, aiohttp.ServerTimeoutError, asyncio.TimeoutError):
            if attempt < retries:
                await asyncio.sleep(backoff)
                backoff *= 2
                continue
            return None, None, None
        except aiohttp.ClientError:
            return None, None, None

    return None, None, None


async def calibrate(session, target, method, timeout, retries, state, logger):
    probe = f"{target}/hyperdirb_wc_{random.randint(100000,999999)}"
    status, headers, body = await fetch(session, probe, method, timeout, retries, state, logger)
    if status is None:
        return
    text = body.decode("utf-8", errors="ignore") if body else ""
    state.baseline_status = status
    state.baseline_len = len(body) if body else 0
    state.baseline_title = extract_title(text)
    state.baseline_hash = body_hash(body) if body else ""
    state.baseline_body = text

    # root fingerprint
    status2, headers2, body2 = await fetch(session, target, method, timeout, retries, state, logger)
    if headers2:
        hdr_str = " ".join(f"{k.lower()}: {v.lower()}" for k, v in headers2.items())
        body2_text = body2.decode("utf-8", errors="ignore") if body2 else ""
        state.fingerprint = {k: v for k, v in headers2.items()
                              if k.lower() in ("server", "x-powered-by", "via", "cf-ray", "etag")}
        state.cdn = detect_signatures(hdr_str, body2_text.lower(), CDN_SIGNATURES)
        state.waf = detect_signatures(hdr_str, body2_text.lower(), WAF_SIGNATURES)
        state.tech = detect_signatures(hdr_str, body2_text.lower(), TECH_SIGNATURES)


async def parse_robots(session, target, method, timeout, retries, state, logger, pq, counter):
    status, headers, body = await fetch(session, f"{target}/robots.txt", "GET", timeout, retries, state, logger)
    if status != 200 or not body:
        return 0
    text = body.decode("utf-8", errors="ignore")
    added = 0
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith(("disallow:", "allow:")):
            path = line.split(":", 1)[1].strip()
            path = normalize_path(path)
            if path and path not in state.visited:
                counter[0] += 1
                heapq.heappush(pq, (-1, counter[0], path))
                added += 1
    return added


async def parse_sitemap(session, target, method, timeout, retries, state, logger, pq, counter):
    status, headers, body = await fetch(session, f"{target}/sitemap.xml", "GET", timeout, retries, state, logger)
    if status != 200 or not body:
        return 0
    added = 0
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(body)
        for loc in root.iter():
            if loc.tag.endswith("loc") and loc.text:
                path = normalize_path(urlparse(loc.text).path)
                if path and path not in state.visited:
                    counter[0] += 1
                    heapq.heappush(pq, (-1, counter[0], path))
                    added += 1
    except ET.ParseError:
        pass
    return added


def print_hit(status, url, clen, tag, color, extra=""):
    print(color + Style.BRIGHT + f"[{tag}] {status} | len={clen:<7} | {url}{extra}")


async def worker(name, session, target, pq, counter, method, timeout, retries,
                  args, state, logger, out_lock, outfile, pbar, seen_lock):
    while True:
        try:
            _, _, word = heapq.heappop(pq)
        except IndexError:
            return

        path = normalize_path(word)
        if not path or path in state.visited:
            continue
        async with seen_lock:
            if path in state.visited:
                continue
            state.visited.add(path)

        depth = path.count("/")
        if depth > args.max_depth:
            continue

        url = f"{target}/{path}"
        status, headers, body = await fetch(session, url, method, timeout, retries, state, logger)
        state.scanned += 1
        pbar.update(1)

        if status is None:
            continue

        if status == 520:
            logger.warning(f"Cloudflare 520 anomaly at {url}")
            continue

        clen = len(body) if body else 0
        text = body.decode("utf-8", errors="ignore") if body else ""

        # soft-404 filtering
        if state.baseline_status is not None and status == state.baseline_status:
            title = extract_title(text)
            same_len = clen == state.baseline_len
            same_title = title == state.baseline_title and title != ""
            sim = similarity(text, state.baseline_body) if not same_len else 1.0
            if same_len or same_title or sim > 0.92:
                continue

        if args.status and status not in args.status:
            continue

        color, tag = None, None
        if status == 200:
            color, tag = Fore.GREEN, "FOUND"
        elif status == 403:
            color, tag = Fore.YELLOW, "FORBIDDEN"
        elif status in (301, 302, 307, 308):
            color, tag = Fore.CYAN, "REDIRECT"
        elif status == 401:
            color, tag = Fore.BLUE, "AUTH"
        elif status == 500:
            color, tag = Fore.RED, "SRV-ERR"
        else:
            continue

        extra = ""
        if tag == "REDIRECT":
            loc = headers.get("Location", "")
            cls = classify_redirect(loc)
            extra = f" -> {loc} [{cls}]"

        record = {
            "url": url, "status": status, "length": clen, "tag": tag,
            "location": headers.get("Location") if tag == "REDIRECT" else None,
            "server": headers.get("Server"), "content_type": headers.get("Content-Type"),
        }

        async with out_lock:
            state.found += 1
            state.results.append(record)
            pbar.write(color + Style.BRIGHT + f"[{tag}] {status} | len={clen:<7} | {url}{extra}")
            if outfile:
                with open(outfile, "a") as f:
                    f.write(f"[{tag}] {status} | len={clen} | {url}{extra}\n")

        # backup file probing
        if args.backup_detect and tag == "FOUND" and "." in path.rsplit("/", 1)[-1]:
            for suf in BACKUP_SUFFIXES:
                cand = path + suf
                if cand not in state.visited:
                    counter[0] += 1
                    heapq.heappush(pq, (0, counter[0], cand))

        # recursion into directories
        looks_like_dir = tag in ("FOUND", "REDIRECT") and "." not in path.rsplit("/", 1)[-1]
        if args.recursive and looks_like_dir and depth < args.max_depth:
            base = path if path.endswith("/") else path + "/"
            for w in args.wordlist_words:
                cand = base + w
                if cand not in state.visited:
                    counter[0] += 1
                    heapq.heappush(pq, (priority_for(cand), counter[0], cand))


def save_checkpoint(path, state):
    data = {"visited": list(state.visited), "results": state.results, "scanned": state.scanned}
    with open(path, "w") as f:
        json.dump(data, f)


def load_checkpoint(path):
    p = Path(path)
    if not p.exists():
        return set(), [], 0
    data = json.loads(p.read_text())
    return set(data.get("visited", [])), data.get("results", []), data.get("scanned", 0)


def write_reports(state, base_name):
    if not state.results:
        return
    json_path = f"{base_name}.json"
    with open(json_path, "w") as f:
        json.dump(state.results, f, indent=2)

    csv_path = f"{base_name}.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(state.results[0].keys()))
        writer.writeheader()
        writer.writerows(state.results)

    html_path = f"{base_name}.html"
    rows = "\n".join(
        f"<tr><td>{r['status']}</td><td>{r['tag']}</td><td>{r['length']}</td>"
        f"<td><a href='{r['url']}'>{r['url']}</a></td><td>{r.get('location') or ''}</td></tr>"
        for r in state.results
    )
    html = f"""<html><head><title>HyperDirb Report</title>
    <style>body{{font-family:sans-serif}}table{{border-collapse:collapse;width:100%}}
    td,th{{border:1px solid #ccc;padding:6px}}th{{background:#222;color:#fff}}</style></head>
    <body><h2>HyperDirb Report - {len(state.results)} findings</h2>
    <table><tr><th>Status</th><th>Tag</th><th>Length</th><th>URL</th><th>Redirect</th></tr>
    {rows}</table></body></html>"""
    with open(html_path, "w") as f:
        f.write(html)

    print(Fore.CYAN + f"[*] Reports written: {json_path}, {csv_path}, {html_path}")


async def run(args):
    logger = setup_logging(args.log)
    target = args.target.rstrip("/")
    state = ScanState(target=target)

    checkpoint_path = args.checkpoint or "checkpoint.json"
    if args.resume:
        visited, results, scanned = load_checkpoint(checkpoint_path)
        state.visited, state.results, state.scanned = visited, results, scanned
        print(Fore.CYAN + f"[*] Resumed: {len(visited)} paths already scanned, {len(results)} prior findings")

    words = load_wordlist(args.wordlist, args.extensions, args.deep_ext)
    args.wordlist_words = words  # used by recursion

    method = args.method
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    connector = aiohttp.TCPConnector(limit=args.threads, ssl=False)
    headers = {"User-Agent": random.choice(USER_AGENTS) if args.random_agent else USER_AGENTS[0]}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        print(Fore.CYAN + "[*] Calibrating soft-404 baseline + fingerprinting target...")
        await calibrate(session, target, method, timeout, args.retries, state, logger)
        if state.baseline_status:
            print(Fore.CYAN + f"[*] Baseline 404 -> status={state.baseline_status} len={state.baseline_len} title='{state.baseline_title}'")
        if state.fingerprint:
            print(Fore.CYAN + f"[*] Fingerprint  -> {state.fingerprint}")
        if state.cdn:
            print(Fore.MAGENTA + f"[*] CDN detected  -> {', '.join(state.cdn)}")
        if state.waf:
            print(Fore.MAGENTA + f"[*] WAF detected  -> {', '.join(state.waf)}")
        if state.tech:
            print(Fore.MAGENTA + f"[*] Tech detected -> {', '.join(state.tech)}")
        print("-" * 70)

        pq = []
        counter = [0]
        for w in words:
            counter[0] += 1
            heapq.heappush(pq, (priority_for(w), counter[0], w))

        if args.robots:
            n = await parse_robots(session, target, method, timeout, args.retries, state, logger, pq, counter)
            if n:
                print(Fore.CYAN + f"[*] robots.txt -> queued {n} extra paths")
        if args.sitemap:
            n = await parse_sitemap(session, target, method, timeout, args.retries, state, logger, pq, counter)
            if n:
                print(Fore.CYAN + f"[*] sitemap.xml -> queued {n} extra paths")

        total_estimate = len(pq)
        out_lock = asyncio.Lock()
        seen_lock = asyncio.Lock()
        pbar = tqdm(total=total_estimate, unit="req", dynamic_ncols=True,
                    bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{rate_fmt}]")

        async def checkpoint_loop():
            while True:
                await asyncio.sleep(5)
                if args.checkpoint_every:
                    save_checkpoint(checkpoint_path, state)

        cp_task = asyncio.create_task(checkpoint_loop()) if args.checkpoint_every else None

        try:
            workers = [
                asyncio.create_task(worker(
                    f"w{i}", session, target, pq, counter, method, timeout, args.retries,
                    args, state, logger, out_lock, args.output, pbar, seen_lock
                ))
                for i in range(args.threads)
            ]
            await asyncio.gather(*workers)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[-] Interrupted, saving checkpoint...")
        finally:
            pbar.close()
            if cp_task:
                cp_task.cancel()
            save_checkpoint(checkpoint_path, state)

    print("-" * 70)
    print(Fore.GREEN + Style.BRIGHT + f"[+] Done. {state.found} findings / {state.scanned} requests sent.")
    if args.report:
        write_reports(state, args.report)


def parse_args():
    p = argparse.ArgumentParser(description="HyperDirb v2 - Async content discovery scanner")
    p.add_argument("target", help="Target base URL, e.g. http://vulnweb.com")
    p.add_argument("wordlist", help="Path to wordlist")
    p.add_argument("-x", "--extensions", help="Comma-separated extensions, e.g. php,txt,bak")
    p.add_argument("-t", "--threads", type=int, default=50, help="Concurrent workers (default 50)")
    p.add_argument("-m", "--method", choices=["GET", "HEAD"], default="GET")
    p.add_argument("--timeout", type=float, default=6)
    p.add_argument("--retries", type=int, default=2, help="Retries per request on connection error/5xx/429")
    p.add_argument("--proxy", help="(reserved) proxy URL")
    p.add_argument("-o", "--output", help="Save live results as plain text")
    p.add_argument("--report", help="Base filename for JSON/CSV/HTML reports, e.g. scan1")
    p.add_argument("--random-agent", action="store_true")
    p.add_argument("-H", "--header", action="append", help="Custom header 'Key: Value'")
    p.add_argument("--cookie", help="Cookie string")
    p.add_argument("-s", "--status", help="Only show these status codes, e.g. 200,301,403",
                    type=lambda s: set(int(x) for x in s.split(",")))
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("--max-depth", type=int, default=2)
    p.add_argument("--backup-detect", action="store_true", help="Auto-probe backup variants of found files")
    p.add_argument("--deep-ext", action="store_true", help="Expand extensions with ~ .bak .old 1 s suffixes")
    p.add_argument("--robots", action="store_true", help="Parse robots.txt and queue disallowed paths")
    p.add_argument("--sitemap", action="store_true", help="Parse sitemap.xml and queue listed paths")
    p.add_argument("--resume", action="store_true", help="Resume from checkpoint.json")
    p.add_argument("--checkpoint", help="Checkpoint file path (default checkpoint.json)")
    p.add_argument("--checkpoint-every", action="store_true", help="Periodically save checkpoint during scan")
    p.add_argument("--log", help="Write debug log to this file")
    return p.parse_args()


if __name__ == "__main__":
    banner()
    args = parse_args()
    args.extensions = args.extensions.split(",") if args.extensions else None
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print(Fore.RED + "\n[-] Aborted by user.")
