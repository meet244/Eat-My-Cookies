"""
Clone a full browser session into a REAL Google Chrome and browse as that person.

Beyond cookies, this restores the *client identity* so the server sees a
consistent device and is far less likely to invalidate the session:

  - the exact User-Agent + User-Agent Client Hints (sec-ch-ua...) from the export
  - the original timezone and UI language (so JS/Date/Intl + Accept-Language match)
  - localStorage and sessionStorage for the captured site (auth/app state that
    lives OUTSIDE cookies)
  - every cookie, across every domain
  - the full browsing history (written straight into the profile's History DB;
    there is no DevTools command for history, so it must be written while
    Chrome is closed)

Why this matters: modern anti-abuse (Cloudflare, Google, etc.) correlates the
session cookies with the device fingerprint and request headers. If you replay
cookies from a mismatched client, the server sees "same cookie, different
device" and forces re-auth. Matching UA/hints/timezone/locale removes those
mismatch signals.

Source is a "Cookie Inspector" device export:
    { meta, device, currentSite{localStorage,sessionStorage,...},
      cookiesBySite{domain:[...]}, requestHeadersBySite }
A plain {domain:[cookies]} dump or a flat cookie list still works (device/
storage simply won't be available).

That export now lives in MongoDB (the extension uploads one document per user).
By default this script connects with backend/.env, lists the stored profiles,
asks in the terminal which one to load, and only then pulls that profile's data.
Set USE_MONGODB=False to read a local JSON file instead.

We use your ACTUAL Chrome (not Playwright), pass NO automation flags
(navigator.webdriver stays false), inject over DevTools for a few seconds, then
disconnect so there is no live automation while you browse. Just press Run.
"""

import hashlib
import html
import json
import os
import sqlite3
import subprocess
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

try:
    import websocket  # pip install websocket-client
except ImportError:
    raise SystemExit("Missing dependency. Run:  pip install websocket-client")

try:
    from pymongo import MongoClient           # pip install pymongo
    from dotenv import load_dotenv as _load_dotenv  # pip install python-dotenv
except ImportError:
    MongoClient = None
    _load_dotenv = None

# ============================ EDIT THESE ============================
# Where the export comes from. True = MongoDB (pick a profile in the terminal);
# False = read the local SOURCE_FILE below.
USE_MONGODB = True
ENV_FILE = Path(__file__).with_name(".env")        # MongoDB credentials
SOURCE_FILE = Path(__file__).with_name("data.json")  # used only if USE_MONGODB=False
# Page to open first. None = use the export's captured site (its origin).
START_URL = None
# Each restored profile gets its OWN isolated Chrome data folder under
# backend/users/<profile name>/ (created on demand). Never touches your normal
# Chrome data. Delete a sub-folder to reset just that one profile.
USERS_DIR = Path(__file__).with_name("users")
DEBUG_PORT = 9222
CHROME_PATH = None                 # None = auto-detect common macOS path
APPLY_DEVICE = True                # match UA / client-hints / timezone / locale
APPLY_STORAGE = True               # inject localStorage + sessionStorage
APPLY_HISTORY = True               # write browsing history into the profile DB
SHOW_START_DASHBOARD = True         # open a launcher listing every cookie site
COLLAPSE_SAME_FAVICON = True        # merge www./subdomains that share a favicon
# ===================================================================

_DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


# ----------------------------------------------------------------------
# Cookie conversion:  browser-export format  ->  CDP CookieParam
# ----------------------------------------------------------------------
def _to_epoch(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def to_cdp_cookie(c):
    name = c.get("name")
    host = (c.get("domain") or "").lstrip(".")
    if not name or not host:
        return None
    path = c.get("path") or "/"
    secure = bool(c.get("secure", False))
    param = {
        "name": name,
        "value": c.get("value") or "",
        "path": path,
        "httpOnly": bool(c.get("httpOnly", False)),
    }
    if c.get("hostOnly"):
        param["url"] = f"https://{host}/"      # host-only: no Domain attribute
    else:
        param["domain"] = "." + host

    same_site = str(c.get("sameSite", "")).lower()
    if same_site in ("no_restriction", "none"):
        param["sameSite"] = "None"
        secure = True                          # Chrome requires Secure for None
    elif same_site == "strict":
        param["sameSite"] = "Strict"
    elif same_site == "lax":
        param["sameSite"] = "Lax"
    param["secure"] = secure

    if not c.get("session"):
        exp = _to_epoch(c.get("expires"))
        if exp:
            param["expires"] = exp
    return param


def parse_bundle(data):
    """Turn a raw export (a JSON file's contents or a MongoDB document) into
    {cookies, device, storage, history, origin}."""
    raw, device, storage, origin, history = [], None, {}, None, []

    if isinstance(data, dict) and "cookiesBySite" in data:      # rich export
        for v in data["cookiesBySite"].values():
            if isinstance(v, list):
                raw.extend(v)
        device = data.get("device")
        history = data.get("history") or []
        cur = data.get("currentSite") or {}
        origin = cur.get("origin") or (data.get("meta") or {}).get("currentUrl")
        cur_origin = cur.get("origin")
        if cur_origin:
            storage[cur_origin] = {
                "local": cur.get("localStorage") or {},
                "session": cur.get("sessionStorage") or {},
                "acceptLanguage": (cur.get("requestHeaders") or {}).get("accept-language"),
            }
    elif isinstance(data, dict):                                # {domain:[...]}
        for v in data.values():
            if isinstance(v, list):
                raw.extend(v)
    elif isinstance(data, list):                                # flat list
        raw = data

    cookies = [p for p in (to_cdp_cookie(c) for c in raw) if p]
    return {"cookies": cookies, "device": device, "storage": storage,
            "history": history, "origin": origin}


def load_bundle(path):
    """Parse a local JSON export file."""
    return parse_bundle(json.load(open(path, "r", encoding="utf-8")))


# ----------------------------------------------------------------------
# MongoDB source:  connect, list profiles, ask which one, then load it
# ----------------------------------------------------------------------
def mongo_collection():
    """Connect to the Atlas collection using backend/.env credentials."""
    if MongoClient is None or _load_dotenv is None:
        raise SystemExit("Missing dependency. Run:  "
                         "pip install pymongo python-dotenv")
    _load_dotenv(ENV_FILE)
    uri = os.getenv("MONGODB_URI")
    if not uri:
        raise SystemExit(f"MONGODB_URI is not set in {ENV_FILE}")
    client = MongoClient(uri, serverSelectionTimeoutMS=8000)
    dbname = os.getenv("MONGODB_DB", "extension_db")
    collname = os.getenv("MONGODB_COLLECTION", "users")
    return client[dbname][collname]


def list_profiles(collection):
    """Every stored profile (username + meta only), sorted by name. The heavy
    cookiesBySite/history fields are NOT fetched here -- only after you pick."""
    docs = list(collection.find({}, {"username": 1, "meta": 1}))
    docs.sort(key=lambda d: str(d.get("username", "")).lower())
    return docs


def _fmt_updated(value):
    """Human-readable 'YYYY-MM-DD HH:MM' from meta.generatedAt (the last time
    this profile was exported/updated), or '?' if it's missing/unparseable."""
    if not value:
        return "?"
    s = str(value)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return s[:10]


def choose_profile(profiles):
    """Show the profiles and block until a valid one is chosen; returns username."""
    print(f"\n{len(profiles)} profile(s) available on MongoDB:")
    for i, p in enumerate(profiles, 1):
        meta = p.get("meta") or {}
        counts = meta.get("counts") or {}
        updated = _fmt_updated(meta.get("generatedAt"))
        print(f"  [{i}] {p.get('username')}"
              f"   ({counts.get('cookieSites', '?')} sites, "
              f"{counts.get('historyPages', '?')} history pages, "
              f"last updated {updated})")
    while True:
        choice = input(f"\nWhich profile do you want to load? "
                       f"[1-{len(profiles)} or username]: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(profiles):
            return profiles[int(choice) - 1]["username"]
        if choice:
            for p in profiles:
                if str(p.get("username", "")).lower() == choice.lower():
                    return p["username"]
        print("  Not a valid choice — try again.")


def load_bundle_from_mongo(collection, username):
    """Fetch one profile's full document and parse it into a bundle."""
    doc = collection.find_one({"username": username})
    if not doc:
        raise SystemExit(f"Profile {username!r} not found in MongoDB.")
    return parse_bundle(doc)


def profile_dir_for(name):
    """backend/users/<name>/ -- this profile's own isolated Chrome data folder.
    The name is sanitized to a single safe folder (no slashes / traversal)."""
    safe = "".join(c if (c.isalnum() or c in " ._-") else "_"
                   for c in str(name or "profile")).strip(" .") or "profile"
    return USERS_DIR / safe


# ----------------------------------------------------------------------
# Device / client-hints helpers
# ----------------------------------------------------------------------
def _brand_list(items):
    return [{"brand": b.get("brand", ""), "version": b.get("version", "")}
            for b in (items or [])]


def ua_metadata(device):
    """Build CDP Emulation userAgentMetadata from the export's clientHints."""
    ch = device.get("clientHints") or {}
    return {
        "brands": _brand_list(ch.get("brands")),
        "fullVersionList": _brand_list(ch.get("fullVersionList")),
        "fullVersion": ch.get("uaFullVersion", ""),
        "platform": ch.get("platform", ""),
        "platformVersion": ch.get("platformVersion", ""),
        "architecture": ch.get("architecture", ""),
        "model": ch.get("model", ""),
        "mobile": bool(ch.get("mobile", False)),
        "bitness": ch.get("bitness", ""),
        "wow64": False,
    }


def chrome_major(path):
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True,
                             timeout=10).stdout
        return int("".join(ch for ch in out.split("Chrome")[-1] if ch.isdigit() or ch == ".").strip(".").split(".")[0])
    except Exception:
        return None


def device_major(device):
    for b in (device.get("clientHints") or {}).get("brands", []):
        if b.get("brand") == "Google Chrome":
            try:
                return int(str(b.get("version")).split(".")[0])
            except (ValueError, TypeError):
                pass
    return None


# ----------------------------------------------------------------------
# Minimal DevTools (CDP) client, with flat-session support
# ----------------------------------------------------------------------
class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, max_size=None, timeout=30)
        self._id = 0

    def call(self, method, params=None, session_id=None):
        self._id += 1
        msg = {"id": self._id, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        self.ws.send(json.dumps(msg))
        while True:
            resp = json.loads(self.ws.recv())
            if resp.get("id") == self._id:
                if "error" in resp:
                    raise RuntimeError(resp["error"])
                return resp.get("result", {})
            # ignore events

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def browser_ws_url(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version",
                                    timeout=1) as r:
            return json.load(r)["webSocketDebuggerUrl"]
    except Exception:
        return None


def launch_chrome(chrome_path, port, profile_dir, device, pin_ua):
    profile_dir.mkdir(parents=True, exist_ok=True)
    args = [
        chrome_path,
        f"--remote-debugging-port={port}",
        "--remote-allow-origins=*",   # Chrome 111+ needs this or the ws is 403'd
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    env = os.environ.copy()
    if device:
        # Timezone + UI language become the persistent baseline for EVERY tab,
        # including ones you open by hand later (survives our disconnect).
        tz = device.get("timezone")
        if tz:
            env["TZ"] = tz
        lang = (device.get("languages") or [device.get("language")] or [None])[0]
        if lang:
            args.append(f"--lang={lang}")
        # Only pin the UA string when the installed Chrome matches the export's
        # major version. Pinning an OLD UA onto a NEWER Chrome would make the UA
        # disagree with the (native) client hints -> a worse, detectable signal.
        ua = device.get("userAgent")
        if ua and pin_ua:
            args.append(f"--user-agent={ua}")
    args.append("about:blank")
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True, env=env)


def set_cookies_in_chunks(cdp, cookies, chunk=400):
    ok = 0
    for i in range(0, len(cookies), chunk):
        batch = cookies[i:i + chunk]
        try:
            cdp.call("Storage.setCookies", {"cookies": batch})
            ok += len(batch)
        except RuntimeError:
            for one in batch:
                try:
                    cdp.call("Storage.setCookies", {"cookies": [one]})
                    ok += 1
                except RuntimeError:
                    pass
    return ok


def open_site_with_identity(cdp, url, device, store):
    """Open the site, apply exact UA/hints/timezone to that tab, then write its
    localStorage/sessionStorage, then reload so the app boots with everything."""
    target = cdp.call("Target.createTarget", {"url": url})["targetId"]
    sid = cdp.call("Target.attachToTarget",
                   {"targetId": target, "flatten": True})["sessionId"]

    if APPLY_DEVICE and device:
        override = {
            "userAgent": device.get("userAgent", ""),
            "userAgentMetadata": ua_metadata(device),
        }
        accept_lang = (store or {}).get("acceptLanguage")
        if accept_lang:
            override["acceptLanguage"] = accept_lang
        if device.get("platform"):
            override["platform"] = device["platform"]
        try:
            cdp.call("Emulation.setUserAgentOverride", override, session_id=sid)
        except RuntimeError:
            pass
        tz = device.get("timezone")
        if tz:
            try:
                cdp.call("Emulation.setTimezoneOverride",
                         {"timezoneId": tz}, session_id=sid)
            except RuntimeError:
                pass

    injected = 0
    if APPLY_STORAGE and store:
        time.sleep(3.0)  # let the origin commit before touching its storage
        ls = store.get("local") or {}
        ss = store.get("session") or {}
        expr = (
            "(function(){var n=0;"
            "var ls=" + json.dumps(ls) + ";"
            "for(var k in ls){try{localStorage.setItem(k,ls[k]);n++;}catch(e){}}"
            "var ss=" + json.dumps(ss) + ";"
            "for(var k in ss){try{sessionStorage.setItem(k,ss[k]);n++;}catch(e){}}"
            "return n;})()"
        )
        try:
            res = cdp.call("Runtime.evaluate",
                           {"expression": expr, "returnByValue": True},
                           session_id=sid)
            injected = res.get("result", {}).get("value", 0)
            cdp.call("Runtime.evaluate",
                     {"expression": "location.reload()"}, session_id=sid)
        except RuntimeError:
            pass
    return injected


# ----------------------------------------------------------------------
# Browsing history:  export list  ->  profile's History SQLite DB
# ----------------------------------------------------------------------
# History cannot be injected over DevTools -- Chrome keeps it in a SQLite DB
# (<profile>/Default/History) that is only safe to write while Chrome is CLOSED.
# So we make sure a correctly-versioned DB exists (letting Chrome create it),
# then INSERT one url + one visit row per entry before the real launch.

# link visit, standalone chain: PageTransition LINK | CHAIN_START | CHAIN_END
_HISTORY_TRANSITION = 805306368
# seconds between the Unix epoch (1970) and Chrome's epoch (1601-01-01 UTC)
_CHROME_EPOCH_OFFSET = 11644473600


def chrome_time(unix_seconds):
    """Unix seconds -> Chrome time (microseconds since 1601-01-01 UTC)."""
    return int((unix_seconds + _CHROME_EPOCH_OFFSET) * 1_000_000)


def _history_db(profile_dir):
    return profile_dir / "Default" / "History"


def ensure_history_db(chrome, port, profile_dir, device, pin_ua):
    """Guarantee a History DB exists, leaving Chrome CLOSED afterwards. On a
    fresh profile we briefly launch Chrome so it creates a DB whose schema
    matches the installed version, then shut it down cleanly."""
    db = _history_db(profile_dir)
    if db.exists():
        return db
    launch_chrome(chrome, port, profile_dir, device, pin_ua)
    ws = None
    for _ in range(80):                       # wait for the debug port
        ws = browser_ws_url(port)
        if ws:
            break
        time.sleep(0.25)
    for _ in range(80):                       # wait for the DB file to appear
        if db.exists():
            break
        time.sleep(0.25)
    try:                                      # clean shutdown -> flushed + unlocked
        if ws:
            c = CDP(ws)
            c.call("Browser.close")
            c.close()
    except Exception:
        pass
    for _ in range(80):                       # wait for the port to be released
        if not browser_ws_url(port):
            break
        time.sleep(0.25)
    time.sleep(0.5)
    return db


def load_history_into_profile(profile_dir, history):
    """INSERT the export's history into the profile's History DB. Chrome must be
    closed. Returns the number of entries written."""
    db = _history_db(profile_dir)
    if not db.exists() or not history:
        return 0
    con = sqlite3.connect(str(db), timeout=30)
    try:
        cur = con.cursor()
        seen = {row[0] for row in cur.execute("SELECT url FROM urls")}
        added = 0
        for h in history:
            url = h.get("url")
            if not url or url in seen:
                continue
            t = _to_epoch(h.get("lastVisit"))
            if t is None:
                continue
            when = chrome_time(t)
            cur.execute(
                "INSERT INTO urls(url,title,visit_count,typed_count,"
                "last_visit_time,hidden) VALUES(?,?,?,?,?,0)",
                (url, h.get("title") or "", int(h.get("visitCount") or 1),
                 int(h.get("typedCount") or 0), when))
            cur.execute(
                "INSERT INTO visits(url,visit_time,transition,visit_duration)"
                " VALUES(?,?,?,0)", (cur.lastrowid, when, _HISTORY_TRANSITION))
            seen.add(url)
            added += 1
        con.commit()
        try:
            cur.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.OperationalError:
            pass
        return added
    finally:
        con.close()


# ----------------------------------------------------------------------
# Start dashboard:  a launcher page listing every site we dropped cookies for
# ----------------------------------------------------------------------
def _is_navigable_host(host):
    """Skip IPs, IPv6, localhost and bare hostnames -- they have no favicon and
    aren't 'websites' you navigate to."""
    if not host or host == "localhost" or "." not in host or ":" in host:
        return False
    last = host.rsplit(".", 1)[-1]
    if last.isdigit():                         # ...ends in a number -> IPv4
        return False
    return True


def history_hits(history):
    """host-suffix -> total visit count, so a site is credited for visits to
    itself AND all of its subdomains (www.claude.ai counts toward claude.ai)."""
    hits = {}
    for h in history or []:
        host = urllib.parse.urlsplit(h.get("url") or "").hostname or ""
        if not host:
            continue
        try:
            visits = int(h.get("visitCount") or 0)
        except (TypeError, ValueError):
            visits = 0
        visits = max(visits, 1)                 # accessed at least once
        labels = host.split(".")
        for i in range(len(labels) - 1):        # every 2+ label suffix, not the TLD
            suffix = ".".join(labels[i:])
            hits[suffix] = hits.get(suffix, 0) + visits
    return hits


def cookie_sites(cookies, history=None):
    """[(host, cookie_count, visit_count)] for every navigable site, ranked by
    how often it was visited in the history (then cookie count, then name)."""
    counts = {}
    for p in cookies:
        host = (p.get("domain") or p.get("url", "")).lstrip(".")
        host = host.replace("https://", "").replace("http://", "").rstrip("/")
        if _is_navigable_host(host):
            counts[host] = counts.get(host, 0) + 1
    hits = history_hits(history)
    rows = [(host, n, hits.get(host, 0)) for host, n in counts.items()]
    rows.sort(key=lambda r: (-r[2], -r[1], r[0]))
    return rows


# image magic bytes -- so an HTML error page served at /favicon.ico is rejected
_FAVICON_MAGIC = (b"\x00\x00\x01\x00", b"\x89PNG", b"GIF8", b"RIFF",
                  b"\xff\xd8", b"<svg", b"<?xml")


def favicon_hash(host, timeout=4):
    """SHA-1 of the site's /favicon.ico bytes, or None if missing/not an image.
    Two hosts with the same hash are visually the same site."""
    try:
        req = urllib.request.Request(f"https://{host}/favicon.ico",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ctype = (r.headers.get("Content-Type") or "").lower()
            data = r.read(200_000)
    except Exception:
        return None
    if not data:
        return None
    looks_img = "image" in ctype or any(
        data[:8].lstrip().startswith(m) for m in _FAVICON_MAGIC)
    return hashlib.sha1(data).hexdigest() if looks_img else None


def _reg_domain(host):
    """Crude registrable domain (last two labels) -- only used to *group*
    merge candidates; the favicon hash is the real gate, so grouping slips
    (e.g. multi-part suffixes) are harmless."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def collapse_by_favicon(sites, profile_dir=None, timeout=3, workers=64):
    """Merge hosts under the same registrable domain ONLY when they serve an
    identical favicon (so www.x + x collapse, but mail.google.com stays). Each
    surviving card keeps the shortest host as its link. Favicon hashes are cached
    next to the profile so only the first run pays the network cost."""
    groups = defaultdict(list)
    for row in sites:
        groups[_reg_domain(row[0])].append(row)

    # a favicon is only worth fetching for hosts that might merge with a sibling
    candidates = [r[0] for g in groups.values() if len(g) > 1 for r in g]

    cache_path = (profile_dir / "favicon-cache.json") if profile_dir else None
    cache = {}
    if cache_path and cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text())
        except Exception:
            cache = {}
    to_fetch = [h for h in candidates if h not in cache]
    if to_fetch:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for host, hh in zip(to_fetch,
                                ex.map(lambda h: favicon_hash(h, timeout),
                                       to_fetch)):
                cache[host] = hh or ""          # "" = no/failed favicon (cached)
        if cache_path:
            try:
                cache_path.write_text(json.dumps(cache))
            except Exception:
                pass
    hashes = {h: (cache.get(h) or None) for h in candidates}

    result = []
    for g in groups.values():
        if len(g) == 1:
            result.append(g[0])
            continue
        clusters = defaultdict(list)
        for host, n, v in g:
            hh = hashes.get(host)
            # None (no/unknown favicon) never merges -> unique key per host
            clusters[hh if hh else f"__none__{host}"].append((host, n, v))
        for members in clusters.values():
            if len(members) == 1:
                result.append(members[0])
            else:
                rep = min(members, key=lambda r: (len(r[0]), -r[2], r[0]))
                result.append((rep[0], sum(m[1] for m in members),
                               max(m[2] for m in members)))
    result.sort(key=lambda r: (-r[2], -r[1], r[0]))
    return result


_START_PAGE_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--border:#e3e6ea;--fg:#1a1c1e;--muted:#6b7280;
--accent:#3b82f6;--shadow:0 1px 2px rgba(0,0,0,.06),0 1px 3px rgba(0,0,0,.05)}
@media (prefers-color-scheme:dark){:root{--bg:#16181c;--card:#1f2227;
--border:#2c3038;--fg:#e6e8eb;--muted:#9aa2ad;--accent:#60a5fa;
--shadow:0 1px 2px rgba(0,0,0,.4)}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 20px}
.search{width:100%;padding:11px 14px;font-size:15px;border:1px solid var(--border);
border-radius:10px;background:var(--card);color:var(--fg);margin-bottom:20px}
.search:focus{outline:none;border-color:var(--accent)}
.grid{display:grid;gap:10px;grid-template-columns:repeat(auto-fill,minmax(210px,1fr))}
.card{display:flex;align-items:center;gap:11px;padding:11px 13px;background:var(--card);
border:1px solid var(--border);border-radius:11px;text-decoration:none;color:inherit;
box-shadow:var(--shadow);transition:transform .08s,border-color .12s}
.card:hover{transform:translateY(-1px);border-color:var(--accent)}
.fav{width:28px;height:28px;border-radius:6px;flex:0 0 28px;object-fit:contain;
background:var(--bg)}
.fav.letter{display:flex;align-items:center;justify-content:center;font-weight:600;
color:#fff;background:var(--accent);font-size:14px}
.meta{min-width:0}.host{display:block;font-weight:550;white-space:nowrap;
overflow:hidden;text-overflow:ellipsis}
.count{display:block;font-size:12px;color:var(--muted)}
.empty{color:var(--muted);padding:24px 0}
"""

_START_PAGE_JS = """
function favErr(img){
  var host=img.getAttribute('data-host');
  if(img.getAttribute('data-step')==='1'){
    var s=document.createElement('span');s.className='fav letter';
    s.textContent=(host[0]||'?').toUpperCase();img.replaceWith(s);return;
  }
  img.setAttribute('data-step','1');
  img.src='https://icons.duckduckgo.com/ip3/'+host+'.ico';
}
var box=document.getElementById('q'),cards=document.querySelectorAll('.card');
box.addEventListener('input',function(){
  var q=box.value.trim().toLowerCase(),shown=0;
  cards.forEach(function(c){
    var hit=c.getAttribute('data-host').indexOf(q)>-1;
    c.style.display=hit?'':'none';if(hit)shown++;
  });
  document.getElementById('empty').style.display=shown?'none':'block';
});
"""


def build_start_page(cookies, history, profile_dir):
    """Write a self-contained launcher HTML page; return (Path, site_count)."""
    sites = cookie_sites(cookies, history)
    if COLLAPSE_SAME_FAVICON:
        sites = collapse_by_favicon(sites, profile_dir)
    cards = []
    for host, _n, v in sites:
        h = html.escape(host, quote=True)
        visits = (f"{v} visit{'s' if v != 1 else ''}" if v
                  else "not in history")
        cards.append(
            f'<a class="card" href="https://{h}/" data-host="{h}" '
            f'target="_blank" rel="noopener" title="{h} — {visits}">'
            f'<img class="fav" loading="lazy" data-host="{h}" '
            f'src="https://{h}/favicon.ico" onerror="favErr(this)" alt="">'
            f'<span class="meta"><span class="host">{h}</span>'
            f'<span class="count">{visits}</span></span></a>'
        )
    doc = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Restored sessions</title><style>" + _START_PAGE_CSS +
        "</style></head><body><div class='wrap'>"
        "<h1>Restored sessions</h1>"
        f"<p class='sub'><b>{len(sites)}</b> sites, ordered by how often you "
        "visited them. Click one to open it in a new tab.</p>"
        "<input id='q' class='search' placeholder='Filter sites…' autofocus>"
        "<div class='grid'>" + "".join(cards) + "</div>"
        "<div id='empty' class='empty' style='display:none'>No matches.</div>"
        "</div><script>" + _START_PAGE_JS + "</script></body></html>"
    )
    profile_dir.mkdir(parents=True, exist_ok=True)
    out = profile_dir / "start.html"
    out.write_text(doc, encoding="utf-8")
    return out, len(sites)


def open_start_dashboard(cdp, cookies, history, profile_dir):
    """Open the launcher page and bring it to the front. Returns (Path, count)."""
    page, count = build_start_page(cookies, history, profile_dir)
    tid = cdp.call("Target.createTarget", {"url": page.as_uri()})["targetId"]
    try:
        cdp.call("Target.activateTarget", {"targetId": tid})
    except RuntimeError:
        pass
    return page, count


def main():
    chrome = CHROME_PATH or _DEFAULT_CHROME
    if not Path(chrome).exists():
        raise SystemExit(f"Chrome not found at {chrome!r}; set CHROME_PATH.")

    if USE_MONGODB:
        print("Connecting to MongoDB...")
        collection = mongo_collection()
        profiles = list_profiles(collection)
        if not profiles:
            raise SystemExit("No profiles found in MongoDB.")
        username = choose_profile(profiles)
        print(f"Loading '{username}' from MongoDB...")
        bundle = load_bundle_from_mongo(collection, username)
        profile_name = username
    else:
        bundle = load_bundle(SOURCE_FILE)
        profile_name = SOURCE_FILE.stem
    cookies, device = bundle["cookies"], bundle["device"]
    start_url = START_URL or bundle["origin"] or "about:blank"

    # This profile's own isolated Chrome data folder: backend/users/<name>/
    profile_dir = profile_dir_for(profile_name)
    profile_dir.mkdir(parents=True, exist_ok=True)
    print(f"Profile folder: {profile_dir}")

    domains = {(p.get("domain") or p.get("url", "")).lstrip(".") for p in cookies}
    print(f"Loaded {len(cookies)} cookies across ~{len(domains)} domains.")

    pin_ua = True
    if device:
        cmaj, dmaj = chrome_major(chrome), device_major(device)
        pin_ua = APPLY_DEVICE and (cmaj is None or dmaj is None or cmaj == dmaj)
        print(f"Device: {device.get('platform')} / Chrome {dmaj} / "
              f"{device.get('timezone')} / "
              f"{(device.get('languages') or ['?'])[0]}")
        if cmaj and dmaj and cmaj != dmaj:
            print(f"  ! Installed Chrome is {cmaj} but export is {dmaj}. Not "
                  "pinning the UA string (would clash with native client hints). "
                  "Re-export from this machine for an exact match.")

    # History goes straight into the profile's SQLite DB, which is only safe to
    # touch while Chrome is closed -- so do it before the launch below.
    if APPLY_HISTORY and bundle["history"]:
        if browser_ws_url(DEBUG_PORT):
            print("  ! Chrome already on the debug port; skipping history "
                  "(it can only be written while Chrome is closed).")
        else:
            ensure_history_db(chrome, DEBUG_PORT, profile_dir,
                              device if APPLY_DEVICE else None, pin_ua)
            n = load_history_into_profile(profile_dir, bundle["history"])
            print(f"Loaded {n}/{len(bundle['history'])} history entries into "
                  "the profile.")

    ws_url = browser_ws_url(DEBUG_PORT)
    if ws_url:
        print(f"Reusing Chrome already listening on :{DEBUG_PORT}")
    else:
        print("Launching your real Google Chrome...")
        launch_chrome(chrome, DEBUG_PORT, profile_dir, device if APPLY_DEVICE else None, pin_ua)
        for _ in range(80):
            ws_url = browser_ws_url(DEBUG_PORT)
            if ws_url:
                break
            time.sleep(0.25)
        if not ws_url:
            raise SystemExit("Could not reach Chrome's debug port; close any "
                             "other debug Chrome and retry.")

    try:
        cdp = CDP(ws_url)
    except websocket.WebSocketBadStatusException:
        raise SystemExit(
            "\nChrome refused the DevTools connection (403). A Chrome from an "
            "OLD run is still on this port without --remote-allow-origins.\n"
            f"Fix: fully QUIT that Chrome (the one using '{profile_dir.name}') "
            "and run again.")

    print("Injecting cookies...")
    ok = set_cookies_in_chunks(cdp, cookies)
    print(f"Set {ok}/{len(cookies)} cookies.")

    if start_url and start_url != "about:blank":
        store = bundle["storage"].get(start_url) or bundle["storage"].get(bundle["origin"])
        n = open_site_with_identity(cdp, start_url, device, store)
        print(f"Opened {start_url}"
              + (f" (+{n} storage keys)" if n else ""))

    # Open the launcher LAST so it's the front-most tab you land on.
    if SHOW_START_DASHBOARD and cookies:
        if COLLAPSE_SAME_FAVICON:
            print("Merging duplicate sites by favicon...")
        page, n_sites = open_start_dashboard(cdp, cookies, bundle["history"],
                                             profile_dir)
        print(f"Start page: {n_sites} sites -> {page}")

    cdp.close()  # disconnect: no live automation while you browse
    print("\nDone. Chrome is yours — the session now matches the original "
          "device's UA, client-hints, timezone, locale, cookies, storage and "
          "history.")
    print(f"Profile saved at: {profile_dir}")


if __name__ == "__main__":
    main()
