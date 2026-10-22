#!/usr/bin/env python3
"""Verzamelt openbare dreigingsinformatie en schrijft site/dreigingsbeeld.json en site/history.json.

Alleen standaardbibliotheek. Bevat geen organisatiespecifieke gegevens: filtering op
producten en de berekening van het dreigingsniveau gebeuren in de HTML bij de gebruiker.
"""
import csv
import email.utils
import html
import io
import json
import os
import re
import time
import urllib.parse
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.path.dirname(__file__), "..", "site")
PAGES_URL = os.environ.get("PAGES_URL", "").rstrip("/")
UA = {"User-Agent": "Mozilla/5.0 (compatible; threat-feed-collector/1.0)"}
NOW = datetime.now(timezone.utc)
STATUS = {}

FEEDS = {
    "security.nl": ["https://www.security.nl/rss/headlines.xml", "https://feeds.feedburner.com/securitynl"],
    "tweakers.net": ["https://tweakers.net/feed/mixed.xml", "https://tweakers.net/feeds/mixed.xml", "https://tweakers.net/feeds/nieuws.xml"],
    "techzine.nl": "https://www.techzine.nl/feed/",
    "computable.nl": ["https://www.computable.nl/rss", "https://www.computable.nl/rss.xml", "https://www.computable.nl/feed/"],
    "nos.nl": "https://feeds.nos.nl/nosnieuwstech",
    "ncsc.nl": "https://feeds.ncsc.nl/nieuws.rss",
    "cybernews.com": "https://cybernews.com/feed/",
    "bleepingcomputer.com": "https://www.bleepingcomputer.com/feed/",
}
GDELT = {
    "incidenten": "(hack OR hackers OR datalek OR ransomware OR cyberaanval OR ddos OR phishing OR gehackt OR cyberincident OR kwetsbaarheid OR lek OR zero-day OR noodpatch OR \"offline gehaald\") sourcecountry:netherlands",
    "soevereiniteit": '("CLOUD Act" OR soevereiniteit OR "digitale autonomie" OR "digitale soevereiniteit" OR exportbeperking OR exportcontrole OR "Amerikaanse sancties" OR "Europese cloud") sourcecountry:netherlands',
}


# ---------- hulpfuncties ----------
def get(url, timeout=30, raw=False, tries=2):
    for n in range(tries):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            return data if raw else data.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or n == tries - 1:
                raise
        except (urllib.error.URLError, TimeoutError):
            if n == tries - 1:
                raise
        time.sleep(5)


def iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if d else ""


def parse_date(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return email.utils.parsedate_to_datetime(s)
    except Exception:
        pass
    m = re.match(r"^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$", s)
    if m:
        return datetime(*map(int, m.groups()), tzinfo=timezone.utc)
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def age_days(s):
    d = parse_date(s)
    return (NOW - d).total_seconds() / 86400 if d else 9999


def strip(s):
    s = re.sub(r"<[^>]+>", " ", s or "")
    return re.sub(r"[ \t]+", " ", html.unescape(s)).strip()


def run(name, fn, default):
    t = time.time()
    try:
        v = fn()
        STATUS[name] = {"ok": True, "n": len(v), "s": round(time.time() - t, 1)}
        print(f"{name}: ok, {len(v)} items, {STATUS[name]['s']}s", flush=True)
        return v
    except Exception as e:  # noqa: BLE001
        STATUS[name] = {"ok": False, "err": f"{type(e).__name__}: {e}"[:200]}
        print(f"{name}: FOUT na {round(time.time() - t, 1)}s: {STATUS[name]['err']}", flush=True)
        return default


def _nt(t):
    return re.sub(r"[^a-z0-9]+", "", (t or "").lower())[:60]


def _nl(u):
    return re.sub(r"[?#].*$", "", re.sub(r"^https?://(www\.)?", "", (u or "").lower())).rstrip("/")


def dedup(items, key=None):
    """Ontdubbelt op genormaliseerde titel én op link (zelfde artikel via RSS en GDELT)."""
    seen, out = set(), []
    for i in items:
        a, b = _nt(i.get("title")), _nl(i.get("link"))
        if (a and a in seen) or (b and b in seen):
            continue
        seen.update(x for x in (a, b) if x)
        out.append(i)
    return out


# ---------- bronnen ----------
def kev():
    try:
        data = json.loads(get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    except Exception:
        data = json.loads(get("https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"))
    keep = ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
            "knownRansomwareCampaignUse", "requiredAction", "shortDescription", "cwes")
    return [{k: v.get(k) for k in keep} for v in data["vulnerabilities"] if age_days(v["dateAdded"]) <= 180]


def ncsc(days=30):
    base = "https://advisories.ncsc.nl/csaf/v2/"
    rows = [r for r in csv.reader(io.StringIO(get(base + "changes.csv"))) if len(r) >= 2]
    from concurrent.futures import ThreadPoolExecutor
    files = [f for f, d in rows if age_days(d) <= days][:160]

    def load(f):
        try:
            return json.loads(get(base + f, timeout=20))
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=8) as ex:
        docs = [d for d in ex.map(load, files) if d]
    out = []
    for doc in docs:
        notes = doc["document"].get("notes", [])
        note = lambda t: next((n.get("text", "") for n in notes if n.get("title") == t), "")  # noqa: E731
        names = []

        def walk(b):
            for x in b or []:
                if x.get("name") and x["name"] not in names:
                    names.append(x["name"])
                walk(x.get("branches"))
        walk(doc.get("product_tree", {}).get("branches"))
        tid = doc["document"]["tracking"]["id"]
        out.append({
            "id": tid, "title": doc["document"]["title"], "date": doc["document"]["tracking"].get("current_release_date"),
            "link": "https://advisories.ncsc.nl/advisory?id=" + urllib.parse.quote(tid),
            "kans": note("Kans"), "schade": note("Schade"), "feiten": note("Feiten"),
            "interp": note("Interpretaties"), "opl": note("Oplossingen"),
            "cwe": "; ".join(f'{n["title"]} {n.get("text", "")}' for n in notes if re.match(r"^CWE-", n.get("title", ""))),
            "cves": [v["cve"] for v in doc.get("vulnerabilities", []) if v.get("cve")], "names": names[:20],
        })
    return out


def datalekt(days=30):
    base = "https://datalekt.nl/wp-json/wp/v2/"
    after = (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    inc = json.loads(get(base + f"incidents?per_page=100&after={after}&_fields=id,date,link,title,content,meta,gebeurtenis,branche"))
    tax = {}
    for t in ("gebeurtenis", "branche"):
        try:
            tax[t] = {x["id"]: strip(x["name"]) for x in json.loads(get(base + f"{t}?per_page=100&_fields=id,name"))}
        except Exception:
            tax[t] = {}
    out = []
    for x in inc:
        m = x.get("meta") or {}
        out.append({
            "dl": True, "title": strip(x["title"]["rendered"]), "link": x["link"], "date": x["date"], "domain": "datalekt.nl",
            "orgname": m.get("organisatie", ""), "inhoud": strip((x.get("content") or {}).get("rendered", ""))[:4000],
            "gebeurtenis": ", ".join(tax["gebeurtenis"].get(i, "") for i in x.get("gebeurtenis", []) if i in tax["gebeurtenis"]),
            "branche": ", ".join(tax["branche"].get(i, "") for i in x.get("branche", []) if i in tax["branche"]),
            "m": {k: m.get(k) for k in ("datum_incident", "bron_naam", "bron_url", "aantal_betrokkenen",
                                         "financiele_schade", "losgeld_gevraagd", "losgeld_betaald", "boetes")},
        })
    return out


def rss(url, domain):
    if isinstance(url, list):
        err = None
        for u in url:
            try:
                return rss(u, domain)
            except Exception as e:  # noqa: BLE001
                err = e
        raise err
    root = ET.fromstring(get(url, raw=True))
    out = []
    for it in root.iter():
        if it.tag.split("}")[-1] not in ("item", "entry"):
            continue
        d = {c.tag.split("}")[-1]: c for c in it}
        link = ""
        if "link" in d:
            link = (d["link"].text or d["link"].get("href") or "").strip()
        date = next((d[k].text for k in ("pubDate", "published", "updated", "date") if k in d and d[k].text), "")
        desc = next((d[k].text for k in ("description", "summary") if k in d and d[k].text), "")
        out.append({"title": strip(d["title"].text if "title" in d else ""), "link": link,
                    "date": iso(parse_date(date)), "desc": strip(desc)[:400], "domain": domain})
    return [i for i in out if age_days(i["date"]) <= 30]


def gdelt(q, days=30):
    url = ("https://api.gdeltproject.org/api/v2/doc/doc?query=" + urllib.parse.quote(q)
           + f"&mode=artlist&maxrecords=150&sort=datedesc&format=json&timespan={days}d")
    t = ""
    for attempt in range(3):
        try:
            t = get(url, timeout=30, tries=1)
        except Exception as e:  # noqa: BLE001
            t = str(e)
        if t.strip().startswith("{"):
            arts = json.loads(t).get("articles", [])
            return [{"title": a.get("title", ""), "link": a.get("url"), "domain": a.get("domain", ""),
                     "date": iso(parse_date(a.get("seendate")))} for a in arts]
        time.sleep(30)
    raise RuntimeError(t.strip()[:120])


def nvd(days=7):
    end, start = NOW, NOW - timedelta(days=days)
    f = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")  # noqa: E731
    items, idx = [], 0
    while True:
        j = json.loads(get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex={idx}"
                           f"&pubStartDate={f(start)}&pubEndDate={f(end)}", timeout=120))
        for v in j.get("vulnerabilities", []):
            c = v["cve"]
            m = c.get("metrics", {})
            scores = [x["cvssData"].get("baseScore", 0) for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30") for x in m.get(k, [])]
            score = max(scores) if scores else None
            if score is not None and score < 7:
                continue
            cpes = re.findall(r"cpe:2\.3:[^\"']+", json.dumps(c.get("configurations", [])))
            items.append({
                "id": c["id"], "date": c.get("published"), "score": score,
                "desc": next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")[:600],
                "cwe": " ".join(d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])),
                "names": " ".join(sorted({" ".join(x.split(":")[3:5]).replace("_", " ") for x in cpes})),
                "inKev": bool(c.get("cisaExploitAdd")),
            })
        idx += j.get("resultsPerPage", 0)
        if idx >= j.get("totalResults", 0) or not j.get("resultsPerPage"):
            break
        time.sleep(7)
    return items


def euvd(days=7):
    start = (NOW - timedelta(days=days)).strftime("%Y-%m-%d")
    raw = []
    for page in range(5):
        j = json.loads(get(f"https://euvdservices.enisa.europa.eu/api/search?fromScore=7&toScore=10&size=100&page={page}&fromDate={start}"))
        raw += j.get("items", [])
        if len(j.get("items", [])) < 100:
            break
    out = []
    for x in raw:
        cve = re.search(r"CVE-\d+-\d+", str(x.get("aliases", "")))
        names = re.findall(r'"name":\s*"([^"]+)"', json.dumps([x.get("enisaIdProduct"), x.get("enisaIdVendor")]))
        out.append({"id": cve.group(0) if cve else x.get("id"), "date": iso(parse_date(x.get("datePublished"))),
                    "score": x.get("baseScore"), "desc": (x.get("description") or "")[:600], "cwe": "",
                    "names": " ".join(names), "inKev": False})
    return out


CVELIST = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/"


def cve_record(cid):
    """Haalt één CVE record op uit de officiële CVE lijst (GitHub) en zet het om naar het eigen formaat."""
    y, n = cid.split("-")[1], cid.split("-")[2]
    j = json.loads(get(f"{CVELIST}cves/{y}/{n[:-3]}xxx/{cid}.json", timeout=20, tries=2))
    cna = j.get("containers", {}).get("cna", {})
    adp = j.get("containers", {}).get("adp", [])
    scores = []
    for c in [cna] + adp:
        for m in c.get("metrics", []):
            for k, v in m.items():
                if k.startswith("cvssV") and isinstance(v, dict) and v.get("baseScore") is not None:
                    scores.append(float(v["baseScore"]))
    cwes = " ".join(d.get("cweId") or d.get("description", "") for c in [cna] + adp
                    for pt in c.get("problemTypes", []) for d in pt.get("descriptions", []))
    names = " ".join(f'{a.get("vendor", "")} {a.get("product", "")}' for a in cna.get("affected", []))
    kev = any("kev" in json.dumps(c).lower() and "dateadded" in json.dumps(c).lower() for c in adp)
    return {"id": cid, "date": j.get("cveMetadata", {}).get("datePublished", ""), "score": max(scores) if scores else None,
            "desc": next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")[:600],
            "cwe": cwes, "names": names, "inKev": kev}


def cvelist(days=7):
    log = json.loads(get(CVELIST + "cves/deltaLog.json", timeout=120))
    ids = []
    for entry in log:
        if age_days(entry.get("fetchTime")) > days:
            continue
        for x in entry.get("new", []):
            if x.get("cveId") and x["cveId"] not in ids:
                ids.append(x["cveId"])
    from concurrent.futures import ThreadPoolExecutor

    def one(cid):
        try:
            return cve_record(cid)
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=16) as ex:
        recs = list(ex.map(one, ids[-1200:]))
    return [r for r in recs if r and (r["score"] is None or r["score"] >= 7)]


STOP = {"powershell", "sharepoint", "openai", "chatgpt", "github", "gitlab", "linkedin", "youtube", "whatsapp", "paypal",
        "tiktok", "javascript", "wordpress", "fortigate", "fortios", "fortimail", "fortisiem", "netscaler", "postgresql",
        "mysql", "macos", "iphone", "ipad", "android", "onedrive", "outlook", "teams", "microsoft", "windows", "deepseek",
        "openssl", "openssh", "bleepingcomputer", "cybernews", "techzine", "tweakers", "security", "nextcloud", "icloud",
        "airdrop", "bitlocker", "sonicwall", "crowdstrike", "cloudflare", "servicenow", "workday", "salesforce", "mastodon",
        "bluesky", "telegram", "signal", "zivver", "topdesk", "notubiz", "datalekt", "ransomware", "phishing", "malware",
        "digid", "mijnoverheid", "eherkenning", "ideal", "postnl", "youtube", "iprox", "openai", "nvidia", "amazon", "linux"}
THREAT = re.compile(r"lek|kwetsbaar|vulnerab|exploit|zero.day|aanval|attack|patch|cve-|hack|ransomware|offline|misbruik|flaw|bug|rce", re.I)


def opkomend(items, ncsc_items, window=4):
    """Detecteert dreigingen die in korte tijd in meerdere onafhankelijke bronnen opduiken (CVE nummers en benamingen)."""
    groups = {}
    def add(key, kind, it):
        g = groups.setdefault(key.lower(), {"key": key, "kind": kind, "items": []})
        g["items"].append(it)
    for it in items:
        if age_days(it.get("date")) > window:
            continue
        text = f'{it.get("title", "")} {it.get("desc", "")}'
        if not THREAT.search(text):
            continue
        for c in set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)):
            add(c.upper(), "cve", it)
        for w in set(re.findall(r"\b[A-Za-z][A-Za-z0-9]*(?:[a-z][A-Z]|[A-Za-z]\d[A-Za-z])[A-Za-z0-9]*\b", text)):
            if len(w) >= 5 and w.lower() not in STOP and not re.match(r"^(i|e)[A-Z]", w):
                add(w, "naam", it)
        for w in set(re.findall(r"\b\w+(?:shell|bleed|jack|hammer|doom|storm)\b", text, re.I)):
            if w.lower() not in STOP:
                add(w, "naam", it)
    out = []
    for g in groups.values():
        doms = sorted({i.get("domain", "") for i in g["items"]})
        if len(doms) < 2:
            continue
        its = sorted(g["items"], key=lambda i: i.get("date", ""))
        cves = sorted({c.upper() for i in its for c in re.findall(r"CVE-\d{4}-\d{4,}", f'{i.get("title","")} {i.get("desc","")}', re.I)})
        if g["kind"] == "cve":
            cves = [g["key"]]
        ncsc_hit = [n["id"] for n in ncsc_items if g["key"].lower() in (n["title"] + " " + " ".join(n.get("cves", []))).lower()
                    or any(c in n.get("cves", []) for c in cves)]
        out.append({"key": g["key"], "kind": g["kind"], "bronnen": doms, "n": len(its), "eerste": its[0].get("date"),
                    "laatste": its[-1].get("date"), "cves": cves[:10], "ncsc": ncsc_hit[:5],
                    "berichten": [{k: i.get(k) for k in ("title", "link", "domain", "date")} for i in its[-12:]]})
    # samenvoegen: een CVE groep die volledig binnen een naamgroep valt verdwijnt
    names = [o for o in out if o["kind"] == "naam"]
    out = [o for o in out if not (o["kind"] == "cve" and any(o["key"] in n["cves"] for n in names))]
    return sorted(out, key=lambda o: (len(o["bronnen"]), o["n"]), reverse=True)[:12]


def epss(ids):
    out = {}
    ids = sorted(set(i for i in ids if i and i.startswith("CVE-")))
    for n in range(0, len(ids), 100):
        j = json.loads(get("https://api.first.org/data/v1/epss?cve=" + ",".join(ids[n:n + 100])))
        for d in j.get("data", []):
            out[d["cve"]] = {"epss": float(d["epss"]), "pct": float(d["percentile"])}
        time.sleep(1)
    return out


def ransomware():
    try:
        arr = json.loads(get("https://api.ransomware.live/v2/countryvictims/NL"))
        if isinstance(arr, dict):
            arr = arr.get("victims") or arr.get("data") or []
        out = [{"title": x.get("post_title") or x.get("victim") or "", "group": x.get("group_name") or x.get("group") or "",
                "date": iso(parse_date(x.get("discovered") or x.get("attackdate") or x.get("published"))),
                "sector": x.get("activity") or x.get("sector") or "", "link": x.get("post_url") or x.get("url") or "",
                "domain": "ransomware.live"} for x in arr]
    except Exception:
        out = [i for i in rss("https://www.ransomware.live/rss.xml", "ransomware.live")
               if re.search(r"netherlands|nederland|\.nl\b|🇳🇱", i["title"] + " " + i["desc"], re.I)]
    return [i for i in out if age_days(i["date"]) <= 60]


# ---------- samenstellen ----------
def main():
    os.makedirs(OUT, exist_ok=True)
    data = {"generated": iso(NOW)}
    data["kev"] = run("KEV", kev, [])
    data["ncsc"] = run("NCSC advisories", ncsc, [])
    data["datalekt"] = run("datalekt", datalekt, [])
    data["ransomware"] = run("ransomware.live", ransomware, [])

    news = []
    for dom, url in FEEDS.items():
        news += run(f"RSS {dom}", lambda u=url, d=dom: rss(u, d), [])

    g = {}
    for i, (k, q) in enumerate(GDELT.items()):
        if i:
            time.sleep(30)
        g[k] = run(f"GDELT {k}", lambda q=q: gdelt(q), [])
    data["gdeltIncidenten"] = g["incidenten"]
    g["nieuws"], g["kwetsbaarheden"] = [], g["incidenten"]
    data["soevereiniteit"] = dedup(g["soevereiniteit"])
    data["nieuws"] = sorted(dedup(news + g["nieuws"] + g["kwetsbaarheden"]), key=lambda i: i["date"], reverse=True)

    cves = run("CVE lijst (cvelistV5)", cvelist, None)
    if not cves:
        cves = run("NVD", nvd, None)
    if cves is None:
        cves = run("EUVD", euvd, [])

    pool = data["nieuws"] + g["incidenten"]
    data["opkomend"] = run("Opkomende dreigingen", lambda: opkomend(pool, data["ncsc"]), [])
    # CVE's die in nieuws of opkomende dreigingen genoemd worden, gericht ophalen
    known = {v["id"] for v in cves}
    wanted = []
    for o in data["opkomend"]:
        wanted += o["cves"]
    for n in data["nieuws"][:300]:
        wanted += [c.upper() for c in re.findall(r"CVE-\d{4}-\d{4,}", f'{n.get("title","")} {n.get("desc","")}', re.I)]
    for cid in list(dict.fromkeys(wanted))[:40]:
        if cid in known:
            continue
        try:
            r = cve_record(cid)
            r["genoemd"] = True
            cves.append(r)
            known.add(cid)
        except Exception:
            pass
    data["nvd"] = cves

    scores = run("EPSS", lambda: epss([v["cveID"] for v in data["kev"] if age_days(v["dateAdded"]) <= 90]
                                      + [v["id"] for v in cves][:2000]), {})
    for v in data["kev"]:
        v["epss"] = scores.get(v["cveID"])
    for v in data["nvd"]:
        v["epss"] = scores.get(v["id"])
    byid = {v["id"]: v for v in data["nvd"]}
    for o in data["opkomend"]:
        o["cveinfo"] = [{k: byid[c].get(k) for k in ("id", "score", "desc", "names", "epss", "cwe")} for c in o["cves"] if c in byid]

    data["status"] = STATUS
    with open(os.path.join(OUT, "dreigingsbeeld.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, separators=(",", ":"))

    # Historie: één regel per dag met algemene signalen (zonder organisatiespecifieke filtering)
    hist = []
    if PAGES_URL:
        try:
            hist = json.loads(get(PAGES_URL + "/history.json"))
        except Exception:
            hist = []
    today = NOW.strftime("%Y-%m-%d")
    row = {
        "date": today,
        "kev7": sum(1 for v in data["kev"] if age_days(v["dateAdded"]) <= 7),
        "ncscHoog": sum(1 for v in data["ncsc"] if "high" in (v["schade"] or "").lower() and age_days(v["date"]) <= 7),
        "cve9": sum(1 for v in cves if (v["score"] or 0) >= 9 and age_days(v["date"]) <= 7),
        "incidenten7": sum(1 for v in data["datalekt"] if age_days(v["date"]) <= 7),
        "ransomwareNL7": sum(1 for v in data["ransomware"] if age_days(v["date"]) <= 7),
    }
    hist = [h for h in hist if h.get("date") != today] + [row]
    hist = sorted(hist, key=lambda h: h["date"])[-180:]
    with open(os.path.join(OUT, "history.json"), "w", encoding="utf-8") as fh:
        json.dump(hist, fh, separators=(",", ":"))

    with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><meta charset=utf-8><title>Dreigingsbeeld data</title>"
                 "<p>Openbare dreigingsdata, elk uur bijgewerkt: "
                 "<a href=dreigingsbeeld.json>dreigingsbeeld.json</a> · <a href=history.json>history.json</a></p>")
    print(json.dumps(STATUS, indent=1))


if __name__ == "__main__":
    main()
