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
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

OUT = os.path.join(os.path.dirname(__file__), "..", "site")
PAGES_URL = os.environ.get("PAGES_URL", "").rstrip("/")
UA = {"User-Agent": "Mozilla/5.0 (compatible; threat-feed-collector/1.0)"}
NOW = datetime.now(timezone.utc)
STATUS = {}

FEEDS = {
    "security.nl": "https://www.security.nl/rss/headlines.xml",
    "tweakers.net": "https://feeds.feedburner.com/tweakers/mixed",
    "techzine.nl": "https://www.techzine.nl/feed/",
    "computable.nl": "https://www.computable.nl/feed/",
    "agconnect.nl": "https://www.agconnect.nl/rss.xml",
    "cybernews.com": "https://cybernews.com/feed/",
    "bleepingcomputer.com": "https://www.bleepingcomputer.com/feed/",
}
GDELT = {
    "incidenten": "(hack OR hackers OR datalek OR ransomware OR cyberaanval OR ddos OR phishing OR gehackt OR cyberincident) sourcecountry:netherlands",
    "nieuws": "(domain:security.nl OR domain:tweakers.net OR domain:techzine.nl OR domain:computable.nl OR domain:agconnect.nl OR domain:ncsc.nl OR domain:cybernews.com)",
    "soevereiniteit": '("CLOUD Act" OR soevereiniteit OR "digitale autonomie" OR "digitale soevereiniteit" OR exportbeperking OR exportcontrole OR "Amerikaanse sancties" OR "Europese cloud") sourcecountry:netherlands',
}


# ---------- hulpfuncties ----------
def get(url, timeout=60, raw=False):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
    return data if raw else data.decode("utf-8", "replace")


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
        return v
    except Exception as e:  # noqa: BLE001
        STATUS[name] = {"ok": False, "err": f"{type(e).__name__}: {e}"[:200]}
        return default


def dedup(items, key=lambda i: i["title"].lower()[:60]):
    seen, out = set(), []
    for i in items:
        k = key(i)
        if k and k not in seen:
            seen.add(k)
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


def ncsc(days=21):
    base = "https://advisories.ncsc.nl/csaf/v2/"
    rows = [r for r in csv.reader(io.StringIO(get(base + "changes.csv"))) if len(r) >= 2]
    out = []
    for f, d in rows:
        if age_days(d) > days:
            continue
        if len(out) >= 120:
            break
        try:
            doc = json.loads(get(base + f))
        except Exception:
            continue
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
    return [i for i in out if age_days(i["date"]) <= 14]


def gdelt(q, days=14):
    url = ("https://api.gdeltproject.org/api/v2/doc/doc?query=" + urllib.parse.quote(q)
           + f"&mode=artlist&maxrecords=150&sort=datedesc&format=json&timespan={days}d")
    for attempt in range(3):
        t = get(url)
        if t.strip().startswith("{"):
            arts = json.loads(t).get("articles", [])
            return [{"title": a.get("title", ""), "link": a.get("url"), "domain": a.get("domain", ""),
                     "date": iso(parse_date(a.get("seendate")))} for a in arts]
        time.sleep(7)
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
    j = json.loads(get(f"https://euvdservices.enisa.europa.eu/api/search?fromScore=7&toScore=10&size=100&fromDate={start}"))
    out = []
    for x in j.get("items", []):
        cve = re.search(r"CVE-\d+-\d+", str(x.get("aliases", "")))
        names = re.findall(r'"name":\s*"([^"]+)"', json.dumps([x.get("enisaIdProduct"), x.get("enisaIdVendor")]))
        out.append({"id": cve.group(0) if cve else x.get("id"), "date": iso(parse_date(x.get("datePublished"))),
                    "score": x.get("baseScore"), "desc": (x.get("description") or "")[:600], "cwe": "",
                    "names": " ".join(names), "inKev": False})
    return out


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
            time.sleep(7)
        g[k] = run(f"GDELT {k}", lambda q=q: gdelt(q), [])
    data["gdeltIncidenten"] = g["incidenten"]
    data["soevereiniteit"] = dedup(g["soevereiniteit"])
    data["nieuws"] = sorted(dedup(news + g["nieuws"]), key=lambda i: i["date"], reverse=True)

    cves = run("NVD", nvd, None)
    if cves is None:
        cves = run("EUVD", euvd, [])
    data["nvd"] = cves

    scores = run("EPSS", lambda: epss([v["cveID"] for v in data["kev"] if age_days(v["dateAdded"]) <= 90]
                                      + [v["id"] for v in cves]), {})
    for v in data["kev"]:
        v["epss"] = scores.get(v["cveID"])
    for v in data["nvd"]:
        v["epss"] = scores.get(v["id"])

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
