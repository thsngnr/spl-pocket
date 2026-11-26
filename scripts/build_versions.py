#!/usr/bin/env python3
"""SPL Pocket için versions.json üretir (Python standart kütüphanesi; indirme için varsa curl).

Kaynaklar:
  enterprise  help.splunk.com sürüm notları dizini + her serinin fixed-issues sayfası (yama sürümleri dahil)
  es          Splunkbase uygulama 263 sürümleri; olmazsa help.splunk.com ES 7/8 sayfaları
  escu        GitHub splunk/security_content sürümleri; olmazsa Splunkbase uygulama 3449
  advisories  advisory.splunk.com/advisories tablosu (uygulamadaki AdvisoryParser ile aynı alanlar)

Bir kaynak okunamazsa o ürünün önceki verisi korunur ve hata "errors" altına yazılır.
Kullanım: python3 scripts/build_versions.py [çıktı yolu, varsayılan versions.json]
"""
import datetime as dt
import html as htmllib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request

UA = "spl-pocket-versions/1.0 (+https://thsngnr.github.io/spl-pocket/)"
ENTERPRISE_INDEX = "https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes"
ENTERPRISE_LINES = 6
ESCU_KEEP = 40


def fetch(url, accept=None):
    # help.splunk.com, Python'un TLS istemcisine 403 veriyor; curl varsa (GitHub runner'larında var) onu kullan.
    if shutil.which("curl"):
        # Not: help.splunk.com "Accept: text/html" başlığında 403 veriyor; HTML için başlık gönderilmez.
        command = ["curl", "-sS", "-L", "--fail", "--max-time", "60", "-A", UA]
        if accept:
            command += ["-H", f"Accept: {accept}"]
        # Runner'da GitHub API kimliksiz isteklere 403 veriyor; workflow'un token'ı yalnızca api.github.com'a gider.
        # Token komut satırında görünmesin diye başlık curl'e stdin'den (-H @-) verilir.
        token = os.environ.get("GITHUB_TOKEN") if url.startswith("https://api.github.com/") else None
        stdin = None
        if token:
            command += ["-H", "@-"]
            stdin = f"Authorization: Bearer {token}\n".encode()
        result = subprocess.run(command + [url], input=stdin, capture_output=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(f"curl {result.returncode} for {url}: {result.stderr.decode(errors='replace').strip()}")
        return result.stdout.decode("utf-8", "replace")
    headers = {"User-Agent": UA, **({"Accept": accept} if accept else {})}
    if url.startswith("https://api.github.com/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        return resp.read().decode("utf-8", "replace")


def vkey(version):
    return tuple(int(p) for p in re.findall(r"\d+", version))


def line_of(version):
    parts = version.split(".")
    return ".".join(parts[:2])


def newest_first(items):
    return sorted(items, key=lambda e: vkey(e["version"]), reverse=True)


def iso_date(value):
    if not value:
        return None
    return value[:10]


# --- Splunk Enterprise -------------------------------------------------------

def enterprise():
    index = fetch(ENTERPRISE_INDEX)
    lines = sorted(set(re.findall(r'release-notes/(\d+\.\d+)(?=["/#?])', index)), key=vkey, reverse=True)
    if not lines:
        raise RuntimeError("no release lines on the release notes index")
    out = []
    for line in lines[:ENTERPRISE_LINES]:
        page_url = f"{ENTERPRISE_INDEX}/{line}/fixed-issues/fixed-issues"
        page = fetch(page_url)
        escaped = re.escape(line)
        # 10.6.2 ve 10.6.2.5 gibi dört parçalı sürümler de.
        found = set(re.findall(rf"splunk-enterprise-({escaped}(?:\.\d+)+)-fixed-issues", page))
        if not found:
            found = {line + ".0"}
        for version in found:
            out.append({
                "version": version,
                "line": line,
                "released": None,
                "notesURL": f"{page_url}/splunk-enterprise-{version}-fixed-issues",
            })
    return newest_first(out)


# --- Enterprise Security ------------------------------------------------------

def splunkbase(app_id):
    data = json.loads(fetch(f"https://splunkbase.splunk.com/api/v1/app/{app_id}/release/", "application/json"))
    if not isinstance(data, list) or not data:
        raise RuntimeError(f"Splunkbase app {app_id}: empty release list")
    out = []
    for r in data:
        name = str(r.get("name", "")).strip()
        if not re.fullmatch(r"\d+(\.\d+)+", name):
            continue
        notes = re.search(r"\((https://[^)\s]+)\)", r.get("release_notes") or "") or re.search(r"https://\S+", r.get("release_notes") or "")
        out.append({
            "version": name,
            "line": line_of(name),
            "released": iso_date(r.get("published_datetime") or r.get("created_datetime")),
            "notesURL": notes.group(1) if notes and notes.groups() else (notes.group(0) if notes else None),
        })
    if not out:
        raise RuntimeError(f"Splunkbase app {app_id}: no numeric releases")
    return newest_first(out)


def es_from_docs():
    out = []
    for major in (8, 7):
        base = f"https://help.splunk.com/en/splunk-enterprise-security-{major}/release-notes-and-resources"
        page = fetch(base)
        for line in set(re.findall(r'release-notes-and-resources/(\d+\.\d+)(?=["/#?])', page)):
            out.append({"version": line + ".0", "line": line, "released": None,
                        "notesURL": f"{base}/{line}/splunk-enterprise-security-release-notes/release-notes-for-splunk-enterprise-security"})
    if not out:
        raise RuntimeError("no ES lines on help.splunk.com")
    return newest_first(out)


def es():
    errors = []
    try:
        return splunkbase(263), errors
    except Exception as e:  # noqa: BLE001
        errors.append(f"splunkbase: {e}")
    return es_from_docs(), errors


# --- ES Content Update --------------------------------------------------------

def escu_from_github():
    data = json.loads(fetch("https://api.github.com/repos/splunk/security_content/releases?per_page=100",
                            "application/vnd.github+json"))
    out = []
    for r in data:
        if r.get("draft") or r.get("prerelease"):
            continue
        tag = str(r.get("tag_name", "")).lstrip("vV")
        if not re.fullmatch(r"\d+(\.\d+)+", tag):
            continue
        out.append({"version": tag, "line": line_of(tag), "released": iso_date(r.get("published_at")),
                    "notesURL": r.get("html_url")})
    if not out:
        raise RuntimeError("GitHub: no ESCU releases")
    return newest_first(out)[:ESCU_KEEP]


def escu():
    errors = []
    try:
        return escu_from_github(), errors
    except Exception as e:  # noqa: BLE001
        errors.append(f"github: {e}")
    return splunkbase(3449)[:ESCU_KEEP], errors


# --- Güvenlik bültenleri (uygulamadaki AdvisoryParser'ın aynısı) ---------------

def _text(raw, keep_breaks=False):
    if raw is None:
        return ""
    s = re.sub(r"<br\s*/?>", "\n" if keep_breaks else " ", raw)
    s = re.sub(r'<span class="advisory-search-only".*?</span>', "", s)
    s = re.sub(r"<[^>]+>", "", s)
    for entity, char in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'"), ("&nbsp;", " ")):
        s = s.replace(entity, char)
    if not keep_breaks:
        s = re.sub(r"\s+", " ", s)
    return s.strip()


def _clean(value):
    return "" if value in ("", "-", "NA", "N/A", "None") else value


def _lines(raw):
    return [x.strip(" ") for x in _text(raw, True).split("\n") if x.strip(" ") and x.strip(" ") not in ("-", "NA")]


def _cves(raw):
    if raw is None:
        return []
    m = re.search(r'data-popover-values="([^"]*)"', raw)
    if m:
        return [x for x in m.group(1).split("___advisory_popover_separator___") if x]
    value = _clean(_text(raw))
    return [x for x in re.split(r"[, \n]", value) if x.startswith("CVE-")] if value else []


def advisories():
    page = fetch("https://advisory.splunk.com/advisories")
    out = []
    cell = re.compile(r'<td[^>]*?label="([^"]+)"[^>]*>(.*?)</td>', re.S)
    for row in page.split('class="advisory-tr"')[1:]:
        row = row.split("</tr>")[0]
        cells = {k: v for k, v in cell.findall(row)}
        svd = _text(cells.get("SVD"))
        if not svd.startswith("SVD-"):
            continue
        score = _text(cells.get("CVSS Score"))
        try:
            float(score)
        except ValueError:
            score = ""
        out.append({
            "id": svd,
            "published": _text(cells.get("Published")),
            "modified": _text(cells.get("Modified")),
            "title": _text(cells.get("Title")),
            "severity": _text(cells.get("Severity")),
            "cves": _cves(cells.get("CVE")),
            "cvssScore": score,
            "cvssVector": _clean(_text(cells.get("CVSS Vector"))),
            "cwe": _clean(_text(cells.get("CWE"))),
            "products": _lines(cells.get("Affected Product")),
            "fixedVersions": _lines(cells.get("Fixed Versions")),
            "affectedVersions": _lines(cells.get("Affected Versions")),
            "components": _lines(cells.get("Affected Components")),
            "description": _text(cells.get("Description")),
            "solution": _clean(_text(cells.get("Solution"))),
            "mitigations": _clean(_text(cells.get("Mitigations"))),
        })
    if not out:
        raise RuntimeError("no advisories parsed")
    return out


# --- Birleştirme ---------------------------------------------------------------

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "versions.json"
    try:
        with open(path, encoding="utf-8") as f:
            previous = json.load(f)
    except (OSError, ValueError):
        previous = {}
    prev_products = previous.get("products", {})
    today = dt.date.today().isoformat()

    products, errors = {}, {}
    for name, job in (("enterprise", lambda: (enterprise(), [])), ("es", es), ("escu", escu)):
        try:
            items, warnings = job()
            if warnings:
                errors[name] = "; ".join(warnings) + " (fallback used)"
        except Exception as e:  # noqa: BLE001
            errors[name] = str(e)
            items = prev_products.get(name, [])
        # İlk görüldüğü gün: tarihi bilinmeyen sürümlerde de "yeni mi" anlaşılsın.
        seen = {e["version"]: e.get("firstSeen") for e in prev_products.get(name, [])}
        for e in items:
            e["firstSeen"] = seen.get(e["version"]) or e.get("firstSeen") or today
        products[name] = items

    try:
        advs = advisories()
    except Exception as e:  # noqa: BLE001
        errors["advisories"] = str(e)
        advs = previous.get("advisories", [])

    doc = {"schema": 1, "products": products, "advisories": advs}
    if errors:
        doc["errors"] = errors
    # İçerik değişmediyse generatedAt de değişmesin (gereksiz commit olmasın).
    comparable = {k: v for k, v in previous.items() if k != "generatedAt"}
    if comparable == doc and previous.get("generatedAt"):
        doc["generatedAt"] = previous["generatedAt"]
    else:
        doc["generatedAt"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    ordered = {"schema": 1, "generatedAt": doc["generatedAt"], "products": products, "advisories": advs}
    if errors:
        ordered["errors"] = errors
    with open(path, "w", encoding="utf-8") as f:
        json.dump(ordered, f, ensure_ascii=False, indent=1)
        f.write("\n")
    counts = ", ".join(f"{k}={len(v)}" for k, v in products.items())
    print(f"versions.json: {counts}, advisories={len(advs)}, errors={errors or 'none'}")


if __name__ == "__main__":
    main()
