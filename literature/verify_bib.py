"""Check every entry of manuscript/references.bib against Crossref (and arXiv).

Run:  python literature/verify_bib.py  -> literature/references_verification.md
For each entry: DOI resolves? title/year/first author match the registry? Entries that cannot be
confirmed automatically are listed in full with Google Scholar / DOI links for manual lookup.
Network lookups only; nothing is written to the bib.
"""
import difflib
import json
import pathlib
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent
BIB = ROOT.parent / "manuscript" / "references.bib"
OUT = ROOT / "references_verification.md"
UA = {"User-Agent": "flow-orientation-audit-bibcheck/1.0"}


def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
        return r.read()


def parse(text):
    entries = []
    for m in re.finditer(r"@(\w+)\{([^,]+),", text):
        i, d = m.end(), 1
        j = i
        while d:
            d += {"{": 1, "}": -1}.get(text[j], 0)
            j += 1
        body = text[i:j - 1]
        f = {}
        for k in re.finditer(r"(\w+)\s*=\s*", body):
            s = k.end()
            if body[s] == "{":
                dd, e = 1, s + 1
                while dd:
                    dd += {"{": 1, "}": -1}.get(body[e], 0)
                    e += 1
                f[k.group(1).lower()] = body[s + 1:e - 1]
            else:
                f[k.group(1).lower()] = re.match(r"[^,\n]*", body[s:]).group(0).strip()
        entries.append((m.group(2), m.group(1), f))
    return entries


def norm(s):
    s = re.sub(r"\\[`'^\"~=.]?\{?(\w)\}?", r"\1", s)
    return re.sub(r"[^a-z0-9 ]", "", s.lower().replace("{", "").replace("}", "")).strip()


def sim(a, b):
    return difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()


def crossref(f):
    if f.get("doi", "").startswith("10.5281/"):  # Zenodo DOIs live in DataCite, not Crossref
        a = json.loads(get("https://api.datacite.org/dois/" + f["doi"]))["data"]["attributes"]
        fam = a["creators"][0]["name"].split(",")[0]
        yr = int(a["publicationYear"])
        return {"title": [a["titles"][0]["title"]], "author": [{"family": fam}],
                "issued": {"date-parts": [[yr]]}}, "datacite"
    if f.get("doi"):
        d = json.loads(get("https://api.crossref.org/works/" + urllib.parse.quote(f["doi"])))
        return d["message"], "doi"
    q = urllib.parse.urlencode({"query.bibliographic": f.get("title", ""), "rows": 1})
    items = json.loads(get("https://api.crossref.org/works?" + q))["message"]["items"]
    return (items[0] if items else None), "search"


def arxiv(f):
    m = re.search(r"(\d{4}\.\d{4,5})", " ".join(str(v) for v in f.values()))
    if not m:
        return None
    root = ET.fromstring(get(f"http://export.arxiv.org/api/query?id_list={m.group(1)}"))
    e = root.find("{http://www.w3.org/2005/Atom}entry")
    t = e.find("{http://www.w3.org/2005/Atom}title").text if e is not None else None
    return {"title": [" ".join((t or "").split())], "id": m.group(1)} if t else None


def check(key, typ, f):
    title, first = f.get("title", ""), f.get("author", "").split(" and ")[0]
    fam = norm(first.split(",")[0]) if "," in first else norm(first.split()[-1] if first else "")
    note = []
    rec = None
    try:
        rec = arxiv(f) if re.search(r"arxiv", " ".join(f.values()), re.I) else None
        src = "arXiv"
        if rec is None:
            rec, how = crossref(f)
            src = "Crossref/" + how
    except Exception as ex:  # network / 404
        return "NOT FOUND", f"lookup failed: {ex}"
    if not rec:
        return "NOT FOUND", "no registry hit"
    rt = (rec.get("title") or [""])[0]
    s = sim(title, rt)
    if s < 0.85:
        note.append(f"title differs (sim {s:.2f}): registry='{rt[:90]}'")
    if "author" in rec and rec["author"]:
        a0 = rec["author"][0]
        if fam and fam not in norm(a0.get("family", "") + " " + a0.get("given", "")):
            note.append(f"first author differs: registry='{rec['author'][0].get('family')}'")
    yr = (rec.get("issued", {}).get("date-parts") or [[None]])[0][0]
    if yr and f.get("year") and abs(int(yr) - int(f["year"])) > 1:
        note.append(f"year differs: bib={f['year']} registry={yr}")
    return ("OK" if not note else "CHECK"), f"{src}; " + ("; ".join(note) if note else "matches")


def main():
    rows = []
    for key, typ, f in parse(BIB.read_text(encoding="utf-8")):
        st, why = check(key, typ, f)
        rows.append((key, f, st, why))
        print(st, key)
    L = ["# Verificación de referencias (automática, Crossref / arXiv)\n",
         f"Generado por `literature/verify_bib.py` sobre `{BIB.name}` ({len(rows)} entradas).",
         "OK = título, primer autor y año coinciden con el registro.",
         "CHECK / NOT FOUND = revisar a mano (ver motivo y la lista extendida abajo).\n",
         "| Estado | Clave | Detalle |", "|---|---|---|"]
    L += [f"| {st} | `{k}` | {why} |" for k, f, st, why in rows]
    L += ["\n## Entradas por revisar a mano (lista extendida)\n"]
    for k, f, st, why in rows:
        if st == "OK":
            continue
        q = urllib.parse.quote(f.get("title", "").replace("{", "").replace("}", ""))
        L += [f"### `{k}` — {st}", f"- Autores: {f.get('author', '')}",
              f"- Título: {f.get('title', '')}",
              f"- Publicación: {f.get('journal') or f.get('booktitle') or f.get('howpublished')}"
              f" {f.get('volume', '')} {f.get('pages', '')} ({f.get('year', '')})",
              f"- DOI/URL en el bib: {f.get('doi') or f.get('url', '—')}",
              f"- Motivo: {why}",
              f"- Scholar: https://scholar.google.com/scholar?q={q}", ""]
    OUT.write_text("\n".join(L), encoding="utf-8")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
