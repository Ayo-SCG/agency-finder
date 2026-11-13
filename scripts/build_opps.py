#!/usr/bin/env python3
"""Turn the public SAM.gov Contract Opportunities extract into small per NAICS JSON files.

Usage: python build_opps.py <ContractOpportunitiesFullCSV.csv> <output folder>
"""
import csv, json, os, re, sys
from collections import defaultdict
from datetime import datetime, timezone

csv.field_size_limit(1 << 30)
SKIP_TYPES = ("award notice", "justification", "sale of surplus", "consolidate")


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def pick(row, idx, *names):
    for n in names:
        i = idx.get(norm(n))
        if i is not None and i < len(row):
            v = (row[i] or "").strip()
            if v:
                return v
    return ""


def day(s):
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", s or "")
    if m:
        return m.group(0)
    m = re.search(r"(\d{1,2})/(\d{1,2})/(\d{4})", s or "")
    if m:
        return "%s-%02d-%02d" % (m.group(3), int(m.group(1)), int(m.group(2)))
    return ""


def main(src, out):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    by = defaultdict(list)
    total = kept = 0
    with open(src, newline="", encoding="cp1252", errors="replace") as f:
        rd = csv.reader(f)
        header = next(rd)
        idx = {norm(h): i for i, h in enumerate(header)}
        if norm("NaicsCode") not in idx or norm("Title") not in idx:
            sys.exit("Unexpected file layout. Columns found: " + ", ".join(header[:60]))
        for row in rd:
            total += 1
            naics = re.sub(r"\D", "", pick(row, idx, "NaicsCode"))[:6]
            if len(naics) != 6:
                continue
            active = pick(row, idx, "Active").lower()
            if active and active not in ("yes", "true", "y", "1"):
                continue
            typ = pick(row, idx, "Type", "BaseType")
            if any(k in typ.lower() for k in SKIP_TYPES):
                continue
            due = day(pick(row, idx, "ResponseDeadLine"))
            if due and due < today:
                continue
            nid = pick(row, idx, "NoticeId")
            link = ("https://sam.gov/opp/%s/view" % nid) if nid else pick(row, idx, "Link")
            by[naics].append({
                "t": pick(row, idx, "Title")[:220],
                "sol": pick(row, idx, "Sol#", "SolicitationNumber"),
                "ag": pick(row, idx, "Department/Ind.Agency", "Department"),
                "sub": pick(row, idx, "Sub-Tier", "SubTier"),
                "off": pick(row, idx, "Office"),
                "type": typ,
                "sa": pick(row, idx, "SetASide", "SetASideCode"),
                "due": due,
                "posted": day(pick(row, idx, "PostedDate")),
                "st": pick(row, idx, "PopState"),
                "link": link,
            })
            kept += 1
    os.makedirs(os.path.join(out, "opps"), exist_ok=True)
    counts = {}
    for naics, items in by.items():
        items.sort(key=lambda o: (o["due"] or "9999", o["t"]))
        counts[naics] = len(items)
        with open(os.path.join(out, "opps", naics + ".json"), "w", encoding="utf-8") as g:
            json.dump(items, g, ensure_ascii=False, separators=(",", ":"))
    with open(os.path.join(out, "opps", "index.json"), "w", encoding="utf-8") as g:
        json.dump({"updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "total": kept, "counts": counts}, g, separators=(",", ":"))
    print("rows read: %d, open notices kept: %d, NAICS codes: %d" % (total, kept, len(counts)))
    if kept < 500:
        sys.exit("Too few notices kept. Refusing to publish a broken update.")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
