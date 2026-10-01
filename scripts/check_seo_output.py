#!/usr/bin/env python3
"""Sanity-check the generated SEO output. Run from the repo root after gen_seo_pages.py:

    python scripts/check_seo_output.py

Exits with status 1 if anything is wrong, so you can run it before every deploy.
"""
import argparse, glob, html, json, os, re, sys
from collections import Counter

BASE = "https://www.flopermit.us"
ap = argparse.ArgumentParser()
ap.add_argument("--public", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend", "public"))
a = ap.parse_args()
os.chdir(a.public)

problems = []
def bad(msg): problems.append(msg)

files = sorted(glob.glob("cities/**/*.html", recursive=True)) + sorted(glob.glob("blog/*.html"))
titles, descs = Counter(), Counter()
for f in files:
    h = open(f, encoding="utf-8").read()
    m = re.search(r'<link rel="canonical" href="([^"]+)"', h)
    if not m: bad(f + ": no canonical"); continue
    can = m.group(1)
    if not can.startswith(BASE + "/"): bad(f + ": canonical not on " + BASE + " -> " + can)
    if f == "cities/index.html" and can != BASE + "/cities/": bad(f + ": hub canonical should be " + BASE + "/cities/")
    elif f == "blog/index.html" and can != BASE + "/blog/": bad(f + ": blog index canonical should be " + BASE + "/blog/")
    elif f not in ("cities/index.html", "blog/index.html") and can != BASE + "/" + f: bad(f + ": canonical != own URL (" + can + ")")
    if "noindex" in h: bad(f + ": noindex page (draft preview) is in the output, remove it before deploying")
    if "[VERIFY" in h: bad(f + ": unresolved [VERIFY] marker is on the page")
    if f.startswith("blog/") and f != "blog/index.html" and '"Article"' not in h: bad(f + ": blog post has no Article schema")
    t = html.unescape(re.search(r"<title>(.*?)</title>", h, re.S).group(1)); d = re.search(r'name="description" content="(.*?)"', h)
    d = html.unescape(d.group(1)) if d else ""
    titles[t] += 1; descs[d] += 1
    if len(t) > 70: bad(f + ": title over 70 chars (%d)" % len(t))
    if not d or len(d) > 155: bad(f + ": description missing or over 155 chars (%d)" % len(d))
    if len(re.findall(r"<h1", h)) != 1: bad(f + ": expected exactly one <h1>")
    if "UNCERTAINTY" in h: bad(f + ": internal UNCERTAINTY note leaked onto the page")
    if re.search(r"https?://flopermit\.us", h): bad(f + ": apex host (non-www) URL found")
    for block in re.findall(r'<script type="application/ld\+json">(.*?)</script>', h, re.S):
        try: json.loads(block)
        except Exception: bad(f + ": invalid JSON-LD")
    for href in set(re.findall(r'href="(/[^"#?]*)"', h)):
        if href in ("/",) or href.startswith(("/adc_logo", "/demo")): continue
        p = href.lstrip("/") + ("index.html" if href.endswith("/") else "")
        if not os.path.exists(p): bad(f + ": broken internal link " + href)
for t, c in titles.items():
    if c > 1: bad("duplicate title on %d pages: %s" % (c, t))
for d, c in descs.items():
    if c > 1: bad("duplicate description on %d pages: %s" % (c, d[:60]))

# sitemap must list every generated page (and nothing that does not exist)
sm = open("sitemap.xml", encoding="utf-8").read()
locs = re.findall(r"<loc>([^<]+)</loc>", sm)
if len(locs) != len(set(locs)): bad("sitemap has duplicate URLs")
for loc in locs:
    if not loc.startswith(BASE + "/"): bad("sitemap URL not on " + BASE + ": " + loc); continue
    p = loc[len(BASE) + 1:]
    if p == "": continue
    p = p + "index.html" if p.endswith("/") else p
    if not os.path.exists(p): bad("sitemap URL has no file: " + loc)
want = {BASE + "/cities/" if f == "cities/index.html" else BASE + "/blog/" if f == "blog/index.html" else BASE + "/" + f for f in files}
for w in sorted(want - set(locs)): bad("page missing from sitemap: " + w)
if "Sitemap: " + BASE + "/sitemap.xml" not in open("robots.txt").read(): bad("robots.txt sitemap line is not " + BASE)

print("pages checked: %d | sitemap URLs: %d" % (len(files), len(locs)))
if problems:
    print("\n%d PROBLEM(S):" % len(problems)); [print("  -", p) for p in problems[:40]]; sys.exit(1)
print("All checks passed.")
