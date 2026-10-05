#!/usr/bin/env python3
"""Flo Permit SEO page generator.

Run from the repo root:
    python scripts/gen_seo_pages.py

Reads:   backend/permit_data.py  (+ scripts/city_info_overrides.json for the cities
         whose name/county/stats only ever existed on the live pages)
Writes:  frontend/public/cities/**   (city pages, city + permit type pages, hubs)
         frontend/public/sitemap.xml, robots.txt, 404.html

Nothing here invents requirements: every checklist line comes from permit_data.py.
Internal research flags ("UNCERTAINTY ...") are never published.
"""
import argparse
import datetime as dt
import html
import importlib.util
import json
import math
import re
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

BASE = "https://www.flopermit.us"
GA_ID = "G-2V1MF78CPY"
MIN_ITEMS = 12      # a city + permit type page needs at least this many checklist items
MIN_UNIQUE = 0.30   # ...and this share must be absent from every other city's list for that type
TITLE_MAX = 70
DESC_MAX = 155

COUNTY_ORDER = ["Broward", "Palm Beach", "Miami-Dade"]
COUNTY_SLUG = {"Broward": "broward-county", "Palm Beach": "palm-beach-county", "Miami-Dade": "miami-dade-county"}
COUNTY_COLORS = {"Broward": "#22d3ee", "Palm Beach": "#a78bfa", "Miami-Dade": "#f59e0b"}
NAME_FIX = {"lauderdale_by_the_sea": "Lauderdale-by-the-Sea"}

COORDS = {
    "fort-lauderdale": (26.1224, -80.1373), "pompano-beach": (26.2379, -80.1248), "hollywood": (26.0112, -80.1495),
    "coral-springs": (26.2712, -80.2706), "coconut-creek": (26.2517, -80.1789), "lauderdale-by-the-sea": (26.1920, -80.0964),
    "deerfield-beach": (26.3184, -80.0998), "pembroke-pines": (26.0031, -80.3141), "lighthouse-point": (26.2757, -80.0874),
    "weston": (26.1004, -80.3998), "davie": (26.0765, -80.2511), "plantation": (26.1224, -80.2531), "sunrise": (26.1536, -80.2981),
    "miramar": (25.9773, -80.3025), "margate": (26.2437, -80.2115), "tamarac": (26.2029, -80.2498), "oakland-park": (26.1724, -80.1319),
    "wilton-manors": (26.1592, -80.1389), "dania-beach": (26.0518, -80.1451), "boca-raton": (26.3587, -80.0831),
    "lake-worth-beach": (26.6168, -80.0615), "delray-beach": (26.4615, -80.0728), "boynton-beach": (26.5254, -80.0661),
    "west-palm-beach": (26.7153, -80.0534), "wellington": (26.6618, -80.2684), "miami": (25.7617, -80.1918),
    "miami-beach": (25.7907, -80.1300), "hialeah": (25.8576, -80.2781), "homestead": (25.4687, -80.4376),
    "miami-gardens": (25.9420, -80.2456), "north-miami": (25.8901, -80.1868), "kendall": (25.6795, -80.3553),
}

# key -> (short label, whether "Permit" belongs in the title)
LABELS = {
    "mechanical": ("Mechanical / HVAC", True), "pool_spa": ("Pool & Spa", True), "windows_doors": ("Window & Door", True),
    "dock": ("Dock & Marine", True), "fire_system": ("Fire Sprinkler & Alarm", True),
    "certificate_of_occupancy": ("Certificate of Occupancy", False), "private_provider": ("Private Provider", False),
    "change_of_contractor": ("Change of Contractor", False), "solar": ("Solar Panel", True), "ev_charger": ("EV Charger", True),
    "business_tax": ("Business Tax Receipt", False), "adu": ("Accessory Dwelling Unit", True), "right_of_way": ("Right-of-Way", True),
    "kitchen_bath": ("Kitchen & Bath Remodel", True),
}

TRADES = {
    "General / Structural": ["building", "demolition", "adu", "interior_buildout", "certificate_of_occupancy", "screen_enclosure",
                             "new_construction_sfr", "residential_renovation", "commercial_tenant", "civil_site_work"],
    "Roofing": ["roofing"],
    "Electrical": ["electrical", "solar", "ev_charger", "generator", "temporary_power", "temporary_electric", "electrical_service_change"],
    "Plumbing": ["plumbing", "water_heater"],
    "Mechanical / HVAC": ["mechanical"],
    "Windows & Doors": ["windows_doors", "hurricane_mitigation"],
    "Pool & Spa": ["pool_spa"],
    "Fence, Driveway & Structures": ["fence", "driveway", "driveway_patio", "shed", "wall", "awning_canopy"],
    "Marine / Waterfront": ["dock", "seawall"],
    "Fire & Safety": ["fire_system"],
    "Signs": ["sign"],
    "Business & Admin": ["private_provider", "business_tax", "change_of_contractor", "change_of_architect_engineer",
                         "right_of_way", "fixturing", "special_event", "kitchen_bath"],
}

OFFICIAL_NOC = ("Florida law requires a recorded Notice of Commencement when the contract price is greater than $5,000 "
                "($15,000 for repair or replacement of an existing heating or air conditioning system).")
NOC_LINE = "NOC: " + OFFICIAL_NOC + " Confirm with the building department whether it is due at application or before the first inspection."
NOC_MENTION = re.compile(r"notice of commencement|\bNOC\b", re.I)
MONEY = re.compile(r"\$\s?([\d,]+)")


def noc_stale(s):
    """True when a line talks about the NOC and quotes a dollar figure other than $5,000 / $15,000."""
    if not NOC_MENTION.search(s):
        return False
    return bool({int(m.replace(",", "")) for m in MONEY.findall(s) if m.replace(",", "")} - {5000, 15000})


def fix_noc(items, stats, insert=True):
    kept, first = [], None
    for s in items:
        if noc_stale(s):
            stats["noc_lines_withheld"] += 1
            if first is None:
                first = len(kept)
        else:
            kept.append(s)
    if first is not None and insert and not any(NOC_MENTION.search(x) and MONEY.search(x) for x in kept):
        kept.insert(first, NOC_LINE)
    return kept


PREFIX_RE = re.compile(r"^(GOTCHA|NOTE|FEE|NOC|WARNING|HVHZ CITY|HVHZ)\s*(?::|\u2014|-)\s*", re.I)
CHIP = {"GOTCHA": ("Gotcha", "gotcha"), "NOTE": ("Note", "note"), "FEE": ("Fee", "fee"), "NOC": ("NOC", "noc"),
        "WARNING": ("Warning", "gotcha"), "HVHZ CITY": ("HVHZ", "hvhz"), "HVHZ": ("HVHZ", "hvhz")}

BASE_CSS = r"""
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#030305;color:#e2e8f0;line-height:1.7;-webkit-font-smoothing:antialiased;font-size:16px}
a{color:#22d3ee;text-decoration:none;transition:color .2s}a:hover{color:#67e8f9}

/* Nav */
.nav{position:sticky;top:0;z-index:50;background:rgba(0,0,0,.7);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid rgba(255,255,255,.05)}
.nav-inner{max-width:1100px;margin:0 auto;padding:20px 32px;display:flex;justify-content:space-between;align-items:center}
.nav-logo{display:flex;align-items:center;gap:10px;text-decoration:none}
.nav-logo img{width:40px;height:40px;border-radius:10px;object-fit:contain}
.nav-logo span{font-weight:900;font-size:20px}.nav-flo{color:#22d3ee}.nav-perm{color:#fff}
.nav-links{display:flex;gap:20px;align-items:center}
.nav-links a{color:#6b7280;font-size:14px;font-weight:500}
.nav-links a:hover{color:#fff}
.nav-cta{background:#22d3ee;color:#000;font-weight:700;font-size:17px;padding:10px 22px;border-radius:8px}
.nav-cta:hover{transform:translateY(-1px);box-shadow:0 4px 15px rgba(6,182,212,.3);color:#000}

/* Hero */
.hero{max-width:1100px;margin:0 auto;padding:64px 32px 48px}
.hero-badge{display:inline-block;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:16px}
.hero h1{font-size:clamp(36px,6vw,56px);font-weight:900;letter-spacing:-.5px;margin-bottom:12px;color:#fff}
.hero h1 em{font-style:normal;color:#22d3ee}
.hero-sub{font-size:20px;color:#6b7280;max-width:550px;margin-bottom:24px}
.hero-cta{display:inline-flex;align-items:center;gap:8px;padding:18px 36px;background:linear-gradient(135deg,#06b6d4,#10b981);color:#000;font-weight:800;font-size:17px;border-radius:12px;transition:transform .2s,box-shadow .2s}
.hero-cta:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(6,182,212,.25);color:#000}

/* Stats bar */
.stats{max-width:1100px;margin:0 auto;padding:0 32px 40px;display:flex;gap:12px;flex-wrap:wrap}
.stat{flex:1;min-width:160px;padding:20px 24px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:12px}
.stat-label{font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;font-weight:600;margin-bottom:2px}
.stat-val{font-size:17px;font-weight:700;color:#fff}
.stat-val a{color:#22d3ee}

/* Sections */
.section{max-width:1100px;margin:0 auto;padding:48px 32px}
.divider{max-width:1100px;margin:0 auto;height:1px;background:rgba(255,255,255,.05)}
.sec-title{font-size:13px;color:#6b7280;font-weight:700;text-transform:uppercase;letter-spacing:2px;margin-bottom:16px}

/* Filter */
.filter-bar{display:flex;gap:12px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.filter-select{padding:14px 22px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-radius:10px;color:#fff;font-size:15px;font-weight:600;font-family:inherit;cursor:pointer;min-width:200px;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%236b7280' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center}
.filter-select:focus{outline:none;border-color:rgba(34,211,238,.3)}
.filter-count{font-size:13px;color:#6b7280}

/* Permit cards */
.trade-group{margin-bottom:8px}
.trade-header{padding:18px 24px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:10px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;font-weight:700;font-size:14px;color:#cbd5e1;transition:background .2s;user-select:none}
.trade-header:hover{background:rgba(255,255,255,.04)}
.trade-header .cnt{font-size:12px;color:#6b7280;font-weight:600;background:rgba(255,255,255,.05);padding:2px 8px;border-radius:6px}
.trade-header .arrow{color:#6b7280;font-size:14px;transition:transform .2s}
.trade-group.open .arrow{transform:rotate(180deg)}
.trade-body{display:none;padding:8px 0;gap:8px}
.trade-group.open .trade-body{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr))}

.permit-card{background:rgba(255,255,255,.015);border:1px solid rgba(255,255,255,.05);border-radius:12px;padding:20px;transition:border-color .2s}
.permit-card:hover{border-color:rgba(255,255,255,.1)}
.pc-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;gap:8px}
.pc-name{font-size:15px;font-weight:700;color:#e2e8f0;line-height:1.3}
.pc-count{font-size:11px;color:#22d3ee;font-weight:700;flex-shrink:0;background:rgba(34,211,238,.08);padding:2px 8px;border-radius:6px}
.pc-items{list-style:none}
.pc-item{font-size:14px;color:#6b7280;padding:8px 0 8px 28px;position:relative;line-height:1.5;border-bottom:1px solid rgba(255,255,255,.02);cursor:pointer;transition:color .2s}
.pc-item:last-child{border-bottom:none}
.pc-item::before{content:"";position:absolute;left:2px;top:12px;width:14px;height:14px;border:1.5px solid rgba(255,255,255,.1);border-radius:3px}
.pc-item.checked{color:#334155;text-decoration:line-through}
.pc-item.checked::before{background:#10b981;border-color:#10b981}
.pc-item.checked::after{content:"✓";position:absolute;left:4px;top:6px;font-size:8px;font-weight:900;color:#000}
.pc-more{font-style:italic;color:#334155;cursor:default}.pc-more::before{display:none!important}

/* Gotchas */
.gotcha-box{background:rgba(245,158,11,.02);border:1px solid rgba(245,158,11,.08);border-radius:14px;padding:24px}
.gotcha-box h2{color:#f59e0b;font-size:26px;margin-bottom:4px;font-weight:800}
.gotcha-box>p{color:#92400e;font-size:15px;margin-bottom:16px}
.gotcha{display:flex;gap:14px;padding:12px 0;border-bottom:1px solid rgba(245,158,11,.04);font-size:15px;color:rgba(252,211,77,.8);line-height:1.6}
.gotcha:last-child{border-bottom:none}
.gotcha-n{flex-shrink:0;width:22px;height:22px;background:rgba(245,158,11,.1);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:#fbbf24}

/* Insurance */
.ins-box{background:rgba(16,185,129,.02);border:1px solid rgba(16,185,129,.1);border-radius:12px;padding:16px;margin:16px 0}
.ins-label{font-size:10px;color:#34d399;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.ins-val{font-family:'Courier New',monospace;font-size:16px;color:#e2e8f0;line-height:1.5}
.copy-btn{margin-top:8px;padding:6px 14px;background:rgba(16,185,129,.1);border:1px solid rgba(16,185,129,.15);border-radius:6px;color:#34d399;font-size:11px;font-weight:700;cursor:pointer;font-family:inherit}
.copy-btn:hover{background:rgba(16,185,129,.2)}

/* Sample analysis */
.sample{max-width:480px;margin:0 auto;border:1px solid rgba(255,255,255,.08);border-radius:14px;overflow:hidden;background:rgba(255,255,255,.02)}
.sample-h{padding:16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid rgba(255,255,255,.05);background:rgba(6,182,212,.03)}
.sample-h .t{font-size:15px;font-weight:800;color:#fff}.sample-h .s{font-size:11px;color:#6b7280}
.sample-score{text-align:center}.sample-score .n{font-size:28px;font-weight:900;color:#f59e0b}.sample-score .l{font-size:9px;color:#6b7280;text-transform:uppercase;letter-spacing:1px}
.sample-body{padding:12px 16px}
.sr{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:14px}
.sr:last-of-type{border-bottom:none}
.sr-m{color:#ef4444;font-weight:800;width:16px;text-align:center}.sr-f{color:#10b981;font-weight:800;width:16px;text-align:center}
.sr-nm{color:#e2e8f0;font-weight:600;flex:1}.sr-nf{color:#475569;flex:1}
.sr-tag{font-size:10px;padding:2px 8px;border-radius:4px;font-weight:700}
.sr-tr{background:rgba(239,68,68,.1);color:#f87171}.sr-tg{background:rgba(16,185,129,.08);color:#34d399}
.sample-warn{margin:10px 0;padding:10px 14px;background:rgba(245,158,11,.04);border:1px solid rgba(245,158,11,.08);border-radius:8px;font-size:13px;color:#fbbf24;line-height:1.5}

/* Pricing */
.pricing-strip{display:flex;justify-content:center;gap:12px;flex-wrap:wrap;padding:16px 0}
.pr{background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:12px;padding:18px 28px;text-align:center;min-width:120px}
.pr.pop{border-color:rgba(34,211,238,.15)}
.pr-label{font-size:9px;color:#6b7280;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:2px}
.pr-price{font-size:32px;font-weight:900;color:#fff}.pr-price span{font-size:12px;color:#6b7280;font-weight:500}
.pr-desc{font-size:13px;color:#475569;margin-top:2px}

/* FAQ */
.faq{border:1px solid rgba(255,255,255,.05);border-radius:10px;margin-bottom:6px;overflow:hidden}
.faq summary{padding:18px 24px;font-size:16px;font-weight:700;color:#94a3b8;cursor:pointer;list-style:none;display:flex;justify-content:space-between;background:rgba(255,255,255,.01)}
.faq summary::after{content:"+";color:#6b7280;font-size:16px}.faq[open] summary::after{content:"-"}
.faq p{padding:0 24px 18px;font-size:15px;color:#6b7280;line-height:1.7}

/* CTA */
.final-cta{text-align:center;padding:60px 24px;max-width:1100px;margin:0 auto}
.final-cta h2{font-size:36px;font-weight:900;margin-bottom:8px;color:#fff}
.final-cta h2 em{font-style:normal;color:#22d3ee}
.final-cta p{color:#6b7280;font-size:18px;margin-bottom:24px}

/* Cross-links */
.xlinks{max-width:1100px;margin:0 auto;padding:24px}
.xlinks h4{font-size:10px;color:#475569;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px}
.xlinks .tags{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px}
.xlinks a.tag{padding:7px 14px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:8px;font-size:11px;color:#6b7280;font-weight:500}
.xlinks a.tag:hover{border-color:rgba(34,211,238,.2);color:#22d3ee}

footer{max-width:1100px;margin:0 auto;padding:24px 32px;border-top:1px solid rgba(255,255,255,.05);display:flex;justify-content:space-between;font-size:11px;color:#475569;flex-wrap:wrap;gap:8px}
footer a{color:#475569;margin-left:12px}footer a:hover{color:#94a3b8}

@media(max-width:768px){
  .nav-links{display:none}.stats{flex-direction:column}
  .trade-body{grid-template-columns:1fr!important}
  .filter-bar{flex-direction:column;align-items:stretch}
  .sample{margin:0 -12px;border-radius:0}
  .pricing-strip{flex-direction:column;align-items:center}
}
"""

EXTRA_CSS = r"""
.crumbs{max-width:1100px;margin:0 auto;padding:20px 32px 0;font-size:13px;color:#6b7280}
.crumbs a{color:#6b7280}.crumbs a:hover{color:#22d3ee}.crumbs .sep{margin:0 8px;color:#334155}
.chip{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.6px;text-transform:uppercase;padding:2px 7px;border-radius:5px;margin-right:8px;vertical-align:1px}
.chip-gotcha{background:rgba(245,158,11,.12);color:#fbbf24}.chip-note{background:rgba(148,163,184,.12);color:#94a3b8}
.chip-fee{background:rgba(34,211,238,.10);color:#22d3ee}.chip-noc{background:rgba(16,185,129,.10);color:#34d399}.chip-hvhz{background:rgba(167,139,250,.12);color:#c4b5fd}
.permit-card.wide{padding:10px 26px}.permit-card.wide .pc-item{font-size:15px;padding:10px 0 10px 30px}.permit-card.wide .pc-item::before{top:15px}
.link-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px}
.link-card{display:block;padding:14px 16px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.05);border-radius:10px;color:#e2e8f0;font-weight:700;font-size:15px}
.link-card small{display:block;color:#6b7280;font-weight:500;font-size:12px;margin-top:3px}.link-card:hover{border-color:rgba(34,211,238,.28);color:#fff}
.view-all{display:inline-block;margin-top:12px;font-size:13px;font-weight:700}
.note-box{margin-top:18px;padding:14px 18px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);border-radius:10px;font-size:13px;color:#6b7280;line-height:1.7}
.sec-sub{color:#6b7280;font-size:15px;margin:-8px 0 20px}
.county-block{margin-bottom:44px}.county-block h2{font-size:22px;font-weight:800;color:#fff;margin-bottom:6px}
details.bytype{border:1px solid rgba(255,255,255,.05);border-radius:10px;margin-bottom:8px;background:rgba(255,255,255,.01)}
details.bytype summary{padding:14px 20px;font-weight:700;font-size:15px;color:#cbd5e1;cursor:pointer}
details.bytype .tags{padding:0 20px 16px;display:flex;flex-wrap:wrap;gap:8px}
details.bytype a.tag{padding:6px 12px;border:1px solid rgba(255,255,255,.06);border-radius:8px;font-size:13px;color:#94a3b8}
details.bytype a.tag:hover{border-color:rgba(34,211,238,.3);color:#22d3ee}
.cta-box{background:rgba(34,211,238,.03);border:1px solid rgba(34,211,238,.12);border-radius:16px;padding:32px;text-align:center}
.cta-box h2{font-size:26px;font-weight:900;color:#fff;margin-bottom:8px}.cta-box p{color:#6b7280;font-size:15px;margin-bottom:20px}
footer .flinks{display:flex;gap:14px;flex-wrap:wrap}
.nav-links a.nav-cta{color:#000}
.hero h1{line-height:1.2}
.stat.wide{flex:2 1 320px}
.pc-sub{list-style:none;font-size:12px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:#22d3ee;padding:18px 0 4px;margin-top:6px;border-top:1px solid rgba(255,255,255,.05)}
.pc-items .pc-sub:first-child{border-top:0;margin-top:0;padding-top:6px}
"""

JS = r"""
document.addEventListener('click',function(e){
  var li=e.target.closest('.pc-item');
  if(li&&!li.classList.contains('pc-more')){li.classList.toggle('checked');return;}
  var th=e.target.closest('.trade-header');
  if(th){th.parentElement.classList.toggle('open');}
});
function filterTypes(){
  var s=document.getElementById('typeFilter'); if(!s) return; var v=s.value, shown=0;
  document.querySelectorAll('.trade-group').forEach(function(g){
    var any=false;
    g.querySelectorAll('.permit-card').forEach(function(c){
      if(v==='all'||c.dataset.type===v){c.style.display='';any=true;shown++}else{c.style.display='none'}
    });
    if(any){g.style.display='';if(v!=='all')g.classList.add('open');}else{g.style.display='none'}
  });
  var fc=document.getElementById('filterCount'); if(fc) fc.textContent=v==='all'?'':'Showing '+shown+' permit type'+(shown!==1?'s':'');
}
var fg=document.querySelector('.trade-group'); if(fg) fg.classList.add('open');
"""

esc = html.escape


# ---------------------------------------------------------------- data loading
def load_module(path):
    spec = importlib.util.spec_from_file_location("permit_data", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def money(v):
    if isinstance(v, (int, float)):
        return "${:,}".format(int(v))
    s = str(v).strip()
    m = re.match(r"^\$?\s*([\d,]+)$", s)
    return "${:,}".format(int(m.group(1).replace(",", ""))) if m else s


DIVIDER_RE = re.compile(r"^(?:(?:GOTCHA|NOTE|FEE|NOC|WARNING|HVHZ CITY|HVHZ)\s*(?::|\u2014|-)\s*)?=+\s*(.+?)\s*=+\s*$", re.I)
TAG_PREFIX_RE = re.compile(r"^(?:GOTCHA|NOTE|FEE|NOC|WARNING|HVHZ CITY|HVHZ)\s*(?::|\u2014|-)\s*", re.I)


def section_title(s):
    """Return the heading text if the line is a section header rather than a requirement, else None."""
    m = DIVIDER_RE.match(s.strip())
    if m:
        return m.group(1).strip(" :")
    body = TAG_PREFIX_RE.sub("", s.strip())
    if body.endswith(":") and len(body) <= 90:
        return body.rstrip(": ").strip()
    return None


def split_sections(items):
    """-> (requirements only, list for display with section headings; empty sections are dropped)."""
    reqs = [i for i in items if not section_title(i)]
    out, pending = [], None
    for i in items:
        if section_title(i):
            pending = i
        else:
            if pending is not None:
                out.append(pending)
                pending = None
            out.append(i)
    return reqs, out


def clean_items(items):
    out, seen = [], set()
    for it in items:
        if not isinstance(it, str):
            continue
        s = re.sub(r"\s+", " ", it).strip()
        if not s or s.upper().startswith("UNCERTAINTY"):
            continue
        if s.lower() in seen:
            continue
        seen.add(s.lower())
        out.append(s)
    return out


def norm(s, city_name):
    s = s.lower().replace(city_name.lower(), " ")
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", s)).strip()


def label_from_name(name):
    base = re.sub(r"\(.*?\)", "", name).split(" \u2014 ")[0]
    pw = bool(re.search(r"\bPermit\s*$", base.strip(), re.I))
    base = re.sub(r"\b(Permit|Package)\s*$", "", base.strip(), flags=re.I).strip(" /-")
    return base, pw


def build_cities(pd, overrides, stats):
    # 1) canonical label per permit key
    names = defaultdict(Counter)
    for types in pd.CITY_SPECIFIC_PERMITS.values():
        for k, v in types.items():
            if isinstance(v, dict) and isinstance(v.get("items"), list):
                names[k][v.get("name", k)] += 1
    labels = {}
    for k, c in names.items():
        labels[k] = LABELS.get(k) or label_from_name(c.most_common(1)[0][0])

    cities = []
    for key, types in pd.CITY_SPECIFIC_PERMITS.items():
        slug = key.replace("_", "-")
        info = dict(pd.CITY_INFO.get(key, {}))
        ov = overrides.get(slug, {})
        info.update({k: v for k, v in ov.items() if v not in (None, "")})
        full_name = info.get("name") or NAME_FIX.get(key) or key.replace("_", " ").title()
        name = re.sub(r"^(City|Town|Village) of\s+", "", re.sub(r"\s*\(.*?\)\s*", " ", full_name).strip(), flags=re.I)
        county = info.get("county")
        if county not in COUNTY_ORDER:
            stats["no_county"].append(slug)
            continue
        c = {"key": key, "slug": slug, "name": name, "full_name": full_name, "county": county, "types": {}, "info": normalize_info(info, stats, slug),
             "gotchas": fix_noc(clean_items(pd.KNOWN_GOTCHAS.get(key, [])), stats, insert=False)}
        for tk, v in types.items():
            if not (isinstance(v, dict) and isinstance(v.get("items"), list)):
                continue
            raw = v["items"]
            items = fix_noc(clean_items(raw), stats)
            full = items
            items, render = split_sections(full)
            stats["section_headers"] = stats.get("section_headers", 0) + (len(full) - len(items))
            stats["uncertainty_removed"] += sum(1 for i in raw if isinstance(i, str) and i.strip().upper().startswith("UNCERTAINTY"))
            label, pw = labels[tk]
            c["types"][tk] = {"key": tk, "slug": tk.replace("_", "-"), "label": label, "pw": pw, "items": items, "render": render, "page": False}
        cities.append(c)

    # 2) decide which city + type combinations are substantial enough for their own page
    by_key = defaultdict(dict)
    for c in cities:
        for tk, t in c["types"].items():
            t["norm"] = {norm(i, c["name"]) for i in t["items"]}
            by_key[tk][c["slug"]] = t["norm"]
    for c in cities:
        for tk, t in c["types"].items():
            if len(t["items"]) < MIN_ITEMS:
                stats["skipped_thin"].append((c["slug"], tk, len(t["items"])))
                continue
            others = set()
            for s, n in by_key[tk].items():
                if s != c["slug"]:
                    others |= n
            uniq = len(t["norm"] - others) / max(len(t["norm"]), 1)
            if uniq < MIN_UNIQUE:
                stats["skipped_dup"].append((c["slug"], tk, round(uniq, 2)))
                continue
            t["page"] = True
    return cities


def normalize_info(info, stats, slug):
    d = {}
    for k in ("phone", "address", "portal_url", "submission", "insurance_holder", "hours"):
        v = info.get(k)
        if isinstance(v, str) and v.strip():
            d[k] = v.strip()
    def amount(v):
        m = re.search(r"[\d,]+", str(v)) if v not in (None, "") else None
        return int(m.group().replace(",", "")) if m else None
    n, h = amount(info.get("noc_threshold")), amount(info.get("noc_threshold_hvac"))
    if n is not None or h is not None:
        if (n in (None, 5000)) and (h in (None, 15000)):
            if n: d["noc"] = "$5,000"
            if h: d["noc_hvac"] = "$15,000"
        else:
            stats["noc_stats_hidden"].append(slug)
    ps = info.get("plan_sets")
    if isinstance(ps, int) or (isinstance(ps, str) and ps.strip().isdigit()):
        n = int(ps)
        d["plan_sets"] = "{} set{}".format(n, "" if n == 1 else "s")
    elif isinstance(ps, str) and ps.strip():
        if len(ps.strip()) <= 40:
            d["plan_sets"] = ps.strip()
        else:
            d["plan_sets_long"] = ps.strip()
    if info.get("hvhz") is True:
        d["hvhz"] = True
    return d


def distance(a, b):
    la1, lo1 = COORDS.get(a["slug"], (None, None))
    la2, lo2 = COORDS.get(b["slug"], (None, None))
    if la1 is None or la2 is None:
        return 9999 if a["county"] != b["county"] else 500
    r = 3959
    p1, p2 = math.radians(la1), math.radians(la2)
    dp, dl = p2 - p1, math.radians(lo2 - lo1)
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def nearby(city, cities, n=6, need_type=None):
    pool = [c for c in cities if c["slug"] != city["slug"]]
    if need_type:
        pool = [c for c in pool if need_type in c["types"] and c["types"][need_type]["page"]]
    pool.sort(key=lambda c: distance(city, c))
    return pool[:n]


# ---------------------------------------------------------------- html helpers
def lab(t):
    return " ".join(w if (w.isupper() and len(w) > 1) else w.lower() for w in t["label"].split())


def make_title(prefix, brand=True):
    opts = [prefix + " (2026 Checklist) | Flo Permit", prefix + " (2026 Checklist)", prefix + " (2026)", prefix]
    for o in opts:
        if len(o) <= TITLE_MAX:
            return o
    return opts[-1]


def noun(t):
    return t["label"] + (" Permit" if t["pw"] else "")


def fit(options, limit):
    for o in options:
        if len(o) <= limit:
            return o
    return options[-1][: limit - 1].rstrip() + "\u2026"


def jsonld(graph):
    data = {"@context": "https://schema.org", "@graph": graph}
    return '<script type="application/ld+json">' + json.dumps(data, ensure_ascii=False).replace("</", "<\\/") + "</script>"


def graph_base(url, title, desc, today, crumbs, faq=None):
    g = [
        {"@type": "Organization", "@id": BASE + "/#org", "name": "Flo Permit", "url": BASE + "/", "logo": BASE + "/adc_logo.png"},
        {"@type": "WebPage", "@id": url + "#webpage", "url": url, "name": title, "description": desc, "dateModified": today,
         "isPartOf": {"@type": "WebSite", "@id": BASE + "/#website", "name": "Flo Permit", "url": BASE + "/"},
         "publisher": {"@id": BASE + "/#org"}},
        {"@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": i + 1, "name": n, "item": BASE + p} for i, (n, p) in enumerate(crumbs)]},
    ]
    if faq and len(faq) >= 2:
        g.append({"@type": "FAQPage", "mainEntity": [
            {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in faq]})
    return g


def shell(title, desc, canonical, body, graph, extra_css="", og_type="website", robots="index, follow, max-image-preview:large", extra_head=""):
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title}</title>
<meta name="description" content="{desc}">
<link rel="canonical" href="{canon}">
<meta name="robots" content="{robots}">
<link rel="icon" type="image/png" href="/adc_logo.png">
<meta property="og:type" content="{og_type}"><meta property="og:site_name" content="Flo Permit"><meta property="og:locale" content="en_US">
<meta property="og:title" content="{title}"><meta property="og:description" content="{desc}"><meta property="og:url" content="{canon}"><meta property="og:image" content="{base}/adc_logo.png">
<meta name="twitter:card" content="summary"><meta name="twitter:title" content="{title}"><meta name="twitter:description" content="{desc}"><meta name="twitter:image" content="{base}/adc_logo.png">
<script async src="https://www.googletagmanager.com/gtag/js?id={ga}"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments)}}gtag('js',new Date());gtag('config','{ga}');</script>
{ld}
{extra_head}
<style>{css}</style>
</head>
<body>
{body}
<script>{js}</script>
</body>
</html>
""".format(title=esc(title), desc=esc(desc), canon=canonical, base=BASE, ga=GA_ID, ld=jsonld(graph),
           css=BASE_CSS + EXTRA_CSS + extra_css, body=body, js=JS, robots=robots, og_type=og_type, extra_head=extra_head)


def nav():
    return ('<nav class="nav"><div class="nav-inner"><a href="{b}/" class="nav-logo"><img src="/adc_logo.png" alt="Flo Permit">'
            '<span><span class="nav-flo">Flo</span> <span class="nav-perm">Permit</span></span></a>'
            '<div class="nav-links"><a href="/cities/">Cities</a><a href="/blog/">Blog</a><a href="{b}/" class="nav-cta">Analyze My Package</a></div></div></nav>').format(b=BASE)


def crumbs_html(crumbs):
    parts = []
    for i, (n, p) in enumerate(crumbs):
        parts.append(esc(n) if i == len(crumbs) - 1 else '<a href="{}">{}</a>'.format(p if p.startswith("/") else p, esc(n)))
    return '<nav class="crumbs" aria-label="Breadcrumb">' + '<span class="sep">/</span>'.join(parts) + "</nav>"


def footer(today):
    links = '<a href="{b}/">Home</a><a href="/cities/">All cities</a><a href="/blog/">Blog</a>'.format(b=BASE)
    for c in COUNTY_ORDER:
        links += '<a href="/cities/{}.html">{}</a>'.format(COUNTY_SLUG[c], c)
    return '<footer><span>\u00a9 {} Flo Permit</span><div class="flinks">{}</div></footer>'.format(today[:4], links)


def item_li(s):
    h = section_title(s)
    if h:
        return '<li class="pc-sub">{}</li>'.format(esc(h))
    m = PREFIX_RE.match(s)
    chip = ""
    if m:
        label, cls = CHIP[m.group(1).upper()]
        chip = '<span class="chip chip-{}">{}</span>'.format(cls, label)
        s = s[m.end():]
    return '<li class="pc-item">{}{}</li>'.format(chip, esc(s))


def stats_html(info):
    cells = []

    def cell(label, val, link=None, wide=False):
        v = '<a href="{}" target="_blank" rel="noopener">{}</a>'.format(esc(link), val) if link else val
        cells.append('<div class="stat{}"><div class="stat-label">{}</div><div class="stat-val">{}</div></div>'.format(" wide" if wide else "", label, v))

    if info.get("phone"): cell("Phone", esc(info["phone"]))
    if info.get("address") and len(info["address"]) <= 90: cell("Address", esc(info["address"]), wide=True)
    if info.get("hours") and len(info["hours"]) <= 90: cell("Hours", esc(info["hours"]), wide=True)
    if info.get("portal_url", "").startswith("http"): cell("Portal", "Online portal \u2192", info["portal_url"])
    if info.get("submission") and len(info["submission"]) <= 90: cell("Submission", esc(info["submission"]), wide=True)
    if info.get("plan_sets"): cell("Plan sets", esc(info["plan_sets"]))
    if info.get("noc"): cell("NOC threshold", esc(info["noc"] + (" ({} HVAC)".format(info["noc_hvac"]) if info.get("noc_hvac") else "")))
    if info.get("hvhz"): cell("Wind zone", "HVHZ (High Velocity)")
    return '<div class="stats">' + "".join(cells) + "</div>" if cells else ""


def insurance_html(info):
    if not info.get("insurance_holder"):
        return ""
    return ('<div class="section" style="padding-top:0;padding-bottom:0"><div class="ins-box"><div class="ins-label">Insurance certificate holder (exact wording)</div>'
            '<div class="ins-val" id="ins-text">{}</div><button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById(\'ins-text\').innerText);'
            'this.textContent=\'Copied!\';setTimeout(()=>this.textContent=\'Copy to Clipboard\',2000)">Copy to Clipboard</button></div></div>').format(esc(info["insurance_holder"]))


def short_gotcha_answers(c, limit=3):
    out = []
    for g in c["gotchas"]:
        g = PREFIX_RE.sub("", g)
        if len(g) <= 260:
            out.append(g)
        if len(out) == limit:
            break
    return out


def faq_city(c):
    i, n, faq = c["info"], c["name"], []
    where = i.get("submission") or ""
    if i.get("portal_url", "").startswith("http"):
        where = (where + (". " if where else "") + "Portal: " + i["portal_url"]).strip()
    if where:
        faq.append(("Where do I submit a permit application in {}?".format(n), where.rstrip(".") + "."))
    if i.get("insurance_holder"):
        faq.append(("What insurance certificate holder wording does {} require?".format(n), "The certificate holder should read: {}".format(i["insurance_holder"])))
    faq.append(("Do I need a Notice of Commencement in {}?".format(n), OFFICIAL_NOC + " Timing can vary, so confirm with the {} building department whether it is due at application or before the first inspection.".format(n)))
    if i.get("plan_sets"):
        faq.append(("How many plan sets does {} require?".format(n), "{} listed. This can vary by permit type, so confirm with the building department.".format(i["plan_sets"].capitalize())))
    elif i.get("plan_sets_long"):
        faq.append(("How many plan sets does {} require?".format(n), i["plan_sets_long"].rstrip(".") + "."))
    if i.get("hvhz"):
        faq.append(("Is {} in the High Velocity Hurricane Zone (HVHZ)?".format(n), "Yes. {} is in the HVHZ, which affects product approval and wind load requirements.".format(n)))
    gs = short_gotcha_answers(c)
    if gs:
        faq.append(("What are common reasons permits get rejected in {}?".format(n), " ".join(g.rstrip(".") + "." for g in gs)))
    return faq


def faq_permit(c, t):
    faq = [qa for qa in faq_city(c) if not qa[0].startswith("What are common reasons")]
    gs = [PREFIX_RE.sub("", i) for i in t["items"] if PREFIX_RE.match(i) and PREFIX_RE.match(i).group(1).upper() == "GOTCHA" and len(i) <= 280][:3]
    if gs:
        faq.append(("What gets a {} application rejected in {}?".format(lab(t), c["name"]),
                    " ".join(g.rstrip(".") + "." for g in gs)))
    return faq


def faq_html(faq):
    if len(faq) < 2:
        return ""
    body = "".join('<details class="faq"><summary>{}</summary><p>{}</p></details>'.format(esc(q), esc(a)) for q, a in faq)
    return '<div class="divider"></div><div class="section"><div class="sec-title">Frequently asked questions</div>{}</div>'.format(body)


def pricing_strip():
    return ('<div class="pricing-strip"><div class="pr"><div class="pr-label">Free</div><div class="pr-price">$0</div><div class="pr-desc">3 analyses to start</div></div>'
            '<div class="pr pop"><div class="pr-label">Pro</div><div class="pr-price">$49<span>/mo</span></div><div class="pr-desc">20 analyses/month</div></div>'
            '<div class="pr"><div class="pr-label">Unlimited</div><div class="pr-price">$149<span>/mo</span></div><div class="pr-desc">Unlimited analyses</div></div>'
            '<div class="pr"><div class="pr-label">Single</div><div class="pr-price">$15.99</div><div class="pr-desc">One time</div></div></div>')


def hero_badge(county):
    cc = COUNTY_COLORS[county]
    rgb = ",".join(str(int(cc[i:i + 2], 16)) for i in (1, 3, 5))
    return '<a href="/cities/{}.html" class="hero-badge" style="background:rgba({r},.08);border:1px solid rgba({r},.2);color:{c}">{} County</a>'.format(COUNTY_SLUG[county], county, r=rgb, c=cc)


def hero_cta(label="Check Your Package Free \u2192"):
    return '<a href="{}/" class="hero-cta">{}</a>'.format(BASE, label)


def link_cards(cards):
    return '<div class="link-grid">' + "".join('<a class="link-card" href="{}">{}<small>{}</small></a>'.format(h, esc(t), esc(s)) for h, t, s in cards) + "</div>"


def city_url(c): return "/cities/{}.html".format(c["slug"])
def permit_url(c, t): return "/cities/{}/{}.html".format(c["slug"], t["slug"])


# ---------------------------------------------------------------- page builders
def build_city_page(c, cities, today):
    n_types, n_items = len(c["types"]), sum(len(t["items"]) for t in c["types"].values())
    n_g = len(c["gotchas"])
    url = BASE + city_url(c)
    title = make_title("{} Permit Requirements".format(c["name"]))
    desc = fit(["{n} permit requirements: {t} permit types, {i} checklist items and {g} common rejection reasons. Run a free analysis on your package.".format(n=c["name"], t=n_types, i=n_items, g=n_g),
                "{n} permit checklist: {t} permit types and {g} common rejection reasons. Free package analysis.".format(n=c["name"], t=n_types, g=n_g)], DESC_MAX)
    crumbs = [("Home", "/"), ("Cities", "/cities/"), (c["county"] + " County", "/cities/{}.html".format(COUNTY_SLUG[c["county"]])), (c["name"], city_url(c))]
    faq = faq_city(c)

    grouped, used = [], set()
    for gname, keys in TRADES.items():
        ts = [c["types"][k] for k in keys if k in c["types"]]
        used.update(k for k in keys if k in c["types"])
        if ts:
            grouped.append((gname, ts))
    rest = [t for k, t in c["types"].items() if k not in used]
    if rest:
        grouped.append(("More permit types", rest))

    options, trade_html = "", ""
    for gname, ts in grouped:
        cards = ""
        for t in ts:
            shown = t["items"][:5]
            lis = "".join(item_li(i) for i in shown)
            if len(t["items"]) > len(shown):
                lis += '<li class="pc-item pc-more">+ {} more requirements</li>'.format(len(t["items"]) - len(shown))
            link = '<a class="view-all" href="{}">View the full {} checklist \u2192</a>'.format(permit_url(c, t), esc(lab(t))) if t["page"] else ""
            options += '<option value="{}">{}</option>'.format(t["key"], esc(noun(t)))
            cards += ('<div class="permit-card" data-type="{k}"><div class="pc-head"><div class="pc-name">{n}</div><span class="pc-count">{c} items</span></div>'
                      '<ul class="pc-items">{l}</ul>{lk}</div>').format(k=t["key"], n=esc(noun(t)), c=len(t["items"]), l=lis, lk=link)
        trade_html += ('<div class="trade-group"><div class="trade-header"><span>{}</span><div style="display:flex;align-items:center;gap:10px"><span class="cnt">{} types</span>'
                       '<span class="arrow">\u25bc</span></div></div><div class="trade-body">{}</div></div>').format(esc(gname), len(ts), cards)

    gotcha_html = ""
    if c["gotchas"]:
        rows = "".join('<div class="gotcha"><span class="gotcha-n">{}</span><span>{}</span></div>'.format(i + 1, esc(PREFIX_RE.sub("", g))) for i, g in enumerate(c["gotchas"]))
        gotcha_html = ('<div class="divider"></div><div class="section"><div class="gotcha-box"><h2>Common rejection reasons in {n}</h2>'
                       '<p>{g} documented. Our analysis checks your package against these.</p>{rows}</div></div>').format(n=esc(c["name"]), g=n_g, rows=rows)

    near = nearby(c, cities, 6)
    near_html = ('<div class="divider"></div><div class="section"><div class="sec-title">Nearby cities</div>{}'
                 '<a class="view-all" href="/cities/{}.html">All {} County cities \u2192</a></div>').format(
        link_cards([(city_url(x), x["name"], "{} permit types".format(len(x["types"]))) for x in near]), COUNTY_SLUG[c["county"]], c["county"])

    body = (nav() + crumbs_html(crumbs)
            + ('<div class="hero">{badge}<h1><em>{n}</em> Permit Requirements</h1>'
              '<p class="hero-sub">Checklists for {t} permit types in {n}, plus {g} common rejection reasons. Check your own package against them in seconds.{fn}</p>'
              '<div style="display:flex;gap:28px;align-items:center;flex-wrap:wrap">{cta}<div style="display:flex;gap:22px">'
              '<div><div style="font-size:32px;font-weight:900;color:#fff">{t}</div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;font-weight:600">Permit types</div></div>'
              '<div><div style="font-size:32px;font-weight:900;color:#fff">{i}</div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;font-weight:600">Requirements</div></div>'
              '<div><div style="font-size:32px;font-weight:900;color:#fff">{g}</div><div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;font-weight:600">Gotchas</div></div>'
              '</div></div></div>').format(badge=hero_badge(c["county"]), n=esc(c["name"]), t=n_types, g=n_g, i=n_items, cta=hero_cta(),
                fn=(" Covers {}.".format(esc(c["full_name"])) if "(" in c["full_name"] else ""))
            + stats_html(c["info"]) + insurance_html(c["info"])
            + '<div class="divider"></div><div class="section"><div class="sec-title">Requirements by permit type</div>'
              '<div class="filter-bar"><select class="filter-select" id="typeFilter" onchange="filterTypes()"><option value="all">All permit types ({})</option>{}</select>'
              '<span class="filter-count" id="filterCount"></span></div>{}'
              '<div class="note-box">Requirements change. Confirm the current checklist with the {} building department before you submit.</div></div>'.format(n_types, options, trade_html, esc(c["name"]))
            + gotcha_html + faq_html(faq)
            + '<div class="divider"></div><div class="section"><div class="cta-box"><h2>Check your <em style="font-style:normal;color:#22d3ee">{n}</em> package.</h2>'
              '<p>Upload your documents and see what is missing before you submit.</p>{cta}'
              '<p style="margin-top:14px;margin-bottom:0;font-size:12px;color:#475569">3 free analyses to start. No credit card needed.</p></div></div>'.format(n=esc(c["name"]), cta=hero_cta("Start Free Analysis \u2192"))
            + pricing_strip() + near_html + footer(today))
    return url, title, desc, shell(title, desc, url, body, graph_base(url, title, desc, today, crumbs, faq))


def build_permit_page(c, t, cities, today):
    url = BASE + permit_url(c, t)
    title = make_title("{} {} Requirements".format(c["name"], noun(t)))
    n_items = len(t["items"])
    desc = fit(["{n} {l} permit checklist: {i} requirements to have ready before you submit. Run a free analysis on your package.".format(n=c["name"], l=lab(t), i=n_items),
                "{n} {l} permit checklist with {i} requirements. Free package analysis.".format(n=c["name"], l=t["label"], i=n_items),
                "{n} {l} checklist: {i} requirements.".format(n=c["name"], l=t["label"], i=n_items)], DESC_MAX)
    crumbs = [("Home", "/"), ("Cities", "/cities/"), (c["county"] + " County", "/cities/{}.html".format(COUNTY_SLUG[c["county"]])),
              (c["name"], city_url(c)), (noun(t), permit_url(c, t))]
    faq = faq_permit(c, t)
    lis = "".join(item_li(i) for i in t["render"])
    sibs = [(permit_url(c, s), noun(s), "{} requirements".format(len(s["items"]))) for k, s in c["types"].items() if s["page"] and k != t["key"]]
    sib_html = ('<div class="divider"></div><div class="section"><div class="sec-title">Other permit types in {}</div>{}'
                '<a class="view-all" href="{}">All {} permit requirements \u2192</a></div>').format(esc(c["name"]), link_cards(sibs[:24]), city_url(c), esc(c["name"])) if sibs else ""
    near = nearby(c, cities, 6, need_type=t["key"])
    near_html = ('<div class="divider"></div><div class="section"><div class="sec-title">{} requirements in nearby cities</div>{}</div>').format(
        esc(noun(t)), link_cards([(permit_url(x, x["types"][t["key"]]), x["name"], "{} requirements".format(len(x["types"][t["key"]]["items"]))) for x in near])) if near else ""

    body = (nav() + crumbs_html(crumbs)
            + '<div class="hero">{badge}<h1><em>{n}</em> {nn} Requirements</h1>'
              '<p class="hero-sub">{i} checklist items for {l} applications in {n}. Click an item to check it off as you gather your documents.</p>{cta}</div>'.format(
                badge=hero_badge(c["county"]), n=esc(c["name"]), nn=esc(noun(t)), i=n_items, l=esc(lab(t)), cta=hero_cta())
            + stats_html(c["info"]) + insurance_html(c["info"])
            + '<div class="divider"></div><div class="section"><div class="sec-title">{nn} checklist for {n}</div><div class="permit-card wide"><ul class="pc-items">{lis}</ul></div>'
              '<div class="note-box">Requirements change. Confirm the current checklist with the {n} building department before you submit. '
              'See every permit type on the <a href="{cu}">{n} permit requirements</a> page.</div></div>'.format(nn=esc(noun(t)), n=esc(c["name"]), lis=lis, cu=city_url(c))
            + faq_html(faq)
            + '<div class="divider"></div><div class="section"><div class="cta-box"><h2>Check your {l} package.</h2>'
              '<p>Upload your documents and see what is missing against the {n} checklist.</p>{cta}'
              '<p style="margin-top:14px;margin-bottom:0;font-size:12px;color:#475569">3 free analyses to start. No credit card needed.</p></div></div>'.format(
                l=esc(lab(t)), n=esc(c["name"]), cta=hero_cta("Start Free Analysis \u2192"))
            + sib_html + near_html + footer(today))
    return url, title, desc, shell(title, desc, url, body, graph_base(url, title, desc, today, crumbs, faq))


def type_browse(cities, county=None, min_pages=2):
    pages = defaultdict(list)
    for c in cities:
        if county and c["county"] != county:
            continue
        for k, t in c["types"].items():
            if t["page"]:
                pages[k].append((c, t))
    out = ""
    for k, lst in sorted(pages.items(), key=lambda kv: -len(kv[1])):
        if len(lst) < min_pages:
            continue
        label = noun(lst[0][1])
        links = "".join('<a class="tag" href="{}">{}</a>'.format(permit_url(c, t), esc(c["name"])) for c, t in sorted(lst, key=lambda x: x[0]["name"]))
        out += '<details class="bytype"><summary>{} requirements ({} cities)</summary><div class="tags">{}</div></details>'.format(esc(label), len(lst), links)
    return out


def build_hub(cities, today):
    url = BASE + "/cities/"
    title = "South Florida Permit Requirements by City (2026) | Flo Permit"
    desc = fit(["Permit requirements for {} South Florida cities across Broward, Palm Beach and Miami-Dade, with rejection reasons and a free package analysis.".format(len(cities))], DESC_MAX)
    crumbs = [("Home", "/"), ("Cities", "/cities/")]
    blocks = ""
    for county in COUNTY_ORDER:
        cs = sorted([c for c in cities if c["county"] == county], key=lambda c: c["name"])
        blocks += ('<div class="county-block"><h2>{co} County</h2><p class="sec-sub">{n} cities. <a href="/cities/{s}.html">{co} County permit requirements \u2192</a></p>{cards}</div>').format(
            co=county, n=len(cs), s=COUNTY_SLUG[county],
            cards=link_cards([(city_url(c), c["name"], "{} permit types \u00b7 {} requirements".format(len(c["types"]), sum(len(t["items"]) for t in c["types"].values()))) for c in cs]))
    body = (nav() + crumbs_html(crumbs)
            + '<div class="hero"><h1>South Florida <em>Permit Requirements</em> by City</h1><p class="hero-sub">City by city permit checklists for Broward, Palm Beach and Miami-Dade. Find your city, pick a permit type, then check your package for free.</p>{}</div>'.format(hero_cta())
            + '<div class="divider"></div><div class="section">' + blocks + '</div>'
            + '<div class="divider"></div><div class="section"><div class="sec-title">Browse by permit type</div>' + type_browse(cities, min_pages=4) + '</div>'
            + footer(today))
    return url, title, desc, shell(title, desc, url, body, graph_base(url, title, desc, today, crumbs))


def build_county(county, cities, today):
    cs = sorted([c for c in cities if c["county"] == county], key=lambda c: c["name"])
    url = BASE + "/cities/{}.html".format(COUNTY_SLUG[county])
    title = make_title("{} County Permit Requirements by City".format(county)).replace("(2026 Checklist)", "(2026)")
    desc = fit(["{co} County permit requirements for {n} cities: checklists, rejection reasons and a free package analysis.".format(co=county, n=len(cs))], DESC_MAX)
    crumbs = [("Home", "/"), ("Cities", "/cities/"), (county + " County", "/cities/{}.html".format(COUNTY_SLUG[county]))]
    cards = link_cards([(city_url(c), c["name"], "{} permit types \u00b7 {} requirements".format(len(c["types"]), sum(len(t["items"]) for t in c["types"].values()))) for c in cs])
    body = (nav() + crumbs_html(crumbs)
            + '<div class="hero"><h1><em>{co} County</em> Permit Requirements</h1><p class="hero-sub">Permit checklists for {n} {co} County cities. Every city wants something slightly different, so pick yours.</p>{cta}</div>'.format(co=county, n=len(cs), cta=hero_cta())
            + '<div class="divider"></div><div class="section"><div class="sec-title">Cities</div>' + cards + '</div>'
            + '<div class="divider"></div><div class="section"><div class="sec-title">Browse by permit type</div>' + type_browse(cities, county=county, min_pages=2) + '</div>'
            + footer(today))
    return url, title, desc, shell(title, desc, url, body, graph_base(url, title, desc, today, crumbs))


NOT_FOUND = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Page not found | Flo Permit</title>
<meta name="robots" content="noindex"><link rel="icon" type="image/png" href="/adc_logo.png">
<style>body{margin:0;background:#030305;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px}
h1{font-size:48px;font-weight:900;color:#fff;margin:0 0 8px}p{color:#6b7280;font-size:17px;margin:0 0 24px}a{color:#22d3ee;margin:0 10px;font-weight:700;text-decoration:none}</style></head>
<body><div><h1>404</h1><p>That page does not exist.</p><a href="https://www.flopermit.us/">Home</a><a href="/cities/">City requirements</a></div></body></html>
"""


def blog_entries(blog_dir, today):
    out = []
    if not blog_dir.exists():
        return out
    for f in sorted(blog_dir.glob("*.html")):
        h = f.read_text(encoding="utf-8", errors="ignore")
        if re.search(r'name="robots" content="noindex', h):
            continue
        m = re.search(r'<link rel="canonical" href="([^"]+)"', h)
        d = re.search(r'"dateModified":\s*"(\d{4}-\d{2}-\d{2})"', h)
        if m:
            out.append((m.group(1), d.group(1) if d else today, "0.7"))
    return out


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    root = Path(__file__).resolve().parent.parent
    ap.add_argument("--data", default=str(root / "backend" / "permit_data.py"))
    ap.add_argument("--overrides", default=str(Path(__file__).resolve().parent / "city_info_overrides.json"))
    ap.add_argument("--out", default=str(root / "frontend" / "public"))
    ap.add_argument("--date", default=dt.date.today().isoformat())
    a = ap.parse_args()
    today, out = a.date, Path(a.out)

    pd = load_module(a.data)
    overrides = json.loads(Path(a.overrides).read_text(encoding="utf-8"))
    stats = {"noc_lines_withheld": 0, "noc_stats_hidden": [], "uncertainty_removed": 0, "skipped_thin": [], "skipped_dup": [], "no_county": []}
    cities = build_cities(pd, overrides, stats)
    cities.sort(key=lambda c: c["name"])

    cdir = out / "cities"
    if cdir.exists():
        shutil.rmtree(cdir)
    cdir.mkdir(parents=True)

    pages, urls = {}, []   # relpath -> html ; urls -> (loc, lastmod, priority)

    def add(rel, built, prio):
        url, title, desc, doc = built
        pages[rel] = (title, desc, doc)
        urls.append((url, today, prio))

    add("cities/index.html", build_hub(cities, today), "0.9")
    for county in COUNTY_ORDER:
        add("cities/{}.html".format(COUNTY_SLUG[county]), build_county(county, cities, today), "0.8")
    n_permit = 0
    for c in cities:
        add("cities/{}.html".format(c["slug"]), build_city_page(c, cities, today), "0.8")
        for t in c["types"].values():
            if t["page"]:
                (cdir / c["slug"]).mkdir(exist_ok=True)
                add("cities/{}/{}.html".format(c["slug"], t["slug"]), build_permit_page(c, t, cities, today), "0.6")
                n_permit += 1
    for rel, (title, desc, doc) in pages.items():
        (out / rel).write_text(doc, encoding="utf-8")

    # sitemap: homepage + generated pages + blog posts (canonical URLs only)
    entries = [(BASE + "/", today, "1.0")] + urls + blog_entries(out / "blog", today)
    seen, xml = set(), ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for loc, last, prio in entries:
        if loc in seen:
            continue
        seen.add(loc)
        xml.append("  <url><loc>{}</loc><lastmod>{}</lastmod><priority>{}</priority></url>".format(loc, last, prio))
    xml.append("</urlset>")
    (out / "sitemap.xml").write_text("\n".join(xml) + "\n", encoding="utf-8")
    (out / "robots.txt").write_text("User-agent: *\nAllow: /\n\nSitemap: {}/sitemap.xml\n".format(BASE), encoding="utf-8")
    (out / "404.html").write_text(NOT_FOUND, encoding="utf-8")

    # report
    long_titles = [r for r, (t, d, _) in pages.items() if len(t) > 60]
    print("Cities: {}  |  city pages: {}  |  permit pages: {}  |  hubs: {}  |  sitemap URLs: {}".format(len(cities), len(cities), n_permit, 1 + len(COUNTY_ORDER), len(seen)))
    print("Skipped (thin, < {} items): {}  |  skipped (near duplicate): {}  |  UNCERTAINTY notes withheld: {}".format(MIN_ITEMS, len(stats["skipped_thin"]), len(stats["skipped_dup"]), stats["uncertainty_removed"]))
    print("Titles over 60 chars: {}  |  longest title: {}  |  longest description: {}".format(len(long_titles), max(len(t) for t, d, _ in pages.values()), max(len(d) for t, d, _ in pages.values())))
    print("NOC: {} checklist/gotcha lines with older thresholds withheld | NOC stat hidden on {} cities".format(stats["noc_lines_withheld"], len(stats["noc_stats_hidden"])))
    print("Section headers converted from checklist lines: {}".format(stats.get("section_headers", 0)))
    if stats["no_county"]:
        print("WARNING no county, skipped:", stats["no_county"])
    for slug, tk, ratio in stats["skipped_dup"][:25]:
        print("  dup-skip {}/{} unique={}".format(slug, tk, ratio))


if __name__ == "__main__":
    main()
