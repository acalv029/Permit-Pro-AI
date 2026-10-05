#!/usr/bin/env python3
"""Correct the Notice of Commencement (NOC) thresholds in the live backend.

Run from the repo root:
    python patch_noc_fix.py

Florida Statutes s. 713.135(1)(e) (2026): an NOC copy is required when the direct contract is
greater than $5,000; repair or replacement of an existing HVAC system is exempt under $15,000.
Your data and AI instructions still carry the older $2,500 / $7,500 figures in about 570 places.

What this does (and nothing else):
  1. Appends a correction layer to backend/permit_data.py. It fixes the figures when the data
     loads, so the checklists, gotchas, city info panel and everything else read correctly.
  2. Edits backend/main.py so the AI instructions are normalized the same way right before they
     are sent (this fixes the city blocks hard coded in main.py).
It checks both files compile, imports the data to confirm nothing stale is left, and puts the
original files back automatically if any check fails. Safe to run twice.
"""
import ast
import pathlib
import re
import subprocess
import sys

DATA = pathlib.Path("backend/permit_data.py")
MAIN = pathlib.Path("backend/main.py")
MARK = "NOTICE OF COMMENCEMENT (NOC) CORRECTION LAYER"

BLOCK = r'''

# =============================================================================
# NOTICE OF COMMENCEMENT (NOC) CORRECTION LAYER
# -----------------------------------------------------------------------------
# Source of truth: Florida Statutes s. 713.135(1)(e) (2026 edition). A copy of the NOC is
# required before the first inspection when the direct contract is greater than $5,000.
# Repair or replacement of an existing heating or air conditioning system is exempt
# when the contract is less than $15,000. The statute applies to every county and city.
#
# Many older city forms and regional pages still print $2,500 / $7,500 (the pre 2023
# figures). Rather than hand edit hundreds of lines, this layer corrects them when the
# data loads, and normalize_noc_prompt() applies the same rules to the AI instructions.
# It is idempotent: running it twice changes nothing the second time.
# =============================================================================
import re as _re

_NOC_STD_ITEM = ("NOC: Required when the direct contract is greater than $5,000 ($15,000 for repair or replacement "
                 "of an existing HVAC system), per Fla. Stat. 713.135. Some older city forms list lower figures. "
                 "Confirm timing with the building department.")
_NOC_STD_PROMPT = ("- NOC threshold: $5,000 general; $15,000 for repair or replacement of an existing HVAC system "
                   "(Fla. Stat. 713.135). Ignore older, lower figures on city forms.")
_NOC_MENTION = _re.compile(r"notice of commencement|\bNOC\b", _re.I)
_NOC_FIG = _re.compile(r"\$\s?(?:2,?500|7,?500)(?!\d)")
_NOC_GOOD = _re.compile(r"\$\s?(?:5,000|15,000)(?!\d)")
_NOC_DICT_FIELDS = {"condition", "notes", "note", "threshold", "when", "applies", "rule", "details", "detail", "requirement"}
_NOC_HVAC_KEY = _re.compile(r"hvac|(?:^|_)a_?c(?:_|$)|mech|air|heat", _re.I)
_NOC_CMP = _re.compile(
    r"\(\s*not\b|[\u2014\-]\s*not\b|\bnot\s+(?:the|like|a)\b|\bnot\s+\$|higher than|lower than|much higher|unique|"
    r"different from|discrepan|conflict|\(or\s+\$|\bor\s+\$5,000|vary|varies|\bdiffer|use \$2,?500|to be safe|"
    r"\bper\s+(?:the\s+|city\s+|application\s+|permit\s+|inspections\s+|dfb\s+|alliance\s+|official\s+|lbts\s+)?"
    r"(?:page|form|checklist|pdf|guide|application)\b|alliance|older|pre-july|uncertainty|\bvs\b|instead of|standard|"
    r"\(\s*(?:roofing|hvac|a/c|ac|fence|dock|solar)\b|"
    r"\b(?:listed|lists|cites?|cited|says?|said|states?|stated|shows?|shown|according to|corrected from|was|were)\b|"
    r"\b(?:19|20)(?:1\d|2[0-5])\b",
    _re.I,
)


def _noc_swap(s):
    s = _re.sub(r"\$\s?2,?500(?!\d)", "$5,000", s)
    s = _re.sub(r"\$\s?7,?500(?!\d)", "$15,000", s)
    s = _re.sub(r"(?:>=|\u2265)\s*\$5,000", "greater than $5,000", s)
    s = _re.sub(r"\$5,000\+", "over $5,000", s)
    return s


def _noc_fix_string(s):
    """Corrected string, or None when the line is a comparison that should be replaced by the standard line."""
    if not _NOC_FIG.search(s):
        return s
    if _NOC_CMP.search(s):
        return None
    return _noc_swap(s)


def _noc_amount_for_key(key):
    return 15000 if _NOC_HVAC_KEY.search(str(key)) else 5000


def _noc_fix_list(lst, ctx=""):
    new, first, dropped = [], None, False
    for it in lst:
        if isinstance(it, str):
            if _NOC_MENTION.search(it) and _NOC_FIG.search(it):
                fixed = _noc_fix_string(it)
                if fixed is None:
                    dropped = True
                    if first is None:
                        first = len(new)
                    continue
                new.append(fixed)
                continue
            new.append(it)
        else:
            _noc_fix_obj(it, ctx)
            new.append(it)
    if dropped and not any(isinstance(x, str) and _NOC_MENTION.search(x) and _NOC_GOOD.search(x) for x in new):
        new.insert(first, _NOC_STD_ITEM)
    lst[:] = new


def _noc_is_threshold_name(name):
    return bool(_re.search(r"noc", name, _re.I)) and bool(_re.search(r"thresh", name, _re.I))


def _noc_fix_dict(d, ctx=""):
    has_noc = any(isinstance(v, str) and _NOC_MENTION.search(v) for v in d.values())
    for k in list(d):
        v, ks = d[k], str(k)
        noc_key = _noc_is_threshold_name(ks) or _noc_is_threshold_name(ctx)
        sem = ks + " " + ctx          # the key and its parents decide HVAC ($15,000) vs general ($5,000)
        if isinstance(v, bool):
            continue
        if isinstance(v, (int, float)):
            if noc_key and v in (2500, 7500):
                d[k] = _noc_amount_for_key(sem)
        elif isinstance(v, str):
            if not _NOC_FIG.search(v):
                continue
            if not (noc_key or _NOC_MENTION.search(v) or (has_noc and ks.lower() in _NOC_DICT_FIELDS)):
                continue
            if _re.fullmatch(r"\s*\$?\s?[\d,]+\s*", v) and noc_key:
                d[k] = "${:,}".format(_noc_amount_for_key(sem))
            else:
                fixed = _noc_fix_string(v)
                d[k] = fixed if fixed is not None else "Per Fla. Stat. 713.135: $5,000 general; $15,000 HVAC repair or replacement."
        else:
            _noc_fix_obj(v, ks + " " + ctx)


def _noc_fix_obj(o, ctx=""):
    if isinstance(o, dict):
        _noc_fix_dict(o, ctx)
    elif isinstance(o, list):
        _noc_fix_list(o, ctx)
    elif isinstance(o, tuple):
        for e in o:
            _noc_fix_obj(e, ctx)


def normalize_noc_prompt(text):
    """Apply the NOC corrections to a block of AI instructions (line by line, section aware)."""
    out, in_noc_section, std_done = [], False, False
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            in_noc_section, std_done = False, False
            out.append(line)
            continue
        is_heading = (not stripped.startswith("-")) and stripped.endswith(":") and len(stripped) < 120
        if is_heading:
            in_noc_section, std_done = bool(_NOC_MENTION.search(stripped)), False
            if in_noc_section:
                line = _re.sub(r"\s*-\s*DIFFERENT(?: FROM OTHER CITIES)?", "", line)
            out.append(line)
            continue
        if _NOC_FIG.search(line) and (in_noc_section or _NOC_MENTION.search(line)):
            fixed = _noc_fix_string(line)
            if fixed is None:
                if not std_done:
                    out.append(_NOC_STD_PROMPT)
                    std_done = True
                continue
            out.append(fixed)
            continue
        out.append(line)
    return "\n".join(out)


def apply_noc_fix(namespace):
    """Correct every module level data structure in place."""
    for name, obj in list(namespace.items()):
        if name.startswith("_") or not isinstance(obj, (dict, list, tuple)):
            continue
        _noc_fix_obj(obj)


apply_noc_fix(globals())
'''

for f in (DATA, MAIN):
    if not f.exists():
        sys.exit("Run this from the repo root (the folder that contains backend/). Missing: %s" % f)

orig_data = DATA.read_text(encoding="utf-8")
orig_main = MAIN.read_text(encoding="utf-8")
data, main = orig_data, orig_main
done, warn = [], []

# 1) permit_data.py: append the correction layer
if MARK not in data:
    data = data.rstrip("\n") + "\n" + BLOCK
    done.append("added the NOC correction layer to backend/permit_data.py")
else:
    done.append("permit_data.py already has the correction layer (left as is)")

# 2) main.py: normalize the AI instructions right before they are sent
if "normalize_noc_prompt" not in main:
    m = re.search(r"^from permit_data import", main, re.M)
    imp = "from permit_data import normalize_noc_prompt  # NOC threshold correction\n"
    if m:
        main = main[:m.start()] + imp + main[m.start():]
    else:
        k = main.find("def analyze_folder_with_claude(")
        if k < 0:
            sys.exit("Could not find a place to import from permit_data in main.py. Send me backend/main.py.")
        main = main[:k] + imp + "\n\n" + main[k:]
    main, n1 = re.subn(r"analyze_with_gemini\(\s*prompt\b", "analyze_with_gemini(normalize_noc_prompt(prompt)", main)
    main, n2 = re.subn(r'"content":\s*prompt\s*\}', '"content": normalize_noc_prompt(prompt)}', main)
    done.append("main.py: AI instructions normalized before sending (Gemini calls: %d, Claude calls: %d)" % (n1, n2))
    if n2 == 0:
        warn.append("Did not find the Claude call (messages content). Send me backend/main.py.")
else:
    done.append("main.py already normalizes the AI instructions (left as is)")

# 3) both files must still compile
for name, text in (("permit_data.py", data), ("main.py", main)):
    try:
        ast.parse(text)
    except SyntaxError as e:
        sys.exit("Refusing to write: %s would not be valid Python (%s). Nothing was changed." % (name, e))

if data == orig_data and main == orig_main:
    print("Nothing to do. " + "; ".join(done))
    sys.exit(0)

DATA.write_text(data, encoding="utf-8")
MAIN.write_text(main, encoding="utf-8")

# 4) self test: import the data, confirm nothing stale is left, confirm the helper works
TEST = r'''
import re, sys
sys.path.insert(0, "backend")
import permit_data as p
fig = re.compile(r"[$]\s?(?:2,?500|7,?500)(?!\d)")
noc = re.compile(r"notice of commencement|\bNOC\b", re.I)
def walk(o):
    if isinstance(o, dict):
        for v in o.values():
            yield v
            yield from walk(v)
    elif isinstance(o, (list, tuple)):
        for v in o:
            yield v
            yield from walk(v)
bad = 0
for n in dir(p):
    if n.startswith("_"):
        continue
    obj = getattr(p, n)
    if isinstance(obj, (dict, list, tuple)):
        for v in walk(obj):
            if isinstance(v, str) and noc.search(v) and fig.search(v):
                bad += 1
assert bad == 0, "%d stale NOC strings still present" % bad
t = p.normalize_noc_prompt("DAVIE NOC REQUIREMENTS:\n- NOC threshold: General $2,500, HVAC $7,500")
assert "$2,500" not in t and "$5,000" in t, t
r = p.get_permit_requirements("miami", "roofing")
assert r and r.get("items"), "get_permit_requirements returned nothing"
print("self test passed")
'''
res = subprocess.run([sys.executable, "-c", TEST], capture_output=True, text=True)
if res.returncode != 0:
    DATA.write_text(orig_data, encoding="utf-8")
    MAIN.write_text(orig_main, encoding="utf-8")
    print("SELF TEST FAILED. Your original files were restored.\n")
    print(res.stdout[-800:], res.stderr[-1200:])
    sys.exit(1)

print("Patched. " + res.stdout.strip())
for d in done:
    print("  +", d)
for w in warn:
    print("  !", w)
print("\nNext: git add . ; git commit -m \"Correct NOC thresholds to Fla. Stat. 713.135\" ; git push")
