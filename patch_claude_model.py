#!/usr/bin/env python3
"""Move backend/main.py off the retired claude-sonnet-4-20250514 model.

Run from the repo root:
    python patch_claude_model.py

What it changes (in your live file, nothing else):
  1. Adds   CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-5")
     so the next model change is a Railway variable, not a code change.
  2. The messages.create call uses CLAUDE_MODEL, turns thinking off (same behavior as before),
     allows 8192 output tokens (the new tokenizer produces about 30% more tokens), and
     reads the reply by block type instead of content[0].text.
  3. The usage log records the real model name.
  4. The cost estimate uses the current price: $2 per million input tokens, $10 per million output.

It refuses to write the file unless the result is valid Python.
"""
import ast
import pathlib
import re
import sys

PATH = pathlib.Path("backend/main.py")
OLD = "claude-sonnet-4-20250514"
NEW_DEFAULT = "claude-sonnet-5"

if not PATH.exists():
    sys.exit("Run this from the repo root (the folder that contains backend/main.py).")

src = PATH.read_text(encoding="utf-8")
orig = src
done, warn = [], []

if OLD not in src and "CLAUDE_MODEL" in src:
    sys.exit("Already patched. Nothing to do.")

# 1) model constant, placed above the function that makes the Claude call
if "CLAUDE_MODEL" not in src:
    marker = "def analyze_folder_with_claude("
    if marker not in src:
        sys.exit("Could not find analyze_folder_with_claude(). Send me backend/main.py and I will patch it directly.")
    src = src.replace(
        marker,
        '# Claude model used for premium analyses. Override with the CLAUDE_MODEL variable in Railway.\n'
        'CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "%s")\n\n\n%s' % (NEW_DEFAULT, marker),
        1,
    )
    done.append("added CLAUDE_MODEL constant (default %s)" % NEW_DEFAULT)

# 2) the API call + how the reply is read
call_re = re.compile(
    r'^(?P<i>[ \t]*)msg = client\.messages\.create\(\s*'
    r'model="%s",\s*max_tokens=4096,\s*'
    r'messages=\[\{"role": "user", "content": prompt\}\],\s*\)\s*\n'
    r'[ \t]*resp = msg\.content\[0\]\.text' % re.escape(OLD),
    re.M,
)
m = call_re.search(src)
if m:
    i = m.group("i")
    new_call = (
        f'{i}msg = client.messages.create(\n'
        f'{i}    model=CLAUDE_MODEL,\n'
        f'{i}    max_tokens=8192,\n'
        f'{i}    # Claude Sonnet 5 thinks by default; this keeps the old no-thinking behavior\n'
        f'{i}    extra_body={{"thinking": {{"type": "disabled"}}}},\n'
        f'{i}    messages=[{{"role": "user", "content": prompt}}],\n'
        f'{i})\n'
        f'{i}# Read text blocks by type (a response can start with a non-text block)\n'
        f'{i}resp = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")\n'
        f'{i}if not resp.strip():\n'
        f'{i}    raise ValueError(f"Claude returned no text (stop_reason={{msg.stop_reason}})")'
    )
    src = src[:m.start()] + new_call + src[m.end():]
    done.append("updated the messages.create call (model, 8192 tokens, thinking off, safe reply parsing)")
else:
    warn.append("Could not find the messages.create call in the expected shape. Send me backend/main.py.")

# 3) usage log + any remaining references to the old model string
n = src.count('model="%s"' % OLD)
if n:
    src = src.replace('model="%s"' % OLD, "model=CLAUDE_MODEL")
    done.append("usage log now records the real model (%d place%s)" % (n, "" if n == 1 else "s"))

# 4) cost estimate: $2 / $10 per million tokens
cost = "input_tokens * 3 + output_tokens * 15"
if cost in src:
    src = src.replace(cost, "input_tokens * 2 + output_tokens * 10")
    done.append("cost estimate uses $2 / $10 per million tokens")
src = src.replace("# Claude Sonnet 4 pricing: $3/1M input, $15/1M output", "# Claude Sonnet 5 pricing: $2/1M input, $10/1M output")

left = src.count(OLD)
if left:
    warn.append("%d reference(s) to %s are still in the file" % (left, OLD))
other_reads = len(re.findall(r"\.content\[0\]\.text", src))
if other_reads:
    warn.append("%d other place(s) still read content[0].text. Fine for calls without thinking, but tell me if any call the Claude API." % other_reads)

try:
    ast.parse(src)
except SyntaxError as e:
    sys.exit("Refusing to write: the patched file would not be valid Python (%s). Nothing was changed." % e)

if src == orig:
    sys.exit("Nothing changed. " + " ".join(warn))
PATH.write_text(src, encoding="utf-8")

print("Patched backend/main.py")
for d in done:
    print("  +", d)
for w in warn:
    print("  !", w)
print("\nNext: git add . ; git commit -m \"Move to Claude Sonnet 5\" ; git push")
