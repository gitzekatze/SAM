#!/usr/bin/env python3
"""Summarizes a D-Bus log written by SAM's proxy (SAM_DBUS_LOG=FILE when
starting an app): how many calls the app made, which calls never got an
answer (candidates for an app that waits and feels slow), and which calls
the proxy blocked, by service.

    scripts/dbus-log-summary.py FILE
"""
import collections
import re
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
calls = {m.group(1): m.group(2) for m in re.finditer(r"^(C\d+): -> (.*)$", text, re.M)}
answered = set(re.findall(r"from (C\d+)", text))
# AddMatch and RemoveMatch are sent without waiting for an answer (the
# "no reply expected" flag), so a missing answer there is not a wait.
NO_WAIT = (".AddMatch ", ".RemoveMatch ")
unanswered = [(c, d) for c, d in calls.items() if c not in answered and " call " in d and not any(w in d + " " for w in NO_WAIT)]
blocked = collections.Counter()
lines = text.splitlines()
for i, line in enumerate(lines):
    if "*HIDDEN*" in line or line.startswith("Filtering message"):
        prev = next((lines[j] for j in range(i - 1, max(i - 3, -1), -1) if re.match(r"^C\d+: ->", lines[j])), "")
        m = re.match(r"^C\d+: -> (\S+) call (\S+)", prev)
        if m:
            blocked[f"{m.group(1)} {m.group(2)}"] += 1
print(f"The app made {len(calls)} calls; {len(unanswered)} got no answer.")
for _, d in unanswered[:20]:
    print(f"  no answer: {d[:160]}")
print(f"The proxy blocked {sum(blocked.values())} calls:")
for k, n in blocked.most_common(20):
    print(f"  {n:4} × {k}")
