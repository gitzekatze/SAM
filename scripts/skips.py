#!/usr/bin/env python3
"""Says which tests did not run, from the skip log `make test` collects
($SAM_SKIP_LOG, one line per skipped test: "test: reason").

    python3 scripts/skips.py target/test-skips.log
"""
import pathlib
import sys
from collections import Counter

path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("target/test-skips.log")
lines = [l for l in path.read_text().splitlines() if l.strip()] if path.exists() else []
if not lines:
    print("Every test ran.")
    sys.exit(0)
print(f"{len(lines)} tests did not run here (they pass without checking anything):")
for line, n in sorted(Counter(lines).items()):
    print(f"  {line}" + (f"  ({n}×)" if n > 1 else ""))
print("CI runs them with SAM_REQUIRE_SANDBOX=1, where a test that cannot run fails.")
