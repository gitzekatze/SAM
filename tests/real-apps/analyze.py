import json, glob, os, sys
R = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(os.path.abspath(__file__))
def load(p):
    try:
        d = json.load(open(p))
        return d.get("data", d) if isinstance(d, dict) else d
    except Exception as e:
        return {"_error": open(p).read()[-400:] if os.path.exists(p) else "missing"}
for txt in sorted(glob.glob(f"{R}/results/*.txt")):
    if txt.endswith(".add.txt") or txt.endswith("session.txt"): continue
    base = txt[:-4]; name = os.path.basename(base)
    info = load(base + ".info2.json"); e = info.get("entry", {}) if isinstance(info, dict) else {}
    p = e.get("profile", {}).get("permissions", {})
    det = e.get("detection") or {}
    st = load(base + ".selftest.json"); res = (st.get("results") or [{}])[0] if isinstance(st, dict) else {}
    ver = load(base + ".verify.json"); rec = ver.get("record", {}) if isinstance(ver, dict) else {}
    hints = load(base + ".hints.json"); rep = load(base + ".repair.json")
    print(f"=== {name}")
    if not e:
        print("  ADD FAILED:", open(base + ".add.txt").read()[-500:] if os.path.exists(base + ".add.txt") else "?"); continue
    print(f"  category={e.get('category')} toolkit={det.get('requirements',{}).get('toolkit')} compat={det.get('compatibility')} verdict={det.get('verdict')} missing={len(det.get('missing',[]))}")
    print(f"  net={p.get('network',{}).get('mode')} wl={p.get('display',{}).get('wayland')} x11={p.get('display',{}).get('x11')} gpu={p.get('devices',{}).get('gpu')} audio={p.get('audio',{}).get('enabled')} dbus={p.get('dbus',{}).get('session',{}).get('mode')} nested={p.get('advanced',{}).get('allow_userns')} args={e.get('profile',{}).get('args')}")
    fs = p.get('filesystem', {}); print("  files:", {k: fs.get(k) for k in ('documents','downloads','pictures','music','videos','desktop') if fs.get(k) not in (None,'none')})
    print(f"  check: passed={rec.get('passed')} failed={rec.get('failed')} {ver.get('_error','') if isinstance(ver,dict) else ''}")
    print(f"  test start: {res.get('status')} - {res.get('detail')}  findings={[f.get('title') for f in res.get('findings',[])]}")
    if isinstance(hints, list): print("  hints:", [h.get('title') for h in hints])
    elif isinstance(hints, dict): print("  hints:", [h.get('title') for h in hints.get('hints', hints.get('items', []))] if '_error' not in hints else hints['_error'][-200:])
    if isinstance(rep, dict): print("  repair:", [s.get('title') for s in rep.get('steps', rep.get('repair_steps', []))][:6], "findings:", [f.get('title') for f in rep.get('findings', [])][:4])
    ll = e.get('last_launch') or {}
    print(f"  last start: {ll.get('summary')}")
