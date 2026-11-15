import frida, time, datetime, importlib.util
spec=importlib.util.spec_from_file_location('dc','decode_capture.py'); dc=importlib.util.module_from_spec(spec); spec.loader.exec_module(dc)
OUT = "otm_bodies.log"
dev=frida.get_usb_device(timeout=10); js=open("otm_bodies.js",encoding="utf-8").read()
logf=open(OUT,"w",encoding="utf-8"); attached={}
def w(s): logf.write(s+"\n"); logf.flush(); print(s,flush=True)
def mk(pid):
  def on(m,d):
    if m.get("type")=="error": w(f"[err {pid}] {m.get('description')}"); return
    p=m.get("payload")
    if not p: return
    t=p.get("t")
    if t=="info": w(f"[info {pid}] {p.get('msg')}"); return
    if t=="OWNERPSK": w(f"\n*** OWNERPSK pid={pid} device={p.get('deviceuuid')} owner={p.get('owneruuid')} psk={p.get('psk')} ***"); return
    if t=="REQ": w(f"[REQ pid={pid}] {p.get('method')} {p.get('uri')}"); return
    if d is not None:
      ts=datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
      try: obj,_=dc.cbor(d); dec=repr(obj)
      except Exception as e: dec=f"<cbor err {e}> "+d.hex()[:80]
      w(f"\n[{t}] {ts} pid={pid} size={p.get('size')}\n   {dec}")
  return on
def attach(pid,name):
  try:
    s=dev.attach(pid); sc=s.create_script(js); sc.on("message",mk(pid)); sc.load(); attached[pid]=s; w(f"[attached] {pid} {name}")
  except Exception as e: w(f"[attach-fail] {pid}: {e}")
w(f"# OTM bodies capture {datetime.datetime.now()}")
while True:
  for p in dev.enumerate_processes():
    if "oneconnect" in p.name and p.pid not in attached: attach(p.pid,p.name)
  time.sleep(1.5)
