#!/usr/bin/env python3
"""fwpanel - tiny web panel for iptables port forwards (DNAT). Python stdlib only.

Rules live in /etc/fwpanel/rules.json and are applied through three dedicated
chains (FWPANEL_PRE / FWPANEL_POST / FWPANEL_FWD), so nothing else in iptables
is ever touched. A watchdog re-applies them if another tool pushes the jumps
out of first position or flushes the chains.

Usage:
  fwpanel.py init [--port N] [--force]   create config, print a random password
  fwpanel.py serve                       run the panel (systemd does this)
  fwpanel.py passwd                      set a new panel password
  fwpanel.py tls on|off                  serve over HTTPS (default) or plain HTTP
  fwpanel.py setkey HEX                  set the key this panel accepts sync from
  fwpanel.py admin METHOD PATH [JSON|-]  call the running panel API locally (no password), e.g. admin GET /api/state
  fwpanel.py allow list|clear            show / clear the panel IP allow-list (lock-out recovery)
  fwpanel.py flush                       remove all fwpanel iptables rules
"""
import argparse
import base64
import getpass
import glob
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import ssl
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

VERSION = "1.6.0"
CONF_DIR = os.environ.get("FWPANEL_DIR", "/etc/fwpanel")
DRY = os.environ.get("FWPANEL_DRY") == "1"
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
CONF_FILE = os.path.join(CONF_DIR, "config.json")
RULES_FILE = os.path.join(CONF_DIR, "rules.json")
TRAFFIC_FILE = os.path.join(CONF_DIR, "traffic.json")
ADMIN_TOKEN_FILE = os.path.join(CONF_DIR, "admin.token")
CERT_FILE = os.path.join(CONF_DIR, "cert.pem")
KEY_FILE = os.path.join(CONF_DIR, "key.pem")

PRE, POST, FWD, MSS = "FWPANEL_PRE", "FWPANEL_POST", "FWPANEL_FWD", "FWPANEL_MSS"
JUMPS = [("nat", "PREROUTING", PRE), ("nat", "POSTROUTING", POST), ("filter", "FORWARD", FWD), ("mangle", "FORWARD", MSS)]
PBKDF_ITERS = 200_000
SESSION_TTL = 12 * 3600
MAX_BODY = 256 * 1024

LOCK = threading.RLock()
SESSIONS = {}   # token -> expiry
FAILS = {}      # ip -> [count, window_start, blocked_until]
CONFIG = {}
RULES = []


def ensure_admin_token():
    """Root-only token that lets the local CLI (`fwpanel.py admin ...`) talk to the running panel on 127.0.0.1."""
    try:
        with open(ADMIN_TOKEN_FILE) as f:
            tok = f.read().strip()
        if tok:
            return tok
    except OSError:
        pass
    tok = secrets.token_hex(24)
    os.makedirs(CONF_DIR, exist_ok=True)
    with open(ADMIN_TOKEN_FILE, "w") as f:
        f.write(tok)
    try:
        os.chmod(ADMIN_TOKEN_FILE, 0o600)
    except OSError:
        pass
    return tok


def admin_token_ok(token, client_ip):
    if not token or client_ip not in ("127.0.0.1", "::1"):
        return False
    try:
        with open(ADMIN_TOKEN_FILE) as f:
            return hmac.compare_digest(token, f.read().strip())
    except OSError:
        return False


def log(msg):
    print(msg, flush=True)


# ---------------------------------------------------------------- iptables --

def run(cmd, inp=None):
    """Run a command; returns (returncode, stdout, stderr). Dry mode only logs."""
    if DRY:
        log("[dry] " + " ".join(cmd) + (("\n" + inp) if inp else ""))
        return 0, "", ""
    p = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=30)
    return p.returncode, p.stdout, p.stderr


def ipt(*args, check=True):
    rc, out, err = run(["iptables", "-w", "5", *args])
    if check and rc != 0:
        raise RuntimeError((err or out).strip() or "iptables failed: " + " ".join(args))
    return rc, out


def build_restore(rules):
    nat = ["*nat", f":{PRE} - [0:0]", f":{POST} - [0:0]"]
    flt = ["*filter", f":{FWD} - [0:0]"]
    acct = []
    allow = []
    for r in rules:
        if not r["enabled"]:
            continue
        for p in (["tcp", "udp"] if r["proto"] == "both" else [r["proto"]]):
            # byte counters per direction (no target = count and continue)
            ct = f'-m conntrack --ctstate DNAT --ctorigdstport {r["listen_port"]}'
            if r["listen_ip"]:
                ct += f' --ctorigdst {r["listen_ip"]}'
            acct.append(f'-A {FWD} -p {p} {ct} --ctdir ORIGINAL -m comment --comment "fwp-{r["id"]}-{p}-up"')
            acct.append(f'-A {FWD} -p {p} {ct} --ctdir REPLY -m comment --comment "fwp-{r["id"]}-{p}-down"')
            d = f"-d {r['listen_ip']}/32 " if r["listen_ip"] else ""
            cm = f'-m comment --comment "fwp-{r["id"]}-{p}"'
            nat.append(f'-A {PRE} {d}-p {p} -m {p} --dport {r["listen_port"]} {cm} '
                       f'-j DNAT --to-destination {r["dest_ip"]}:{r["dest_port"]}')
            if r["masq"]:
                nat.append(f'-A {POST} -d {r["dest_ip"]}/32 -p {p} -m {p} '
                           f'--dport {r["dest_port"]} {cm} -j MASQUERADE')
            allow.append(f'-A {FWD} -d {r["dest_ip"]}/32 -p {p} -m {p} '
                         f'--dport {r["dest_port"]} {cm} -j ACCEPT')
    flt += acct
    flt.append(f"-A {FWD} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
    flt += allow
    nat.append("COMMIT")
    flt.append("COMMIT")
    # TCP MSS clamp on every fwpanel tunnel, so big packets never get black-holed inside the tunnel
    mng = ["*mangle", f":{MSS} - [0:0]"]
    for tname in tunnel_names():
        for d in ("-o", "-i"):
            mng.append(f"-A {MSS} {d} {tname} -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
    mng.append("COMMIT")
    return "\n".join(nat + flt + mng) + "\n"


def jump_first(table, parent, chain):
    _, out = ipt("-t", table, "-S", parent, check=False)
    lines = [l for l in out.splitlines() if l.startswith("-A ")]
    return bool(lines) and lines[0].split() == ["-A", parent, "-j", chain]


def chain_exists(table, chain):
    rc, _ = ipt("-t", table, "-nL", chain, check=False)
    return rc == 0


def ensure_jumps():
    for table, parent, chain in JUMPS:
        if jump_first(table, parent, chain):
            continue
        for _ in range(20):
            rc, _ = ipt("-t", table, "-D", parent, "-j", chain, check=False)
            if rc != 0:
                break
        ipt("-t", table, "-I", parent, "1", "-j", chain)


def set_ip_forward():
    if DRY:
        return
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        with open("/etc/sysctl.d/99-fwpanel.conf", "w") as f:
            f.write("net.ipv4.ip_forward=1\n")
    except OSError as e:
        log(f"warning: cannot enable ip_forward: {e}")


def apply_all(rules):
    set_ip_forward()
    try:
        accumulate()      # counters restart from zero after the restore, so bank them first
    except Exception as e:
        log(f"accumulate before apply failed: {e}")
    rc, _, err = run(["iptables-restore", "-w", "5", "--noflush"], inp=build_restore(rules))
    if rc != 0:
        raise RuntimeError(err.strip() or "iptables-restore failed")
    LAST_RAW["rules"] = {}
    ensure_jumps()


def flush_all():
    for table, parent, chain in JUMPS:
        for _ in range(20):
            rc, _ = ipt("-t", table, "-D", parent, "-j", chain, check=False)
            if rc != 0:
                break
        ipt("-t", table, "-F", chain, check=False)
        ipt("-t", table, "-X", chain, check=False)


def healthy():
    if DRY:
        return True
    return all(chain_exists(t, c) and jump_first(t, p, c) for t, p, c in JUMPS)


def counters():
    _, out = ipt("-t", "nat", "-L", PRE, "-v", "-n", "-x", check=False)
    res = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+\d+\s+DNAT\b.*fwp-(\d+)-(?:tcp|udp)", line)
        if m:
            res[int(m.group(2))] = res.get(int(m.group(2)), 0) + int(m.group(1))
    return res


def read_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except OSError:
        return False


# ---------------------------------------------------------------- live stats --

LIVE_INTERVAL = 2.0
LIVE_IDLE = 15.0          # sampler sleeps unless a browser polled /api/live recently
LAST_LIVE_REQ = 0.0
HIST_RX, HIST_TX = deque(maxlen=90), deque(maxlen=90)
SKIP_IF = re.compile(r"^(lo|gre0|gretap0|erspan0|ip6gre0|ip6tnl0|sit0|tunl0|ifb\d+|veth.*|docker.*|br-.*)$")


def read_netdev():
    res = {}
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, _, rest = line.partition(":")
                name = name.strip()
                v = rest.split()
                if len(v) >= 9 and not SKIP_IF.match(name):
                    res[name] = (int(v[0]), int(v[8]))
    except OSError:
        pass
    return res


def default_iface(names):
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                v = line.split()
                if len(v) > 7 and v[1] == "00000000" and v[7] == "00000000" and v[0] in names:
                    return v[0]
    except OSError:
        pass
    return "eth0" if "eth0" in names else (sorted(names)[0] if names else "")


def rule_bytes():
    _, out = ipt("-L", FWD, "-v", "-n", "-x", check=False)
    res = {}
    for line in out.splitlines():
        m = re.match(r"\s*\d+\s+(\d+)\s.*fwp-(\d+)-(?:tcp|udp)-(up|down)", line)
        if m:
            d = res.setdefault(int(m.group(2)), {"up": 0, "down": 0})
            d[m.group(3)] += int(m.group(1))
    return res


IDLE_INTERVAL = 30.0      # accounting tick while nobody watches the UI
SAVE_EVERY = 30.0
TRAFFIC = {"rules": {}, "ifaces": {}}      # persistent totals (survive restarts and reboots)
LAST_RAW = {"rules": {}, "t": 0.0}
RATES = {"ts": 0, "ifaces": {}, "rules": {}}
TRAFFIC_DIRTY = False
LAST_ACC = 0.0


def boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip()
    except OSError:
        return ""


def uptime():
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return 0.0


def accumulate():
    """Add counter deltas to the persistent totals. Returns (dt, {iface: (rx, tx)}, {rule: (up, down)})."""
    global TRAFFIC_DIRTY, LAST_ACC
    with LOCK:
        now = time.time()
        dt = now - LAST_RAW["t"] if LAST_RAW["t"] else None
        bid = boot_id()
        d_if, d_rules = {}, {}
        for n, (rx, tx) in read_netdev().items():
            e = TRAFFIC["ifaces"].setdefault(n, {"rx": rx, "tx": tx, "since": int(now - uptime()),   # first sight: start from the boot totals
                                                 "raw_rx": rx, "raw_tx": tx, "boot": bid})
            if e.get("boot") == bid and rx >= e["raw_rx"] and tx >= e["raw_tx"]:
                drx, dtx = rx - e["raw_rx"], tx - e["raw_tx"]      # same boot: nothing is lost across panel restarts
            else:
                drx, dtx = rx, tx                                  # reboot / counter reset
            e["rx"] += drx
            e["tx"] += dtx
            e["raw_rx"], e["raw_tx"], e["boot"] = rx, tx, bid
            d_if[n] = (drx, dtx)
            if drx or dtx:
                TRAFFIC_DIRTY = True
        prev = LAST_RAW["rules"]
        cur = rule_bytes()
        for rid, c in cur.items():
            p = prev.get(rid, {"up": 0, "down": 0})
            du = c["up"] - p["up"] if c["up"] >= p["up"] else c["up"]
            dd = c["down"] - p["down"] if c["down"] >= p["down"] else c["down"]
            e = TRAFFIC["rules"].setdefault(str(rid), {"up": 0, "down": 0, "since": int(now)})
            e["up"] += du
            e["down"] += dd
            d_rules[rid] = (du, dd)
            if du or dd:
                TRAFFIC_DIRTY = True
        LAST_RAW["rules"], LAST_RAW["t"], LAST_ACC = cur, now, now
        return dt, d_if, d_rules


def persist_traffic(force=False):
    global TRAFFIC_DIRTY
    with LOCK:
        if TRAFFIC_DIRTY or force:
            save_json(TRAFFIC_FILE, TRAFFIC)
            TRAFFIC_DIRTY = False


def prune_traffic():
    global TRAFFIC_DIRTY
    with LOCK:
        ids = {str(r["id"]) for r in RULES}
        for k in [k for k in TRAFFIC["rules"] if k not in ids]:
            del TRAFFIC["rules"][k]
            TRAFFIC_DIRTY = True


def sampler():
    last_run, last_save = 0.0, time.time()
    while True:
        time.sleep(0.5)
        active = time.time() - LAST_LIVE_REQ < LIVE_IDLE
        if time.time() - last_run < (LIVE_INTERVAL if active else IDLE_INTERVAL):
            continue
        last_run = time.time()
        try:
            dt, d_if, d_rules = accumulate()
            if time.time() - LAST_LIVE_REQ < LIVE_IDLE and dt and dt < 10:
                ifaces = {n: {"rx": a * 8 / dt, "tx": b * 8 / dt} for n, (a, b) in d_if.items()}
                rules = {rid: {"up": u * 8 / dt, "down": d * 8 / dt} for rid, (u, d) in d_rules.items()}
                main = default_iface(list(d_if))
                if main in ifaces:
                    HIST_RX.append(round(ifaces[main]["rx"]))
                    HIST_TX.append(round(ifaces[main]["tx"]))
                RATES.update(ts=time.time(), ifaces=ifaces, rules=rules)
            if time.time() - last_save > SAVE_EVERY:
                persist_traffic()
                last_save = time.time()
        except Exception as e:
            log(f"sampler error: {e}")


def live_snapshot():
    global LAST_LIVE_REQ
    LAST_LIVE_REQ = time.time()
    if time.time() - LAST_ACC > 2:
        accumulate()
    with LOCK:
        nics = read_netdev()
        main = default_iface(list(nics))
        alias = CONFIG.get("iface_alias", {})
        ifaces = []
        for n in sorted(nics, key=lambda x: (x != main, x)):
            e, r = TRAFFIC["ifaces"].get(n, {}), RATES["ifaces"].get(n, {})
            ifaces.append({"name": n, "alias": alias.get(n, ""), "main": n == main,
                           "rx": r.get("rx", 0), "tx": r.get("tx", 0),
                           "rx_total": e.get("rx", 0), "tx_total": e.get("tx", 0), "since": e.get("since", 0)})
        rules = {}
        for ru in RULES:
            e, r = TRAFFIC["rules"].get(str(ru["id"]), {}), RATES["rules"].get(ru["id"], {})
            rules[str(ru["id"])] = {"up": r.get("up", 0), "down": r.get("down", 0),
                                    "up_total": e.get("up", 0), "down_total": e.get("down", 0), "since": e.get("since", 0)}
        return {"ts": RATES["ts"], "main": main, "ifaces": ifaces, "rules": rules,
                "hist": {"rx": list(HIST_RX), "tx": list(HIST_TX)}}


def reset_rule_traffic(rid):
    with LOCK:
        accumulate()
        TRAFFIC["rules"][str(rid)] = {"up": 0, "down": 0, "since": int(time.time())}
        persist_traffic(force=True)


def reset_iface_traffic(name):
    with LOCK:
        accumulate()
        e = TRAFFIC["ifaces"].get(name)
        if e:
            e["rx"] = e["tx"] = 0
            e["since"] = int(time.time())
        persist_traffic(force=True)


# ------------------------------------------------------------------ storage --

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def hash_pw(password, salt=None, iters=PBKDF_ITERS):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iters).hex()
    return {"pw_salt": salt, "pw_hash": h, "pw_iters": iters}


def check_pw(password):
    try:
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(CONFIG["pw_salt"]),
                                int(CONFIG.get("pw_iters", PBKDF_ITERS))).hex()
    except Exception:
        return False
    return hmac.compare_digest(h, CONFIG.get("pw_hash", ""))


# --------------------------------------------------------------- validation --

def to_port(v, name):
    try:
        n = int(str(v).strip())
    except ValueError:
        raise ValueError(f"{name}: عدد نامعتبر")
    if not 1 <= n <= 65535:
        raise ValueError(f"{name}: باید بین 1 تا 65535 باشد")
    return n


def to_ipv4(v, name, allow_empty=False):
    v = str(v or "").strip()
    if not v and allow_empty:
        return ""
    try:
        ip = ipaddress.IPv4Address(v)
    except ValueError:
        raise ValueError(f"{name}: آی‌پی IPv4 نامعتبر")
    if ip.is_multicast or ip.is_unspecified:
        raise ValueError(f"{name}: آی‌پی مجاز نیست")
    return str(ip)


def clean_rule(d, rid):
    proto = str(d.get("proto", "tcp")).lower()
    if proto not in ("tcp", "udp", "both"):
        raise ValueError("پروتکل باید tcp یا udp یا both باشد")
    comment = re.sub(r"[\x00-\x1f]", "", str(d.get("comment", "")))[:80].strip()
    listen_port = to_port(d.get("listen_port"), "پورت ورودی")
    dest_port = to_port(d.get("dest_port") or d.get("listen_port"), "پورت مقصد")
    return {
        "id": rid,
        "enabled": bool(d.get("enabled", True)),
        "proto": proto,
        "listen_ip": to_ipv4(d.get("listen_ip"), "آی‌پی ورودی", allow_empty=True),
        "listen_port": listen_port,
        "dest_ip": to_ipv4(d.get("dest_ip"), "آی‌پی مقصد"),
        "dest_port": dest_port,
        "masq": bool(d.get("masq", True)),
        "comment": comment,
        "sync": bool(d.get("sync", True)),
        "managed": re.sub(r"[^A-Za-z0-9_-]", "", str(d.get("managed", "")))[:24],
    }


def protos(r):
    return {"tcp", "udp"} if r["proto"] == "both" else {r["proto"]}


SSH_PORTS = {22}


def detect_ssh_ports():
    """Ports sshd listens on (so a forward can never lock the admin out)."""
    ports = {22}
    try:
        out = subprocess.run(["ss", "-tlnpH"], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            cols = line.split()
            if "sshd" in line and len(cols) > 3 and cols[3].rsplit(":", 1)[-1].isdigit():
                ports.add(int(cols[3].rsplit(":", 1)[-1]))
    except Exception:
        pass
    return ports


def check_conflicts(rule, others):
    if rule["listen_port"] == CONFIG.get("port") and "tcp" in protos(rule):
        raise ValueError("این پورت مال خود پنل است")
    if rule["listen_port"] in SSH_PORTS and "tcp" in protos(rule):
        raise ValueError(f"پورت {rule['listen_port']} (SSH) برای جلوگیری از قفل شدن سرور مجاز نیست")
    if not rule["enabled"]:
        return
    for o in others:
        if not o["enabled"] or o["id"] == rule["id"]:
            continue
        if o["listen_port"] != rule["listen_port"] or not (protos(o) & protos(rule)):
            continue
        if o["listen_ip"] == rule["listen_ip"] or not o["listen_ip"] or not rule["listen_ip"]:
            raise ValueError(f"تداخل با قانون #{o['id']}: همین پورت و پروتکل قبلاً فوروارد شده")


def commit(new_rules):
    """Apply new_rules; on failure roll back to the previous set."""
    global RULES
    old = RULES
    try:
        apply_all(new_rules)
    except Exception:
        try:
            apply_all(old)
        except Exception as e2:
            log(f"rollback failed: {e2}")
        raise
    RULES = new_rules
    save_json(RULES_FILE, {"rules": RULES})
    prune_traffic()
    SYNC_EVENT.set()


# --------------------------------------------------------------------- sync --
# A panel can push its forwards to other panels ("links", e.g. the Iran servers):
# every rule here becomes  Iran:port -> <tunnel ip>:port  on the remote panel.
# Requests are authenticated with an HMAC (shared key), so plain HTTP is fine.

SYNC_EVENT = threading.Event()
SYNC_INTERVAL = 300


def sign(secret_hex, ts, body):
    return hmac.new(bytes.fromhex(secret_hex), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()


def source_name():
    return re.sub(r"[^A-Za-z0-9_-]", "", socket.gethostname())[:24] or "peer"


def rule_sig(r):
    return (r["listen_ip"], r["listen_port"], r["proto"], r["dest_ip"], r["dest_port"], r["masq"], r["enabled"])


def apply_sync(data):
    """Receiver side: replace the rules managed by `source`, keep manual rules."""
    src = re.sub(r"[^A-Za-z0-9_-]", "", str(data.get("source", "peer")))[:24] or "peer"
    items = data.get("rules")
    if not isinstance(items, list) or len(items) > 2000:
        raise ValueError("bad payload")
    with LOCK:
        base = [r for r in RULES if r.get("managed") != src]
        old_ids = {rule_sig(r): r["id"] for r in RULES if r.get("managed") == src}
        incoming, skipped = [], []
        for it in items:
            if not isinstance(it, dict):
                continue
            try:
                r = clean_rule({**it, "managed": src, "sync": False}, 0)
            except ValueError as e:
                skipped.append({"port": it.get("listen_port"), "reason": str(e)})
                continue
            # adopt identical manual rules (already pointing at the same target)
            base = [o for o in base if not (not o.get("managed") and o["listen_ip"] == r["listen_ip"]
                                            and o["listen_port"] == r["listen_port"] and o["dest_ip"] == r["dest_ip"]
                                            and o["dest_port"] == r["dest_port"] and protos(o) <= protos(r))]
            used = {x["id"] for x in base + incoming}
            rid = old_ids.get(rule_sig(r))
            r["id"] = rid if rid and rid not in used else max(used | {0}) + 1
            try:
                check_conflicts(r, base + incoming)
            except ValueError as e:
                skipped.append({"port": r["listen_port"], "reason": str(e)})
                continue
            incoming.append(r)
        new = base + incoming

        def strip(rs):
            return sorted(json.dumps({k: v for k, v in x.items() if k != "id"}, sort_keys=True) for x in rs)

        changed = strip(new) != strip(RULES)
        if changed:
            commit(new)
    return {"ok": True, "applied": len(incoming), "skipped": skipped, "changed": changed}


def link_payload(link):
    with LOCK:
        rules = [r for r in RULES if r["enabled"] and r.get("sync", True) and not r.get("managed")]
    return {"source": source_name(), "rules": [
        {"proto": r["proto"], "listen_port": r["listen_port"], "dest_ip": link["tunnel_ip"],
         "dest_port": r["listen_port"], "masq": True, "enabled": True, "comment": r["comment"]}
        for r in rules]}


def http_sync(link, payload):
    body = json.dumps(payload, ensure_ascii=False).encode()
    ts = str(int(time.time()))
    req = urllib.request.Request(
        link["url"].rstrip("/") + "/api/sync", data=body, method="POST",
        headers={"Content-Type": "application/json", "X-FWP-Time": ts, "X-FWP-Sig": sign(link["secret"], ts, body)})
    ctx = ssl._create_unverified_context() if link["url"].startswith("https") else None  # HMAC authenticates
    try:
        with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", "")
        except Exception:
            msg = ""
        raise RuntimeError(f"HTTP {e.code} {msg}".strip())
    except Exception as e:
        raise RuntimeError(str(e))


def sync_link(link_id):
    with LOCK:
        link = next((dict(l) for l in CONFIG.get("links", []) if l["id"] == link_id), None)
    if not link:
        return None
    try:
        res = http_sync(link, link_payload(link))
        msg = f"{res.get('applied', 0)} قانون همگام شد"
        if res.get("skipped"):
            msg += f" • {len(res['skipped'])} رد شد: " + "; ".join(
                f"{x.get('port')}: {x.get('reason')}" for x in res["skipped"][:3])
        st = {"ok": True, "msg": msg}
    except Exception as e:
        st = {"ok": False, "msg": str(e)[:200]}
    st["ts"] = int(time.time())
    with LOCK:
        for l in CONFIG.get("links", []):
            if l["id"] == link_id:
                l["status"] = st
        save_json(CONF_FILE, CONFIG)
    return st


def sync_worker():
    while True:
        SYNC_EVENT.wait(SYNC_INTERVAL)
        time.sleep(0.8)          # debounce bursts of edits
        SYNC_EVENT.clear()
        for l in list(CONFIG.get("links", [])):
            if l.get("enabled", True):
                try:
                    sync_link(l["id"])
                except Exception as e:
                    log(f"sync error: {e}")


def public_link(l):
    return {"id": l["id"], "name": l["name"], "url": l["url"], "tunnel_ip": l["tunnel_ip"],
            "enabled": l.get("enabled", True), "status": l.get("status"), "installer": bool(l.get("boot")), "installed": bool(l.get("installed")),
            "tunnel": (l.get("boot") or {}).get("tunnel", {}).get("name", ""),
            "tunnel_kind": (l.get("boot") or {}).get("tunnel", {}).get("kind", "gre6") if (l.get("boot") or {}).get("tunnel") else ""}


# ----------------------------------------------------------------- settings --

def ip_allowed(ip):
    nets = CONFIG.get("allow_ips") or []
    if not nets:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def detect_primary_ip():
    m = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)", run(["ip", "-4", "route", "get", "1.1.1.1"])[1])
    return m.group(1) if m else ""


def detect_ipv6():
    out = run(["ip", "-6", "-o", "addr", "show", "scope", "global"])[1]
    found = re.findall(r"inet6 ([0-9a-f:]+)/\d+", out)
    # SLAAC (EUI-64) addresses contain "ff:fe" and are often filtered by data centers: list static-looking ones first
    return sorted(set(found), key=lambda a: ("ff:fe" in a, a))


def ensure_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    ip = detect_primary_ip()
    cmd = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
           "-days", "3650", "-subj", "/CN=fwpanel", "-keyout", KEY_FILE, "-out", CERT_FILE]
    if ip:
        cmd += ["-addext", f"subjectAltName=IP:{ip}"]
    rc, _, _ = run(cmd)
    if rc == 0 and not DRY:
        os.chmod(KEY_FILE, 0o600)
    return rc == 0


def restart_self():
    """Re-exec the panel (after settings changed) once the HTTP response is out."""
    def _go():
        time.sleep(1.0)
        try:
            accumulate()
            persist_traffic(force=True)
        except Exception:
            pass
        os.execv(sys.executable, [sys.executable] + sys.argv)
    threading.Thread(target=_go, daemon=True).start()


def settings_get(client_ip):
    return {"port": CONFIG.get("port"), "tls": bool(CONFIG.get("tls", True)), "tls_ready": os.path.exists(CERT_FILE),
            "allow_ips": list(CONFIG.get("allow_ips") or []), "client_ip": client_ip, "version": VERSION,
            "hostname": socket.gethostname(), "ssh_ports": sorted(SSH_PORTS),
            "ipv4": detect_primary_ip(), "ipv6": detect_ipv6()}


def settings_set(data, client_ip):
    restart, notes = False, []
    with LOCK:
        if "port" in data:
            port = to_port(data["port"], "پورت پنل")
            if port != CONFIG.get("port"):
                if port in SSH_PORTS:
                    raise ValueError("این پورت مال SSH است")
                for r in RULES:
                    if r["enabled"] and r["listen_port"] == port and "tcp" in protos(r):
                        raise ValueError(f"این پورت برای فوروارد #{r['id']} استفاده می‌شود")
                probe = socket.socket()
                try:
                    probe.bind(("0.0.0.0", port))
                except OSError:
                    raise ValueError("این پورت روی سرور اشغال است")
                finally:
                    probe.close()
                CONFIG["port"] = port
                restart = True
        if "tls" in data:
            want = bool(data["tls"])
            if want and not ensure_cert():
                raise ValueError("ساخت گواهی ناموفق بود (openssl نصب نیست؟)")
            if want != bool(CONFIG.get("tls", True)):
                CONFIG["tls"] = want
                restart = True
        if "allow_ips" in data:
            raw = data["allow_ips"]
            items = re.split(r"[\s,]+", raw) if isinstance(raw, str) else list(raw or [])
            nets = []
            for x in [i.strip() for i in items if str(i).strip()][:50]:
                try:
                    net = ipaddress.ip_network(x, strict=False)
                except ValueError:
                    raise ValueError(f"آی‌پی یا رنج نامعتبر: {x}")
                if net.version != 4:
                    raise ValueError("فقط IPv4 پشتیبانی می‌شود")
                nets.append(str(net) if net.prefixlen < 32 else str(net.network_address))
            if nets and not any(ipaddress.ip_address(client_ip) in ipaddress.ip_network(n, strict=False) for n in nets):
                nets.append(client_ip)
                notes.append("آی‌پی فعلی خودت هم به لیست اضافه شد تا قفل نشوی")
            if nets:
                CONFIG["allow_ips"] = nets
            else:
                CONFIG.pop("allow_ips", None)
        save_json(CONF_FILE, CONFIG)
    if restart:
        restart_self()
    return {"ok": True, "restart": restart, "port": CONFIG.get("port"), "tls": bool(CONFIG.get("tls", True)), "notes": notes}


# ------------------------------------------------------------------ tunnels --
# GRE tunnels managed by fwpanel: one script + one systemd unit per tunnel (fwp-tunnel-NAME).
# The engine can test a tunnel, discover the real path MTU and set it, clamp TCP MSS, tune the kernel and repair common problems.

TUN_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,14}$")
TUN_DIR = os.environ.get("FWPANEL_TUNDIR", "/usr/local/sbin")
UNIT_DIR = os.environ.get("FWPANEL_UNITDIR", "/etc/systemd/system")
OVERHEAD = {"gre4": 24, "gre6": 44}       # outer IP header + GRE header
DEFAULT_TUN_MTU = 1440
TUNE = [   # (sysctl key, wanted value, "raise" = only ever increase numeric values)
    ("net.ipv4.ip_forward", "1", None),
    ("net.ipv4.conf.all.rp_filter", "2", None),
    ("net.ipv4.conf.default.rp_filter", "2", None),
    ("net.ipv4.tcp_mtu_probing", "1", None),
    ("net.core.default_qdisc", "fq", None),
    ("net.ipv4.tcp_congestion_control", "bbr", None),
    ("net.core.rmem_max", "67108864", "raise"),
    ("net.core.wmem_max", "67108864", "raise"),
    ("net.core.netdev_max_backlog", "16384", "raise"),
]


def tunnel_files(name, kind, local, remote, ip_cidr, mtu=DEFAULT_TUN_MTU):
    """Systemd-managed tunnel: kind 'gre6' (GRE over IPv6) or 'gre4' (GRE over IPv4)."""
    if kind == "gre4":
        add = f"ip tunnel add $IF mode gre local {local} remote {remote} ttl 255 2>/dev/null"
    else:
        add = f"ip -6 tunnel add $IF mode ip6gre local {local} remote {remote} ttl 255 encaplimit none 2>/dev/null"
    script = f"""#!/bin/bash
# managed by fwpanel
IF={name}
case "$1" in
up)
 {add}
 ip addr add {ip_cidr} dev $IF 2>/dev/null
 ip link set $IF mtu {mtu} txqueuelen 10000 up
 ;;
down) ip link del $IF 2>/dev/null ;;
esac
exit 0
"""
    unit = f"""[Unit]
Description=fwpanel {kind.upper()} tunnel {name}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={TUN_DIR}/fwp-tunnel-{name}.sh up
ExecStop={TUN_DIR}/fwp-tunnel-{name}.sh down

[Install]
WantedBy=multi-user.target
"""
    return script, unit


def parse_tunnel_script(name, txt):
    kind = "gre6" if "ip6gre" in txt else "gre4"
    m = re.search(r"local (\S+) remote (\S+) ttl", txt)
    ip = re.search(r"ip addr add (\S+) dev", txt)
    mtu = re.search(r"mtu (\d+)", txt)
    cidr = ip.group(1) if ip else ""
    peer = ""
    try:
        iface = ipaddress.ip_interface(cidr)
        hosts = [str(h) for h in iface.network.hosts() if h != iface.ip]
        peer = hosts[0] if hosts else ""
    except ValueError:
        pass
    return {"name": name, "kind": kind, "local": m.group(1) if m else "", "remote": m.group(2) if m else "",
            "ip": cidr, "peer_ip": peer, "mtu": int(mtu.group(1)) if mtu else DEFAULT_TUN_MTU}


def live_link(name, fallback_mtu):
    if DRY:
        return {"up": True, "mtu_live": fallback_mtu, "rx": 0, "tx": 0}
    rc, out, _ = run(["ip", "-j", "-s", "link", "show", name])
    try:
        j = json.loads(out)[0]
        st = j.get("stats64") or j.get("stats") or {}
        return {"up": "UP" in j.get("flags", []) and "LOWER_UP" in j.get("flags", []), "mtu_live": j.get("mtu"),
                "rx": (st.get("rx") or {}).get("bytes", 0), "tx": (st.get("tx") or {}).get("bytes", 0)}
    except (ValueError, IndexError, TypeError, KeyError):
        return {"up": False, "mtu_live": None, "rx": 0, "tx": 0}


def list_tunnels(live=True):
    res = []
    for path in sorted(glob.glob(os.path.join(TUN_DIR, "fwp-tunnel-*.sh"))):
        name = os.path.basename(path)[len("fwp-tunnel-"):-3]
        try:
            with open(path) as f:
                t = parse_tunnel_script(name, f.read())
        except OSError:
            continue
        if live:
            t.update(live_link(name, t["mtu"]))
        res.append(t)
    return res


def tunnel_names():
    return [os.path.basename(p)[len("fwp-tunnel-"):-3] for p in sorted(glob.glob(os.path.join(TUN_DIR, "fwp-tunnel-*.sh")))]


def find_tunnel(name):
    for t in list_tunnels():
        if t["name"] == name:
            return t
    raise KeyError(name)


def validate_tunnel(name, kind, local, remote, ip_cidr):
    if not TUN_NAME_RE.match(name or ""):
        raise ValueError("نام تونل: حروف کوچک انگلیسی/عدد، حداکثر ۱۵ کاراکتر")
    if kind not in ("gre4", "gre6"):
        raise ValueError("نوع تونل باید gre4 یا gre6 باشد")
    cls = ipaddress.IPv4Address if kind == "gre4" else ipaddress.IPv6Address
    try:
        loc, rem = str(cls(str(local).strip())), str(cls(str(remote).strip()))
    except ValueError:
        raise ValueError("آدرس " + ("IPv4" if kind == "gre4" else "IPv6") + " دو سر تونل نامعتبر است")
    if loc == rem:
        raise ValueError("آدرس دو سر تونل نباید یکی باشد")
    try:
        iface = ipaddress.ip_interface(ip_cidr)
        if iface.version != 4 or iface.network.prefixlen != 30:
            raise ValueError
    except ValueError:
        raise ValueError("آی‌پی تونل باید به شکل A.B.C.D/30 باشد")
    return loc, rem, str(iface)


def write_tunnel(name, kind, local, remote, ip_cidr, mtu):
    script, unit = tunnel_files(name, kind, local, remote, ip_cidr, mtu)
    if DRY and not os.environ.get("FWPANEL_TUNDIR"):
        log(f"[dry] write tunnel {name} {kind} {local} -> {remote} {ip_cidr} mtu {mtu}")
        return
    os.makedirs(TUN_DIR, exist_ok=True)
    path = os.path.join(TUN_DIR, f"fwp-tunnel-{name}.sh")
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)
    with open(os.path.join(UNIT_DIR, f"fwp-tunnel-{name}.service"), "w") as f:
        f.write(unit)


def create_tunnel_local(name, kind, local, remote, ip_cidr, mtu=DEFAULT_TUN_MTU):
    write_tunnel(name, kind, local, remote, ip_cidr, mtu)
    if DRY:
        return
    run(["systemctl", "daemon-reload"])
    rc, _, err = run(["systemctl", "enable", "--now", f"fwp-tunnel-{name}.service"])
    if rc != 0:
        raise RuntimeError(err.strip() or "systemctl enable failed")
    try:
        with LOCK:
            apply_all(RULES)      # adds the MSS clamp for the new tunnel
    except Exception as e:
        log(f"apply after tunnel create failed: {e}")


def ping_stats(out):
    loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", out or "")
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out or "")
    return (float(loss.group(1)) if loss else 100.0,
            {"min": float(rtt.group(1)), "avg": float(rtt.group(2)), "max": float(rtt.group(3)), "jitter": float(rtt.group(4))} if rtt else None)


def outer_ping(t, size, count=1):
    v = "-6" if t["kind"] == "gre6" else "-4"
    return run(["ping", v, "-c", str(count), "-W", "1", "-M", "do", "-s", str(size), "-I", t["local"], t["remote"]])[0] == 0


def find_outer_pmtu(t):
    """Largest packet the real path between the two tunnel endpoints carries (DF pings, binary search). None = no answer."""
    if DRY:
        return 1500
    hdr = 48 if t["kind"] == "gre6" else 28        # IP + ICMP headers
    hi, lo = 1500 - hdr, 1280 - hdr
    if outer_ping(t, hi):
        return 1500
    if not outer_ping(t, lo):
        return None
    while hi - lo > 1:
        mid = (hi + lo) // 2
        if outer_ping(t, mid):
            lo = mid
        else:
            hi = mid
    return lo + hdr


def tunnel_test(name):
    t = find_tunnel(name)
    res = {"name": name, "kind": t["kind"], "mtu": t.get("mtu_live") or t["mtu"], "up": t.get("up", False), "peer": t["peer_ip"], "ts": int(time.time())}
    if DRY:
        res.update(outer_ok=True, loss=0.0, rtt={"min": 0.8, "avg": 1.1, "max": 2.0, "jitter": 0.3}, status="healthy")
        return res
    v = "-6" if t["kind"] == "gre6" else "-4"
    res["outer_ok"] = run(["ping", v, "-c", "3", "-W", "1", "-I", t["local"], t["remote"]])[0] == 0
    _, out, _ = run(["ping", "-c", "10", "-i", "0.2", "-W", "1", t["peer_ip"]])
    loss, rtt = ping_stats(out)
    res.update(loss=loss, rtt=rtt)
    if not res["up"] or loss >= 100:
        res["status"] = "down"
    elif loss > 2 or (rtt and rtt["max"] > rtt["avg"] * 5 + 20):
        res["status"] = "degraded"
    else:
        res["status"] = "healthy"
    return res


def set_tunnel_mtu(t, mtu):
    run(["ip", "link", "set", t["name"], "mtu", str(mtu)])
    write_tunnel(t["name"], t["kind"], t["local"], t["remote"], t["ip"], mtu)


def tune_system():
    """Kernel settings that matter for forwarding: BBR + fq, big socket buffers, loose rp_filter, ip_forward."""
    steps = []
    if DRY:
        return [{"ok": True, "msg": "تنظیمات کرنل (در حالت dry اعمال نشد)"}]
    run(["modprobe", "tcp_bbr"])
    try:
        with open("/proc/sys/net/ipv4/tcp_available_congestion_control") as f:
            have_bbr = "bbr" in f.read().split()
    except OSError:
        have_bbr = False
    lines = []
    for key, want, mode in TUNE:
        path = "/proc/sys/" + key.replace(".", "/")
        if key.endswith("congestion_control") and not have_bbr:
            steps.append({"ok": False, "msg": "BBR در این کرنل نیست؛ همان الگوریتم فعلی می‌ماند"})
            continue
        try:
            with open(path) as f:
                cur = f.read().strip()
        except OSError:
            continue
        if mode == "raise" and cur.isdigit() and int(cur) >= int(want):
            want = cur
        if cur != want:
            try:
                with open(path, "w") as f:
                    f.write(want)
                steps.append({"ok": True, "msg": f"{key}: {cur} ← {want}"})
            except OSError as e:
                steps.append({"ok": False, "msg": f"{key}: {e}"})
                continue
        lines.append(f"{key}={want}")
    try:
        with open("/etc/sysctl.d/98-fwpanel-tune.conf", "w") as f:
            f.write("# written by fwpanel\n" + "\n".join(lines) + "\n")
    except OSError:
        pass
    if not steps:
        steps.append({"ok": True, "msg": "تنظیمات کرنل از قبل مناسب بود"})
    return steps


def tunnel_optimize(name):
    t = find_tunnel(name)
    steps = []
    before = t.get("mtu_live") or t["mtu"]
    pm = find_outer_pmtu(t)
    if pm is None:
        target = 1400
        steps.append({"ok": False, "msg": f"مسیر بین دو سر تونل به بسته‌ی بزرگ جواب نداد؛ MTU امن {target} گذاشته شد"})
    else:
        target = max(1280, pm - OVERHEAD[t["kind"]])
        steps.append({"ok": True, "msg": f"حداکثر بسته‌ی مسیر واقعی: {pm} ← MTU تونل: {target}"})
    set_tunnel_mtu(t, target)
    if not DRY and t["peer_ip"] and run(["ping", "-c", "2", "-W", "1", t["peer_ip"]])[0] == 0:
        # verify end to end with full-size packets; step down until they pass
        while target > 1280 and run(["ping", "-c", "2", "-W", "1", "-M", "do", "-s", str(target - 28), t["peer_ip"]])[0] != 0:
            target = max(1280, target - 16)
            set_tunnel_mtu(t, target)
            steps.append({"ok": False, "msg": f"بسته‌ی کامل از تونل رد نشد؛ MTU به {target} کاهش یافت"})
        steps.append({"ok": True, "msg": f"تست بسته‌ی کامل با MTU {target} از داخل تونل: موفق"})
    elif not DRY:
        steps.append({"ok": False, "msg": "سر مقابل جواب نداد؛ تست بسته‌ی کامل انجام نشد"})
    try:
        with LOCK:
            apply_all(RULES)
        steps.append({"ok": True, "msg": "کلمپ MSS برای TCP روی تونل فعال شد"})
    except Exception as e:
        steps.append({"ok": False, "msg": f"کلمپ MSS: {e}"})
    steps += tune_system()
    return {"name": name, "mtu_before": before, "mtu_after": target, "outer_pmtu": pm, "steps": steps}


def tunnel_fix(name):
    """Diagnose a tunnel and repair what can be repaired automatically."""
    t = find_tunnel(name)
    checks = []

    def add(ok, msg, fixed=False):
        checks.append({"ok": ok, "msg": msg, "fixed": fixed})

    script = os.path.join(TUN_DIR, f"fwp-tunnel-{name}.sh")
    if DRY:
        return [{"ok": True, "msg": "بررسی (حالت dry)", "fixed": False}]
    rc = run(["ip", "link", "show", name])[0]
    if rc != 0:
        run(["bash", script, "up"])
        add(run(["ip", "link", "show", name])[0] == 0, "اینترفیس تونل وجود نداشت؛ دوباره ساخته شد", True)
    else:
        add(True, "اینترفیس تونل وجود دارد")
    live = live_link(name, t["mtu"])
    if not live["up"]:
        run(["ip", "link", "set", name, "up"])
        add(live_link(name, t["mtu"])["up"], "اینترفیس پایین بود؛ بالا آمد", True)
    else:
        add(True, "اینترفیس بالاست")
    if t["ip"] and t["ip"].split("/")[0] not in run(["ip", "-o", "addr", "show", "dev", name])[1]:
        run(["ip", "addr", "add", t["ip"], "dev", name])
        add(True, f"آی‌پی {t['ip']} روی تونل نبود؛ اضافه شد", True)
    else:
        add(True, "آی‌پی تونل درست است")
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            fwd = f.read().strip()
        if fwd != "1":
            set_ip_forward()
        add(True, "ip_forward روشن است" if fwd == "1" else "ip_forward خاموش بود؛ روشن شد", fwd != "1")
    except OSError:
        pass
    for key in (f"net.ipv4.conf.{name}.rp_filter", "net.ipv4.conf.all.rp_filter"):
        path = "/proc/sys/" + key.replace(".", "/")
        try:
            with open(path) as f:
                cur = f.read().strip()
            if cur == "1":
                with open(path, "w") as f:
                    f.write("2")
                add(True, f"{key} سخت‌گیرانه بود؛ روی حالت loose (۲) رفت", True)
        except OSError:
            pass
    v = "-6" if t["kind"] == "gre6" else "-4"
    outer = run(["ping", v, "-c", "3", "-W", "1", "-I", t["local"], t["remote"]])[0] == 0
    add(outer, "سر مقابل از مسیر بیرونی جواب می‌دهد" if outer else
        "سر مقابل از مسیر بیرونی جواب نمی‌دهد: آدرس دو سر، فایروال سرور یا مسیر شبکه را بررسی کن")
    peer = run(["ping", "-c", "3", "-W", "1", t["peer_ip"]])[0] == 0 if t["peer_ip"] else False
    if peer:
        add(True, "از داخل تونل پینگ سر مقابل جواب می‌دهد")
    elif outer and t["kind"] == "gre4":
        add(False, "مسیر بیرونی سالم است ولی از داخل تونل جواب نمی‌آید: احتمالاً GRE (پروتکل ۴۷) فیلتر است؛ تونل GRE6 را امتحان کن")
    else:
        add(False, "از داخل تونل جواب نمی‌آید: مطمئن شو سر مقابل هم ساخته شده و آی‌پی‌ها درست است")
    drop = run(["iptables", "-S", "INPUT"])[1]
    if re.search(r"-j (DROP|REJECT)", drop) and re.search(r"-p (gre|47)|--protocol (gre|47)", drop):
        add(False, "یک قانون فایروال بسته‌های GRE را می‌اندازد (iptables INPUT)")
    return checks


def tunnel_restart(name):
    find_tunnel(name)
    if DRY:
        return
    rc, _, err = run(["systemctl", "restart", f"fwp-tunnel-{name}.service"])
    if rc != 0:
        script = os.path.join(TUN_DIR, f"fwp-tunnel-{name}.sh")
        run(["bash", script, "down"])
        run(["bash", script, "up"])


def tunnel_delete(name, force=False):
    find_tunnel(name)
    used = [l["name"] for l in CONFIG.get("links", []) if (l.get("boot") or {}).get("tunnel", {}).get("name") == name]
    if used and not force:
        raise ValueError("این تونل برای لینک «" + "، ".join(used) + "» ساخته شده؛ با «حذف اجباری» پاک می‌شود")
    if not DRY or os.environ.get("FWPANEL_TUNDIR"):
        run(["systemctl", "disable", "--now", f"fwp-tunnel-{name}.service"])
        for path in (os.path.join(TUN_DIR, f"fwp-tunnel-{name}.sh"), os.path.join(UNIT_DIR, f"fwp-tunnel-{name}.service")):
            try:
                os.remove(path)
            except OSError:
                pass
        run(["systemctl", "daemon-reload"])
        run(["ip", "link", "del", name])
        try:
            with LOCK:
                apply_all(RULES)
        except Exception as e:
            log(f"apply after tunnel delete failed: {e}")


# ---------------------------------------------------------------- installer --

def payload_bytes():
    """This panel's files (code, web assets, scripts) as a flat tar.gz - the layout install.sh expects.

    Works both from a repo checkout (src/ + scripts/) and from an installed copy (/opt/fwpanel, everything flat).
    """
    base = os.path.dirname(os.path.abspath(__file__))
    scripts = os.path.join(os.path.dirname(base), "scripts")
    wanted = {   # name inside the archive -> places to look for it
        "fwpanel.py": [os.path.join(base, "fwpanel.py")],
        "install.sh": [os.path.join(base, "install.sh"), os.path.join(scripts, "local-install.sh")],
        "uninstall.sh": [os.path.join(base, "uninstall.sh"), os.path.join(scripts, "uninstall.sh")],
        "fwpanel.sh": [os.path.join(base, "fwpanel.sh"), os.path.join(scripts, "fwpanel.sh")],
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for arc, places in wanted.items():
            src = next((x for x in places if os.path.exists(x)), None)
            if src:
                t.add(src, arcname=arc)
        t.add(WEB_DIR, arcname="web")
    return buf.getvalue()


def payload_b64():
    return base64.encodebytes(payload_bytes()).decode()


def build_installer(args, callback="", optimize=""):
    """Self-extracting installer (works as a file, from `curl | bash` and from `bash <(curl ...)`): the panel's own files
    sit in a here-document, so the script never needs to re-read itself. It deletes itself when run from a file."""
    head = (
        "#!/usr/bin/env bash\n"
        f"# fwpanel {VERSION} - self-extracting installer\n"
        "set -uo pipefail\n"
        f"ARGS=({' '.join(shlex.quote(str(a)) for a in args)})\n"
        f"FWP_CB={shlex.quote(callback)}\n"
        f"FWP_OPT={shlex.quote(optimize)}\n"
        '[ "$(id -u)" = 0 ] || { echo "run as root (sudo -i first)" >&2; exit 1; }\n'
        'TMP="$(mktemp -d)"; trap \'rm -rf "$TMP"\' EXIT\n'
        "base64 -d <<'__FWPANEL_PAYLOAD__' | tar -xz -C \"$TMP\" || { echo \"corrupt installer\" >&2; exit 1; }\n"
    )
    tail = (
        "__FWPANEL_PAYLOAD__\n"
        'RC=0; bash "$TMP/install.sh" "${ARGS[@]}" "$@" || RC=$?\n'
        'if [ $RC -eq 0 ] && [ -n "$FWP_OPT" ]; then\n'
        '  echo "optimizing the tunnel (MTU, MSS, kernel)..."\n'
        '  python3 /opt/fwpanel/fwpanel.py admin POST "/api/tunnels/$FWP_OPT/optimize" >/dev/null 2>&1 || true\n'
        "fi\n"
        'if [ -n "$FWP_CB" ]; then\n'
        '  curl -fsSk -m 20 -X POST -H "Content-Type: application/json" -d "{\\\"ok\\\": $([ $RC -eq 0 ] && echo true || echo false)}" "$FWP_CB" >/dev/null 2>&1 || true\n'
        "fi\n"
        'case "$0" in /dev/*|bash|-bash|sh) ;; *) [ -f "$0" ] && rm -f "$0" 2>/dev/null ;; esac\n'
        "exit $RC\n"
    )
    return (head + payload_b64() + tail).encode()


def installer_tunnel_name(link):
    return ((link.get("boot") or {}).get("tunnel") or {}).get("name", "")


def installer_args(link):
    b = link["boot"]
    a = ["--port", str(b["port"]), "--https" if b.get("scheme") == "https" else "--http", "--sync-key", link["secret"]]
    t = b.get("tunnel")
    if t:
        kind = t.get("kind", "gre6")
        a += ["--tunnel", t["name"], "--kind", kind, "--local", t.get("iran_ep") or t["iran_v6"],
              "--remote", t.get("foreign_ep") or t["foreign_v6"], "--ip", t["iran_ip"] + "/30"]
    return a


# ------------------------------------------------------------ iran install jobs --
# "Add Iran server" without touching the Iran server by hand: this panel SSHes in (password asked once, never stored),
# installs the panel there, builds and tests the best tunnel, optimises it, links the panels and syncs the rules.

JOBS, JOBS_LOCK = {}, threading.Lock()
SSH_BIN = os.environ.get("FWPANEL_SSH_BIN", "ssh")
REMOTE_PY = os.environ.get("FWPANEL_REMOTE_PY", "/opt/fwpanel/fwpanel.py")      # these three exist only so tests can fake the remote
REMOTE_ENV = os.environ.get("FWPANEL_REMOTE_ENV", "")
REMOTE_TMP = os.environ.get("FWPANEL_REMOTE_TMP", "/root/.fwpanel-setup")
DL_TOKENS = {}                                                                  # one-time "run this on the Iran server" tokens
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$")


def new_job(kind):
    jid = secrets.token_hex(6)
    job = {"id": jid, "kind": kind, "state": "running", "steps": [], "result": None, "ts": time.time()}
    with JOBS_LOCK:
        for k in [k for k, v in JOBS.items() if time.time() - v["ts"] > 3600]:
            del JOBS[k]
        JOBS[jid] = job
    return job


def jlog(job, level, fa, en=None):
    job["steps"].append({"t": int(time.time()), "level": level, "msg": fa, "en": en or fa})


def explain_ssh_error(err):
    e = (err or "").strip()
    if "Permission denied" in e:
        return ("رمز اشتباه است، یا سرور ورود root با رمز را اجازه نمی‌دهد (PermitRootLogin / PasswordAuthentication)",
                "wrong password, or the server does not allow root login with a password")
    if "timed out" in e or "refused" in e or "No route" in e or "unreachable" in e:
        return ("اتصال برقرار نشد: IP، پورت SSH یا فایروال سرور را بررسی کن", "cannot connect: check the IP, the SSH port and the firewall")
    if "Could not resolve" in e:
        return ("آدرس سرور پیدا نشد", "host name not found")
    return (e[:200] or "اتصال SSH ناموفق بود", e[:200] or "SSH connection failed")


class SshClient:
    """ssh to the Iran server as root. The password is given to ssh through SSH_ASKPASS (never on a command line or in a file);
    right after the first login a throw-away key is installed and used for the rest of the job, then removed again."""

    def __init__(self, host, port, password="", identity="", jid="x"):
        self.host, self.port, self.password, self.jid = host, int(port), password, jid
        self.key, self.temp_key = identity or "", False
        self.dir = tempfile.mkdtemp(prefix="fwp-ssh-")
        os.chmod(self.dir, 0o700)
        self.askpass = ""
        if password and not identity:
            self.askpass = os.path.join(self.dir, "askpass.sh")
            with open(self.askpass, "w") as f:
                f.write('#!/bin/sh\nprintf "%s\\n" "$FWP_SSH_PASS"\n')
            os.chmod(self.askpass, 0o700)

    def _args(self, mode):
        a = [SSH_BIN, "-p", str(self.port), "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.dir}/known_hosts",
             "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "LogLevel=ERROR"]
        if mode == "key":
            a += ["-i", self.key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        else:
            a += ["-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no", "-o", "NumberOfPasswordPrompts=1"]
        return a + [f"root@{self.host}"]

    def run(self, cmd, stdin=None, timeout=180, mode=None):
        mode = mode or ("key" if self.key else "password")
        env = dict(os.environ)
        if mode == "password":
            env.update(SSH_ASKPASS=self.askpass, SSH_ASKPASS_REQUIRE="force", FWP_SSH_PASS=self.password)
            env.setdefault("DISPLAY", ":0")
        try:
            p = subprocess.run(self._args(mode) + [cmd], input=stdin, capture_output=True, env=env, timeout=timeout, start_new_session=True)
        except subprocess.TimeoutExpired:
            return 124, "", "timed out"
        return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")

    def bootstrap(self):
        if self.key:                                   # key file given: no password needed
            rc, _, err = self.run("true")
            if rc != 0:
                raise RuntimeError(explain_ssh_error(err)[0])
            return
        if not self.password:
            raise RuntimeError("رمز root سرور ایران لازم است")
        rc, _, err = self.run("true", mode="password")
        if rc != 0:
            raise RuntimeError(explain_ssh_error(err)[0])
        keypath = os.path.join(self.dir, "key")
        rc = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"fwpanel-temp-{self.jid}", "-f", keypath]).returncode
        if rc != 0:
            raise RuntimeError("ساخت کلید موقت SSH ناموفق بود (openssh-client نصب است؟)")
        with open(keypath + ".pub", "rb") as f:
            pub = f.read()
        rc, _, err = self.run("umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys", stdin=pub, mode="password")
        if rc != 0:
            raise RuntimeError(explain_ssh_error(err)[0])
        self.key, self.temp_key = keypath, True
        rc, _, err = self.run("true")
        if rc != 0:
            raise RuntimeError("ورود با کلید موقت ناموفق بود: " + explain_ssh_error(err)[0])

    def fingerprints(self):
        try:
            out = subprocess.run(["ssh-keygen", "-lf", f"{self.dir}/known_hosts"], capture_output=True, text=True, timeout=10).stdout
            return [l.split()[1] for l in out.splitlines() if len(l.split()) > 1][:2]
        except Exception:
            return []

    def cleanup(self):
        if self.temp_key and self.key:
            self.run(f"sed -i '/fwpanel-temp-{self.jid}/d' ~/.ssh/authorized_keys", timeout=30)
        shutil.rmtree(self.dir, ignore_errors=True)


def radmin(ssh, method, path, body=None, timeout=180):
    """Call the panel on the remote server through its local admin CLI."""
    cmd = f"{REMOTE_ENV} python3 {REMOTE_PY} admin {method} '{path}'" + (" -" if body is not None else "")
    rc, out, err = ssh.run(cmd, stdin=json.dumps(body).encode() if body is not None else None, timeout=timeout)
    if rc != 0:
        raise RuntimeError(((err or out).strip()[:300]) or "remote call failed")
    return json.loads(out or "{}")


def v6_candidates(raw):
    return sorted(set(re.findall(r"inet6 ([0-9a-f:]+)/\d+", raw or "")), key=lambda a: ("ff:fe" in a, a))


def used_inner_nets(local_tunnels, remote_tunnels):
    nets = set()
    for t in list(local_tunnels) + list(remote_tunnels):
        try:
            nets.add(ipaddress.ip_interface(t["ip"]).network)
        except (ValueError, KeyError):
            pass
    return nets


def free_inner_net(used):
    for i in range(64):
        n = ipaddress.ip_network(f"192.168.70.{i * 4}/30")
        if n not in used:
            return n
    raise RuntimeError("رنج آی‌پی داخلی تونل‌ها پر شده")


def free_tunnel_name(local_names, remote_names):
    for i in range(1, 100):
        if f"tun{i}" not in local_names and f"tun{i}" not in remote_names:
            return f"tun{i}"
    raise RuntimeError("اسم آزاد برای تونل پیدا نشد")


def pair_loss(ssh, local_peer, remote_peer):
    """Loss (%) of 5 pings through the tunnel in both directions; None when it could not be measured."""
    if DRY:
        return 0.0, 0.0
    _, out, _ = run(["ping", "-c", "5", "-i", "0.2", "-W", "1", remote_peer])
    a = ping_stats(out)[0]
    _, o2, _ = ssh.run(f"ping -c 5 -i 0.2 -W 1 {local_peer}")
    return a, ping_stats(o2)[0]


def negotiate_tunnel(job, ssh, host, mode, remote_tunnels, remote_names):
    """Try the possible tunnels in order (GRE6 over working IPv6 pairs first, then GRE4); keep the first one that really passes traffic."""
    local_v6 = detect_ipv6()
    _, raw, _ = ssh.run("ip -6 -o addr show scope global 2>/dev/null")
    remote_v6 = v6_candidates(raw)
    cands = []
    if mode in ("auto", "gre6"):
        jlog(job, "info", f"IPv6 این سرور: {len(local_v6)} آدرس • IPv6 سرور ایران: {len(remote_v6)} آدرس",
             f"IPv6 here: {len(local_v6)} addr, Iran: {len(remote_v6)} addr")
        tested = 0
        for fv in local_v6:
            for iv in remote_v6:
                if tested >= 6:
                    break
                tested += 1
                a = run(["ping", "-6", "-c", "2", "-W", "2", "-I", fv, iv])[0] == 0
                b = ssh.run(f"ping -6 -c 2 -W 2 -I {iv} {fv} >/dev/null 2>&1")[0] == 0
                if a and b:
                    cands.append(("gre6", fv, iv))
                    jlog(job, "ok", f"مسیر IPv6 سالم: {fv} ↔ {iv}", f"working IPv6 path: {fv} <-> {iv}")
    if mode in ("auto", "gre4"):
        fp = detect_primary_ip()
        try:
            public = bool(fp) and not ipaddress.ip_address(fp).is_private
            ipaddress.IPv4Address(host)
        except ValueError:
            public = False
        if public:
            cands.append(("gre4", fp, host))
        else:
            jlog(job, "warn", "GRE4 ممکن نیست (هر دو سرور باید IPv4 عمومی داشته باشند و پشت NAT نباشند)", "GRE4 not possible (needs public IPv4 on both, no NAT)")
    if not cands:
        return None
    local_t = list_tunnels(live=False)
    for kind, fep, iep in cands:
        net = free_inner_net(used_inner_nets(local_t, remote_tunnels))
        hosts = list(net.hosts())
        iran_ip, foreign_ip = str(hosts[0]), str(hosts[1])
        name = free_tunnel_name(tunnel_names(), remote_names)
        jlog(job, "info", f"ساخت تونل {kind.upper()} ({name}) و آزمایش واقعی ترافیک…", f"creating {kind.upper()} tunnel {name} and testing real traffic...")
        try:
            create_tunnel_local(name, kind, fep, iep, f"{foreign_ip}/30")
            radmin(ssh, "POST", "/api/tunnels", {"name": name, "kind": kind, "local": iep, "remote": fep, "ip": f"{iran_ip}/30"})
            time.sleep(2)
            la, lb = pair_loss(ssh, foreign_ip, iran_ip)
            if la is not None and lb is not None and la <= 20 and lb <= 20:
                jlog(job, "ok", f"تونل {kind.upper()} سالم است (افت بسته: {la:.0f}٪ / {lb:.0f}٪)", f"{kind.upper()} tunnel works (loss {la:.0f}% / {lb:.0f}%)")
                return {"name": name, "kind": kind, "foreign_ep": fep, "iran_ep": iep, "foreign_ip": foreign_ip, "iran_ip": iran_ip}
            jlog(job, "warn", f"تونل {kind.upper()} ساخته شد ولی ترافیک رد نمی‌شود" +
                 (" (احتمالاً GRE بین این دو سرور فیلتر است)" if kind == "gre4" else ""), f"{kind.upper()} tunnel built but no traffic passes")
        except Exception as e:
            jlog(job, "warn", f"ساخت تونل {kind.upper()} ناموفق: {e}", f"{kind.upper()} tunnel failed: {e}")
        try:                                                       # remove the failed attempt on both ends
            tunnel_delete(name, force=True)
        except Exception:
            pass
        try:
            radmin(ssh, "DELETE", f"/api/tunnels/{name}?force=1")
        except Exception:
            pass
    return None


def run_install_iran(job, p):
    ssh = None
    try:
        host, port, scheme = p["host"], p["ssh_port"], p["scheme"]
        secret = secrets.token_hex(32)
        ssh = SshClient(host, port, p.get("password", ""), p.get("identity", ""), job["id"])
        jlog(job, "info", f"اتصال به {host}:{port} …", f"connecting to {host}:{port} ...")
        ssh.bootstrap()
        fps = ssh.fingerprints()
        jlog(job, "ok", "اتصال برقرار شد" + (f" (اثر انگشت سرور: {fps[0]})" if fps else ""), "connected" + (f" (host key {fps[0]})" if fps else ""))
        p.pop("password", None)

        rc, out, _ = ssh.run('echo uid=$(id -u); . /etc/os-release 2>/dev/null; echo os=${ID:-?}; '
                             'for c in python3 iptables openssl curl; do command -v $c >/dev/null 2>&1 && echo have-$c=1 || echo have-$c=0; done; '
                             'test -f /etc/fwpanel/config.json && python3 -c "import json;print(\'haskey=\' + str(int(bool(json.load(open(\'/etc/fwpanel/config.json\')).get(\'sync_secret\')))))" || echo haskey=0')
        info = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        if info.get("uid") != "0":
            raise RuntimeError("روی سرور ایران باید با کاربر root وارد شوی")
        if info.get("haskey") == "1" and not p.get("replace_key"):
            raise RuntimeError("این سرور ایران از پنل دیگری قانون می‌گیرد. اگر می‌خواهی اینجا جایگزین شود، تیک «جایگزین کردن کلید قبلی» را بزن")
        missing = [c for c in ("python3", "iptables", "openssl") if info.get(f"have-{c}") != "1"]
        if missing:
            jlog(job, "info", f"نصب پیش‌نیازها: {' '.join(missing)}", f"installing prerequisites: {' '.join(missing)}")
            rc, out, err = ssh.run("DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 iptables openssl", timeout=600)
            if rc != 0:
                raise RuntimeError("نصب پیش‌نیازها روی سرور ایران ناموفق بود (دسترسی به مخزن apt؟): " + (err or out).strip()[-200:])

        jlog(job, "info", "ارسال و نصب پنل روی سرور ایران…", "uploading and installing the panel on the Iran server...")
        rc, _, err = ssh.run(f"rm -rf {REMOTE_TMP}; mkdir -p {REMOTE_TMP} && tar -xz -C {REMOTE_TMP}", stdin=payload_bytes(), timeout=300)
        if rc != 0:
            raise RuntimeError("ارسال فایل‌ها ناموفق بود: " + err.strip()[-200:])
        args = f"--port {p['panel_port']} --{scheme} --sync-key {secret}" + (" --replace-key" if p.get("replace_key") else "")
        rc, out, err = ssh.run(f"{REMOTE_ENV} bash {REMOTE_TMP}/install.sh {args} 2>&1; rc=$?; rm -rf {REMOTE_TMP}; exit $rc", timeout=900)
        if rc != 0:
            raise RuntimeError("نصب پنل ناموفق بود: " + out.strip()[-300:])
        pw = re.search(r"^PASSWORD=(\S+)", out, re.M)
        iran_password = pw.group(1) if pw else ""
        for _ in range(15):
            try:
                radmin(ssh, "GET", "/api/state", timeout=20)
                break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("پنل روی سرور ایران بالا نیامد")
        jlog(job, "ok", "پنل روی سرور ایران نصب شد", "panel installed on the Iran server")

        tun, target, url = None, "", f"{scheme}://{host}:{p['panel_port']}"
        mode = p.get("tunnel", "auto")
        if mode != "none":
            remote_tunnels = radmin(ssh, "GET", "/api/tunnels").get("tunnels", [])
            tun = negotiate_tunnel(job, ssh, host, mode, remote_tunnels, [t["name"] for t in remote_tunnels])
        if tun:
            target = tun["foreign_ip"]
            url = f"{scheme}://{tun['iran_ip']}:{p['panel_port']}"
            if p.get("optimize", True):
                jlog(job, "info", "بهینه‌سازی تونل (کشف MTU واقعی، MSS، تنظیمات کرنل) روی هر دو سرور…", "optimizing the tunnel on both servers...")
                for where, fn in (("این سرور", lambda: tunnel_optimize(tun["name"])),
                                  ("سرور ایران", lambda: radmin(ssh, "POST", f"/api/tunnels/{tun['name']}/optimize", timeout=300))):
                    try:
                        r = fn()
                        jlog(job, "ok", f"{where}: MTU {r['mtu_before']} ← {r['mtu_after']}", f"{where}: MTU {r['mtu_before']} -> {r['mtu_after']}")
                        for st in r["steps"]:
                            jlog(job, "info" if st["ok"] else "warn", "   " + st["msg"], "   " + st["msg"])
                    except Exception as e:
                        jlog(job, "warn", f"بهینه‌سازی {where} کامل نشد: {e}", f"optimize failed on {where}: {e}")
        else:
            if mode != "none":
                jlog(job, "warn", "هیچ تونلی ممکن نشد؛ فوروارد بدون تونل و مستقیم از اینترنت انجام می‌شود", "no tunnel possible: falling back to a direct connection")
            target = detect_primary_ip()
            try:
                if not target or ipaddress.ip_address(target).is_private:
                    raise ValueError
            except ValueError:
                raise RuntimeError("بدون تونل، این سرور باید IPv4 عمومی داشته باشد (پشت NAT است؟)")

        with LOCK:
            links = CONFIG.setdefault("links", [])
            link = {"id": max([l["id"] for l in links], default=0) + 1, "name": p["name"], "url": url, "tunnel_ip": target,
                    "secret": secret, "enabled": True, "installed": True,
                    "boot": {"port": p["panel_port"], "scheme": scheme, **({"tunnel": tun} if tun else {})}}
            links.append(link)
            save_json(CONF_FILE, CONFIG)
        SYNC_EVENT.set()
        st = sync_link(link["id"])
        jlog(job, "ok" if st and st["ok"] else "warn", "همگام‌سازی: " + (st["msg"] if st else "-"), "sync: " + (st["msg"] if st else "-"))
        tres = None
        if tun:
            try:
                tres = tunnel_test(tun["name"])
                jlog(job, "ok" if tres["status"] == "healthy" else "warn",
                     f"تست نهایی تونل: {tres['status']} • افت {tres['loss']:.0f}٪ • تأخیر {((tres.get('rtt') or {}).get('avg', 0)):.1f}ms • MTU {tres['mtu']}",
                     f"final tunnel test: {tres['status']}, loss {tres['loss']:.0f}%, rtt {((tres.get('rtt') or {}).get('avg', 0)):.1f}ms, MTU {tres['mtu']}")
            except Exception as e:
                jlog(job, "warn", f"تست نهایی تونل: {e}", f"final tunnel test failed: {e}")
        job["result"] = {"link_id": link["id"], "name": p["name"], "panel_url": f"{scheme}://{host}:{p['panel_port']}/", "password": iran_password,
                         "tunnel": tun, "test": tres, "sync": st}
        jlog(job, "ok", "همه‌چیز آماده است", "all done")
        job["state"] = "done"
    except Exception as e:
        jlog(job, "err", str(e))
        job["state"] = "error"
    finally:
        p.pop("password", None)
        if ssh:
            try:
                ssh.cleanup()
            except Exception:
                pass


def start_install_job(d):
    name = re.sub(r"[\x00-\x1f]", "", str(d.get("name", ""))).strip()[:30]
    host = str(d.get("host", "")).strip()
    if not name:
        raise ValueError("نام لازم است")
    if not HOST_RE.match(host):
        raise ValueError("آدرس سرور ایران نامعتبر است")
    p = {"name": name, "host": host, "ssh_port": to_port(d.get("ssh_port") or 22, "پورت SSH"), "panel_port": to_port(d.get("panel_port") or 9443, "پورت پنل ایران"),
         "scheme": "https" if d.get("scheme") == "https" else "http", "tunnel": d.get("tunnel", "auto") if d.get("tunnel", "auto") in ("auto", "gre6", "gre4", "none") else "auto",
         "optimize": bool(d.get("optimize", True)), "replace_key": bool(d.get("replace_key")),
         "password": str(d.get("password", ""))[:256], "identity": str(d.get("identity", ""))[:300]}
    if not p["password"] and not p["identity"]:
        raise ValueError("رمز root سرور ایران لازم است")
    if p["identity"] and not os.path.isfile(p["identity"]):
        raise ValueError("فایل کلید پیدا نشد")
    with LOCK:
        for l in CONFIG.get("links", []):
            if l["url"].split("//", 1)[-1].split(":")[0] == host:
                raise ValueError("این سرور قبلاً لینک شده است")
    job = new_job("install-iran")
    threading.Thread(target=run_install_iran, args=(job, p), daemon=True).start()
    return job


def finish_command_install(link_id):
    """Called when an Iran server finished the one-line install: sync, then test and optimise this end of the tunnel."""
    try:
        with LOCK:
            link = next((l for l in CONFIG.get("links", []) if l["id"] == link_id), None)
            if link:
                link["installed"] = True
                save_json(CONF_FILE, CONFIG)
        time.sleep(2)
        sync_link(link_id)
        name = installer_tunnel_name(link or {})
        if name:
            tunnel_optimize(name)
    except Exception as e:
        log(f"finish install failed: {e}")


# --------------------------------------------------------------------- http --

MIME = {".html": "text/html; charset=utf-8", ".js": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".woff": "font/woff"}
SEC_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "fwpanel"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # --- helpers
    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in {**SEC_HEADERS, **{kk: vv for kk, vv in (extra or {}).items() if kk != "Set-Cookie"}}.items():
            self.send_header(k, v)
        if extra and "Set-Cookie" in extra:
            self.send_header("Set-Cookie", extra["Set-Cookie"])
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), extra=extra)

    def _err(self, code, msg):
        self._json(code, {"error": msg})

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("درخواست خیلی بزرگ است")
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise ValueError("JSON نامعتبر")
        if not isinstance(data, dict):
            raise ValueError("JSON نامعتبر")
        return data

    def _token(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return c["fwp_sid"].value if "fwp_sid" in c else None

    def _authed(self):
        if admin_token_ok(self.headers.get("X-Admin-Token"), self.client_address[0]):
            return True
        t = self._token()
        with LOCK:
            exp = SESSIONS.get(t)
            if exp and exp > time.time():
                return True
            SESSIONS.pop(t, None)
        return False

    def _csrf_ok(self):
        if self.headers.get("X-Requested-With") != "fwpanel":
            return False
        origin = self.headers.get("Origin")
        host = self.headers.get("Host")
        if origin and host and origin.split("://", 1)[-1] != host:
            return False
        return True

    # --- routing
    def _gate(self, path):
        if path != "/api/sync" and not path.startswith("/dl/") and self.client_address[0] not in ("127.0.0.1", "::1") and not ip_allowed(self.client_address[0]):
            self._err(403, "forbidden")
            return False
        return True

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if not self._gate(path):
            return
        if path.startswith("/dl/"):
            return self._dl(path)
        if path.startswith("/api/"):
            return self._api("GET", path)
        files = {"/": "index.html", "/app.js": "app.js", "/app.css": "app.css", "/favicon.svg": "favicon.svg"}
        name = files.get(path)
        fm = re.fullmatch(r"/fonts/([A-Za-z0-9._-]+\.woff2?)", path)
        if fm:
            name = "fonts/" + fm.group(1)
        if not name:
            return self._err(404, "not found")
        try:
            with open(os.path.join(WEB_DIR, name), "rb") as f:
                body = f.read()
        except OSError:
            return self._err(404, "not found")
        extra = {"Cache-Control": "public, max-age=604800"} if name.startswith("fonts/") else None
        self._send(200, body, MIME.get(os.path.splitext(name)[1], "application/octet-stream"), extra)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if self._gate(path):
            if path.startswith("/dl/"):
                return self._dl(path)
            self._api("POST", path)

    def do_PUT(self):
        path = self.path.split("?", 1)[0]
        if self._gate(path):
            self._api("PUT", path)

    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        if self._gate(path):
            self._api("DELETE", path)

    # --- api
    def _api(self, method, path):
        try:
            if path == "/api/sync" and method == "POST":
                return self._sync_recv()
            if method != "GET" and not self._csrf_ok():
                return self._err(403, "forbidden")
            if path == "/api/login" and method == "POST":
                return self._login()
            if not self._authed():
                return self._err(401, "unauthorized")
            if path == "/api/logout" and method == "POST":
                with LOCK:
                    SESSIONS.pop(self._token(), None)
                return self._json(200, {"ok": True}, {"Set-Cookie": self._cookie("", 0)})
            if path == "/api/state" and method == "GET":
                return self._state()
            if path == "/api/live" and method == "GET":
                return self._json(200, live_snapshot())
            m = re.fullmatch(r"/api/rules/(\d+)/reset", path)
            if m and method == "POST":
                if not any(r["id"] == int(m.group(1)) for r in RULES):
                    return self._err(404, "قانون پیدا نشد")
                reset_rule_traffic(int(m.group(1)))
                return self._json(200, {"ok": True})
            m = re.fullmatch(r"/api/iface/([A-Za-z0-9_.@:-]{1,32})/(reset|alias)", path)
            if m and method in ("POST", "PUT"):
                name, what = m.group(1), m.group(2)
                if what == "reset":
                    reset_iface_traffic(name)
                else:
                    alias = re.sub(r"[\x00-\x1f<>]", "", str(self._body().get("alias", ""))).strip()[:24]
                    with LOCK:
                        al = CONFIG.setdefault("iface_alias", {})
                        if alias:
                            al[name] = alias
                        else:
                            al.pop(name, None)
                        save_json(CONF_FILE, CONFIG)
                return self._json(200, {"ok": True})
            if path == "/api/export" and method == "GET":
                with LOCK:
                    return self._json(200, {"rules": RULES})
            if path == "/api/rules" and method == "POST":
                return self._rule_save(None)
            m = re.fullmatch(r"/api/rules/(\d+)", path)
            if m and method == "PUT":
                return self._rule_save(int(m.group(1)))
            if m and method == "DELETE":
                return self._rule_delete(int(m.group(1)))
            if path == "/api/apply" and method == "POST":
                with LOCK:
                    apply_all(RULES)
                return self._json(200, {"ok": True})
            if path == "/api/tunnels" and method == "GET":
                return self._json(200, {"tunnels": list_tunnels(), "linked": {(l.get("boot") or {}).get("tunnel", {}).get("name"): l["name"] for l in CONFIG.get("links", []) if (l.get("boot") or {}).get("tunnel")}})
            if path == "/api/tunnels" and method == "POST":
                d = self._body()
                name = str(d.get("name", "")).strip()
                loc, rem, cidr = validate_tunnel(name, str(d.get("kind", "")), d.get("local"), d.get("remote"), d.get("ip"))
                if name in tunnel_names():
                    raise ValueError("تونلی با این نام وجود دارد")
                if run(["ip", "link", "show", name])[0] == 0 and not DRY:
                    raise ValueError("یک اینترفیس با این نام روی سرور هست")
                create_tunnel_local(name, d["kind"], loc, rem, cidr, int(d.get("mtu") or DEFAULT_TUN_MTU))
                return self._json(200, {"ok": True})
            m = re.fullmatch(r"/api/tunnels/([a-z][a-z0-9_-]{0,14})/(test|optimize|fix|restart)", path)
            if m and method == "POST":
                try:
                    name, what = m.group(1), m.group(2)
                    if what == "test":
                        return self._json(200, {"result": tunnel_test(name)})
                    if what == "optimize":
                        return self._json(200, tunnel_optimize(name))
                    if what == "fix":
                        return self._json(200, {"checks": tunnel_fix(name)})
                    tunnel_restart(name)
                    return self._json(200, {"ok": True})
                except KeyError:
                    return self._err(404, "تونل پیدا نشد")
            m = re.fullmatch(r"/api/tunnels/([a-z][a-z0-9_-]{0,14})", path)
            if m and method == "PUT":
                try:
                    t = find_tunnel(m.group(1))
                except KeyError:
                    return self._err(404, "تونل پیدا نشد")
                mtu = int(self._body().get("mtu", 0))
                if not 1280 <= mtu <= 1500:
                    raise ValueError("MTU باید بین ۱۲۸۰ تا ۱۵۰۰ باشد")
                set_tunnel_mtu(t, mtu)
                return self._json(200, {"ok": True, "mtu": mtu})
            if m and method == "DELETE":
                try:
                    tunnel_delete(m.group(1), force="force=1" in self.path)
                except KeyError:
                    return self._err(404, "تونل پیدا نشد")
                return self._json(200, {"ok": True})
            if path == "/api/system/tune" and method == "POST":
                return self._json(200, {"steps": tune_system()})
            if path == "/api/iran/install" and method == "POST":
                job = start_install_job(self._body())
                return self._json(200, {"job": job["id"]})
            m = re.fullmatch(r"/api/jobs/([0-9a-f]{12})", path)
            if m and method == "GET":
                job = JOBS.get(m.group(1))
                if not job:
                    return self._err(404, "کار پیدا نشد")
                return self._json(200, {k: job[k] for k in ("id", "state", "steps", "result")})
            if path == "/api/settings" and method == "GET":
                with LOCK:
                    return self._json(200, settings_get(self.client_address[0]))
            if path == "/api/settings" and method == "POST":
                return self._json(200, settings_set(self._body(), self.client_address[0]))
            if path == "/api/links/new-iran" and method == "POST":
                return self._link_new_iran()
            m = re.fullmatch(r"/api/links/(\d+)/installer", path)
            if m and method == "GET":
                return self._link_installer(int(m.group(1)))
            if path == "/api/links" and method == "GET":
                with LOCK:
                    return self._json(200, {"links": [public_link(l) for l in CONFIG.get("links", [])],
                                            "receive": bool(CONFIG.get("sync_secret"))})
            if path == "/api/links" and method == "POST":
                return self._link_save(None)
            m = re.fullmatch(r"/api/links/(\d+)", path)
            if m and method == "PUT":
                return self._link_save(int(m.group(1)))
            if m and method == "DELETE":
                return self._link_delete(int(m.group(1)))
            m = re.fullmatch(r"/api/links/(\d+)/sync", path)
            if m and method == "POST":
                st = sync_link(int(m.group(1)))
                return self._json(200, {"status": st}) if st else self._err(404, "لینک پیدا نشد")
            if path == "/api/synckey" and method == "POST":
                with LOCK:
                    CONFIG["sync_secret"] = secrets.token_hex(32)
                    save_json(CONF_FILE, CONFIG)
                    return self._json(200, {"key": CONFIG["sync_secret"]})
            if path == "/api/synckey" and method == "DELETE":
                with LOCK:
                    CONFIG.pop("sync_secret", None)
                    save_json(CONF_FILE, CONFIG)
                    if any(r.get("managed") for r in RULES):   # release them: they are now normal rules
                        commit([{**r, "managed": ""} for r in RULES])
                return self._json(200, {"ok": True})
            if path == "/api/import" and method == "POST":
                return self._import()
            if path == "/api/password" and method == "POST":
                return self._password()
            self._err(404, "not found")
        except ValueError as e:
            self._err(400, str(e))
        except Exception as e:  # iptables or I/O failure
            log(f"error: {e}")
            self._err(500, str(e))

    def _cookie(self, token, max_age):
        flags = "; HttpOnly; SameSite=Strict; Path=/"
        if getattr(self.server, "tls", False):
            flags += "; Secure"
        return f"fwp_sid={token}; Max-Age={max_age}{flags}"

    def _login(self):
        ip = self.client_address[0]
        now = time.time()
        with LOCK:
            f = FAILS.get(ip)
            if f and f[2] > now:
                return self._err(429, "تلاش بیش از حد. چند دقیقه بعد دوباره امتحان کن")
        data = self._body()
        if check_pw(str(data.get("password", ""))):
            token = secrets.token_urlsafe(32)
            with LOCK:
                FAILS.pop(ip, None)
                SESSIONS[token] = now + SESSION_TTL
                for t in [t for t, e in SESSIONS.items() if e < now]:
                    del SESSIONS[t]
            return self._json(200, {"ok": True}, {"Set-Cookie": self._cookie(token, SESSION_TTL)})
        with LOCK:
            f = FAILS.get(ip)
            if not f or now - f[1] > 600:
                f = [0, now, 0]
            f[0] += 1
            if f[0] >= 8:
                f[2] = now + 600
            FAILS[ip] = f
        time.sleep(0.8)
        self._err(401, "رمز عبور اشتباه است")

    def _state(self):
        with LOCK:
            rules = [dict(r) for r in RULES]
        cnt = counters()
        for r in rules:
            r["pkts"] = cnt.get(r["id"], 0)
        self._json(200, {"rules": rules, "status": {
            "ip_forward": read_ip_forward() or DRY,
            "chains_ok": healthy(),
            "panel_port": CONFIG.get("port"),
            "links": len(CONFIG.get("links", [])),
            "sync_receive": bool(CONFIG.get("sync_secret")),
            "version": VERSION,
        }})

    def _rule_save(self, rid):
        data = self._body()
        with LOCK:
            if rid is not None and not any(r["id"] == rid for r in RULES):
                return self._err(404, "قانون پیدا نشد")
            new_id = rid if rid is not None else max([r["id"] for r in RULES], default=0) + 1
            if rid is not None:   # partial update (e.g. toggle) keeps other fields
                cur = next(r for r in RULES if r["id"] == rid)
                if cur.get("managed") and CONFIG.get("sync_secret"):
                    return self._err(400, f"این قانون خودکار است (از پنل «{cur['managed']}»). از همان پنل تغییرش بده، "
                                          "یا در تنظیمات «دریافت همگام‌سازی» را غیرفعال کن")
                data = {**cur, **data}
            data["managed"] = ""
            rule = clean_rule(data, new_id)
            check_conflicts(rule, RULES)
            new = [rule if r["id"] == new_id else r for r in RULES]
            if rid is None:
                new.append(rule)
            commit(new)
        self._json(200, {"rule": rule})

    def _rule_delete(self, rid):
        with LOCK:
            cur = next((r for r in RULES if r["id"] == rid), None)
            if not cur:
                return self._err(404, "قانون پیدا نشد")
            if cur.get("managed") and CONFIG.get("sync_secret"):
                return self._err(400, f"این قانون خودکار است (از پنل «{cur['managed']}»). از همان پنل حذفش کن، "
                                      "یا در تنظیمات «دریافت همگام‌سازی» را غیرفعال کن")
            commit([r for r in RULES if r["id"] != rid])
        self._json(200, {"ok": True})

    def _sync_recv(self):
        ip = self.client_address[0]
        now = time.time()
        secret = CONFIG.get("sync_secret")
        if not secret:
            return self._err(403, "sync disabled")
        key = "sync:" + ip
        with LOCK:
            f = FAILS.get(key)
            if f and f[2] > now:
                return self._err(429, "too many attempts")
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return self._err(413, "too large")
        raw = self.rfile.read(n)
        ts, sig = self.headers.get("X-FWP-Time", ""), self.headers.get("X-FWP-Sig", "")
        if not (ts.isdigit() and abs(now - int(ts)) <= 120 and hmac.compare_digest(sign(secret, ts, raw), sig)):
            with LOCK:
                f = FAILS.get(key)
                if not f or now - f[1] > 600:
                    f = [0, now, 0]
                f[0] += 1
                if f[0] >= 10:
                    f[2] = now + 600
                FAILS[key] = f
            return self._err(401, "bad signature")
        try:
            data = json.loads(raw or b"{}")
            if not isinstance(data, dict):
                raise ValueError("bad payload")
            self._json(200, apply_sync(data))
        except ValueError as e:
            self._err(400, str(e))

    def _dl(self, path):
        """One-time install command for an Iran server:  curl .../dl/TOKEN | bash   (no SSH, nothing stored on the Iran disk)."""
        now = time.time()
        for k in [k for k, v in DL_TOKENS.items() if v["exp"] < now]:
            del DL_TOKENS[k]
        m = re.fullmatch(r"/dl/([A-Za-z0-9_-]{20,64})(/done)?", path)
        tok = DL_TOKENS.get(m.group(1)) if m else None
        if not m or not tok:
            return self._err(404, "این آدرس منقضی شده یا قبلاً استفاده شده است")
        with LOCK:
            link = next((dict(l) for l in CONFIG.get("links", []) if l["id"] == tok["link_id"]), None)
        if not link:
            DL_TOKENS.pop(m.group(1), None)
            return self._err(404, "لینک پیدا نشد")
        if m.group(2):                                       # the Iran server reports back: verify from this side, then forget the token
            DL_TOKENS.pop(m.group(1), None)
            threading.Thread(target=finish_command_install, args=(link["id"],), daemon=True).start()
            return self._json(200, {"ok": True})
        tok["gets"] += 1
        if tok["gets"] > 5:
            DL_TOKENS.pop(m.group(1), None)
            return self._err(404, "این آدرس منقضی شده است")
        scheme = "https" if getattr(self.server, "tls", False) else "http"
        cb = f"{scheme}://{self.headers.get('Host') or ('127.0.0.1:%s' % CONFIG.get('port'))}/dl/{m.group(1)}/done"
        body = build_installer(installer_args(link), callback=cb, optimize=installer_tunnel_name(link))
        self._send(200, body, "text/x-shellscript; charset=utf-8", {"Content-Disposition": "inline"})

    def _link_new_iran(self):
        d = self._body()
        name = re.sub(r"[\x00-\x1f]", "", str(d.get("name", ""))).strip()[:30]
        if not name:
            raise ValueError("نام لازم است")
        port = to_port(d.get("port") or 9443, "پورت پنل ایران")
        scheme = "https" if d.get("scheme") == "https" else "http"
        tun = d.get("tunnel") if isinstance(d.get("tunnel"), dict) and d["tunnel"].get("enabled") else None
        boot = {"port": port, "scheme": scheme}
        warnings = []
        if tun:
            tname = str(tun.get("name", "")).strip().lower()
            if not TUN_NAME_RE.match(tname):
                raise ValueError("نام تونل: حروف کوچک انگلیسی/عدد، حداکثر ۱۵ کاراکتر")
            kind = "gre4" if str(tun.get("kind", "gre6")).lower() == "gre4" else "gre6"
            cls = ipaddress.IPv4Address if kind == "gre4" else ipaddress.IPv6Address
            try:
                f_ep = str(cls(str(tun.get("foreign_ep") or tun.get("foreign_v6", "")).strip()))
                i_ep = str(cls(str(tun.get("iran_ep") or tun.get("iran_v6", "")).strip()))
            except ValueError:
                raise ValueError("آدرس " + ("IPv4" if kind == "gre4" else "IPv6") + " دو سر تونل نامعتبر است")
            if f_ep == i_ep:
                raise ValueError("آدرس دو سر تونل نباید یکی باشد")
            f4, i4 = to_ipv4(tun.get("foreign_ip"), "آی‌پی تونل سمت خارج"), to_ipv4(tun.get("iran_ip"), "آی‌پی تونل سمت ایران")
            if f4 == i4 or ipaddress.ip_address(i4) not in ipaddress.ip_network(f4 + "/30", strict=False):
                raise ValueError("دو آی‌پی تونل باید متفاوت و داخل یک رنج /30 باشند (مثل 10.20.0.1 و 10.20.0.2)")
            boot["tunnel"] = {"name": tname, "kind": kind, "foreign_ep": f_ep, "iran_ep": i_ep, "foreign_ip": f4, "iran_ip": i4}
            target, url = f4, f"{scheme}://{i4}:{port}"
        else:
            iran_ip = to_ipv4(d.get("iran_ip"), "آی‌پی عمومی سرور ایران")
            target = to_ipv4(d.get("target_ip") or detect_primary_ip(), "آی‌پی مقصد (همین سرور)")
            url = f"{scheme}://{iran_ip}:{port}"
        with LOCK:
            links = CONFIG.setdefault("links", [])
            link = {"id": max([l["id"] for l in links], default=0) + 1, "name": name, "url": url, "tunnel_ip": target,
                    "secret": secrets.token_hex(32), "enabled": True, "boot": boot}
            if tun:
                try:
                    t = boot["tunnel"]
                    create_tunnel_local(t["name"], t["kind"], t["foreign_ep"], t["iran_ep"], t["foreign_ip"] + "/30")
                except Exception as e:
                    raise ValueError(f"ساخت تونل روی این سرور ناموفق بود: {e}")
            links.append(link)
            save_json(CONF_FILE, CONFIG)
            pub = public_link(link)
        SYNC_EVENT.set()
        token = secrets.token_urlsafe(24)
        DL_TOKENS[token] = {"link_id": link["id"], "exp": time.time() + 1800, "gets": 0}
        self._json(200, {"link": pub, "warnings": warnings, "token": token, "expires": int(time.time() + 1800)})

    def _link_installer(self, lid):
        with LOCK:
            link = next((dict(l) for l in CONFIG.get("links", []) if l["id"] == lid), None)
        if not link or not link.get("boot"):
            return self._err(404, "برای این لینک اسکریپت نصب وجود ندارد")
        fname = "install-" + (re.sub(r"[^A-Za-z0-9_-]", "", link["name"]) or "iran") + ".sh"
        self._send(200, build_installer(installer_args(link)), "text/x-shellscript; charset=utf-8",
                   {"Content-Disposition": f'attachment; filename="{fname}"'})

    def _link_save(self, lid):
        data = self._body()
        name = re.sub(r"[\x00-\x1f]", "", str(data.get("name", ""))).strip()[:30]
        url = str(data.get("url", "")).strip().rstrip("/")
        if not name:
            raise ValueError("نام لازم است")
        if not re.fullmatch(r"https?://[A-Za-z0-9.\-\[\]:]+", url):
            raise ValueError("آدرس پنل نامعتبر است (مثال: http://1.2.3.4:9443)")
        tip = to_ipv4(data.get("tunnel_ip"), "آی‌پی تونل")
        secret = str(data.get("secret", "")).strip()
        with LOCK:
            links = CONFIG.setdefault("links", [])
            cur = next((l for l in links if l["id"] == lid), None) if lid else None
            if lid and not cur:
                return self._err(404, "لینک پیدا نشد")
            if (secret or not cur) and not re.fullmatch(r"[0-9a-fA-F]{64}", secret):
                raise ValueError("کلید همگام‌سازی نامعتبر است")
            link = cur or {"id": max([l["id"] for l in links], default=0) + 1}
            link.update(name=name, url=url, tunnel_ip=tip, enabled=bool(data.get("enabled", True)))
            if secret:
                link["secret"] = secret.lower()
            if not cur:
                links.append(link)
            save_json(CONF_FILE, CONFIG)
            pub = public_link(link)
        SYNC_EVENT.set()
        self._json(200, {"link": pub})

    def _link_delete(self, lid):
        with LOCK:
            link = next((dict(l) for l in CONFIG.get("links", []) if l["id"] == lid), None)
        if not link:
            return self._err(404, "لینک پیدا نشد")
        warn = ""
        try:   # tell the remote panel to drop the rules this panel manages
            http_sync(link, {"source": source_name(), "rules": []})
        except Exception as e:
            warn = f"قوانین خودکار روی سرور مقصد پاک نشد: {e}"
        with LOCK:
            CONFIG["links"] = [l for l in CONFIG.get("links", []) if l["id"] != lid]
            save_json(CONF_FILE, CONFIG)
        self._json(200, {"ok": True, "warning": warn})

    def _import(self):
        data = self._body()
        items = data.get("rules")
        if not isinstance(items, list) or len(items) > 2000:
            raise ValueError("فایل پشتیبان نامعتبر است")
        new = []
        for i, it in enumerate(items, 1):
            if not isinstance(it, dict):
                raise ValueError("فایل پشتیبان نامعتبر است")
            rule = clean_rule(it, i)
            check_conflicts(rule, new)
            new.append(rule)
        with LOCK:
            commit(new)
        self._json(200, {"ok": True, "count": len(new)})

    def _password(self):
        data = self._body()
        new = str(data.get("new", ""))
        if not check_pw(str(data.get("old", ""))):
            raise ValueError("رمز فعلی اشتباه است")
        if len(new) < 8:
            raise ValueError("رمز جدید حداقل ۸ کاراکتر باشد")
        with LOCK:
            CONFIG.update(hash_pw(new))
            save_json(CONF_FILE, CONFIG)
            SESSIONS.clear()
        self._json(200, {"ok": True}, {"Set-Cookie": self._cookie("", 0)})


# --------------------------------------------------------------------- main --

def watchdog():
    while True:
        time.sleep(30)
        try:
            with LOCK:
                if not healthy():
                    log("rules missing or out of order, re-applying")
                    apply_all(RULES)
        except Exception as e:
            log(f"watchdog error: {e}")


def load_state():
    global CONFIG, RULES
    CONFIG = load_json(CONF_FILE, {})
    RULES = load_json(RULES_FILE, {"rules": []}).get("rules", [])
    t = load_json(TRAFFIC_FILE, {})
    TRAFFIC["rules"], TRAFFIC["ifaces"] = t.get("rules", {}), t.get("ifaces", {})


def cmd_init(args):
    cfg = load_json(CONF_FILE, {})
    ensure_admin_token()
    if cfg.get("pw_hash") and not args.force:
        if args.port:
            cfg["port"] = args.port
            save_json(CONF_FILE, cfg)
        print("config exists, password unchanged")
        return
    pw = "".join(secrets.choice("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(16))
    cfg = {"port": args.port or cfg.get("port") or 9443, **hash_pw(pw)}
    save_json(CONF_FILE, cfg)
    print(f"PORT={cfg['port']}")
    print(f"PASSWORD={pw}")


def cmd_passwd(args):
    cfg = load_json(CONF_FILE, {})
    pw = sys.stdin.readline().strip() if args.stdin else getpass.getpass("New password: ")
    if len(pw) < 8:
        sys.exit("password must be at least 8 characters")
    cfg.update(hash_pw(pw))
    save_json(CONF_FILE, cfg)
    print("password updated (restart the service to drop old sessions)")


def cmd_serve(_args):
    load_state()
    ensure_admin_token()
    SSH_PORTS.update(detect_ssh_ports())
    if not CONFIG.get("pw_hash"):
        sys.exit("no password set - run: fwpanel.py init")
    port = int(CONFIG.get("port") or os.environ.get("FWPANEL_PORT") or 9443)   # config wins so a port change survives a restart
    CONFIG["port"] = port
    try:
        apply_all(RULES)
        log(f"applied {len([r for r in RULES if r['enabled']])} rule(s)")
    except Exception as e:
        log(f"initial apply failed: {e}")
    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=sampler, daemon=True).start()
    threading.Thread(target=sync_worker, daemon=True).start()
    SYNC_EVENT.set()
    bind = os.environ.get("FWPANEL_BIND", "0.0.0.0")
    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.daemon_threads = True
    srv.tls = bool(CONFIG.get("tls", True)) and os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
    if srv.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    def _term(*_):
        try:
            accumulate()
            persist_traffic(force=True)
        finally:
            os._exit(0)
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    log(f"fwpanel {VERSION} listening on {'https' if srv.tls else 'http'}://{bind}:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


def cmd_tls(args):
    cfg = load_json(CONF_FILE, {})
    cfg["tls"] = args.mode == "on"
    save_json(CONF_FILE, cfg)
    print(f"tls {'enabled' if cfg['tls'] else 'disabled (plain HTTP)'} - restart the service to apply")


def cmd_admin(args):
    """Call the running panel's API from the server itself (no password): admin METHOD PATH [JSON | -]"""
    try:
        with open(ADMIN_TOKEN_FILE) as f:
            tok = f.read().strip()
    except OSError:
        sys.exit("no admin token - is fwpanel installed here? (run as root)")
    cfg = load_json(CONF_FILE, {})
    port = cfg.get("port") or 9443
    scheme = "https" if cfg.get("tls", True) and os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) else "http"   # same rule as serve
    body = sys.stdin.buffer.read() if args.body == "-" else (args.body.encode() if args.body else None)
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{port}{args.path}", data=body, method=args.method.upper(),
                                 headers={"X-Admin-Token": tok, "X-Requested-With": "fwpanel", "Content-Type": "application/json"})
    ctx = ssl._create_unverified_context() if scheme == "https" else None
    try:
        with urllib.request.urlopen(req, timeout=90, context=ctx) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        sys.stderr.write(e.read().decode(errors="replace") + "\n")
        sys.exit(1)
    except Exception as e:
        sys.exit(f"cannot reach the panel on 127.0.0.1:{port}: {e}")
    sys.stdout.buffer.write(data)


def api_local(method, path, body=None):
    """Call the running panel from this server (root-only admin token)."""
    try:
        with open(ADMIN_TOKEN_FILE) as f:
            tok = f.read().strip()
    except OSError:
        sys.exit("no admin token - is fwpanel installed here? (run as root)")
    cfg = load_json(CONF_FILE, {})
    scheme = "https" if cfg.get("tls", True) and os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) else "http"
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{cfg.get('port') or 9443}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"X-Admin-Token": tok, "X-Requested-With": "fwpanel", "Content-Type": "application/json"})
    ctx = ssl._create_unverified_context() if scheme == "https" else None
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", "")
        except Exception:
            msg = ""
        sys.exit(msg or f"HTTP {e.code}")
    except Exception as e:
        sys.exit(f"cannot reach the panel: {e}")


def watch_job(jid):
    colors = {"ok": "\033[32m", "warn": "\033[33m", "err": "\033[31m", "info": "\033[36m"}
    marks = {"ok": "+", "warn": "!", "err": "x", "info": ">"}
    seen = 0
    while True:
        j = api_local("GET", f"/api/jobs/{jid}")
        for st in j["steps"][seen:]:
            print(f"  {colors.get(st['level'], '')}{marks.get(st['level'], '>')} {st['en']}\033[0m", flush=True)
        seen = len(j["steps"])
        if j["state"] != "running":
            return j
        time.sleep(1)


def cmd_add_iran(args):
    """Interactive: set up an Iran server from here (installs the panel there, builds + optimises the tunnel, links and syncs)."""
    ask = lambda q, d="": (input(f"  {q}" + (f" [{d}]" if d else "") + ": ").strip() or d)
    print("\n  Add an Iran server\n  ------------------")
    host = args.host or ask("Iran server IP or host")
    port = args.ssh_port or ask("SSH port", "22")
    name = args.name or ask("Name for this server", "Iran-1")
    pw = os.environ.get(args.password_env, "") if args.password_env else ""
    if not pw and not args.identity:
        pw = getpass.getpass("  root password of the Iran server (typed here, never stored): ")
    body = {"name": name, "host": host, "ssh_port": port, "password": pw, "identity": args.identity or "", "tunnel": args.tunnel,
            "panel_port": args.panel_port, "scheme": args.scheme, "optimize": not args.no_optimize, "replace_key": args.replace_key}
    print()
    jid = api_local("POST", "/api/iran/install", body)["job"]
    j = watch_job(jid)
    r = j.get("result") or {}
    print()
    if j["state"] == "done":
        t = (r.get("test") or {})
        print("  ============================================================")
        print(f"   Iran server '{r['name']}' is ready")
        print("  ============================================================")
        print(f"   panel     : {r['panel_url']}")
        print(f"   password  : {r.get('password') or '(unchanged, panel already existed)'}")
        if r.get("tunnel"):
            print(f"   tunnel    : {r['tunnel']['name']} ({r['tunnel']['kind'].upper()})  {r['tunnel']['iran_ip']} <-> {r['tunnel']['foreign_ip']}")
            if t:
                print(f"   health    : {t['status']}, loss {t['loss']:.0f}%, rtt {((t.get('rtt') or {}).get('avg', 0)):.1f} ms, MTU {t['mtu']}")
        else:
            print("   tunnel    : none (direct over the internet)")
        print("   Create forwards in THIS panel: they appear on the Iran server automatically.")
        return 0
    print("  Failed. Nothing is left half-configured except what the log above shows.")
    return 1


def cmd_job_watch(args):
    return 0 if watch_job(args.id)["state"] == "done" else 1


def cmd_setkey(args):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.key):
        sys.exit("sync key must be 64 hex characters")
    cfg = load_json(CONF_FILE, {})
    cfg["sync_secret"] = args.key.lower()
    save_json(CONF_FILE, cfg)
    print("sync key set")


def cmd_allow(args):
    cfg = load_json(CONF_FILE, {})
    if args.action == "clear":
        cfg.pop("allow_ips", None)
        save_json(CONF_FILE, cfg)
        print("IP allow-list cleared (restart not needed)")
    else:
        print("\n".join(cfg.get("allow_ips", [])) or "(empty: everyone may open the panel)")


def cmd_flush(_args):
    flush_all()
    print("fwpanel rules removed")


def main():
    ap = argparse.ArgumentParser(description="iptables port-forward web panel")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("init")
    p.add_argument("--port", type=int)
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("passwd")
    p.add_argument("--stdin", action="store_true")
    p.set_defaults(fn=cmd_passwd)
    sub.add_parser("serve").set_defaults(fn=cmd_serve)
    p = sub.add_parser("tls")
    p.add_argument("mode", choices=["on", "off"])
    p.set_defaults(fn=cmd_tls)
    p = sub.add_parser("admin")
    p.add_argument("method")
    p.add_argument("path")
    p.add_argument("body", nargs="?")
    p.set_defaults(fn=cmd_admin)
    p = sub.add_parser("add-iran")
    p.add_argument("--host")
    p.add_argument("--ssh-port", type=int)
    p.add_argument("--name")
    p.add_argument("--password-env", help="read the root password from this environment variable instead of asking")
    p.add_argument("--identity", help="path of an SSH private key on this server (instead of a password)")
    p.add_argument("--tunnel", default="auto", choices=["auto", "gre6", "gre4", "none"])
    p.add_argument("--panel-port", type=int, default=9443)
    p.add_argument("--scheme", default="http", choices=["http", "https"])
    p.add_argument("--no-optimize", action="store_true")
    p.add_argument("--replace-key", action="store_true")
    p.set_defaults(fn=cmd_add_iran)
    p = sub.add_parser("job-watch")
    p.add_argument("id")
    p.set_defaults(fn=cmd_job_watch)
    p = sub.add_parser("setkey")
    p.add_argument("key")
    p.set_defaults(fn=cmd_setkey)
    p = sub.add_parser("allow")
    p.add_argument("action", choices=["list", "clear"])
    p.set_defaults(fn=cmd_allow)
    sub.add_parser("flush").set_defaults(fn=cmd_flush)
    args = ap.parse_args()
    sys.exit((args.fn if getattr(args, "fn", None) else cmd_serve)(args) or 0)


if __name__ == "__main__":
    main()
