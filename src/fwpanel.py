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
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

VERSION = "1.4.0"
CONF_DIR = os.environ.get("FWPANEL_DIR", "/etc/fwpanel")
DRY = os.environ.get("FWPANEL_DRY") == "1"
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
CONF_FILE = os.path.join(CONF_DIR, "config.json")
RULES_FILE = os.path.join(CONF_DIR, "rules.json")
TRAFFIC_FILE = os.path.join(CONF_DIR, "traffic.json")
ADMIN_TOKEN_FILE = os.path.join(CONF_DIR, "admin.token")
CERT_FILE = os.path.join(CONF_DIR, "cert.pem")
KEY_FILE = os.path.join(CONF_DIR, "key.pem")

PRE, POST, FWD = "FWPANEL_PRE", "FWPANEL_POST", "FWPANEL_FWD"
JUMPS = [("nat", "PREROUTING", PRE), ("nat", "POSTROUTING", POST), ("filter", "FORWARD", FWD)]
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
    return "\n".join(nat + flt) + "\n"


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
            "enabled": l.get("enabled", True), "status": l.get("status"), "installer": bool(l.get("boot")),
            "tunnel": (l.get("boot") or {}).get("tunnel", {}).get("name", "")}


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

TUN_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,14}$")


def tunnel_files(name, local6, remote6, ip_cidr):
    script = f"""#!/bin/bash
# managed by fwpanel
IF={name}
case "$1" in
up)
 ip -6 tunnel add $IF mode ip6gre local {local6} remote {remote6} ttl 255 encaplimit none 2>/dev/null
 ip addr add {ip_cidr} dev $IF 2>/dev/null
 ip link set $IF mtu 1440 txqueuelen 10000 up
 ;;
down) ip link del $IF 2>/dev/null ;;
esac
exit 0
"""
    unit = f"""[Unit]
Description=fwpanel GRE6 tunnel {name}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fwp-tunnel-{name}.sh up
ExecStop=/usr/local/sbin/fwp-tunnel-{name}.sh down

[Install]
WantedBy=multi-user.target
"""
    return script, unit


def create_tunnel_local(name, local6, remote6, ip_cidr):
    script, unit = tunnel_files(name, local6, remote6, ip_cidr)
    if DRY:
        log(f"[dry] create tunnel {name} {local6} -> {remote6} {ip_cidr}")
        return
    with open(f"/usr/local/sbin/fwp-tunnel-{name}.sh", "w") as f:
        f.write(script)
    os.chmod(f"/usr/local/sbin/fwp-tunnel-{name}.sh", 0o755)
    with open(f"/etc/systemd/system/fwp-tunnel-{name}.service", "w") as f:
        f.write(unit)
    run(["systemctl", "daemon-reload"])
    rc, _, err = run(["systemctl", "enable", "--now", f"fwp-tunnel-{name}.service"])
    if rc != 0:
        raise RuntimeError(err.strip() or "systemctl enable failed")


def ping6_ok(local6, remote6):
    if DRY:
        return True
    return run(["ping", "-6", "-c", "2", "-W", "2", "-I", local6, remote6])[0] == 0


# ---------------------------------------------------------------- installer --

def payload_b64():
    """This panel's files (code, web assets, scripts) as a flat base64 tar.gz - the layout install.sh expects.

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
    return base64.encodebytes(buf.getvalue()).decode()


def build_installer(args):
    """Self-extracting installer: this panel's own files + the install.sh arguments."""
    payload = payload_b64()
    head = (
        "#!/usr/bin/env bash\n"
        f"# fwpanel {VERSION} - self-extracting installer\n"
        "set -euo pipefail\n"
        f"ARGS=({' '.join(shlex.quote(str(a)) for a in args)})\n"
        '[ "$(id -u)" = 0 ] || { echo "run as root (sudo bash $0)" >&2; exit 1; }\n'
        'TMP="$(mktemp -d)"; trap \'rm -rf "$TMP"\' EXIT\n'
        'awk \'/^__PAYLOAD__$/ {p=1; next} p\' "$0" | base64 -d | tar -xz -C "$TMP"\n'
        'bash "$TMP/install.sh" "${ARGS[@]}" "$@"\n'
        "exit 0\n"
        "__PAYLOAD__\n"
    )
    return (head + payload).encode()


def installer_args(link):
    b = link["boot"]
    a = ["--port", str(b["port"]), "--https" if b.get("scheme") == "https" else "--http", "--sync-key", link["secret"]]
    t = b.get("tunnel")
    if t:
        a += ["--tunnel", t["name"], "--local6", t["iran_v6"], "--remote6", t["foreign_v6"], "--ip", t["iran_ip"] + "/30"]
    return a


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
        if path != "/api/sync" and self.client_address[0] not in ("127.0.0.1", "::1") and not ip_allowed(self.client_address[0]):
            self._err(403, "forbidden")
            return False
        return True

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if not self._gate(path):
            return
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
            try:
                f6, i6 = str(ipaddress.IPv6Address(str(tun.get("foreign_v6", "")).strip())), str(ipaddress.IPv6Address(str(tun.get("iran_v6", "")).strip()))
            except ValueError:
                raise ValueError("آدرس IPv6 نامعتبر است")
            f4, i4 = to_ipv4(tun.get("foreign_ip"), "آی‌پی تونل سمت خارج"), to_ipv4(tun.get("iran_ip"), "آی‌پی تونل سمت ایران")
            if f4 == i4 or ipaddress.ip_address(i4) not in ipaddress.ip_network(f4 + "/30", strict=False):
                raise ValueError("دو آی‌پی تونل باید متفاوت و داخل یک رنج /30 باشند (مثل 10.20.0.1 و 10.20.0.2)")
            boot["tunnel"] = {"name": tname, "foreign_v6": f6, "iran_v6": i6, "foreign_ip": f4, "iran_ip": i4}
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
                    create_tunnel_local(t["name"], t["foreign_v6"], t["iran_v6"], t["foreign_ip"] + "/30")
                except Exception as e:
                    raise ValueError(f"ساخت تونل روی این سرور ناموفق بود: {e}")
            links.append(link)
            save_json(CONF_FILE, CONFIG)
            pub = public_link(link)
        SYNC_EVENT.set()
        self._json(200, {"link": pub, "warnings": warnings})

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
    p = sub.add_parser("setkey")
    p.add_argument("key")
    p.set_defaults(fn=cmd_setkey)
    p = sub.add_parser("allow")
    p.add_argument("action", choices=["list", "clear"])
    p.set_defaults(fn=cmd_allow)
    sub.add_parser("flush").set_defaults(fn=cmd_flush)
    args = ap.parse_args()
    (args.fn if getattr(args, "fn", None) else cmd_serve)(args)


if __name__ == "__main__":
    main()
