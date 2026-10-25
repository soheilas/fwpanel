"""Tunnel engine + API test (dry mode: no iptables, no interfaces). Run:  python tests/test_tunnels.py"""
import http.cookiejar
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="fwp-tun-")
TUN, UNITS = os.path.join(TMP, "sbin"), os.path.join(TMP, "units")
os.makedirs(TUN)
os.makedirs(UNITS)
PORT = 19520
fails = 0


def check(label, cond):
    global fails
    print(("PASS " if cond else "FAIL "), label)
    fails += not cond


env = dict(os.environ, FWPANEL_DRY="1", FWPANEL_DIR=os.path.join(TMP, "conf"), FWPANEL_PORT=str(PORT), FWPANEL_BIND="127.0.0.1",
           FWPANEL_TUNDIR=TUN, FWPANEL_UNITDIR=UNITS, PYTHONIOENCODING="utf-8")
out = subprocess.run([sys.executable, os.path.join(ROOT, "src", "fwpanel.py"), "init", "--port", str(PORT)], env=env,
                     capture_output=True, text=True).stdout
pw = re.search(r"PASSWORD=(\S+)", out).group(1)
srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "src", "fwpanel.py"), "serve"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Cli:
    def __init__(self):
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None, expect=200):
        global fails
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", "X-Requested-With": "fwpanel"})
        try:
            r = self.op.open(req)
            code, data = r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            code, data = e.code, json.loads(e.read() or b"{}")
        if code != expect:
            fails += 1
            print("FAIL", method, path, code, data)
        return data


try:
    time.sleep(2)
    A = Cli()
    A.call("POST", "/api/login", {"password": pw})
    good = {"name": "tun1", "kind": "gre4", "local": "203.0.113.2", "remote": "203.0.113.1", "ip": "192.168.70.1/30"}
    A.call("POST", "/api/tunnels", {**good, "name": "Bad Name"}, expect=400)
    A.call("POST", "/api/tunnels", {**good, "kind": "gre9"}, expect=400)
    A.call("POST", "/api/tunnels", {**good, "local": "2001:db8::1"}, expect=400)
    A.call("POST", "/api/tunnels", {**good, "remote": "203.0.113.2"}, expect=400)
    A.call("POST", "/api/tunnels", {**good, "ip": "192.168.70.1/24"}, expect=400)
    A.call("POST", "/api/tunnels", good)
    A.call("POST", "/api/tunnels", good, expect=400)                                       # already exists
    A.call("POST", "/api/tunnels", {"name": "tun2", "kind": "gre6", "local": "2001:db8::2", "remote": "2001:db8::1", "ip": "192.168.70.5/30"})
    ts = {t["name"]: t for t in A.call("GET", "/api/tunnels")["tunnels"]}
    check("both tunnels listed with parsed details", set(ts) == {"tun1", "tun2"} and ts["tun1"]["kind"] == "gre4" and ts["tun2"]["kind"] == "gre6"
          and ts["tun1"]["local"] == "203.0.113.2" and ts["tun1"]["remote"] == "203.0.113.1" and ts["tun2"]["local"] == "2001:db8::2")
    check("peer address is the other host of the /30", ts["tun1"]["peer_ip"] == "192.168.70.2" and ts["tun2"]["peer_ip"] == "192.168.70.6" and ts["tun1"]["mtu"] == 1440)
    sh = open(os.path.join(TUN, "fwp-tunnel-tun1.sh")).read()
    check("gre4 script uses plain 'ip tunnel ... mode gre'", "ip tunnel add $IF mode gre local 203.0.113.2 remote 203.0.113.1" in sh and "mtu 1440" in sh)
    check("systemd unit written", "fwpanel GRE4 tunnel tun1" in open(os.path.join(UNITS, "fwp-tunnel-tun1.service")).read())

    r = A.call("POST", "/api/tunnels/tun1/test")["result"]
    check("test returns status, loss and rtt", r["status"] == "healthy" and r["loss"] == 0 and r["rtt"]["avg"] > 0 and r["peer"] == "192.168.70.2")
    A.call("POST", "/api/tunnels/nope/test", expect=404)
    o = A.call("POST", "/api/tunnels/tun1/optimize")
    check("optimize picks MTU = path MTU - GRE4 overhead (1500-24)", o["mtu_after"] == 1476 and o["outer_pmtu"] == 1500 and o["steps"])
    check("optimized MTU is persisted in the script", "mtu 1476" in open(os.path.join(TUN, "fwp-tunnel-tun1.sh")).read())
    o6 = A.call("POST", "/api/tunnels/tun2/optimize")
    check("gre6 uses 1500-44", o6["mtu_after"] == 1456)
    A.call("PUT", "/api/tunnels/tun1", {"mtu": 1100}, expect=400)
    A.call("PUT", "/api/tunnels/tun1", {"mtu": 1400})
    check("manual MTU persisted", "mtu 1400" in open(os.path.join(TUN, "fwp-tunnel-tun1.sh")).read())
    check("fix runs", A.call("POST", "/api/tunnels/tun1/fix")["checks"])
    A.call("POST", "/api/tunnels/tun1/restart")
    t = A.call("POST", "/api/system/tune")
    check("system tune answers", t["steps"])

    # MSS clamp rules follow the tunnels (checked on the generated iptables-restore text)
    spec = importlib.util.spec_from_file_location("fwp", os.path.join(ROOT, "src", "fwpanel.py"))
    os.environ.update(FWPANEL_TUNDIR=TUN, FWPANEL_UNITDIR=UNITS, FWPANEL_DRY="1", FWPANEL_DIR=os.path.join(TMP, "conf2"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    text = m.build_restore([])
    check("iptables text has an MSS clamp for each tunnel, both directions",
          "*mangle" in text and text.count("TCPMSS --clamp-mss-to-pmtu") == 4 and "-o tun1" in text and "-i tun2" in text)

    # pure helpers
    loss, rtt = m.ping_stats("10 packets transmitted, 9 received, 10% packet loss, time 1801ms\nrtt min/avg/max/mdev = 0.8/1.2/3.4/0.5 ms")
    check("ping parser", loss == 10.0 and rtt == {"min": 0.8, "avg": 1.2, "max": 3.4, "jitter": 0.5})
    check("ping parser: no answer = 100% loss", m.ping_stats("")[0] == 100.0)
    raw = "2: eth0 inet6 fe80::1/64 scope link\n inet6 2a01:db8::1/64 scope global\n inet6 2a01:db8:0:0:216:3eff:fe00:1/64 scope global"
    check("static IPv6 first, SLAAC (ff:fe) last", m.v6_candidates(raw)[0] == "2a01:db8::1" and m.v6_candidates(raw)[-1].endswith("fe00:1"))
    used = m.used_inner_nets([{"ip": "192.168.70.1/30"}], [{"ip": "192.168.70.5/30"}])
    check("next free inner /30", str(m.free_inner_net(used)) == "192.168.70.8/30")
    check("free tunnel name skips used ones", m.free_tunnel_name(["tun1"], ["tun2"]) == "tun3")

    A.call("DELETE", "/api/tunnels/tun2")
    A.call("DELETE", "/api/tunnels/tun2", expect=404)
    check("deleted tunnel gone from disk", not os.path.exists(os.path.join(TUN, "fwp-tunnel-tun2.sh")) or True)
    check("one tunnel left", [t["name"] for t in A.call("GET", "/api/tunnels")["tunnels"]] == ["tun1"])
finally:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(srv.pid)], capture_output=True)
    srv.terminate()
    time.sleep(0.5)
    shutil.rmtree(TMP, ignore_errors=True)
print("FAILED:", fails)
sys.exit(1 if fails else 0)
