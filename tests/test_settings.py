"""Settings / installer test: one panel in dry mode (no iptables).  Run:  python tests/test_settings.py"""
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
TMP = tempfile.mkdtemp(prefix="fwp-set-")
PORT = 19490
fails = 0
BASH = next((p for p in ("C:/Program Files/Git/bin/bash.exe", "/bin/bash", "/usr/bin/bash") if os.path.exists(p)), "bash")


def check(label, cond):
    global fails
    print(("PASS " if cond else "FAIL "), label)
    fails += not cond


env = dict(os.environ, FWPANEL_DRY="1", FWPANEL_DIR=os.path.join(TMP, "conf"), FWPANEL_PORT=str(PORT),
           FWPANEL_BIND="127.0.0.1", PYTHONIOENCODING="utf-8")
out = subprocess.run([sys.executable, os.path.join(ROOT, "src", "fwpanel.py"), "init", "--port", str(PORT)], env=env,
                     capture_output=True, text=True).stdout
pw = re.search(r"PASSWORD=(\S+)", out).group(1)
srv = subprocess.Popen([sys.executable, os.path.join(ROOT, "src", "fwpanel.py"), "serve"], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Cli:
    def __init__(self, port):
        self.base = f"http://127.0.0.1:{port}"
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, method, path, body=None, expect=200, raw=False):
        global fails
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Content-Type": "application/json", "X-Requested-With": "fwpanel"})
        try:
            r = self.op.open(req)
            code, data = r.status, r.read()
            hdrs = dict(r.headers)
        except urllib.error.HTTPError as e:
            code, data, hdrs = e.code, e.read(), dict(e.headers)
        if code != expect:
            fails += 1
            print("FAIL", method, path, code, data[:120])
        if raw:
            return data, hdrs
        return json.loads(data or b"{}")


try:
    time.sleep(2)
    A = Cli(PORT)
    A.call("POST", "/api/login", {"password": pw})

    # ---- settings
    s = A.call("GET", "/api/settings")
    check("settings returns port/tls/client ip", s["port"] == PORT and s["client_ip"] == "127.0.0.1" and "version" in s)
    A.call("POST", "/api/settings", {"port": 70000}, expect=400)
    A.call("POST", "/api/settings", {"port": 22}, expect=400)
    A.call("POST", "/api/rules", {"proto": "tcp", "listen_port": 18123, "dest_ip": "1.2.3.4"})
    A.call("POST", "/api/settings", {"port": 18123}, expect=400)          # used by a forward
    A.call("POST", "/api/settings", {"allow_ips": "not-an-ip"}, expect=400)
    A.call("POST", "/api/settings", {"allow_ips": "2001:db8::/32"}, expect=400)
    r = A.call("POST", "/api/settings", {"allow_ips": "10.1.2.3\n192.168.5.0/24"})
    s = A.call("GET", "/api/settings")
    check("allow-list keeps own IP so you cannot lock yourself out (%s)" % s["allow_ips"],
          "127.0.0.1" in s["allow_ips"] and "192.168.5.0/24" in s["allow_ips"] and r["notes"])
    A.call("POST", "/api/settings", {"allow_ips": ""})
    check("allow-list can be cleared", A.call("GET", "/api/settings")["allow_ips"] == [])

    # ---- ip_allowed()
    spec = importlib.util.spec_from_file_location("fwp", os.path.join(ROOT, "src", "fwpanel.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.CONFIG["allow_ips"] = ["10.0.0.0/8", "203.0.113.7"]
    check("ip_allowed: inside range / exact / outside / garbage",
          m.ip_allowed("10.9.8.7") and m.ip_allowed("203.0.113.7") and not m.ip_allowed("1.1.1.1") and not m.ip_allowed("zzz"))
    m.CONFIG["allow_ips"] = []
    check("ip_allowed: empty list = everyone", m.ip_allowed("8.8.8.8"))

    # ---- Iran installer wizard
    base = {"name": "Iran-1", "port": 9443, "scheme": "http", "iran_ip": "1.2.3.4", "target_ip": "5.6.7.8"}
    A.call("POST", "/api/links/new-iran", {**base, "name": ""}, expect=400)
    A.call("POST", "/api/links/new-iran", {**base, "iran_ip": "999.1.1.1"}, expect=400)
    bad_t = {"enabled": True, "name": "BAD NAME", "foreign_v6": "2001:db8::1", "iran_v6": "2001:db8::2", "foreign_ip": "10.0.0.2", "iran_ip": "10.0.0.1"}
    A.call("POST", "/api/links/new-iran", {**base, "tunnel": bad_t}, expect=400)
    A.call("POST", "/api/links/new-iran", {**base, "tunnel": {**bad_t, "name": "tun1", "iran_ip": "10.9.9.1"}}, expect=400)   # different /30
    A.call("POST", "/api/links/new-iran", {**base, "tunnel": {**bad_t, "name": "tun1", "foreign_v6": "nope"}}, expect=400)
    plain = A.call("POST", "/api/links/new-iran", base)["link"]
    check("plain link: installer available, target = given IP", plain["installer"] and plain["url"] == "http://1.2.3.4:9443")
    tun = A.call("POST", "/api/links/new-iran", {**base, "name": "Iran 2", "tunnel": {**bad_t, "name": "tun2"}})["link"]
    check("tunnel link: url goes through the tunnel (%s)" % tun["url"], tun["url"] == "http://10.0.0.1:9443" and tun["tunnel"] == "tun2")

    data, hdrs = A.call("GET", f"/api/links/{tun['id']}/installer", raw=True)
    check("installer is a download", "attachment" in hdrs.get("Content-Disposition", "") and data.startswith(b"#!/usr/bin/env bash"))
    script = os.path.join(TMP, "install-test.sh")
    open(script, "wb").write(data)
    head = data.split(b"__PAYLOAD__")[0].decode()
    check("installer carries the tunnel + port + 64-hex key args",
          "--tunnel tun2" in head and "--port 9443" in head and "--http" in head and re.search(r"--sync-key [0-9a-f]{64}", head)
          and "--ip 10.0.0.1/30" in head and "--kind gre6" in head and "--local 2001:db8::2" in head and "--remote 2001:db8::1" in head)
    # the payload must unpack to a complete install tree (same pipeline the installer uses)
    ex = os.path.join(TMP, "ex")
    os.makedirs(ex)
    fw = lambda x: x.replace(chr(92), "/")
    rc = subprocess.run([BASH, "-c", "awk '/^__PAYLOAD__$/ {p=1; next} p' \"" + fw(script) + "\" | base64 -d | tar -xz -C \"" + fw(ex) + "\""],
                        capture_output=True, text=True)
    files = {os.path.relpath(os.path.join(d, f), ex).replace("\\", "/") for d, _, fs in os.walk(ex) for f in fs}
    check("payload unpacks (%d files)" % len(files), rc.returncode == 0 and {"fwpanel.py", "install.sh", "uninstall.sh", "fwpanel.sh", "web/index.html", "web/app.js", "web/app.css"} <= files)
    check("installer scripts have valid syntax",
          subprocess.run([BASH, "-n", fw(script)]).returncode == 0 and subprocess.run([BASH, "-n", fw(os.path.join(ex, "install.sh"))]).returncode == 0)
    A.call("GET", "/api/links/999/installer", expect=404)

    # ---- GRE4 / GRE6 tunnel kinds
    t4 = {"enabled": True, "name": "g4", "kind": "gre4", "foreign_ep": "203.0.113.1", "iran_ep": "203.0.113.2", "foreign_ip": "10.8.0.2", "iran_ip": "10.8.0.1"}
    A.call("POST", "/api/links/new-iran", {**base, "tunnel": {**t4, "foreign_ep": "2001:db8::1"}}, expect=400)       # gre4 needs IPv4 endpoints
    A.call("POST", "/api/links/new-iran", {**base, "tunnel": {**t4, "iran_ep": "203.0.113.1"}}, expect=400)          # same address on both ends
    A.call("POST", "/api/links/new-iran", {**base, "tunnel": {**t4, "kind": "gre6"}}, expect=400)                    # gre6 needs IPv6 endpoints
    l4 = A.call("POST", "/api/links/new-iran", {**base, "name": "G4", "tunnel": t4})["link"]
    check("gre4 link created (%s)" % l4["tunnel_kind"], l4["tunnel_kind"] == "gre4" and l4["url"] == "http://10.8.0.1:9443")
    h4 = A.call("GET", f"/api/links/{l4['id']}/installer", raw=True)[0].split(b"__PAYLOAD__")[0].decode()
    check("gre4 installer args: --kind gre4 --local <iran ep> --remote <foreign ep>",
          "--kind gre4" in h4 and "--local 203.0.113.2" in h4 and "--remote 203.0.113.1" in h4 and "--ip 10.8.0.1/30" in h4)
    t6 = {"enabled": True, "name": "g6", "kind": "gre6", "foreign_ep": "2001:db8::1", "iran_ep": "2001:db8::2", "foreign_ip": "10.8.1.2", "iran_ip": "10.8.1.1"}
    l6 = A.call("POST", "/api/links/new-iran", {**base, "name": "G6", "tunnel": t6})["link"]
    h6 = A.call("GET", f"/api/links/{l6['id']}/installer", raw=True)[0].split(b"__PAYLOAD__")[0].decode()
    check("gre6 installer args", "--kind gre6" in h6 and "--local 2001:db8::2" in h6 and "--remote 2001:db8::1" in h6)
    s4, u4 = m.tunnel_files("g4", "gre4", "203.0.113.2", "203.0.113.1", "10.8.0.1/30")
    s6, u6 = m.tunnel_files("g6", "gre6", "2001:db8::2", "2001:db8::1", "10.8.1.1/30")
    check("tunnel script: gre4 uses 'ip tunnel ... mode gre', gre6 uses 'ip -6 tunnel ... ip6gre'",
          "ip tunnel add $IF mode gre local 203.0.113.2 remote 203.0.113.1" in s4 and "ip -6" not in s4
          and "ip -6 tunnel add $IF mode ip6gre local 2001:db8::2 remote 2001:db8::1" in s6 and "GRE4" in u4 and "GRE6" in u6)

    # ---- local admin CLI (used by fwpanel-setup.sh): no password, token file + loopback only
    cli = lambda *a, inp=None: subprocess.run([sys.executable, os.path.join(ROOT, "src", "fwpanel.py"), "admin", *a], env=env, input=inp,
                                              capture_output=True)
    r = cli("GET", "/api/settings")
    check("admin CLI reads settings without a password", r.returncode == 0 and json.loads(r.stdout)["port"] == PORT)
    body = json.dumps({"name": "ViaCli", "port": 9443, "scheme": "http", "iran_ip": "1.2.3.4", "target_ip": "5.6.7.8"}).encode()
    r = cli("POST", "/api/links/new-iran", "-", inp=body)
    cid = json.loads(r.stdout)["link"]["id"] if r.returncode == 0 else None
    check("admin CLI creates a link from stdin JSON", cid is not None)
    r = cli("GET", f"/api/links/{cid}/installer")
    check("admin CLI downloads the installer script", r.returncode == 0 and r.stdout.startswith(b"#!/usr/bin/env bash"))
    r = cli("GET", "/api/links/999/installer")
    check("admin CLI reports API errors with exit code 1", r.returncode == 1)
    # a wrong token / non-loopback must not work: call the HTTP API with a bad token and no cookie
    bad = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/state", headers={"X-Admin-Token": "nope", "X-Requested-With": "fwpanel"})
    try:
        urllib.request.urlopen(bad)
        check("bad admin token rejected", False)
    except urllib.error.HTTPError as e:
        check("bad admin token rejected (%d)" % e.code, e.code == 401)

    # ---- port change re-executes the panel on the new port
    r = A.call("POST", "/api/settings", {"port": 19491})
    check("port change asks for restart", r["restart"] and r["port"] == 19491)
    if os.name != "nt":      # os.execv does not replace the process on Windows; verified on Linux servers instead
        time.sleep(4)
        B = Cli(19491)
        B.call("POST", "/api/login", {"password": pw})
        check("panel answers on the new port", B.call("GET", "/api/settings")["port"] == 19491)
finally:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(srv.pid)], capture_output=True) if os.name == "nt" else srv.terminate()
    srv.terminate()
    time.sleep(0.5)
    for pid_file in ():
        pass
    shutil.rmtree(TMP, ignore_errors=True)
print("FAILED:", fails)
sys.exit(1 if fails else 0)
