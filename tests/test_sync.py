"""Local sync test: two panels in dry mode (no iptables). Run:  python tests/test_sync.py"""
import http.cookiejar
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

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
TMP = tempfile.mkdtemp(prefix="fwp-sync-")
PORTS = {"A": 19450, "B": 19451}
procs, pws = {}, {}
fails = 0


def start(name):
    d = os.path.join(TMP, name)
    env = dict(os.environ, FWPANEL_DRY="1", FWPANEL_DIR=d, FWPANEL_PORT=str(PORTS[name]), FWPANEL_BIND="127.0.0.1",
               PYTHONIOENCODING="utf-8")
    out = subprocess.run([sys.executable, os.path.join(HERE, "src", "fwpanel.py"), "init", "--port", str(PORTS[name])],
                         env=env, capture_output=True, text=True).stdout
    pws[name] = re.search(r"PASSWORD=(\S+)", out).group(1)
    procs[name] = subprocess.Popen([sys.executable, os.path.join(HERE, "src", "fwpanel.py"), "serve"], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Cli:
    def __init__(self, name):
        self.base = f"http://127.0.0.1:{PORTS[name]}"
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.call("POST", "/api/login", {"password": pws[name]})

    def call(self, method, path, body=None, expect=200):
        global fails
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
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


def check(label, cond):
    global fails
    print(("PASS " if cond else "FAIL "), label)
    fails += not cond


try:
    for n in "AB":
        start(n)
    time.sleep(2)
    A, B = Cli("A"), Cli("B")
    key = B.call("POST", "/api/synckey")["key"]
    # a manual rule on B that is identical to what A will push (must be adopted) and one that conflicts
    B.call("POST", "/api/rules", {"proto": "both", "listen_port": 443, "dest_ip": "192.168.60.2", "dest_port": 443, "comment": "manual-443"})
    B.call("POST", "/api/rules", {"proto": "tcp", "listen_port": 8028, "dest_ip": "9.9.9.9", "dest_port": 1, "comment": "manual-conflict"})
    B.call("POST", "/api/rules", {"proto": "tcp", "listen_port": 7777, "dest_ip": "8.8.8.8", "dest_port": 7777, "comment": "manual-keep"})
    # A rules
    A.call("POST", "/api/rules", {"proto": "both", "listen_port": 443, "dest_ip": "10.0.0.1", "comment": "de-1"})
    A.call("POST", "/api/rules", {"proto": "tcp", "listen_port": 8028, "dest_ip": "10.0.0.2", "comment": "fe"})
    A.call("POST", "/api/rules", {"proto": "udp", "listen_port": 2087, "dest_ip": "10.0.0.3", "comment": "no-sync", "sync": False})
    # bad links
    A.call("POST", "/api/links", {"name": "x", "url": "ftp://x", "tunnel_ip": "1.1.1.1", "secret": key}, expect=400)
    A.call("POST", "/api/links", {"name": "x", "url": "http://127.0.0.1:19451", "tunnel_ip": "1.1.1.1", "secret": "abc"}, expect=400)
    # wrong key -> sync fails with a clear status
    lk = A.call("POST", "/api/links", {"name": "badkey", "url": "http://127.0.0.1:19451", "tunnel_ip": "192.168.60.2", "secret": "0" * 64})["link"]
    time.sleep(2.5)
    st = [l for l in A.call("GET", "/api/links")["links"] if l["id"] == lk["id"]][0]["status"]
    check("wrong key rejected (%s)" % st["msg"], st and not st["ok"] and "401" in st["msg"])
    A.call("DELETE", f"/api/links/{lk['id']}")
    # good link
    lk = A.call("POST", "/api/links", {"name": "mobin", "url": "http://127.0.0.1:19451", "tunnel_ip": "192.168.60.2", "secret": key})["link"]
    time.sleep(3)
    st = [l for l in A.call("GET", "/api/links")["links"] if l["id"] == lk["id"]][0]["status"]
    check("sync ok (%s)" % st["msg"], st and st["ok"])
    rules = B.call("GET", "/api/state")["rules"]
    by = {(r["listen_port"], r["proto"]): r for r in rules}
    check("443 adopted as managed, manual duplicate gone", sum(1 for r in rules if r["listen_port"] == 443) == 1 and by[(443, "both")]["managed"])
    check("443 target = tunnel ip:443", by[(443, "both")]["dest_ip"] == "192.168.60.2" and by[(443, "both")]["dest_port"] == 443)
    check("8028 conflict with manual rule skipped", by[(8028, "tcp")]["dest_ip"] == "9.9.9.9" and not by[(8028, "tcp")]["managed"])
    check("manual-keep untouched", by[(7777, "tcp")]["dest_ip"] == "8.8.8.8")
    check("sync=false rule not pushed", (2087, "udp") not in by)
    # managed rules are read-only on B
    mid = by[(443, "both")]["id"]
    B.call("DELETE", f"/api/rules/{mid}", expect=400)
    B.call("PUT", f"/api/rules/{mid}", {"enabled": False}, expect=400)
    # edit on A propagates
    ra = [r for r in A.call("GET", "/api/state")["rules"] if r["listen_port"] == 8028][0]
    A.call("DELETE", f"/api/rules/{ra['id']}")
    A.call("POST", "/api/rules", {"proto": "tcp", "listen_port": 19208, "dest_ip": "10.0.0.4", "comment": "de-2"})
    time.sleep(3)
    ports = sorted((r["listen_port"], bool(r["managed"])) for r in B.call("GET", "/api/state")["rules"])
    check("A edit propagated (%s)" % ports, (19208, True) in ports and (443, True) in ports)
    # signed endpoint rejects garbage
    import urllib.request as ur
    try:
        ur.urlopen(ur.Request("http://127.0.0.1:19451/api/sync", data=b'{"rules":[]}', method="POST",
                              headers={"X-FWP-Time": str(int(time.time())), "X-FWP-Sig": "00"}))
        check("unsigned sync rejected", False)
    except urllib.error.HTTPError as e:
        check("unsigned sync rejected (%d)" % e.code, e.code == 401)
    # unlink cleans remote managed rules
    d = A.call("DELETE", f"/api/links/{lk['id']}")
    left = B.call("GET", "/api/state")["rules"]
    check("unlink removed managed rules, manual kept (%s)" % [(r['listen_port'], bool(r['managed'])) for r in left],
          all(not r["managed"] for r in left) and len(left) == 2)
    # turning receiving off releases synced rules so they can be edited / deleted locally
    key2 = B.call("POST", "/api/synckey")["key"]
    lk2 = A.call("POST", "/api/links", {"name": "mobin2", "url": "http://127.0.0.1:19451", "tunnel_ip": "192.168.60.2", "secret": key2})["link"]
    time.sleep(3)
    mrules = [r for r in B.call("GET", "/api/state")["rules"] if r["managed"]]
    check("relinked, managed rules present (%d)" % len(mrules), len(mrules) >= 1)
    B.call("DELETE", f"/api/rules/{mrules[0]['id']}", expect=400)
    B.call("DELETE", "/api/synckey")
    after = B.call("GET", "/api/state")["rules"]
    check("receiving off -> no managed rules left", all(not r["managed"] for r in after))
    B.call("DELETE", f"/api/rules/{mrules[0]['id']}")
    check("released rule can be deleted", all(r["id"] != mrules[0]["id"] for r in B.call("GET", "/api/state")["rules"]))
finally:
    for p in procs.values():
        p.terminate()
    time.sleep(0.5)
    shutil.rmtree(TMP, ignore_errors=True)
print("FAILED:", fails)
sys.exit(1 if fails else 0)
