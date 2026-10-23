"""API smoke test against a locally running fwpanel in dry mode.
Run:  FWPANEL_DRY=1 FWPANEL_DIR=<tmp> FWPANEL_PORT=19443 python src/fwpanel.py serve   (in another shell)
      python tests/test_api.py http://127.0.0.1:19443 <password>
"""
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

base, password = sys.argv[1], sys.argv[2]
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
fails = 0


def call(method, path, body=None, csrf=True, expect=200):
    global fails
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    req.add_header("Content-Type", "application/json")
    if csrf:
        req.add_header("X-Requested-With", "fwpanel")
    try:
        r = op.open(req)
        code, data = r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        code, data = e.code, json.loads(e.read() or b"{}")
    ok = code == expect
    fails += not ok
    print(("PASS" if ok else "FAIL"), method, path, code, (data.get("error") or "")[:70])
    return data


call("GET", "/api/state", expect=401)
call("POST", "/api/login", {"password": "wrong"}, expect=401)
call("POST", "/api/login", {"password": password}, csrf=False, expect=403)
call("POST", "/api/login", {"password": password})
st = call("GET", "/api/state")
r1 = call("POST", "/api/rules", {"proto": "both", "listen_port": 443, "dest_ip": "10.30.30.2", "dest_port": 443, "comment": "t1"})["rule"]
call("POST", "/api/rules", {"proto": "tcp", "listen_port": 443, "dest_ip": "1.2.3.4"}, expect=400)          # conflict
call("POST", "/api/rules", {"proto": "udp", "listen_port": 22, "dest_ip": "1.2.3.4"}, expect=200)           # udp 22 is fine
call("POST", "/api/rules", {"proto": "tcp", "listen_port": 22, "dest_ip": "1.2.3.4"}, expect=400)           # ssh protected
call("POST", "/api/rules", {"proto": "tcp", "listen_port": 19443, "dest_ip": "1.2.3.4"}, expect=400)        # panel port
call("POST", "/api/rules", {"proto": "tcp", "listen_port": 80, "dest_ip": "999.1.1.1"}, expect=400)
call("POST", "/api/rules", {"proto": "tcp", "listen_port": 70000, "dest_ip": "1.1.1.1"}, expect=400)
call("POST", "/api/rules", {"proto": "icmp", "listen_port": 80, "dest_ip": "1.1.1.1"}, expect=400)
call("PUT", f"/api/rules/{r1['id']}", {"enabled": False})
call("PUT", "/api/rules/999", {"enabled": False}, expect=404)
call("POST", "/api/rules", {"proto": "tcp", "listen_port": 443, "dest_ip": "1.2.3.4"})                       # ok: r1 disabled
exp = call("GET", "/api/export")
call("POST", "/api/import", exp)
call("POST", "/api/apply")
call("DELETE", f"/api/rules/{r1['id']}")
call("POST", "/api/password", {"old": "bad", "new": "newpassword1"}, expect=400)
call("POST", "/api/password", {"old": password, "new": "newpassword1"})
call("GET", "/api/state", expect=401)
call("POST", "/api/login", {"password": "newpassword1"})
call("POST", "/api/logout")
call("GET", "/api/state", expect=401)
print("FAILED:", fails)
sys.exit(1 if fails else 0)
