"""Install-job tests (no network, no real SSH, nothing touched on this machine). Run:  python tests/test_job.py

Unit tests with fakes: tunnel negotiation, the full install flow, error cases, and (Linux only) the SSH password mechanism
against a fake `ssh` that checks that the password never appears on a command line and the temporary key is removed.
"""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="fwp-job-")
os.environ.update(FWPANEL_DRY="1", FWPANEL_DIR=os.path.join(TMP, "conf"), FWPANEL_TUNDIR=os.path.join(TMP, "sbin"),
                  FWPANEL_UNITDIR=os.path.join(TMP, "units"))
os.makedirs(os.environ["FWPANEL_TUNDIR"])
os.makedirs(os.environ["FWPANEL_UNITDIR"])
spec = importlib.util.spec_from_file_location("fwp", os.path.join(ROOT, "src", "fwpanel.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
fails = 0


def check(label, cond):
    global fails
    print(("PASS " if cond else "FAIL "), label)
    fails += not cond


class FakeSsh:
    """Pretends to be the Iran server."""
    def __init__(self, host, port, password="", identity="", jid="x", **kw):
        self.cmds = []
        FakeSsh.last = self
        self.password = password

    def bootstrap(self):
        if self.password == "wrong":
            raise RuntimeError("رمز اشتباه است")

    def fingerprints(self):
        return ["SHA256:fake"]

    def cleanup(self):
        self.cleaned = True

    def run(self, cmd, stdin=None, timeout=0, mode=None):
        self.cmds.append(cmd)
        if cmd.startswith("echo uid="):
            return 0, f"uid={FakeSsh.uid}\nos=ubuntu\nhave-python3=1\nhave-iptables=1\nhave-openssl=1\nhave-curl=1\nhaskey={FakeSsh.haskey}\n", ""
        if "ip -6 -o addr show" in cmd:
            return 0, FakeSsh.v6, ""
        if "tar -xz" in cmd:
            return 0, "", ""
        if "install.sh" in cmd:
            return 0, "fwpanel is running: http://x\nPASSWORD=Pw123\n", ""
        if cmd.startswith("ping"):
            return (0 if FakeSsh.ping_ok else 1), "5 packets transmitted, 5 received, 0% packet loss\n", ""
        return 0, "", ""

    uid, haskey, v6, ping_ok = "0", "0", "", True


calls = []


def fake_radmin(ssh, method, path, body=None, timeout=0):
    calls.append((method, path))
    if path == "/api/state":
        return {"ok": True}
    if path == "/api/tunnels" and method == "GET":
        return {"tunnels": []}
    if path.endswith("/optimize"):
        return {"mtu_before": 1440, "mtu_after": 1456, "steps": [{"ok": True, "msg": "m"}]}
    return {"ok": True}


m.SshClient, m.radmin = FakeSsh, fake_radmin
m.sync_link = lambda lid: {"ok": True, "msg": "1 قانون همگام شد", "ts": 1}
m.detect_ipv6 = lambda: ["2a01:db8::1", "2a01:db8:0:0:216:3eff:fe00:1"]
m.detect_primary_ip = lambda: "93.184.216.34"
m.run = lambda cmd, inp=None: (0, "", "")          # every local ping "works"
m.CONFIG["port"] = 9443


def job(**kw):
    p = {"name": "Iran-T", "host": "198.51.100.7", "ssh_port": 22, "panel_port": 9443, "scheme": "http", "tunnel": "auto", "optimize": True,
         "replace_key": False, "password": "pw", "identity": ""}
    p.update(kw)
    j = m.new_job("t")
    m.run_install_iran(j, p)
    return j


# 1) happy path with a working IPv6 pair -> GRE6 tunnel, optimised, link stored
FakeSsh.uid, FakeSsh.haskey, FakeSsh.v6, FakeSsh.ping_ok = "0", "0", "inet6 2a02:db8::2/64 scope global\n", True
j = job()
levels = [s["level"] for s in j["steps"]]
r = j["result"] or {}
check("happy path finishes (%s)" % j["state"], j["state"] == "done" and not [s for s in j["steps"] if s["level"] == "err"])
check("GRE6 chosen first and tunnel created on both ends", (r.get("tunnel") or {}).get("kind") == "gre6" and ("POST", "/api/tunnels") in calls)
check("both ends optimised", sum(1 for c in calls if c[1].endswith("/optimize")) == 1 and any("MTU" in s["msg"] for s in j["steps"]))
check("result carries panel url + the Iran panel password", r.get("panel_url") == "http://198.51.100.7:9443/" and r.get("password") == "Pw123")
link = m.CONFIG["links"][-1]
check("link stored: tunnel ip is the foreign end, url goes through the tunnel", link["tunnel_ip"] == r["tunnel"]["foreign_ip"] and r["tunnel"]["iran_ip"] in link["url"] and link["installed"])
check("sync key was passed to the installer, password removed from the job",
      "--sync-key " + link["secret"] in FakeSsh.last.cmds[-3] + FakeSsh.last.cmds[-2] + FakeSsh.last.cmds[-1] or any(link["secret"] in c for c in FakeSsh.last.cmds))
check("the temporary SSH access is always cleaned up", getattr(FakeSsh.last, "cleaned", False))
check("password never in the job log", "pw" not in json.dumps(j["steps"]).replace("password", ""))
check("local tunnel files exist in the tunnel dir", bool(m.tunnel_names()))

# 2) IPv6 unusable, GRE4 possible (public IPv4s): falls back to GRE4
for n in list(m.tunnel_names()):
    m.tunnel_delete(n, force=True)
m.CONFIG["links"] = []
FakeSsh.v6 = ""
j = job(host="198.51.100.8")
check("no IPv6 -> GRE4 over the public IPs", j["state"] == "done" and (j["result"]["tunnel"] or {}).get("kind") == "gre4"
      and j["result"]["tunnel"]["foreign_ep"] == "93.184.216.34" and j["result"]["tunnel"]["iran_ep"] == "198.51.100.8")

# 3) tunnel fails the traffic test on every candidate -> clean fallback to a direct connection
for n in list(m.tunnel_names()):
    m.tunnel_delete(n, force=True)
m.CONFIG["links"] = []
orig_pair = m.pair_loss
m.pair_loss = lambda *a: (100.0, 100.0)
j = job(host="198.51.100.9")
check("no working tunnel -> direct mode with a warning, nothing left behind",
      j["state"] == "done" and j["result"]["tunnel"] is None and any(s["level"] == "warn" for s in j["steps"]) and not m.tunnel_names()
      and m.CONFIG["links"][-1]["tunnel_ip"] == "93.184.216.34")
m.pair_loss = orig_pair

# 4) tunnel type forced to none
m.CONFIG["links"] = []
j = job(host="198.51.100.10", tunnel="none")
check("tunnel=none builds no tunnel", j["state"] == "done" and j["result"]["tunnel"] is None and not m.tunnel_names())

# 5) errors
m.CONFIG["links"] = []
j = job(host="198.51.100.11", password="wrong")
check("wrong password -> clear error, cleanup done", j["state"] == "error" and "رمز" in j["steps"][-1]["msg"] and FakeSsh.last.cleaned)
FakeSsh.haskey = "1"
j = job(host="198.51.100.12")
check("Iran server already syncs from another panel -> refuses", j["state"] == "error" and "پنل دیگری" in j["steps"][-1]["msg"])
j = job(host="198.51.100.12", replace_key=True)
check("...unless replace_key is set", j["state"] == "done")
FakeSsh.haskey, FakeSsh.uid = "0", "1000"
j = job(host="198.51.100.13")
check("non-root login refused", j["state"] == "error" and "root" in j["steps"][-1]["msg"])

# 6) request validation
for bad in ({"name": "", "host": "1.2.3.4", "password": "x"}, {"name": "a", "host": "bad host!", "password": "x"}, {"name": "a", "host": "1.2.3.4"},
            {"name": "a", "host": "1.2.3.4", "password": "x", "ssh_port": 70000}):
    try:
        m.start_install_job(bad)
        check("bad request rejected: %s" % list(bad), False)
    except ValueError:
        check("bad request rejected: %s" % list(bad), True)

# 7) real SshClient mechanics against a fake ssh binary (Linux only)
if os.name != "nt":
    import shutil
    import subprocess
    importlib.reload(m) if False else None
    spec2 = importlib.util.spec_from_file_location("fwp2", os.path.join(ROOT, "src", "fwpanel.py"))
    m2 = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(m2)
    fake_home = os.path.join(TMP, "remote-home")
    os.makedirs(fake_home)
    log = os.path.join(TMP, "ssh.log")
    shim = os.path.join(TMP, "fake-ssh")
    with open(shim, "w") as f:
        f.write('''#!/bin/bash
echo "$@" >> "%s"
cmd="${@: -1}"
case " $* " in
  *PreferredAuthentications*) pw="$("$SSH_ASKPASS")"; [ "$pw" = "s3cret" ] || { echo "Permission denied" >&2; exit 255; } ;;
  *" -i "*) ;;
  *) echo "no auth given" >&2; exit 255 ;;
esac
HOME="%s" bash -c "$cmd"
''' % (log, fake_home))
    os.chmod(shim, 0o755)
    m2.SSH_BIN = shim
    c = m2.SshClient("203.0.113.5", 22, password="s3cret", jid="job123")
    askpass = c.askpass
    c.bootstrap()
    auth = open(os.path.join(fake_home, ".ssh", "authorized_keys")).read()
    check("password login worked and a temporary key was installed", "fwpanel-temp-job123" in auth and c.temp_key)
    rc, out, _ = c.run("echo hello")
    check("later commands use the key, not the password", rc == 0 and out.strip() == "hello" and "-i" in open(log).read().splitlines()[-1])
    check("the password never appears on any ssh command line", "s3cret" not in open(log).read())
    check("askpass file holds no password", "s3cret" not in open(askpass).read())
    c.cleanup()
    check("temporary key removed from the server", "fwpanel-temp-job123" not in open(os.path.join(fake_home, ".ssh", "authorized_keys")).read())
    check("local temp dir removed", not os.path.exists(c.dir))
    c2 = m2.SshClient("203.0.113.5", 22, password="bad", jid="j2")
    try:
        c2.bootstrap()
        check("wrong password raises", False)
    except RuntimeError as e:
        check("wrong password raises a readable error (%s)" % str(e)[:40], "رمز" in str(e))
    c2.cleanup()
shutil.rmtree(TMP, ignore_errors=True) if os.name != "nt" else None
print("FAILED:", fails)
sys.exit(1 if fails else 0)
