#!/usr/bin/env python3
"""Build standalone single-file scripts into dist/:

    python3 tools/build_standalone.py [install.sh options...]   ->  dist/fwpanel-installer.sh  (install the panel on ONE server)
    python3 tools/build_standalone.py --setup                    ->  dist/fwpanel-setup.sh      (0-to-100 setup of foreign + Iran servers)

Options given to the first form are baked into the installer, e.g.
    python3 tools/build_standalone.py --port 9443 --http
The resulting file can be copied to any Debian/Ubuntu server (installer) or any Linux machine with SSH access (setup).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fwpanel  # noqa: E402

NL = bytes([10])

out_dir = os.path.join(ROOT, "dist")
os.makedirs(out_dir, exist_ok=True)
if sys.argv[1:2] == ["--setup"]:
    out = os.path.join(out_dir, "fwpanel-setup.sh")
    with open(os.path.join(ROOT, "scripts", "setup-servers.sh"), "rb") as f:
        head = f.read().rstrip(NL).replace(bytes([13, 10]), NL) + NL
    with open(out, "wb") as f:
        f.write(head + b"__PAYLOAD__" + NL + fwpanel.payload_b64().encode())
else:
    out = os.path.join(out_dir, "fwpanel-installer.sh")
    with open(out, "wb") as f:
        f.write(fwpanel.build_installer(sys.argv[1:]))
try:
    os.chmod(out, 0o755)
except OSError:
    pass
print(f"written {out} ({os.path.getsize(out) // 1024} KB, fwpanel {fwpanel.VERSION})")
