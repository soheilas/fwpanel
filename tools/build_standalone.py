#!/usr/bin/env python3
"""Build a standalone single-file installer into dist/:

    python3 tools/build_standalone.py [install.sh options...]   ->  dist/fwpanel-installer.sh  (install the panel on ONE server)

Options are baked into the installer, e.g.
    python3 tools/build_standalone.py --port 9443 --http
The resulting file can be copied to any Debian/Ubuntu server.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import fwpanel  # noqa: E402

out_dir = os.path.join(ROOT, "dist")
os.makedirs(out_dir, exist_ok=True)
out = os.path.join(out_dir, "fwpanel-installer.sh")
with open(out, "wb") as f:
    f.write(fwpanel.build_installer(sys.argv[1:]))
try:
    os.chmod(out, 0o755)
except OSError:
    pass
print(f"written {out} ({os.path.getsize(out) // 1024} KB, fwpanel {fwpanel.VERSION})")
