#!/usr/bin/env bash
# Remove fwpanel. Your config, rules and password in /etc/fwpanel are kept unless you pass --purge.
# GRE6 tunnels created through fwpanel (fwp-tunnel-*.service) are left running; remove them yourself if you want.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1
PREFIX="${FWPANEL_PREFIX:-}"      # test mode: only touch files under this prefix

if [ -z "$PREFIX" ]; then
  if [ -f /opt/fwpanel/fwpanel.py ]; then
    python3 /opt/fwpanel/fwpanel.py flush >/dev/null 2>&1 || true     # remove the forwarding rules from iptables
  fi
  systemctl disable --now fwpanel >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/fwpanel.service
  systemctl daemon-reload
fi
rm -rf "$PREFIX/opt/fwpanel"
rm -f "$PREFIX/usr/local/bin/fwpanel"
if [ "$PURGE" = 1 ]; then
  rm -rf "$PREFIX/etc/fwpanel"
  [ -z "$PREFIX" ] && rm -f /etc/sysctl.d/99-fwpanel.conf
  echo "fwpanel removed (config purged)."
else
  echo "fwpanel removed. Config kept in /etc/fwpanel (use --purge to delete it)."
fi
