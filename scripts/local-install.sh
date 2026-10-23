#!/usr/bin/env bash
# fwpanel local installer (Debian / Ubuntu): installs from an already extracted tree.
# Most people want the online one-liner in the README instead; this script is what it (and the generated installers) run.
#
#   sudo bash install.sh [options]
#
#   --port N            panel port (default 9443)
#   --http | --https    serve the panel over plain HTTP or HTTPS (self-signed). Default: https
#   --sync-key HEX      64-hex key this panel accepts forwarding rules from (used by generated Iran installers)
#   --replace-key       allow --sync-key to replace a key that is already set (the panel that used the old key stops syncing)
#   --tunnel NAME [--kind gre6|gre4] --local ADDR --remote ADDR --ip A.B.C.D/30
#                       also create a persistent GRE tunnel: gre6 (default, IPv6 addresses) or gre4 (public IPv4 addresses);
#                       this server = local, the peer = remote, --ip = this side's tunnel address
#   --uninstall         remove the panel (config and password are kept)
#   --purge             with --uninstall: also delete /etc/fwpanel
set -euo pipefail

PORT=""; MODE=""; REPLACE_KEY=0; SYNC_KEY=""; TUN=""; KIND="gre6"; LOCAL6=""; REMOTE6=""; TUNIP=""; UNINSTALL=0; PURGE=0
# FWPANEL_PREFIX=/some/dir runs a file-only dry install (no apt, no systemd, no tunnel) - used by the tests
PREFIX="${FWPANEL_PREFIX:-}"
DIR="$PREFIX/opt/fwpanel"
CONF="$PREFIX/etc/fwpanel"
export FWPANEL_DIR="$CONF"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port)      PORT="${2:-}"; shift 2 ;;
    --http)      MODE=http; shift ;;
    --https)     MODE=https; shift ;;
    --sync-key)  SYNC_KEY="${2:-}"; shift 2 ;;
    --replace-key) REPLACE_KEY=1; shift ;;
    --tunnel)    TUN="${2:-}"; shift 2 ;;
    --kind)      KIND="${2:-}"; shift 2 ;;
    --local|--local6)   LOCAL6="${2:-}"; shift 2 ;;
    --remote|--remote6) REMOTE6="${2:-}"; shift 2 ;;
    --ip)        TUNIP="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge)     PURGE=1; shift ;;
    -h|--help)   sed -n '2,16p' "${BASH_SOURCE[0]}"; exit 0 ;;
    # legacy positional form: install.sh 9443 http
    [0-9]*)      PORT="$1"; shift ;;
    http|https)  MODE="$1"; shift ;;
    *)           die "unknown option: $1" ;;
  esac
done

[ "$(id -u)" = 0 ] || die "run as root"

if [ "$UNINSTALL" = 1 ]; then
  exec bash "$SRC/uninstall.sh" $([ "$PURGE" = 1 ] && echo --purge)
fi

[ -z "$PORT" ] || { [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; } || die "bad port: $PORT"
[ -z "$SYNC_KEY" ] || [[ "$SYNC_KEY" =~ ^[0-9a-fA-F]{64}$ ]] || die "--sync-key must be 64 hex characters"
if [ -n "$TUN$LOCAL6$REMOTE6$TUNIP" ]; then
  [[ "$TUN" =~ ^[a-z][a-z0-9_-]{0,14}$ ]] || die "bad --tunnel name"
  [ "$KIND" = gre6 ] || [ "$KIND" = gre4 ] || die "--kind must be gre6 or gre4"
  [ -n "$LOCAL6" ] && [ -n "$REMOTE6" ] && [[ "$TUNIP" =~ ^[0-9.]+/[0-9]+$ ]] || die "--tunnel needs --local, --remote and --ip A.B.C.D/30"
fi

need() { command -v "$1" >/dev/null 2>&1; }
if [ -z "$PREFIX" ] && { ! need python3 || ! need iptables || ! need openssl; }; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq python3 iptables openssl
fi

mkdir -p "$DIR/web" "$CONF"
chmod 700 "$CONF"
install -m 755 "$SRC/fwpanel.py" "$DIR/fwpanel.py"
for f in install.sh uninstall.sh fwpanel.sh; do [ -f "$SRC/$f" ] && install -m 755 "$SRC/$f" "$DIR/$f"; done
[ -f "$DIR/fwpanel.sh" ] && { mkdir -p "$PREFIX/usr/local/bin"; ln -sf /opt/fwpanel/fwpanel.sh "$PREFIX/usr/local/bin/fwpanel"; }
cp -r "$SRC"/web/. "$DIR/web/"
chmod -R a+rX "$DIR/web"

if [ ! -f "$CONF/cert.pem" ]; then
  IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
    -subj "/CN=fwpanel" ${IP:+-addext "subjectAltName=IP:$IP"} \
    -keyout "$CONF/key.pem" -out "$CONF/cert.pem" 2>/dev/null
  chmod 600 "$CONF/key.pem"
fi

if [ -n "$SYNC_KEY" ] && [ "$REPLACE_KEY" = 0 ] && [ -f "$CONF/config.json" ]; then
  OLDKEY="$(python3 -c "import json;print(json.load(open('$CONF/config.json')).get('sync_secret',''))" 2>/dev/null || true)"
  if [ -n "$OLDKEY" ] && [ "$OLDKEY" != "$SYNC_KEY" ]; then
    die "this server already receives rules from another panel (a sync key is set). Nothing was changed. Re-run with --replace-key to take over (the other panel will stop syncing here)."
  fi
fi

INIT="$(python3 "$DIR/fwpanel.py" init ${PORT:+--port "$PORT"})"      # no --port on upgrades: the configured port is kept
FIRST_RUN=0; echo "$INIT" | grep -q '^PASSWORD=' && FIRST_RUN=1
[ -n "$SYNC_KEY" ] && python3 "$DIR/fwpanel.py" setkey "$SYNC_KEY" >/dev/null
if [ "$FIRST_RUN" = 1 ] || [ -n "$MODE" ]; then
  python3 "$DIR/fwpanel.py" tls "$([ "$MODE" = http ] && echo off || echo on)" >/dev/null
fi

# ---- optional GRE6 tunnel (persistent) ----
if [ -n "$TUN" ] && [ -z "$PREFIX" ]; then
  cat > "/usr/local/sbin/fwp-tunnel-$TUN.sh" <<EOF
#!/bin/bash
# managed by fwpanel
IF=$TUN
case "\$1" in
up)
 $([ "$KIND" = gre4 ] && echo "ip tunnel add \$IF mode gre local $LOCAL6 remote $REMOTE6 ttl 255" || echo "ip -6 tunnel add \$IF mode ip6gre local $LOCAL6 remote $REMOTE6 ttl 255 encaplimit none") 2>/dev/null
 ip addr add $TUNIP dev \$IF 2>/dev/null
 ip link set \$IF mtu 1440 txqueuelen 10000 up
 ;;
down) ip link del \$IF 2>/dev/null ;;
esac
exit 0
EOF
  chmod 755 "/usr/local/sbin/fwp-tunnel-$TUN.sh"
  cat > "/etc/systemd/system/fwp-tunnel-$TUN.service" <<EOF
[Unit]
Description=fwpanel ${KIND^^} tunnel $TUN
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/fwp-tunnel-$TUN.sh up
ExecStop=/usr/local/sbin/fwp-tunnel-$TUN.sh down

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "fwp-tunnel-$TUN.service" >/dev/null 2>&1
fi

if [ -n "$PREFIX" ]; then
  echo "file-only install into $PREFIX done (test mode, service not started)"
  exit 0
fi

cat > /etc/systemd/system/fwpanel.service <<EOF
[Unit]
Description=fwpanel - iptables port forward web panel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/fwpanel/fwpanel.py serve
Restart=always
RestartSec=3
PrivateTmp=yes
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable fwpanel >/dev/null 2>&1
systemctl restart fwpanel
sleep 2
systemctl is-active fwpanel >/dev/null || { journalctl -u fwpanel -n 20 --no-pager; exit 1; }

SCHEME="$(python3 -c "import json;print('https' if json.load(open('$CONF/config.json')).get('tls', True) else 'http')")"
PORT="$(python3 -c "import json;print(json.load(open('$CONF/config.json')).get('port', 9443))")"
ADDR="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)"
[ -n "$ADDR" ] || ADDR="$(hostname -I | awk '{print $1}')"

echo
echo "fwpanel is running:  $SCHEME://$ADDR:$PORT/"
echo "manage it with the  fwpanel  command (menu), e.g.  fwpanel status | fwpanel log | fwpanel password"
if [ "$FIRST_RUN" = 1 ]; then
  echo "$INIT" | grep '^PASSWORD='
  echo "(save the password now - it is shown only once; change it later from Settings)"
else
  echo "(existing config kept; password unchanged. Reset it with: python3 $DIR/fwpanel.py passwd)"
fi
if [ -n "$TUN" ]; then
  echo
  echo "tunnel '$TUN' ($KIND) created: $TUNIP  ($LOCAL6 -> $REMOTE6)"
  PV=-6; [ "$KIND" = gre4 ] && PV=-4
  if ping $PV -c 2 -W 2 -I "$LOCAL6" "$REMOTE6" >/dev/null 2>&1; then
    echo "  path to the peer ($KIND outer addresses): OK"
  elif [ "$KIND" = gre4 ]; then
    echo "  WARNING: no reply from $REMOTE6. ICMP may be filtered, or the peer is not set up yet. GRE (IP protocol 47) must be allowed between the two servers."
  else
    echo "  WARNING: no IPv6 reply from $REMOTE6 using source $LOCAL6."
    echo "  Data centers often block auto-generated (SLAAC, ...ff:fe...) addresses: try the server's other global IPv6 address."
  fi
fi
