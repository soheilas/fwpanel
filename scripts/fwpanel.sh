#!/usr/bin/env bash
# fwpanel - management command (installed as /usr/local/bin/fwpanel).
#
#   fwpanel                 show the menu
#   fwpanel start|stop|restart|status|log
#   fwpanel enable|disable  start the panel at boot (default: enabled)
#   fwpanel info            panel address, port, protocol, allow-list, version
#   fwpanel password        set a new panel password
#   fwpanel port [N]        change the panel port
#   fwpanel tls on|off      switch between HTTPS and HTTP
#   fwpanel allow-clear     remove the IP allow-list (if you locked yourself out)
#   fwpanel add-iran        set up an Iran server over SSH (asks for its IP and root password) or print a one-line command
#   fwpanel update          update to the latest release
#   fwpanel uninstall       remove the panel (config is kept unless you say otherwise)
REPO="soheilas/fwpanel"
DIR=/opt/fwpanel
CONF=/etc/fwpanel
PY="python3 $DIR/fwpanel.py"

red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; cyan='\033[0;36m'; bold='\033[1m'; plain='\033[0m'
ok()   { printf "${green}%s${plain}\n" "$*"; }
warn() { printf "${yellow}%s${plain}\n" "$*"; }
err()  { printf "${red}%s${plain}\n" "$*" >&2; }

[ "$(id -u)" = 0 ] || { err "Run as root:  sudo fwpanel"; exit 1; }
[ -f "$DIR/fwpanel.py" ] || { err "fwpanel is not installed. Install it with:"; echo "  bash <(curl -Ls https://raw.githubusercontent.com/$REPO/main/install.sh)"; exit 1; }

version()  { sed -n 's/^VERSION = "\(.*\)"/\1/p' "$DIR/fwpanel.py" | head -1; }
cfg_get()  { python3 -c "import json,sys; print(json.load(open('$CONF/config.json')).get(sys.argv[1], sys.argv[2]))" "$1" "$2" 2>/dev/null; }
running()  { systemctl is-active --quiet fwpanel; }
enabled()  { systemctl is-enabled --quiet fwpanel 2>/dev/null; }
my_ip()    { ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1; }
scheme()   { [ "$(cfg_get tls True)" = False ] && echo http || echo https; }
url()      { echo "$(scheme)://$(my_ip):$(cfg_get port 9443)/"; }
pause()    { [ -t 0 ] && { echo; read -r -p "Press Enter to go back to the menu... " _; }; }

# talk to the running panel without a password (root-only token); falls back to editing the config when it is stopped
api_set() {   # api_set '{"port": 1234}'
  if running; then $PY admin POST /api/settings "$1" >/dev/null 2>&1; else return 1; fi
}
cfg_set() {   # cfg_set key json-value
  python3 - "$1" "$2" <<'PY'
import json, sys
p = "/etc/fwpanel/config.json"
c = json.load(open(p)); c[sys.argv[1]] = json.loads(sys.argv[2]); json.dump(c, open(p, "w"), indent=2)
PY
}

do_info() {
  echo
  printf "  ${bold}fwpanel${plain} v%s\n" "$(version)"
  echo "  ----------------------------------------"
  printf "  state       : "; running && ok "running" || err "stopped"
  printf "  autostart   : "; enabled && echo yes || echo no
  echo "  address     : $(url)"
  echo "  port        : $(cfg_get port 9443)   protocol: $(scheme | tr a-z A-Z)"
  local allow; allow="$(python3 -c "import json;print(', '.join(json.load(open('$CONF/config.json')).get('allow_ips',[])) or 'everyone')" 2>/dev/null)"
  echo "  allowed IPs : $allow"
  echo "  config      : $CONF   (rules.json, traffic.json, config.json)"
  echo
}

do_password() {
  local p1 p2
  read -r -s -p "New password (min 8 chars, Enter = generate a random one): " p1; echo
  if [ -z "$p1" ]; then p1="$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print(''.join(secrets.choice(a) for _ in range(16)))")"; GEN=1
  else
    [ "${#p1}" -ge 8 ] || { err "too short"; return 1; }
    read -r -s -p "Repeat it: " p2; echo
    [ "$p1" = "$p2" ] || { err "passwords do not match"; return 1; }
  fi
  printf '%s\n' "$p1" | $PY passwd --stdin >/dev/null && systemctl restart fwpanel
  ok "password updated (all sessions were logged out)"
  [ "${GEN:-0}" = 1 ] && { echo "  new password: $p1"; GEN=0; }
}

do_port() {
  local n="${1:-}"
  [ -n "$n" ] || read -r -p "New panel port [1-65535]: " n
  [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le 65535 ] || { err "invalid port"; return 1; }
  if api_set "{\"port\": $n}"; then
    ok "port changed; the panel is restarting"; sleep 3
  else
    cfg_set port "$n" && systemctl restart fwpanel && ok "port changed"
  fi
  echo "  new address: $(url)"
}

do_tls() {
  case "${1:-}" in
    on|https)  api_set '{"tls": true}'  || { $PY tls on  >/dev/null && systemctl restart fwpanel; } ;;
    off|http)  api_set '{"tls": false}' || { $PY tls off >/dev/null && systemctl restart fwpanel; } ;;
    *) err "usage: fwpanel tls on|off"; return 1 ;;
  esac
  sleep 3; ok "protocol switched"; echo "  new address: $(url)"
}

do_add_iran() { $PY add-iran "$@"; }

do_update() {
  command -v curl >/dev/null || { err "curl is required"; return 1; }
  if ! curl -fsSL -m 15 -o /dev/null "https://raw.githubusercontent.com/$REPO/main/install.sh"; then
    err "cannot reach GitHub from this server (blocked?)."
    echo "  Update it offline: create an installer in your foreign panel (Settings -> add Iran server) or copy a new release to this server."
    return 1
  fi
  bash <(curl -fsSL "https://raw.githubusercontent.com/$REPO/main/install.sh") --update "$@"
}

do_uninstall() {
  read -r -p "Remove fwpanel and its forwarding rules? [y/N] " a; [[ "$a" =~ ^[Yy] ]] || { echo "cancelled"; return 0; }
  read -r -p "Also delete the config, rules and password in $CONF? [y/N] " b
  if [[ "$b" =~ ^[Yy] ]]; then bash "$DIR/uninstall.sh" --purge; else bash "$DIR/uninstall.sh"; fi
  exit 0
}

usage() {
  echo
  printf "  ${bold}fwpanel${plain} management\n"
  echo "  ----------------------------------------"
  echo "  fwpanel               - show the menu"
  echo "  fwpanel start|stop|restart|status|log"
  echo "  fwpanel enable|disable - autostart at boot"
  echo "  fwpanel info          - address, port, protocol"
  echo "  fwpanel password      - set a new password"
  echo "  fwpanel port [N]      - change the panel port"
  echo "  fwpanel tls on|off    - HTTPS / HTTP"
  echo "  fwpanel allow-clear   - remove the IP allow-list"
  echo "  fwpanel add-iran      - set up an Iran server (SSH or one-line command)"
  echo "  fwpanel update        - update to the latest release"
  echo "  fwpanel uninstall     - remove fwpanel"
  echo
}

menu() {
  while true; do
    clear 2>/dev/null
    echo
    printf "  ${bold}${cyan}fwpanel${plain} ${bold}management menu${plain}   v%s\n" "$(version)"
    echo "  ------------------------------------------------"
    echo "   0. Exit"
    echo "   1. Update fwpanel"
    echo "   2. Uninstall fwpanel"
    echo "  ------------------------------------------------"
    echo "   3. Show panel info"
    echo "   4. Reset panel password"
    echo "   5. Change panel port"
    echo "   6. Switch HTTP / HTTPS"
    echo "   7. Clear IP allow-list"
    echo "  ------------------------------------------------"
    echo "   8. Start        9. Stop        10. Restart"
    echo "  11. Status      12. View logs"
    echo "  13. Enable autostart   14. Disable autostart"
    echo "  15. Add an Iran server (install + tunnel + sync)"
    echo "  ------------------------------------------------"
    printf "  state: "; running && printf "${green}running${plain}" || printf "${red}stopped${plain}"
    printf "   autostart: "; enabled && printf "${green}yes${plain}" || printf "${yellow}no${plain}"
    printf "\n  address: %s\n\n" "$(url)"
    read -r -p "  Please enter your choice [0-15]: " c
    case "$c" in
      0) exit 0 ;;
      1) do_update; pause ;;
      2) do_uninstall ;;
      3) do_info; pause ;;
      4) do_password; pause ;;
      5) do_port; pause ;;
      6) read -r -p "  Serve over HTTPS? [y = HTTPS / n = HTTP]: " t; [[ "$t" =~ ^[Yy] ]] && do_tls on || do_tls off; pause ;;
      7) $PY allow clear; pause ;;
      8) systemctl start fwpanel && ok "started"; pause ;;
      9) systemctl stop fwpanel && ok "stopped"; pause ;;
      10) systemctl restart fwpanel && ok "restarted"; pause ;;
      11) systemctl status fwpanel --no-pager; pause ;;
      12) journalctl -u fwpanel --no-pager -n 60; pause ;;
      13) systemctl enable fwpanel >/dev/null 2>&1 && ok "autostart enabled"; pause ;;
      14) systemctl disable fwpanel >/dev/null 2>&1 && ok "autostart disabled"; pause ;;
      15) do_add_iran; pause ;;
      *) err "invalid choice"; sleep 1 ;;
    esac
  done
}

case "${1:-}" in
  "")            menu ;;
  start)         systemctl start fwpanel && ok "started" ;;
  stop)          systemctl stop fwpanel && ok "stopped" ;;
  restart)       systemctl restart fwpanel && ok "restarted" ;;
  status)        systemctl status fwpanel --no-pager ;;
  log|logs)      journalctl -u fwpanel --no-pager -n "${2:-60}" ;;
  enable)        systemctl enable fwpanel >/dev/null 2>&1 && ok "autostart enabled" ;;
  disable)       systemctl disable fwpanel >/dev/null 2>&1 && ok "autostart disabled" ;;
  info|settings) do_info ;;
  password|passwd) do_password ;;
  port)          do_port "${2:-}" ;;
  tls)           do_tls "${2:-}" ;;
  allow-clear)   $PY allow clear ;;
  add-iran)      shift; do_add_iran "$@" ;;
  update)        shift; do_update "$@" ;;
  uninstall)     do_uninstall ;;
  version|-v|--version) version ;;
  help|-h|--help) usage ;;
  *)             usage; exit 1 ;;
esac
