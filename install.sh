#!/usr/bin/env bash
# fwpanel - one-line installer (Debian / Ubuntu)
#
#   bash <(curl -Ls https://raw.githubusercontent.com/soheilas/fwpanel/main/install.sh)
#
# Options (all optional):
#   --version vX.Y.Z   install a specific release instead of the latest
#   --port N           panel port (default: random, asked interactively)
#   --http | --https   panel protocol (default: http)
#   --update           update an existing install, keep its settings
#   --yes              never ask questions (fresh install: random port, http)
# The options of the local installer (--sync-key, --replace-key, --tunnel ...) are passed through.
set -uo pipefail

REPO="soheilas/fwpanel"
red='\033[0;31m'; green='\033[0;32m'; yellow='\033[0;33m'; cyan='\033[0;36m'; bold='\033[1m'; plain='\033[0m'
ok()   { printf "${green}%s${plain}\n" "$*"; }
info() { printf "${cyan}==>${plain} %s\n" "$*"; }
warn() { printf "${yellow}%s${plain}\n" "$*"; }
die()  { printf "${red}error: %s${plain}\n" "$*" >&2; exit 1; }

VERSION=""; PORT=""; MODE=""; UPDATE=0; YES=0; PASS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --port)    PORT="${2:-}"; shift 2 ;;
    --http)    MODE=http; shift ;;
    --https)   MODE=https; shift ;;
    --update)  UPDATE=1; shift ;;
    --yes|-y)  YES=1; shift ;;
    -h|--help) sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
    --sync-key|--tunnel|--local6|--remote6|--ip) PASS+=("$1" "${2:-}"); shift 2 ;;
    --replace-key) PASS+=("$1"); shift ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

PREFIX="${FWPANEL_PREFIX:-}"      # file-only test mode (used by the automated tests)
[ "$(id -u)" = 0 ] || die "please run as root (sudo -i, then run the command again)"

printf "${bold}${cyan}"
cat <<'BANNER'
   __                                  _
  / _|_      ___ __   __ _ _ __   ___| |
 | |_\ \ /\ / / '_ \ / _` | '_ \ / _ \ |
 |  _|\ V  V /| |_) | (_| | | | |  __/ |
 |_|   \_/\_/ | .__/ \__,_|_| |_|\___|_|
              |_|    port forward panel
BANNER
printf "${plain}\n"

command -v apt-get >/dev/null 2>&1 || warn "this installer is made for Debian / Ubuntu; other systems may not work."

need_pkgs=()
for c in curl tar python3 iptables openssl; do command -v "$c" >/dev/null 2>&1 || need_pkgs+=("$c"); done
if [ ${#need_pkgs[@]} -gt 0 ] && [ -z "$PREFIX" ]; then
  info "installing: ${need_pkgs[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq "${need_pkgs[@]}" >/dev/null || die "could not install ${need_pkgs[*]}"
fi

# ---- pick the version to install
if [ -n "$VERSION" ]; then
  REF="refs/tags/$VERSION"
else
  TAG="$(curl -fsSL --connect-timeout 8 -m 15 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  if [ -n "$TAG" ]; then REF="refs/tags/$TAG"; VERSION="$TAG"; else REF="refs/heads/main"; VERSION="main"; fi
fi
info "downloading fwpanel $VERSION"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl -fsSL --connect-timeout 10 -m 120 "https://github.com/$REPO/archive/$REF.tar.gz" | tar -xz -C "$TMP" \
  || die "download failed. Is GitHub reachable from this server? (On Iranian servers it often is not: use the offline installer created by your foreign panel.)"
SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1)"
[ -f "$SRC/src/fwpanel.py" ] || die "unexpected download layout"

# ---- flat staging tree: exactly what the local installer expects
ST="$TMP/stage"; mkdir -p "$ST"
cp "$SRC/src/fwpanel.py" "$ST/"; cp -r "$SRC/src/web" "$ST/web"
cp "$SRC/scripts/local-install.sh" "$ST/install.sh"; cp "$SRC/scripts/uninstall.sh" "$SRC/scripts/fwpanel.sh" "$ST/"

CONF="$PREFIX/etc/fwpanel"
EXISTING=0; [ -f "$CONF/config.json" ] && EXISTING=1
if [ "$EXISTING" = 1 ] && [ "$UPDATE" = 0 ]; then info "existing installation found: updating and keeping your settings"; UPDATE=1; fi

ARGS=()
if [ "$EXISTING" = 0 ]; then
  if [ -z "$PORT" ]; then
    RANDPORT="$(shuf -i 20000-60000 -n 1 2>/dev/null || echo $((20000 + RANDOM % 40000)))"
    if [ "$YES" = 0 ] && [ -t 0 ]; then
      echo
      read -r -p "Choose the panel port yourself? [y/N] (N = random port $RANDPORT): " a
      if [[ "$a" =~ ^[Yy] ]]; then
        while true; do read -r -p "Panel port [1-65535]: " PORT; [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] && break; echo "invalid port"; done
      else PORT="$RANDPORT"; fi
    else PORT="$RANDPORT"; fi
  fi
  if [ -z "$MODE" ]; then
    MODE=http
    if [ "$YES" = 0 ] && [ -t 0 ]; then
      read -r -p "Serve the panel over HTTPS with a self-signed certificate? [y/N] (N = plain HTTP): " a
      [[ "$a" =~ ^[Yy] ]] && MODE=https
    fi
  fi
fi
[ -n "$PORT" ] && ARGS+=(--port "$PORT")
[ -n "$MODE" ] && ARGS+=("--$MODE")

info "installing"
OUT="$(FWPANEL_PREFIX="$PREFIX" bash "$ST/install.sh" "${ARGS[@]}" "${PASS[@]}" 2>&1)"; RC=$?
printf '%s\n' "$OUT" | sed 's/^/    /'
[ $RC -eq 0 ] || die "installation failed (see the output above)"
[ -z "$PREFIX" ] || { ok "file-only install into $PREFIX done"; exit 0; }

PASSWORD="$(printf '%s\n' "$OUT" | sed -n 's/^PASSWORD=//p' | head -1)"
ADDR="$(printf '%s\n' "$OUT" | sed -n 's/^fwpanel is running: *//p' | head -1)"

echo
INSTALLED="$(sed -n 's/^VERSION = "\(.*\)"/\1/p' /opt/fwpanel/fwpanel.py | head -1)"
printf "${green}${bold}fwpanel %s is installed and running.${plain}\n" "${INSTALLED:-$VERSION}"
echo "------------------------------------------------------------"
echo "  Panel address : ${ADDR:-see: fwpanel info}"
if [ -n "$PASSWORD" ]; then
  echo "  Password      : $PASSWORD"
  warn "  Save the password now: it is shown only once (change it any time with: fwpanel password)."
else
  echo "  Password      : unchanged (reset it with: fwpanel password)"
fi
echo "------------------------------------------------------------"
echo "  fwpanel               - open the management menu"
echo "  fwpanel status|log    - state and logs"
echo "  fwpanel port|password - change the port / the password"
echo "  fwpanel update        - update to the latest release"
echo "  fwpanel uninstall     - remove it"
echo "------------------------------------------------------------"
exit 0
