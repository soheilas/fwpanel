#!/usr/bin/env bash
# fwpanel-setup - set up everything, 0 to 100, from one command:
#   panel on the foreign server, panel on every Iran server, the GRE6 tunnel between them,
#   automatic rule sync, and (optionally) your first forwards.
#
# Run it from any Linux/macOS machine (or WSL / Git Bash) that can SSH to the servers as root,
# or directly ON the foreign server with --foreign local.
#
#   bash <(curl -Ls https://raw.githubusercontent.com/soheilas/fwpanel/main/scripts/setup-servers.sh) \
#        --foreign 1.2.3.4 --iran 5.6.7.8 [--iran 9.9.9.9] [options]
#
# The panel files are downloaded once on the machine you run this on and pushed over SSH: the servers
# themselves do not need GitHub access (important for Iranian servers).
#
#   --foreign HOST[:SSHPORT]   foreign server ("local" = the machine you run this on)
#   --iran HOST[:SSHPORT]      Iran server; repeat the option for several servers
#   --key FILE                 SSH private key (otherwise ssh asks for the passwords itself)
#   --panel-port N             panel port on every server (default 9443)
#   --https                    serve panels over HTTPS (self-signed) instead of plain HTTP
#   --no-tunnel                skip the GRE6 tunnel: Iran forwards straight to the foreign server's public IP
#   --tunnel-net A.B.C         private range for tunnels (default 192.168.70) - one /30 per Iran server
#   --foreign-ip IP            public IPv4 of the foreign server (only needed with --no-tunnel or behind NAT)
#   --rule PORT=IP[:DPORT]     create a forward on the foreign panel (TCP+UDP); repeatable. DPORT defaults to PORT
#   --replace-key              take over an Iran server that already receives rules from another panel
#   --yes                      do not ask for confirmation
#
# Needs: root on every server, Debian/Ubuntu, internet access on the servers for apt (only if python3/iptables are missing).
set -uo pipefail

[ "${BASH_VERSINFO[0]:-0}" -ge 4 ] || { echo "error: bash 4+ is required (on macOS: brew install bash, or run it on a Linux box / WSL)" >&2; exit 1; }

FOREIGN=""; IRANS=(); KEY=""; PPORT=9443; SCHEME=http; TUNNEL=1; NET=192.168.70; FIP=""; RULES=(); YES=0; REPLACE=""

die()  { echo "error: $*" >&2; exit 1; }
say()  { echo; echo "==> $*"; }
info() { echo "    $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --foreign)    FOREIGN="${2:-}"; shift 2 ;;
    --iran)       IRANS+=("${2:-}"); shift 2 ;;
    --key)        KEY="${2:-}"; shift 2 ;;
    --panel-port) PPORT="${2:-}"; shift 2 ;;
    --https)      SCHEME=https; shift ;;
    --no-tunnel)  TUNNEL=0; shift ;;
    --tunnel-net) NET="${2:-}"; shift 2 ;;
    --foreign-ip) FIP="${2:-}"; shift 2 ;;
    --rule)       RULES+=("${2:-}"); shift 2 ;;
    --replace-key) REPLACE="--replace-key"; shift ;;
    --yes|-y)     YES=1; shift ;;
    -h|--help)    sed -n '2,24p' "$0"; exit 0 ;;
    *)            die "unknown option: $1 (try --help)" ;;
  esac
done
[ -n "$FOREIGN" ] || die "--foreign is required (try --help)"
[ ${#IRANS[@]} -gt 0 ] || die "give at least one --iran server"
[[ "$PPORT" =~ ^[0-9]+$ ]] && [ "$PPORT" -ge 1 ] && [ "$PPORT" -le 65535 ] || die "bad --panel-port"
[[ "$NET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--tunnel-net must look like 192.168.70"
[ ${#IRANS[@]} -le 60 ] || die "too many Iran servers for one tunnel range"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- ssh helpers
SSHBASE=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -o ServerAliveInterval=15)
[ -z "$KEY" ] || SSHBASE+=(-i "$KEY" -o IdentitiesOnly=yes)
case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) ;; *) SSHBASE+=(-o ControlMaster=auto -o "ControlPath=$WORK/cm-%C" -o ControlPersist=10m) ;; esac

host_of() { local t="$1"; echo "${t%%:*}"; }
port_of() { local t="$1"; if [[ "$t" == *:* ]]; then echo "${t##*:}"; else echo 22; fi; }

# run a command on a server: rsh TARGET command...   (TARGET "local" runs on this machine)
rsh() {
  local t="$1"; shift
  if [ "$t" = local ]; then bash -c "$*"; else ssh "${SSHBASE[@]}" -p "$(port_of "$t")" "root@$(host_of "$t")" "$@"; fi
}
fadmin() { rsh "$FOREIGN" "python3 /opt/fwpanel/fwpanel.py admin $*"; }          # call the foreign panel API (stdin = body when last arg is -)
jget()   { rsh "$FOREIGN" "python3 -c 'import sys,json; d=json.load(sys.stdin); print($1)'"; }   # json from stdin

# ---------------------------------------------------------------- payload (this script carries the panel)
REPO="soheilas/fwpanel"
extract_payload() {
  if awk '/^__PAYLOAD__$/ {f=1} END {exit !f}' "$0" 2>/dev/null; then          # single-file build: the panel is inside this script
    awk '/^__PAYLOAD__$/ {p=1; next} p' "$0" | base64 -d > "$WORK/payload.tgz" || die "cannot unpack the embedded panel"
    return
  fi
  local st="$WORK/stage" d src; mkdir -p "$st"
  d="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
  if [ -f "$d/../src/fwpanel.py" ]; then                                        # run from a repo checkout
    src="$d/.."
  else                                                                          # run through curl: fetch the repo here
    command -v curl >/dev/null || die "curl is required on this machine"
    info "downloading fwpanel from GitHub"
    curl -fsSL --connect-timeout 10 -m 120 "https://github.com/$REPO/archive/refs/heads/main.tar.gz" | tar -xz -C "$WORK" || die "download failed (GitHub unreachable from this machine?)"
    src="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d -name 'fwpanel-*' | head -1)"
    [ -f "$src/src/fwpanel.py" ] || die "unexpected download layout"
  fi
  cp "$src/src/fwpanel.py" "$st/"; cp -r "$src/src/web" "$st/web"
  cp "$src/scripts/local-install.sh" "$st/install.sh"; cp "$src/scripts/uninstall.sh" "$src/scripts/fwpanel.sh" "$st/"
  tar -czf "$WORK/payload.tgz" -C "$st" .
}

push_install() {   # push_install TARGET "install.sh args"  -> prints the installer output, sets LAST_OUT
  local t="$1" args="$2"
  if [ "$t" = local ]; then
    mkdir -p /root/.fwpanel-setup && tar -xz -C /root/.fwpanel-setup < "$WORK/payload.tgz"
  else
    rsh "$t" "mkdir -p /root/.fwpanel-setup && tar -xz -C /root/.fwpanel-setup" < "$WORK/payload.tgz" || return 1
  fi
  LAST_OUT="$(rsh "$t" "bash /root/.fwpanel-setup/install.sh $args 2>&1")"; local rc=$?
  rsh "$t" "rm -rf /root/.fwpanel-setup" >/dev/null 2>&1
  printf '%s\n' "$LAST_OUT" | sed 's/^/    | /'
  return $rc
}

pw_of() { printf '%s\n' "$1" | sed -n 's/^PASSWORD=//p' | head -1; }
v6_static_first() { awk '{print (($0 ~ /ff:fe/) ? "1 " : "0 ") $0}' | sort | cut -d' ' -f2; }
v6_list() { rsh "$1" "ip -6 -o addr show scope global 2>/dev/null | sed -n 's/.*inet6 \\([0-9a-f:]*\\)\\/.*/\\1/p'" | v6_static_first; }

# ---------------------------------------------------------------- plan
say "plan"
info "foreign server : $FOREIGN"
for i in "${!IRANS[@]}"; do info "iran server $((i+1))  : ${IRANS[$i]}"; done
info "panels         : $SCHEME, port $PPORT"
info "connection     : $([ "$TUNNEL" = 1 ] && echo "GRE6 tunnel (range $NET.0/24), automatic IPv6 selection" || echo "direct over the public internet (no tunnel)")"
[ ${#RULES[@]} -eq 0 ] || info "first forwards : ${RULES[*]}"
if [ "$YES" != 1 ]; then read -r -p "    continue? [y/N] " a; [[ "$a" =~ ^[Yy] ]] || { echo "aborted."; exit 1; }; fi

extract_payload

# ---------------------------------------------------------------- 1. preflight
say "1/6 checking SSH access"
for t in "$FOREIGN" "${IRANS[@]}"; do
  out="$(rsh "$t" 'echo "uid=$(id -u) os=$(. /etc/os-release 2>/dev/null; echo ${ID:-?}) py=$(command -v python3 >/dev/null && echo yes || echo no)"' 2>&1)" \
    || die "cannot SSH to $t as root: $out"
  info "$t: $out"
  [[ "$out" == *"uid=0"* ]] || die "$t: you must connect as root"
done

for t in "${IRANS[@]}"; do
  HAS="$(rsh "$t" "python3 -c \"import json;print(1 if json.load(open('/etc/fwpanel/config.json')).get('sync_secret') else 0)\" 2>/dev/null || echo 0")"
  if [ "$HAS" = 1 ] && [ -z "$REPLACE" ]; then
    die "$t already receives rules from another panel. Nothing was changed. Use --replace-key to take it over (the other panel will stop syncing to it)."
  fi
done

# ---------------------------------------------------------------- 2. foreign panel
say "2/6 installing the panel on the foreign server"
push_install "$FOREIGN" "--port $PPORT --$SCHEME" || die "panel installation failed on $FOREIGN"
FPW="$(pw_of "$LAST_OUT")"
[ -n "$FPW" ] || info "(panel was already installed here: password unchanged)"
sleep 2
rsh "$FOREIGN" "python3 /opt/fwpanel/fwpanel.py admin GET /api/settings" > "$WORK/fsettings.json" || die "the foreign panel does not answer"
FIPV4="$(jget 'd.get("ipv4","")' < "$WORK/fsettings.json")"
[ -n "$FIP" ] || FIP="$FIPV4"
info "foreign public IPv4: ${FIP:-unknown}"
[ "$TUNNEL" = 1 ] || [ -n "$FIP" ] || die "could not detect the foreign IPv4: pass --foreign-ip"

# ---------------------------------------------------------------- 3. Iran servers
declare -a LINK_IDS=() IRAN_PW=() IRAN_URL=() IRAN_NOTE=()
for i in "${!IRANS[@]}"; do
  IT="${IRANS[$i]}"; IH="$(host_of "$IT")"; N=$((i+1)); B=$((i*4))
  say "3/6 Iran server $N ($IH): tunnel + link"
  USE_T=0; FV6=""; IV6=""
  if [ "$TUNNEL" = 1 ]; then
    mapfile -t FL < <(v6_list "$FOREIGN"); mapfile -t IL < <(v6_list "$IT")
    info "IPv6 on foreign: ${FL[*]:-none}"; info "IPv6 on iran   : ${IL[*]:-none}"
    for fv in "${FL[@]:-}"; do
      for iv in "${IL[@]:-}"; do
        [ -n "$fv" ] && [ -n "$iv" ] || continue
        if rsh "$FOREIGN" "ping -6 -c2 -W2 -I $fv $iv >/dev/null 2>&1" && rsh "$IT" "ping -6 -c2 -W2 -I $iv $fv >/dev/null 2>&1"; then
          FV6="$fv"; IV6="$iv"; USE_T=1; break 2
        fi
      done
    done
    if [ "$USE_T" = 1 ]; then info "working IPv6 pair: $FV6 <-> $IV6"; else info "WARNING: no working IPv6 path between the servers; falling back to a direct connection for this server"; fi
  fi
  TNAME="tun$N"; TF="$NET.$((B+2))"; TI="$NET.$((B+1))"
  if [ "$USE_T" = 1 ]; then
    BODY="{\"name\":\"Iran-$N\",\"port\":$PPORT,\"scheme\":\"$SCHEME\",\"iran_ip\":\"$IH\",\"target_ip\":\"$FIP\",\"tunnel\":{\"enabled\":true,\"name\":\"$TNAME\",\"foreign_v6\":\"$FV6\",\"iran_v6\":\"$IV6\",\"foreign_ip\":\"$TF\",\"iran_ip\":\"$TI\"}}"
  else
    [ -n "$FIP" ] || die "need --foreign-ip for a direct connection"
    BODY="{\"name\":\"Iran-$N\",\"port\":$PPORT,\"scheme\":\"$SCHEME\",\"iran_ip\":\"$IH\",\"target_ip\":\"$FIP\"}"
  fi
  RESP="$(printf '%s' "$BODY" | fadmin POST /api/links/new-iran - 2>&1)" || die "creating the link failed: $RESP"
  LID="$(printf '%s' "$RESP" | jget 'd["link"]["id"]')" || die "unexpected answer: $RESP"
  LINK_IDS+=("$LID")
  info "link #$LID created$([ "$USE_T" = 1 ] && echo " (tunnel $TNAME: foreign $TF <-> iran $TI)")"

  say "4/6 Iran server $N ($IH): installing the panel"
  fadmin GET "/api/links/$LID/installer" > "$WORK/iran$N.sh" || die "could not generate the Iran installer"
  rsh "$IT" "cat > /root/.fwp-iran.sh" < "$WORK/iran$N.sh" || die "upload to $IH failed"
  IOUT="$(rsh "$IT" "bash /root/.fwp-iran.sh $REPLACE 2>&1; rm -f /root/.fwp-iran.sh")"; IRC=$?
  printf '%s\n' "$IOUT" | sed 's/^/    | /'
  [ $IRC -eq 0 ] || die "installation failed on $IH"
  IRAN_PW+=("$(pw_of "$IOUT")")
  if [ "$USE_T" = 1 ]; then IRAN_URL+=("$SCHEME://$IH:$PPORT/"); IRAN_NOTE+=("tunnel $TNAME  $TI <-> $TF"); else IRAN_URL+=("$SCHEME://$IH:$PPORT/"); IRAN_NOTE+=("direct to $FIP"); fi
done

# ---------------------------------------------------------------- 5. forwards
if [ ${#RULES[@]} -gt 0 ]; then
  say "5/6 creating the first forwards on the foreign panel"
  for r in "${RULES[@]}"; do
    LP="${r%%=*}"; DEST="${r#*=}"; DIP="${DEST%%:*}"; DP="$LP"; [[ "$DEST" == *:* ]] && DP="${DEST##*:}"
    [[ "$LP" =~ ^[0-9]+$ ]] && [[ "$DP" =~ ^[0-9]+$ ]] || die "bad --rule: $r (use PORT=IP[:DPORT])"
    OUT="$(printf '{"proto":"both","listen_port":%s,"dest_ip":"%s","dest_port":%s,"comment":"fwpanel-setup"}' "$LP" "$DIP" "$DP" | fadmin POST /api/rules - 2>&1)" \
      && info "forward $LP -> $DIP:$DP created" || info "forward $r FAILED: $OUT"
  done
else
  say "5/6 no --rule given: create forwards later in the foreign panel"
fi

# ---------------------------------------------------------------- 6. sync + verify
say "6/6 syncing and verifying"
sleep 2
for i in "${!IRANS[@]}"; do
  LID="${LINK_IDS[$i]}"
  ST="$(fadmin POST "/api/links/$LID/sync" 2>&1)"
  info "Iran $((i+1)) sync: $(printf '%s' "$ST" | rsh "$FOREIGN" "python3 -c 'import sys,json; s=json.load(sys.stdin)[\"status\"]; print((\"OK \" if s[\"ok\"] else \"FAILED \")+s[\"msg\"])'" 2>/dev/null || echo "$ST")"
done
for i in "${!IRANS[@]}"; do
  TF="$NET.$((i*4+2))"; TI="$NET.$((i*4+1))"
  if [[ "${IRAN_NOTE[$i]}" == tunnel* ]]; then
    rsh "$FOREIGN" "ping -c2 -W2 $TI >/dev/null 2>&1" && info "tunnel $TF <-> $TI : OK" || info "tunnel $TF <-> $TI : NO REPLY (check IPv6 / firewall)"
  fi
done

# ---------------------------------------------------------------- summary
PUBHOST="$(host_of "$FOREIGN")"; [ "$FOREIGN" = local ] && PUBHOST="${FIP:-this-server}"
echo
echo "============================================================"
echo " fwpanel is ready"
echo "============================================================"
echo " foreign panel : $SCHEME://$PUBHOST:$PPORT/"
echo "   password    : ${FPW:-<unchanged, panel was already installed>}"
for i in "${!IRANS[@]}"; do
  echo " iran $((i+1)) panel  : ${IRAN_URL[$i]}   (${IRAN_NOTE[$i]})"
  echo "   password    : ${IRAN_PW[$i]:-<unchanged, panel was already installed>}"
done
echo
echo " Create forwards in the FOREIGN panel only: they are copied to every Iran server automatically."
echo " Change the passwords from Settings after the first login. Save this output now."
exit 0
