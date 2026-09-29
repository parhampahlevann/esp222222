#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager v3.0 - point-to-point tunnel over IP protocol 50 (ESP)
#                            + Rathole reverse tunnel carried inside it
#
#    Iran server   : 10.10.10.2   (menu option 1)   rathole CLIENT
#    Kharej client : 10.10.10.1   (menu option 2)   rathole SERVER
#
#  How it works
#   * Linux kernel XFRM (IPsec ESP) + an "xfrm interface" (espt0) on each side.
#     No IKE daemon and no handshake: only encrypted ESP packets hit the wire.
#   * Cipher: AES-256-GCM in the kernel (AES-NI accelerated, very light).
#   * The master key is derived from a built-in token (same on both servers, so
#     nothing has to be copied). Per-direction session keys are derived from it
#     and rotate every hour with zero downtime (both sides derive the same keys
#     from the UTC clock; previous/current/next hour inbound SAs are loaded).
#   * The xfrm policies only allow traffic between 10.10.10.2 <-> 10.10.10.1.
#   * The public (outer) address of the peer can be IPv4 or IPv6.
#   * Optional fallback transport: ESP-in-UDP (NAT / protocol 50 blocked).
#
#  v3.0 reversed rathole tunnel
#   * The rathole core (official release, downloaded automatically) is installed
#     on BOTH servers.
#   * The Iran rathole CLIENT dials OUT to 10.10.10.1:2089 (source 10.10.10.2).
#     That connection travels inside the ESP tunnel, so it is encrypted by ESP
#     and the control port is never reachable from the internet.
#   * The Kharej rathole SERVER (bound to 10.10.10.1:2089) opens the public
#     ports. Every connection to those ports is pushed through the reverse
#     tunnel to the Iran server, which hands it to the local service
#     (default target 127.0.0.1:<port>, configurable).
#   * Ports, forward protocol (tcp/udp/both) and transport (ESP / ESP-in-UDP) are
#     asked on BOTH servers - enter the same values on both.
#   * Rathole runs as its own systemd unit (esp-tunnel-rathole) that depends on
#     the ESP service. The rathole auth token is derived from the master key.
#
#  Watchdog (unchanged from v1.1)
#   * asymmetric-blackout detector (TX moving, RX frozen) -> early rebuild
#   * xfrm error counters polled every cycle, forensic snapshot before rebuilds
#   * unconditional preventive rebuild every FORCE_REBUILD_SEC (default 12h)
#   * on-demand health check (Live Log -> option 4)
#
#  Usage:  bash esp-tunnel.sh        (interactive menu, run as root)
#          esp-tunnel                (after first install)
# ==============================================================================

APP="esp-tunnel"
VERSION="3.0"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"

# rathole (reverse tunnel engine)
LIB_DIR="/usr/local/lib/${APP}"
RH_BIN="${LIB_DIR}/rathole"
RH_CONF="${CONF_DIR}/rathole.toml"
RH_UNIT="${APP}-rathole"
RH_UNIT_FILE="/etc/systemd/system/${RH_UNIT}.service"
RH_REPO="rathole-org/rathole"
RH_FALLBACK_TAG="v0.5.0"          # used when the latest tag cannot be resolved
RH_HB_INTERVAL=15                 # server heartbeat (s)  - must stay below RH_HB_TIMEOUT
RH_HB_TIMEOUT=45                  # client heartbeat timeout (s)
MAX_FWD_PORTS=300                 # rathole needs one service per port

# fixed values - nothing is asked for these
DEFAULT_RH_PORT=2089              # rathole control port (TCP, on the tunnel address only)
DEFAULT_UDP_PORT=2089             # ESP-in-UDP port (only used when that transport is chosen)
DEFAULT_TOKEN="djF8YjAzYTc3ZTllMTkzY2VhMmQ3YTVhYmIxNTY1MDg4YzEzOGJlMzYyNjY0MTk0"

IF_NAME="espt0"
IF_ID=42
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
RH_SRV_IP="$IP_KHAREJ"            # the rathole SERVER lives on the Kharej tunnel address
NET_PREFIX=30
EPOCH_LEN=3600          # key rotation period (seconds)
SEQ_STEP=1000000        # initial ESP sequence seed per second inside an epoch
MTU_ESP=1400
MTU_UDP=1380
DEFAULT_FORCE_REBUILD_SEC=43200   # 12h - unconditional preventive rebuild, 0 = disabled
DEFAULT_RX_STALL_SEC=45           # seconds of "tx moving, rx frozen" before an early rebuild

# ---- runtime state (filled by load_config) -----------------------------------
ROLE=""; TOKEN=""; MASTER=""; PEER_IP=""; MODE="esp"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_ESP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0
FORCE_REBUILD_SEC="$DEFAULT_FORCE_REBUILD_SEC"; RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"
RH_PORT="$DEFAULT_RH_PORT"; RH_TARGET="127.0.0.1"; RH_AUTH=""

# ---- daemon watchdog state (globals; meaningful only while cmd_daemon runs) --
RX0=0; TX0=0; RX_STALL_START=0; LAST_REBUILD=0; FAILS=0; PEER_STATE="unknown"; XPREV=""

PY_UDP='
import socket, sys
port = int(sys.argv[1])
fam = socket.AF_INET6 if len(sys.argv) > 2 and sys.argv[2] == "6" else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind(("::" if fam == socket.AF_INET6 else "0.0.0.0", port))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP = UDP_ENCAP_ESPINUDP
while True:
    try:
        s.recvfrom(65535)
    except Exception:
        pass
'

# ------------------------------------------------------------------------------
#  Small helpers
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'; C_G=$'\e[1;32m'; C_Y=$'\e[1;33m'; C_B=$'\e[1;36m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
fi
info() { echo "${C_B}[*]${C_0} $*"; }
ok()   { echo "${C_G}[+]${C_0} $*"; }
warn() { echo "${C_Y}[!]${C_0} $*" >&2; }
err()  { echo "${C_R}[x]${C_0} $*" >&2; }
log()  { echo "[${APP}] $*"; }          # daemon logs (journald adds timestamps)
have() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Please run as root (sudo -i)."
    exit 1
  fi
}

confirm() {   # confirm "question" [y|n]   (default answer)
  local def=${2:-n} a p="[y/N]"
  [[ $def == y ]] && p="[Y/n]"
  read -r -p "$1 $p " a
  a=${a:-$def}
  [[ $a =~ ^[Yy] ]]
}

pause() { read -r -p "Press Enter to continue..." _; }

valid_ip() {
  local o
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    (( 10#$o <= 255 )) || return 1
  done
  return 0
}

valid_ip6() {
  local a=$1 h rest n=0 dbl=0
  local -a g=()
  [[ $a == *:* && $a =~ ^[0-9a-fA-F:]+$ ]] || return 1
  [[ $a == "::" ]] && return 1
  [[ $a == *:::* ]] && return 1
  [[ $a == :* && $a != ::* ]] && return 1
  [[ $a == *: && $a != *:: ]] && return 1
  if [[ $a == *::* ]]; then
    dbl=1
    rest=${a#*::}
    [[ $rest == *::* ]] && return 1
  fi
  IFS=':' read -ra g <<< "$a"
  for h in "${g[@]}"; do
    [[ -z $h ]] && continue
    (( ${#h} <= 4 )) || return 1
    n=$((n + 1))
  done
  if (( dbl )); then
    (( n <= 7 )) || return 1
  else
    (( n == 8 )) || return 1
  fi
  return 0
}

is_private_ip() {
  [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]
}

valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

# "1080, 443 ,8000-8100"  ->  "1080,443,8000-8100"   (returns 1 if invalid)
norm_ports() {
  local raw=${1//[[:space:]]/} spec a b
  local -a out=() specs=()
  raw=${raw//،/,}
  [[ -n $raw ]] || return 1
  IFS=',' read -ra specs <<< "$raw"
  for spec in "${specs[@]}"; do
    [[ -z $spec ]] && continue
    if [[ $spec =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
      valid_port "$a" && valid_port "$b" && (( 10#$a <= 10#$b )) || return 1
      out+=("$((10#$a))-$((10#$b))")
    else
      valid_port "$spec" || return 1
      out+=("$((10#$spec))")
    fi
  done
  (( ${#out[@]} > 0 )) || return 1
  local IFS=,
  echo "${out[*]}"
}

ports_include() {   # ports_include "1080,8000-8100" 8050
  local spec a b
  local -a specs=()
  IFS=',' read -ra specs <<< "$1"
  for spec in "${specs[@]}"; do
    if [[ $spec == *-* ]]; then a=${spec%-*}; b=${spec#*-}; else a=$spec; b=$spec; fi
    (( $2 >= a && $2 <= b )) && return 0
  done
  return 1
}

# "1080,8000-8002" -> one port per line, sorted, no duplicates
expand_ports() {
  local spec a b p
  local -a specs=()
  IFS=',' read -ra specs <<< "$1"
  {
    for spec in "${specs[@]}"; do
      [[ -z $spec ]] && continue
      if [[ $spec == *-* ]]; then a=${spec%-*}; b=${spec#*-}; else a=$spec; b=$spec; fi
      for (( p = 10#$a; p <= 10#$b; p++ )); do echo "$p"; done
    done
  } | sort -nu
}

ssh_ports() {
  local p
  p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
  [[ -n $p ]] || p=$(ss -Hltnp 2>/dev/null | awk '/sshd/{n=split($4,a,":"); print a[n]}')
  [[ -n $p ]] || p=22
  echo "$p ${SSH_CONNECTION##* }"
}

kdf() { printf '%s' "$1" | sha512sum | awk '{print $1}'; }

# Sets LOCAL_ADDR (our source address towards $1, IPv4 or IPv6) and WAN_DEV
route_info() {
  local out fam=4
  [[ $1 == *:* ]] && fam=6
  out=$(ip -"$fam" route get "$1" 2>/dev/null | head -n1)
  LOCAL_ADDR=$(awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")
  WAN_DEV=$(awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")
  [[ -n $LOCAL_ADDR && -n $WAN_DEV ]]
}

rh_role_name() { if [[ $ROLE == kharej ]]; then echo server; else echo client; fi; }

# ------------------------------------------------------------------------------
#  Config
# ------------------------------------------------------------------------------
load_config() {
  [[ -r $CONF ]] || return 1
  TOKEN=""; PEER_IP=""; RH_TARGET=""
  # shellcheck disable=SC1090
  source "$CONF"
  MODE=${MODE:-esp}; FWD_PROTO=${FWD_PROTO:-both}
  FORCE_REBUILD_SEC=${FORCE_REBUILD_SEC:-$DEFAULT_FORCE_REBUILD_SEC}
  RX_STALL_SEC=${RX_STALL_SEC:-$DEFAULT_RX_STALL_SEC}
  RH_TARGET=${RH_TARGET:-127.0.0.1}
  # fixed ports: never read from the config so both sides always agree
  RH_PORT=$DEFAULT_RH_PORT; UDP_PORT=$DEFAULT_UDP_PORT
  PEER_PUB=$PEER_IP
  case $ROLE in
    iran)   LOCAL_INNER=$IP_IRAN;   PEER_INNER=$IP_KHAREJ; OUT_LABEL=i2k; IN_LABEL=k2i ;;
    kharej) LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN;   OUT_LABEL=k2i; IN_LABEL=i2k ;;
    *) return 1 ;;
  esac
  # configs written by esp-tunnel 1.x / 2.x have no TOKEN/PEER_IP -> must be re-installed
  [[ -n $TOKEN && -n $PEER_PUB ]] || return 1
  MASTER=$(kdf "${TOKEN}|master")
  RH_AUTH=$(kdf "${MASTER}|rathole|auth" | cut -c1-40)
  if [[ $MODE == udp ]]; then MTU=$MTU_UDP; else MTU=$MTU_ESP; fi
  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      echo "# ${APP} config - contains the secret token, keep private"
      printf 'ROLE=%q\n'      "$ROLE"
      printf 'TOKEN=%q\n'     "$TOKEN"
      printf 'PEER_IP=%q\n'   "$PEER_IP"
      printf 'MODE=%q\n'      "$MODE"
      printf 'PORTS=%q\n'     "$PORTS"
      printf 'FWD_PROTO=%q\n' "$FWD_PROTO"
      printf 'FORCE_REBUILD_SEC=%q\n' "$FORCE_REBUILD_SEC"
      printf 'RX_STALL_SEC=%q\n'      "$RX_STALL_SEC"
      printf 'RH_TARGET=%q\n' "$RH_TARGET"
    } > "$CONF"
  )
  chmod 600 "$CONF"
}

# ------------------------------------------------------------------------------
#  Pre-flight: dependencies + kernel support
# ------------------------------------------------------------------------------
ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()
  have systemctl || { err "systemd is required (systemctl not found)."; return 1; }
  for c in ip iptables ping ss sha256sum sha512sum awk od head; do
    have "$c" || missing+=("$c")
  done
  if [[ $PEER_PUB == *:* ]] && ! have ip6tables; then missing+=(ip6tables); fi
  if [[ $MODE == udp ]] && ! have python3; then missing+=(python3); fi
  if ! rh_works "$RH_BIN"; then
    for c in unzip curl; do have "$c" || missing+=("$c"); done
  fi
  (( ${#missing[@]} == 0 )) && return 0

  if   have apt-get; then pm=apt
  elif have dnf;     then pm=dnf
  elif have yum;     then pm=yum
  fi
  [[ -n $pm ]] || { err "Missing commands: ${missing[*]} (no supported package manager found)."; return 1; }

  for c in "${missing[@]}"; do
    case $c in
      ip|ss)   [[ $pm == apt ]] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      ping)    [[ $pm == apt ]] && pkgs+=(iputils-ping) || pkgs+=(iputils) ;;
      iptables|ip6tables) pkgs+=(iptables) ;;
      python3|unzip|curl) pkgs+=("$c") ;;
      *)       pkgs+=(coreutils) ;;
    esac
  done
  info "Installing missing packages: ${pkgs[*]}"
  if [[ $pm == apt ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
  else
    timeout 300 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1
  fi
  for c in "${missing[@]}"; do
    have "$c" || { err "Could not install '$c'. Install it manually and run again."; return 1; }
  done
  return 0
}

load_modules() {
  local m
  for m in xfrm_interface xfrm_user esp4 esp6 gcm aesni_intel nf_conntrack xt_TCPMSS ip6table_filter; do
    modprobe -q "$m" 2>/dev/null
  done
  return 0
}

check_kernel() {
  local t="espchk0" out virt k
  virt=$(systemd-detect-virt 2>/dev/null)
  case $virt in
    openvz|lxc|lxc-libvirt) warn "Virtualization '$virt' detected - XFRM/IPsec normally does NOT work inside containers." ;;
  esac
  load_modules
  ip link del "$t" 2>/dev/null
  if ! out=$(ip link add "$t" type xfrm dev lo if_id 4242 2>&1); then
    err "This kernel has no XFRM-interface support: $out"
    err "Needs Linux >= 4.19 (uname -r) on a real/KVM server (not OpenVZ/LXC)."
    return 1
  fi
  ip link del "$t" 2>/dev/null
  k=$(printf '%072d' 0)
  if ! out=$(ip xfrm state add src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 mode tunnel \
             aead 'rfc4106(gcm(aes))' "0x$k" 128 2>&1); then
    err "Kernel lacks AES-GCM ESP support: $out"
    return 1
  fi
  ip xfrm state delete src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 2>/dev/null

  if [[ $PEER_PUB == *:* ]]; then
    # the peer is reached over IPv6: the kernel must be able to build ESP SAs on IPv6 addresses
    if ! out=$(ip xfrm state add src fd00::2 dst fd00::3 proto esp spi 0x1c0ffee1 mode tunnel \
               aead 'rfc4106(gcm(aes))' "0x$k" 128 2>&1); then
      err "Kernel cannot create ESP tunnels over IPv6: $out"
      return 1
    fi
    ip xfrm state delete src fd00::2 dst fd00::3 proto esp spi 0x1c0ffee1 2>/dev/null
    if [[ $MODE == udp ]]; then
      if ! out=$(ip xfrm state add src fd00::2 dst fd00::3 proto esp spi 0x1c0ffee2 mode tunnel \
                 aead 'rfc4106(gcm(aes))' "0x$k" 128 encap espinudp "$UDP_PORT" "$UDP_PORT" :: 2>&1); then
        err "This kernel does not support ESP-in-UDP over IPv6: $out"
        err "Run the install again and choose raw ESP (transport 1) for an IPv6 peer."
        return 1
      fi
      ip xfrm state delete src fd00::2 dst fd00::3 proto esp spi 0x1c0ffee2 2>/dev/null
    fi
  fi
  return 0
}

# ------------------------------------------------------------------------------
#  Firewall (iptables / ip6tables, dedicated chains so cleanup is exact)
# ------------------------------------------------------------------------------
ipt()  { iptables  -w 5 "$@"; }
ipt6() { ip6tables -w 5 "$@"; }

fw_chain_reset() {   # <cmd> <table> <chain> <hook-chain>
  local cmd=$1 t=$2 c=$3 h=$4
  while "$cmd" -w 5 -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  "$cmd" -w 5 -t "$t" -N "$c" 2>/dev/null || "$cmd" -w 5 -t "$t" -F "$c"
  "$cmd" -w 5 -t "$t" -I "$h" 1 -j "$c"
}

fw_chain_remove() {  # <cmd> <table> <chain> <hook-chain>
  local cmd=$1 t=$2 c=$3 h=$4
  while "$cmd" -w 5 -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  "$cmd" -w 5 -t "$t" -F "$c" 2>/dev/null
  "$cmd" -w 5 -t "$t" -X "$c" 2>/dev/null
}

fw_remove() {
  if have iptables; then
    fw_chain_remove iptables filter ESPT_IN   INPUT
    fw_chain_remove iptables filter ESPT_FWD  FORWARD
    fw_chain_remove iptables mangle ESPT_MSS  POSTROUTING
    # nat chains only existed in the legacy DNAT versions - cleaned up if still there
    fw_chain_remove iptables nat    ESPT_PRE  PREROUTING
    fw_chain_remove iptables nat    ESPT_POST POSTROUTING
  fi
  if have ip6tables; then
    fw_chain_remove ip6tables filter ESPT_IN INPUT
  fi
}

fw_apply() {
  # accept the tunnel transport from the peer + everything that comes out of the tunnel
  fw_chain_reset iptables filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT
  if [[ $PEER_PUB != *:* ]]; then
    if [[ $MODE == udp ]]; then
      ipt -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$UDP_PORT" -j ACCEPT
    else
      ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
    fi
  fi
  if [[ $ROLE == kharej ]]; then
    # the rathole control port lives on the tunnel address only - never answer it from the WAN side
    ipt -I ESPT_IN 1 -i "$WAN_DEV" -p tcp -d "$RH_SRV_IP" --dport "$RH_PORT" -j DROP
  fi

  # IPv6 transport (the tunnel itself carries IPv4 only, so only the outer packets need this)
  if [[ $PEER_PUB == *:* ]]; then
    if have ip6tables; then
      fw_chain_reset ip6tables filter ESPT_IN INPUT
      if [[ $MODE == udp ]]; then
        ipt6 -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$UDP_PORT" -j ACCEPT
      else
        ipt6 -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
      fi
    else
      log "WARN: ip6tables not found - the IPv6 transport is not whitelisted in the firewall"
    fi
  fi

  fw_chain_reset iptables filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  # avoid fragmentation / PMTU black holes inside the tunnel
  fw_chain_reset iptables mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  return 0
}

sysctl_apply() {
  printf 'net.ipv4.ip_forward = 1\n' > "$SYSCTL_FILE"
  sysctl -qw net.ipv4.ip_forward=1 >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

# ------------------------------------------------------------------------------
#  Interface / policies / security associations
# ------------------------------------------------------------------------------
iface_setup() {
  local out
  ip link del "$IF_NAME" 2>/dev/null
  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
    log "ERROR: cannot create interface $IF_NAME: $out"; return 1
  fi
  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || { log "ERROR: cannot set $LOCAL_INNER on $IF_NAME"; return 1; }
  ip link set "$IF_NAME" mtu "$MTU" up            || { log "ERROR: cannot bring $IF_NAME up"; return 1; }
  return 0
}

policies_remove() {
  local a b
  for a in "$IP_IRAN" "$IP_KHAREJ"; do
    if [[ $a == "$IP_IRAN" ]]; then b=$IP_KHAREJ; else b=$IP_IRAN; fi
    ip xfrm policy delete src "$a/32" dst "$b/32" dir out if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst "$b/32" dir in  if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" 2>/dev/null
  done
}

policies_setup() {
  local out
  policies_remove
  # out : only 10.10.10.local -> 10.10.10.peer may enter the tunnel
  # in  : only 10.10.10.peer  -> 10.10.10.local is accepted for this host
  # fwd : replies coming back through the tunnel (source must be the peer tunnel IP)
  # (the tmpl addresses are the OUTER addresses and may be IPv4 or IPv6)
  out=$(ip xfrm policy add src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
        tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy out: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy in: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy fwd: $out"; return 1; }
  return 0
}

# SA registry: one line per installed SA -> "<dir> <epoch> <spi> <src> <dst>"
sa_add() {   # sa_add <in|out> <epoch>
  local dir=$1 e=$2 src dst label spi key seq out oa=0.0.0.0
  local -a args=()
  if [[ $dir == out ]]; then src=$LOCAL_ADDR; dst=$PEER_PUB;  label=$OUT_LABEL
  else                       src=$PEER_PUB;   dst=$LOCAL_ADDR; label=$IN_LABEL
  fi
  [[ $PEER_PUB == *:* ]] && oa="::"
  grep -q "^$dir $e " "$REG" 2>/dev/null && return 0

  spi="0x1$(kdf "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
  key=$(kdf "${MASTER}|key|${label}|${e}" | cut -c1-72)     # 32-byte AES key + 4-byte GCM salt
  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        aead 'rfc4106(gcm(aes))' "0x${key}" 128)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" "$oa"); fi
  args+=(if_id "$IF_ID")

  ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
  if [[ $dir == out ]]; then
    # start the sequence counter high inside the epoch so a restart never reuses a GCM nonce
    seq=$(( ($(date +%s) % EPOCH_LEN) * SEQ_STEP ))
    if ! out=$(ip xfrm state add "${args[@]}" replay-oseq "$seq" 2>&1); then
      out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
      log "note: replay-oseq not supported by this iproute2, continuing without it"
    fi
  else
    out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
  fi
  echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

prune_sa() {   # prune_sa <current-epoch>
  local e=$1 dir ep spi src dst keep tmp
  [[ -f $REG ]] || return 0
  tmp=$(mktemp)
  while read -r dir ep spi src dst; do
    [[ -n $spi ]] || continue
    keep=1
    if [[ $dir == out ]]; then
      (( ep != e )) && keep=0
    else
      (( ep < e - 1 || ep > e + 1 )) && keep=0
    fi
    if (( keep )); then
      echo "$dir $ep $spi $src $dst" >> "$tmp"
    else
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
      log "removed expired SA ($dir, epoch $ep)"
    fi
  done < "$REG"
  cat "$tmp" > "$REG"
  rm -f "$tmp"
}

install_epoch() {   # newest outbound first, inbound for previous/current/next epoch
  local e=$1 x
  sa_add out "$e" || return 1
  for x in $((e - 1)) "$e" $((e + 1)); do
    sa_add in "$x" || return 1
  done
  prune_sa "$e"
  return 0
}

sa_flush() {
  local dir ep spi src dst
  if [[ -f $REG ]]; then
    while read -r dir ep spi src dst; do
      [[ -n $spi ]] && ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    done < "$REG"
  fi
  rm -f "$REG"
}

udp_helper_stop() {
  if [[ -f $UDP_PID_FILE ]]; then
    kill "$(cat "$UDP_PID_FILE")" 2>/dev/null
    rm -f "$UDP_PID_FILE"
  fi
}

udp_helper_start() {   # holds the UDP socket that lets the kernel decapsulate ESP-in-UDP
  local fam=4
  [[ $PEER_PUB == *:* ]] && fam=6
  udp_helper_stop
  python3 -c "$PY_UDP" "$UDP_PORT" "$fam" >/dev/null 2>&1 &
  echo $! > "$UDP_PID_FILE"
  sleep 0.7
  if ! kill -0 "$(cat "$UDP_PID_FILE")" 2>/dev/null; then
    log "ERROR: cannot open UDP port $UDP_PORT for ESP-in-UDP (already in use?)"
    return 1
  fi
  return 0
}

teardown_all() {
  fw_remove
  udp_helper_stop
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null
  return 0
}

setup_all() {
  teardown_all
  mkdir -p "$RUN_DIR"; : > "$REG"
  load_modules
  route_info "$PEER_PUB" || { log "ERROR: no route to peer $PEER_PUB"; return 1; }
  iface_setup            || return 1
  policies_setup         || return 1
  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  install_epoch "$CUR_EPOCH" || return 1
  if [[ $MODE == udp ]]; then udp_helper_start || return 1; fi
  sysctl_apply
  fw_apply
  log "tunnel up: role=$ROLE ${LOCAL_INNER} <-> ${PEER_INNER}  transport=$MODE  rathole=$(rh_role_name)  local=$LOCAL_ADDR($WAN_DEV) peer=$PEER_PUB mtu=$MTU epoch=$CUR_EPOCH"
  return 0
}

# ------------------------------------------------------------------------------
#  Rathole core: download, config, service
# ------------------------------------------------------------------------------
rh_arch() {   # asset suffix of the official release for this CPU
  case $(uname -m) in
    x86_64|amd64)  echo "x86_64-unknown-linux-gnu" ;;
    aarch64|arm64) echo "aarch64-unknown-linux-musl" ;;
    armv7l|armv7)  echo "armv7-unknown-linux-musleabihf" ;;
    *) return 1 ;;
  esac
}

rh_works() { [[ -x $1 ]] && "$1" --version >/dev/null 2>&1; }

rh_version() { "$RH_BIN" --version 2>/dev/null | awk '/Build Version/{print $3; exit}'; }

# latest release tag WITHOUT the rate-limited GitHub API (follows the /releases/latest redirect)
rh_latest_tag() {
  local tag
  have curl || return 1
  tag=$(curl -fsSL --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${RH_REPO}/releases/latest" 2>/dev/null | sed 's#.*/tag/##')
  [[ $tag =~ ^v[0-9]+(\.[0-9]+)+$ ]] && echo "$tag"
}

rh_install_from() {   # rh_install_from <zip-or-binary>  -> $RH_BIN
  local f=$1 tmp
  [[ -f $f ]] || { err "File not found: $f"; return 1; }
  tmp=$(mktemp -d)
  if [[ $(head -c2 "$f" 2>/dev/null) == PK ]]; then
    unzip -o -q "$f" -d "$tmp" 2>/dev/null || { err "Cannot unzip $f"; rm -rf "$tmp"; return 1; }
    f=$(find "$tmp" -type f -name rathole | head -n1)
    [[ -n $f ]] || { err "No 'rathole' binary inside the archive."; rm -rf "$tmp"; return 1; }
  fi
  mkdir -p "$LIB_DIR"
  install -m 755 "$f" "${RH_BIN}.new" || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
  if ! rh_works "${RH_BIN}.new"; then
    rm -f "${RH_BIN}.new"
    err "This rathole binary does not run on this system (wrong CPU, or glibc too old)."
    return 1
  fi
  mv -f "${RH_BIN}.new" "$RH_BIN"      # atomic: safe even while the old binary is running
}

rh_fetch() {   # rh_fetch <url> -> installs it
  local tmp rc
  tmp=$(mktemp)
  curl -fL -sS --retry 2 --connect-timeout 10 --max-time 180 -o "$tmp" "$1" && rh_install_from "$tmp"
  rc=$?
  rm -f "$tmp"
  return $rc
}

# ensure_rathole [force]   force = download again even if a core is already installed
ensure_rathole() {
  local force=${1:-} tag arch ans
  if [[ -z $force ]] && rh_works "$RH_BIN"; then
    ok "rathole core is already installed (v$(rh_version))."
    return 0
  fi
  # a rathole that another script already put on this server can be reused - handy when GitHub is blocked
  if [[ -z $force ]] && have rathole && rh_install_from "$(command -v rathole)"; then
    ok "Reused the rathole found in PATH (v$(rh_version))."
    return 0
  fi
  arch=$(rh_arch) || { err "Unsupported CPU architecture: $(uname -m)"; return 1; }
  tag=$(rh_latest_tag)
  if [[ -n $tag ]]; then
    info "Downloading rathole ${tag} (${arch})..."
    if rh_fetch "https://github.com/${RH_REPO}/releases/download/${tag}/rathole-${arch}.zip"; then
      ok "rathole ${tag} installed."; return 0
    fi
  fi
  if [[ $tag != "$RH_FALLBACK_TAG" ]]; then
    info "Trying rathole ${RH_FALLBACK_TAG}..."
    if rh_fetch "https://github.com/${RH_REPO}/releases/download/${RH_FALLBACK_TAG}/rathole-${arch}.zip"; then
      ok "rathole ${RH_FALLBACK_TAG} installed."; return 0
    fi
  fi
  warn "Could not download rathole (is GitHub reachable from this server?)."
  echo "Give a direct URL (a mirror) or a local path to a rathole zip/binary you uploaded (scp), or press Enter to abort."
  read -r -p "URL or path: " ans
  [[ -n $ans ]] || return 1
  if [[ $ans =~ ^https?:// ]]; then rh_fetch "$ans"; else rh_install_from "$ans"; fi || return 1
  ok "rathole installed (v$(rh_version))."
  return 0
}

# ports that are already listening on this server (rathole of THIS tunnel excluded)
busy_ports() {   # busy_ports "<norm ports>" -> space separated list
  local mp used p
  mp=$(systemctl show -p MainPID --value "$RH_UNIT" 2>/dev/null); mp=${mp:-0}
  used=$(ss -Hltunp 2>/dev/null | awk -v mp="$mp" '
    mp != 0 && index($0, "pid=" mp ",") { next }
    { n = split($5, a, ":"); print a[n] }' | sort -u)
  for p in $(expand_ports "$1"); do
    grep -qx "$p" <<< "$used" && printf '%s ' "$p"
  done
  return 0
}

rh_write_config() {
  local p pr
  local -a protos=() plist=()
  [[ -n $RH_AUTH && -n $PORTS ]] || { log "ERROR: rathole config needs the token and a port list"; return 1; }
  case $FWD_PROTO in tcp) protos=(tcp) ;; udp) protos=(udp) ;; *) protos=(tcp udp) ;; esac
  mapfile -t plist < <(expand_ports "$PORTS")
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      if [[ $ROLE == kharej ]]; then
        # Kharej = rathole SERVER: control port on the tunnel address, public ports on this server
        cat <<EOF
# generated by ${APP} - changes are overwritten
[server]
bind_addr = "${RH_SRV_IP}:${RH_PORT}"
default_token = "${RH_AUTH}"
heartbeat_interval = ${RH_HB_INTERVAL}

[server.transport]
type = "tcp"

[server.transport.tcp]
nodelay = true
keepalive_secs = 20
keepalive_interval = 8
EOF
        for pr in "${protos[@]}"; do
          for p in "${plist[@]}"; do
            printf '\n[server.services.%s_%s]\ntype = "%s"\nbind_addr = "0.0.0.0:%s"\n' "$pr" "$p" "$pr" "$p"
          done
        done
      else
        # Iran = rathole CLIENT: dials the Kharej tunnel address, hands connections to local services
        cat <<EOF
# generated by ${APP} - changes are overwritten
[client]
remote_addr = "${RH_SRV_IP}:${RH_PORT}"
default_token = "${RH_AUTH}"
heartbeat_timeout = ${RH_HB_TIMEOUT}
retry_interval = 1

[client.transport]
type = "tcp"

[client.transport.tcp]
nodelay = true
keepalive_secs = 20
keepalive_interval = 8
EOF
        for pr in "${protos[@]}"; do
          for p in "${plist[@]}"; do
            printf '\n[client.services.%s_%s]\ntype = "%s"\nlocal_addr = "%s:%s"\n' "$pr" "$p" "$pr" "$RH_TARGET" "$p"
          done
        done
      fi
    } > "$RH_CONF"
  )
  chmod 600 "$RH_CONF"
}

write_rh_unit() {
  cat > "$RH_UNIT_FILE" <<EOF
[Unit]
Description=Rathole reverse tunnel over the ESP tunnel (${APP})
After=network-online.target ${APP}.service
Requires=${APP}.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BIN} rh-run
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

# runs under systemd: wait for the tunnel address, then become rathole
cmd_rh_run() {
  local i mode
  load_config || { log "ERROR: missing or invalid $CONF (re-install with menu option 1 / 2)"; exit 1; }
  rh_works "$RH_BIN" || { log "ERROR: rathole core missing at $RH_BIN (menu option 10)"; exit 1; }
  [[ -s $RH_CONF ]] || rh_write_config || exit 1
  for i in $(seq 1 60); do
    ip -4 addr show dev "$IF_NAME" 2>/dev/null | grep -q "inet ${LOCAL_INNER}/" && break
    sleep 1
  done
  if [[ $ROLE == kharej ]]; then mode=--server; else mode=--client; fi
  log "[rathole] starting as ${ROLE} (${mode#--}), control ${RH_SRV_IP}:${RH_PORT}, core v$(rh_version)"
  exec "$RH_BIN" "$mode" "$RH_CONF"
}

start_rathole() {
  rh_works "$RH_BIN" || { err "rathole core is missing - use menu option 10."; return 1; }
  rh_write_config    || return 1
  write_rh_unit
  systemctl daemon-reload
  systemctl enable "$RH_UNIT" >/dev/null 2>&1
  systemctl restart "$RH_UNIT"
  sleep 2
  if systemctl is-active --quiet "$RH_UNIT"; then
    ok "Rathole reverse-tunnel service is running ($(rh_role_name))."
    return 0
  fi
  err "Rathole service failed to start. Last log lines:"
  journalctl -u "$RH_UNIT" -n 25 --no-pager
  return 1
}

# number of established TCP connections on the rathole control port (control + data channels)
rh_conn_count() {
  ss -Htn state established 2>/dev/null | awk -v a="${RH_SRV_IP}:${RH_PORT}" \
    '{for(i=1;i<=NF;i++) if($i==a){c++; break}} END{print c+0}'
}

# "<ports listening>/<ports configured>" on the Kharej server (rathole opens a port only while the client is connected)
rh_listen_summary() {
  local used p n=0 t=0
  used=$(ss -Hltun 2>/dev/null | awk '{k=split($5,a,":"); print a[k]}' | sort -u)
  for p in $(expand_ports "$PORTS"); do
    t=$((t + 1))
    grep -qx "$p" <<< "$used" && n=$((n + 1))
  done
  echo "$n/$t"
}

# after an ESP rebuild the tunnel address is recreated - make sure the rathole server still listens on it
rh_post_rebuild() {
  [[ $ROLE == kharej ]] || return 0
  systemctl is-active --quiet "$RH_UNIT" 2>/dev/null || return 0
  if ! ss -Hltn "sport = :${RH_PORT}" 2>/dev/null | grep -q "${LOCAL_INNER}:${RH_PORT}"; then
    log "rathole control listener missing after the rebuild - restarting rathole"
    systemctl restart --no-block "$RH_UNIT"
  fi
}

# ------------------------------------------------------------------------------
#  Watchdog helpers: interface counters, xfrm error counters, forensic dump
# ------------------------------------------------------------------------------
if_counters() {   # prints "<rx_bytes> <tx_bytes>" for $IF_NAME
  local r t
  r=$(cat "/sys/class/net/${IF_NAME}/statistics/rx_bytes" 2>/dev/null) || r=0
  t=$(cat "/sys/class/net/${IF_NAME}/statistics/tx_bytes" 2>/dev/null) || t=0
  echo "${r:-0} ${t:-0}"
}

xfrm_nonzero_counters() {   # e.g. "XfrmInStateProtoError=3 XfrmInTmplMismatch=1"
  awk '$2 != 0 {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat 2>/dev/null
}

# Dumps SA state, interface counters, xfrm error counters and recent *kernel*
# log (not the whole boot buffer) so a rebuild that just happened is still
# diagnosable afterwards. Uses fd 3 for the SA-registry loop so the inner
# `... | while read` pipelines don't fight over stdin.
forensic_snapshot() {
  local reason=$1 dir ep spi src dst line
  log "----- forensic snapshot: ${reason} -----"
  if [[ -s $REG ]]; then
    while read -r dir ep spi src dst <&3; do
      [[ -n $spi ]] || continue
      ip xfrm state get src "$src" dst "$dst" proto esp spi "$spi" 2>&1 | while IFS= read -r line; do
        log "xfrm-state (${dir}/epoch ${ep}): ${line}"
      done
    done 3< "$REG"
  fi
  ip -s link show "$IF_NAME" 2>&1 | while IFS= read -r line; do log "link: ${line}"; done
  local x; x=$(xfrm_nonzero_counters)
  log "xfrm error counters: ${x:-none (clean)}"
  journalctl -k -n 40 --no-pager 2>/dev/null | while IFS= read -r line; do log "kernel: ${line}"; done
  log "----- end forensic snapshot -----"
}

# Common rebuild path for every watchdog trigger: logs (with or without a full
# forensic dump), tears down + rebuilds, and resets all watchdog counters so
# the freshly-rebuilt tunnel gets a clean slate.
watchdog_rebuild() {   # watchdog_rebuild "<reason>" [skip-forensic]
  local reason=$1
  if [[ ${2:-} == skip-forensic ]]; then
    log "$reason"
  else
    forensic_snapshot "$reason"
  fi
  if route_info "$PEER_PUB" && setup_all; then
    log "rebuild complete"
    rh_post_rebuild
  else
    log "ERROR: rebuild attempt failed, will retry next cycle"
  fi
  LAST_REBUILD=$(date +%s)
  RX_STALL_START=0
  FAILS=0
  PEER_STATE="unknown"
  read -r RX0 TX0 <<< "$(if_counters)"
}

# ------------------------------------------------------------------------------
#  Daemon (runs under systemd): setup, hourly key rotation, health watchdog
# ------------------------------------------------------------------------------
cmd_daemon() {
  local tries=0 last_fix=0 e now xcur rx tx
  load_config || { log "ERROR: missing or invalid $CONF"; exit 1; }
  mkdir -p "$RUN_DIR"
  trap 'log "stop signal received"; exit 0' TERM INT

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && { log "ERROR: no route to $PEER_PUB after 60s"; exit 1; }
    sleep 2
  done
  setup_all || { log "ERROR: setup failed"; exit 1; }
  LAST_REBUILD=$(date +%s)
  read -r RX0 TX0 <<< "$(if_counters)"
  XPREV=$(xfrm_nonzero_counters)
  log "watchdog active: rx-stall trigger ${RX_STALL_SEC}s, preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled)"

  while true; do
    sleep 5 &
    wait $!
    now=$(date +%s)

    # --- hourly key rotation (make-before-break, no packet loss) ---
    e=$(( now / EPOCH_LEN ))
    if (( e != CUR_EPOCH )); then
      log "key rotation: epoch $CUR_EPOCH -> $e"
      if install_epoch "$e"; then CUR_EPOCH=$e; else log "WARN: key rotation failed, will retry"; fi
    fi

    # --- unconditional preventive rebuild (the "every 12h" safety net) ---
    if (( FORCE_REBUILD_SEC > 0 && now - LAST_REBUILD >= FORCE_REBUILD_SEC )); then
      watchdog_rebuild "scheduled preventive rebuild (every $((FORCE_REBUILD_SEC/3600))h)" skip-forensic
      continue
    fi

    # --- interface missing ---
    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      watchdog_rebuild "interface $IF_NAME vanished"
      continue
    fi

    # --- xfrm kernel error counters: early warning, logged even without a rebuild ---
    xcur=$(xfrm_nonzero_counters)
    if [[ -n $xcur && $xcur != "$XPREV" ]]; then
      log "WARN: new xfrm error counters: $xcur"
    fi
    XPREV=$xcur

    # --- asymmetric blackout: outbound flowing, nothing received (the exact
    #     pattern seen in production - TX climbing, RX frozen on both ends) ---
    read -r rx tx <<< "$(if_counters)"
    if (( tx > TX0 && rx == RX0 )); then
      (( RX_STALL_START == 0 )) && RX_STALL_START=$now
      if (( now - RX_STALL_START >= RX_STALL_SEC )); then
        watchdog_rebuild "asymmetric blackout: no inbound traffic for ${RX_STALL_SEC}s while outbound is active"
        continue
      fi
    else
      RX_STALL_START=0; RX0=$rx; TX0=$tx
    fi

    # --- ping watchdog (also exercises the path when otherwise idle) ---
    if ping -c1 -W1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
      if [[ $PEER_STATE != up ]]; then log "peer $PEER_INNER reachable - tunnel UP"; fi
      PEER_STATE=up; FAILS=0
    else
      FAILS=$(( FAILS + 1 ))
      if (( FAILS == 3 )); then PEER_STATE=down; log "peer $PEER_INNER not answering for ~15s"; fi
      if (( FAILS >= 12 )); then
        if (( now - last_fix >= 180 )); then
          last_fix=$now
          watchdog_rebuild "peer unreachable (ping) for 60s+"
        fi
        FAILS=3
      fi
    fi
  done
}

cmd_teardown() { teardown_all; log "tunnel torn down"; }

cmd_fw() {
  load_config || exit 1
  route_info "$PEER_PUB" || exit 1
  fw_apply
  log "firewall rules reloaded"
}

# ------------------------------------------------------------------------------
#  Installation helpers
# ------------------------------------------------------------------------------
install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  if [[ ! -f $src ]]; then
    err "Save this script to a file first (bash esp-tunnel.sh); it cannot install itself from a pipe."
    return 1
  fi
  if [[ $src != "$BIN" ]]; then
    install -m 755 "$src" "$BIN" || return 1
  fi
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP (IP protocol 50) tunnel (${APP})
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BIN} daemon
ExecStopPost=${BIN} teardown
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  write_unit
  systemctl daemon-reload
  systemctl enable "$APP" >/dev/null 2>&1
  systemctl restart "$APP"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    [[ -s $REG ]] && ip link show "$IF_NAME" >/dev/null 2>&1 && break
  done
  if systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; then
    ok "Tunnel service is running (auto-starts on boot)."
  else
    err "Service failed to start. Last log lines:"
    journalctl -u "$APP" -n 25 --no-pager
    return 1
  fi
  start_rathole
}

confirm_reinstall() {
  if load_config 2>/dev/null; then
    warn "A tunnel is already configured on this server (role: $ROLE)."
    confirm "Re-install and overwrite it?" n || return 1
  elif [[ -r $CONF ]]; then
    warn "An older config format was found - it will be replaced by this install."
  fi
  return 0
}

# Asks for the PUBLIC address of the other server (IPv4 or IPv6) -> PEER_IP
ask_peer_addr() {   # ask_peer_addr "<label>"
  local a
  while true; do
    read -r -p "$1 (IPv4 or IPv6): " a
    a=${a//[[:space:]]/}
    a=${a#[}; a=${a%]}            # tolerate [2001:db8::1]
    a=${a,,}
    if valid_ip "$a" || valid_ip6 "$a"; then PEER_IP=$a; return 0; fi
    err "Invalid IPv4 / IPv6 address."
  done
}

ask_transport() {
  local c
  echo
  echo "Transport (must be the SAME on both servers):"
  echo "  1) Raw ESP - IP protocol 50   (default: fastest, smallest overhead)"
  echo "  2) ESP-in-UDP (port ${DEFAULT_UDP_PORT})   (fallback: use it if protocol 50 is blocked or a NAT is in front of a server)"
  read -r -p "Select [1]: " c
  if [[ $c == 2 ]]; then MODE=udp; else MODE=esp; fi
  UDP_PORT=$DEFAULT_UDP_PORT
}

ask_ports() {
  local raw norm p cnt busy prompt
  if [[ $ROLE == kharej ]]; then
    prompt="Ports to OPEN on this Kharej server (comma separated, e.g. 1080,443,8000-8100): "
  else
    prompt="Ports to forward to the services on this Iran server (comma separated, same list as on Kharej): "
  fi
  echo "Enter the SAME port list on both servers."
  while true; do
    read -r -p "$prompt" raw
    if ! norm=$(norm_ports "$raw"); then
      err "Invalid list. Use numbers 1-65535 separated by commas (ranges like 8000-8100 are allowed)."
      continue
    fi
    cnt=$(expand_ports "$norm" | wc -l)
    if (( cnt > MAX_FWD_PORTS )); then
      err "$cnt ports requested - rathole needs one service per port, the limit here is $MAX_FWD_PORTS."
      continue
    fi
    if ports_include "$norm" "$RH_PORT"; then
      err "Port $RH_PORT is reserved for the tunnel (rathole control / ESP-in-UDP). Remove it."
      continue
    fi
    if [[ $ROLE == kharej ]]; then
      for p in $(ssh_ports); do
        [[ $p =~ ^[0-9]+$ ]] || continue
        if ports_include "$norm" "$p"; then
          err "Port $p is the SSH port of this server - opening it for the tunnel would lock you out. Remove it."
          continue 2
        fi
      done
      busy=$(busy_ports "$norm")
      if [[ -n $busy ]]; then
        err "Already used by a local service on this server: ${busy}- rathole could not open them. Free them or choose other ports."
        continue
      fi
    fi
    PORTS=$norm
    break
  done
  if [[ $ROLE == iran ]]; then warn_unlistened; fi
}

warn_unlistened() {   # Iran side: forwarded ports that have no local service yet
  local used p miss="" n=0
  used=$(ss -Hltun 2>/dev/null | awk '{k=split($5,a,":"); print a[k]}' | sort -u)
  for p in $(expand_ports "$PORTS"); do
    if ! grep -qx "$p" <<< "$used"; then
      n=$((n + 1))
      (( n <= 15 )) && miss+="$p "
    fi
  done
  if (( n > 0 )); then
    warn "No local service is listening yet on ${n} of these ports: ${miss}$( (( n > 15 )) && echo '...')"
    warn "That is fine if you start the services later - connections to those ports fail until they run."
  fi
}

ask_fwd_proto() {
  local c
  echo
  echo "Forward which protocol on those ports? (must be the SAME on both servers)"
  echo "  1) TCP + UDP (default)   2) TCP only   3) UDP only"
  echo "  (rathole carries UDP inside its TCP channel - for latency-sensitive UDP prefer TCP only if you can)"
  read -r -p "Select [1]: " c
  case $c in 2) FWD_PROTO=tcp ;; 3) FWD_PROTO=udp ;; *) FWD_PROTO=both ;; esac
}

# Iran side: where the forwarded services listen on this server
ask_rh_target() {
  local a def=${RH_TARGET:-127.0.0.1}
  echo
  echo "Where do the forwarded services listen on THIS (Iran) server?"
  echo "  127.0.0.1 works for services bound to 127.0.0.1 or 0.0.0.0."
  echo "  Use ${IP_IRAN} only if they listen exclusively on the tunnel address."
  while true; do
    read -r -p "Target address [${def}]: " a
    a=${a:-$def}
    if valid_ip "$a"; then RH_TARGET=$a; return 0; fi
    err "Invalid IPv4 address."
  done
}

warn_nat() {
  if [[ $PEER_PUB != *:* && $MODE == esp ]] && is_private_ip "$LOCAL_ADDR"; then
    warn "This server's address towards the peer is private ($LOCAL_ADDR) - it looks like NAT."
    warn "Raw ESP through NAT often fails - if it does, re-install using ESP-in-UDP."
  fi
}

# ------------------------------------------------------------------------------
#  Menu actions
# ------------------------------------------------------------------------------
setup_iran() {
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the IRAN server side (tunnel IP ${IP_IRAN}) - rathole CLIENT"
  info "It dials ${RH_SRV_IP}:${RH_PORT} through the ESP tunnel and hands traffic to local services."
  ROLE=iran; TOKEN=$DEFAULT_TOKEN; RH_TARGET=127.0.0.1
  echo
  ask_peer_addr "Kharej (foreign) client public address"
  PEER_PUB=$PEER_IP
  ask_transport
  ensure_deps    || { pause; return; }
  check_kernel   || { pause; return; }
  ensure_rathole || { pause; return; }

  if ! route_info "$PEER_PUB"; then err "No route to $PEER_PUB from this server."; pause; return; fi
  warn_nat

  echo
  ask_ports
  ask_fwd_proto
  ask_rh_target

  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC
  write_config
  load_config
  start_service || { pause; return; }

  echo
  info "Testing the tunnel (5 pings to ${PEER_INNER})..."
  echo "(If the Kharej side is not installed yet, this fails - that is normal.)"
  ping -c 5 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 3
  echo
  info "Waiting for the rathole reverse tunnel (${IP_IRAN} -> ${RH_SRV_IP}:${RH_PORT})..."
  for _ in $(seq 1 12); do
    (( $(rh_conn_count) >= 1 )) && break
    sleep 1
  done
  if (( $(rh_conn_count) >= 1 )); then
    ok "Reverse tunnel is connected."
  else
    warn "Not connected yet - the client keeps retrying by itself. Install the Kharej side (option 2) if you have not."
    warn "Log: journalctl -u ${RH_UNIT} -n 30 --no-pager"
  fi
  echo "Ports [${PORTS}] (${FWD_PROTO}) opened on the Kharej server are delivered to ${RH_TARGET}:<same port> on THIS server."
  echo "The services must be running here and listening on ${RH_TARGET} (or 0.0.0.0)."
  echo "On the Kharej server enter this server's public address, the SAME ports, protocol and transport."
  echo "Open the ESP protocol (IP proto 50$( [[ $MODE == udp ]] && echo ", UDP ${UDP_PORT}" )) in your provider's external firewall if it has one."
  echo
  pause
}

setup_kharej() {
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the KHAREJ client side (tunnel IP ${IP_KHAREJ}) - rathole SERVER"
  info "It listens on ${RH_SRV_IP}:${RH_PORT} inside the tunnel and opens the public ports on THIS server."
  ROLE=kharej; TOKEN=$DEFAULT_TOKEN; RH_TARGET=127.0.0.1
  echo
  ask_peer_addr "Iran server public address"
  PEER_PUB=$PEER_IP
  ask_transport
  ensure_deps    || { pause; return; }
  check_kernel   || { pause; return; }
  ensure_rathole || { pause; return; }

  if ! route_info "$PEER_PUB"; then err "No route to Iran server $PEER_PUB."; pause; return; fi
  warn_nat

  echo
  ask_ports
  ask_fwd_proto

  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC
  write_config
  load_config
  start_service || { pause; return; }

  echo
  info "Testing the tunnel (5 pings to ${PEER_INNER})..."
  echo "(If the Iran side is not installed yet, this fails - that is normal.)"
  ping -c 5 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 3
  echo
  info "Waiting for the Iran rathole client to connect..."
  for _ in $(seq 1 12); do
    (( $(rh_conn_count) >= 1 )) && break
    sleep 1
  done
  if (( $(rh_conn_count) >= 1 )); then
    ok "Reverse tunnel is connected."
  else
    warn "Not connected yet. Install/start the Iran side (option 1) - it will connect by itself."
  fi
  echo "Public ports [${PORTS}] (${FWD_PROTO}) on THIS server are carried through the reverse tunnel to the Iran server."
  echo "A port opens only while the Iran client is connected."
  if have ufw && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    warn "ufw is active here: allow the forwarded ports too (ufw allow <port>)."
  fi
  echo "Open the ESP protocol (IP proto 50$( [[ $MODE == udp ]] && echo ", UDP ${UDP_PORT}" )) in your provider's external firewall if it has one."
  echo
  pause
}

cmd_status() {
  local st epoch left line st_rh rh_desc
  if ! load_config 2>/dev/null; then
    warn "Tunnel is not installed (or the config is from an older version). Use menu option 1 (Iran) or 2 (Kharej)."
    return
  fi
  st=$(systemctl is-active "$APP" 2>/dev/null)
  epoch=$(( $(date +%s) / EPOCH_LEN ))
  left=$(( EPOCH_LEN - $(date +%s) % EPOCH_LEN ))
  if [[ $ROLE == kharej ]]; then
    rh_desc="server, listens ${RH_SRV_IP}:${RH_PORT}"
  else
    rh_desc="client, dials ${RH_SRV_IP}:${RH_PORT}"
  fi

  echo "${C_B}===================== ESP Tunnel status =====================${C_0}"
  echo "Role          : $ROLE   (${LOCAL_INNER}  <->  ${PEER_INNER})"
  echo "Peer public IP: $PEER_PUB"
  if [[ $MODE == udp ]]; then echo "Transport     : ESP-in-UDP, port $UDP_PORT"
  else echo "Transport     : raw ESP (IP protocol 50)"; fi
  echo "Cipher        : AES-256-GCM, MTU $MTU, next key rotation in $((left / 60)) min (epoch $epoch)"
  echo "Watchdog      : rx-stall trigger ${RX_STALL_SEC}s, preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled)"
  if [[ $st == active ]]; then echo "Service       : ${C_G}active${C_0}"; else echo "Service       : ${C_R}${st}${C_0}"; fi
  st_rh=$(systemctl is-active "$RH_UNIT" 2>/dev/null)
  if [[ $st_rh == active ]]; then
    echo "Rathole       : ${C_G}active${C_0} (${rh_desc}, core v$(rh_version), live connections: $(rh_conn_count))"
  else
    echo "Rathole       : ${C_R}${st_rh}${C_0}"
  fi

  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    echo "Interface     : $(ip -br addr show "$IF_NAME" | awk '{print $1, $2, $3}')"
  else
    echo "Interface     : ${C_R}$IF_NAME missing${C_0}"
  fi
  echo "Loaded SAs    : $(wc -l < "$REG" 2>/dev/null || echo 0)  (1 outbound + 3 inbound expected)"
  echo
  echo "--- Ping through the tunnel (10 packets) ---"
  ping -c 10 -i 0.2 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 2
  echo
  echo "--- Interface counters ---"
  ip -s link show "$IF_NAME" 2>/dev/null | sed -n '3,6p'
  echo
  line=$(awk '$2 != 0 {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat 2>/dev/null)
  if [[ -n $line ]]; then
    echo "XFRM counters (non-zero = drops/errors): $line"
  else
    echo "XFRM counters : clean (no errors)"
  fi
  echo
  echo "--- Forwarded ports (${FWD_PROTO}) : [${PORTS}] ---"
  if [[ $ROLE == kharej ]]; then
    echo "Public ports listening: $(rh_listen_summary)   (a port opens only while the Iran client is connected)"
  else
    echo "Target on this server : ${RH_TARGET}"
  fi
  echo
  echo "Tip: check raw ESP on the wire:  tcpdump -ni $WAN_DEV 'ip proto 50'   (IPv6 peer: 'ip6 proto 50')"
}

live_counters() {
  local stop=0 rx0 tx0 rp0 tp0 rx tx rp tp x0 x
  trap 'stop=1' INT
  rx0=$(<"/sys/class/net/$IF_NAME/statistics/rx_bytes");   tx0=$(<"/sys/class/net/$IF_NAME/statistics/tx_bytes")
  rp0=$(<"/sys/class/net/$IF_NAME/statistics/rx_packets"); tp0=$(<"/sys/class/net/$IF_NAME/statistics/tx_packets")
  x0=$(awk '{s+=$2} END{print s+0}' /proc/net/xfrm_stat 2>/dev/null)
  echo "Live traffic on $IF_NAME (Ctrl+C to stop)"
  while (( ! stop )); do
    sleep 1
    rx=$(<"/sys/class/net/$IF_NAME/statistics/rx_bytes");   tx=$(<"/sys/class/net/$IF_NAME/statistics/tx_bytes")
    rp=$(<"/sys/class/net/$IF_NAME/statistics/rx_packets"); tp=$(<"/sys/class/net/$IF_NAME/statistics/tx_packets")
    x=$(awk '{s+=$2} END{print s+0}' /proc/net/xfrm_stat 2>/dev/null)
    printf '%s  RX %7d kbit/s %6d pps | TX %7d kbit/s %6d pps | xfrm errors +%d\n' \
      "$(date +%T)" $(( (rx - rx0) * 8 / 1000 )) $(( rp - rp0 )) $(( (tx - tx0) * 8 / 1000 )) $(( tp - tp0 )) $(( x - x0 ))
    rx0=$rx; tx0=$tx; rp0=$rp; tp0=$tp; x0=$x
  done
  trap - INT
}

health_check() {
  local out loss x rhc=0 rh_note=""
  echo "Running health check (~3s of pings)..."
  out=$(ping -c 10 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1)
  echo "$out" | tail -n 3
  loss=$(grep -oE '[0-9]+% packet loss' <<< "$out" | grep -oE '^[0-9]+')
  echo
  echo "Interface    : $(ip -br link show "$IF_NAME" 2>/dev/null || echo "${IF_NAME} missing")"
  x=$(xfrm_nonzero_counters)
  echo "XFRM errors  : ${x:-none (clean)}"
  echo "SAs loaded   : $(wc -l < "$REG" 2>/dev/null || echo 0) (expect 4: 1 outbound + 3 inbound)"
  rhc=$(rh_conn_count)
  echo "Rathole      : $(rh_role_name), service $(systemctl is-active "$RH_UNIT" 2>/dev/null), connections on ${RH_SRV_IP}:${RH_PORT}: ${rhc}"
  if ! systemctl is-active --quiet "$RH_UNIT" 2>/dev/null || (( rhc == 0 )); then
    rh_note=" - but the rathole reverse tunnel is NOT connected"
  fi
  echo
  if [[ -z $loss ]]; then
    echo "${C_R}Verdict: could not measure (ping did not run)${C_0}"
  elif (( loss == 0 )) && [[ -z $x ]]; then
    if [[ -n $rh_note ]]; then
      echo "${C_Y}Verdict: ESP link healthy (0% loss, no xfrm errors)${rh_note}${C_0}"
    else
      echo "${C_G}Verdict: healthy (0% loss, no xfrm errors)${C_0}"
    fi
  elif (( loss < 50 )); then
    echo "${C_Y}Verdict: degraded (${loss}% loss)${rh_note}${C_0}"
  else
    echo "${C_R}Verdict: down / severely degraded (${loss}% loss)${C_0}"
  fi
}

live_log() {
  local c
  if ! load_config 2>/dev/null; then warn "Tunnel is not installed."; return; fi
  echo
  echo "Live Log:"
  echo "  1) Service log (events, key rotations, up/down, forensic snapshots)"
  echo "  2) Live ping monitor (packet loss + latency/jitter through the tunnel)"
  echo "  3) Live traffic counters (kbit/s, pps, errors)"
  echo "  4) Run health check now"
  echo "  5) Rathole log (reverse tunnel)"
  read -r -p "Select [1]: " c
  case ${c:-1} in
    1) echo "(Ctrl+C to return)"; trap ':' INT; journalctl -u "$APP" -f -n 40 --no-pager; trap - INT ;;
    2) echo "(Ctrl+C to stop and see the summary)"; trap ':' INT; ping -O -i 0.5 -I "$IF_NAME" "$PEER_INNER"; trap - INT ;;
    3) live_counters ;;
    4) health_check; pause ;;
    5) echo "(Ctrl+C to return)"; trap ':' INT; journalctl -u "$RH_UNIT" -f -n 40 --no-pager; trap - INT ;;
    *) warn "Invalid choice." ;;
  esac
}

uninstall_all() {
  confirm "Remove the tunnel completely (services, rathole core, interface, keys, firewall rules)?" n || return
  systemctl disable --now "$RH_UNIT" >/dev/null 2>&1
  systemctl disable --now "$APP" >/dev/null 2>&1
  teardown_all
  rm -f "$UNIT_FILE" "$RH_UNIT_FILE" "$SYSCTL_FILE"
  rm -rf "$CONF_DIR" "$RUN_DIR" "$LIB_DIR"
  systemctl daemon-reload
  systemctl reset-failed "$APP" "$RH_UNIT" 2>/dev/null
  rm -f "$BIN"
  ok "Tunnel fully removed (net.ipv4.ip_forward was left unchanged)."
}

change_ports() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  info "Current ports: [${PORTS}] (${FWD_PROTO})"
  warn "Run this option on BOTH servers and enter the same ports and protocol."
  ask_ports
  ask_fwd_proto
  if [[ $ROLE == iran ]]; then ask_rh_target; fi
  write_config
  rh_write_config || return
  systemctl restart "$RH_UNIT" && ok "Rathole restarted with the new settings."
}

show_token() {
  local t
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  echo "${C_Y}Token (built into the script, must be identical on both servers):${C_0}"
  echo "$TOKEN"
  echo
  echo "The ESP keys and the rathole auth are derived from this token."
  read -r -p "Enter a NEW token to replace it (Enter = keep): " t
  [[ -n $t ]] || return 0
  t=${t//[[:space:]]/}
  if (( ${#t} < 16 )); then err "Too short (min 16 characters)."; return; fi
  TOKEN=$t
  write_config
  load_config
  systemctl restart "$APP" && ok "Tunnel restarted with the new token."
  systemctl restart "$RH_UNIT" 2>/dev/null
  warn "Set the SAME token on the other server (this option), otherwise the tunnel will not come up."
}

restart_tunnel() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  systemctl restart "$APP" && ok "Tunnel restarted."
  systemctl restart "$RH_UNIT" && ok "Rathole restarted."
}

update_rathole() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  ensure_deps || return
  ensure_rathole force || return
  systemctl restart "$RH_UNIT" && ok "Rathole restarted with core v$(rh_version)."
}

change_watchdog() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  local h s
  echo "Current: preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled), rx-stall trigger ${RX_STALL_SEC}s"
  read -r -p "New preventive-rebuild interval in hours (0 = disable) [$((FORCE_REBUILD_SEC/3600))]: " h
  h=${h:-$((FORCE_REBUILD_SEC/3600))}
  [[ $h =~ ^[0-9]+$ ]] || { err "Invalid number."; return; }
  read -r -p "New rx-stall trigger in seconds, min 10 [$RX_STALL_SEC]: " s
  s=${s:-$RX_STALL_SEC}
  [[ $s =~ ^[0-9]+$ ]] && (( s >= 10 )) || { err "Invalid number (min 10)."; return; }
  FORCE_REBUILD_SEC=$(( h * 3600 ))
  RX_STALL_SEC=$s
  write_config
  if systemctl is-active --quiet "$APP"; then systemctl restart "$APP"; fi
  ok "Updated: preventive rebuild $( (( h == 0 )) && echo disabled || echo "every ${h}h"), rx-stall trigger ${RX_STALL_SEC}s."
}

banner() {
  [[ -t 1 ]] && clear
  echo "${C_B}==============================================================${C_0}"
  echo "${C_B}   ESP Tunnel Manager v${VERSION}  -  ESP + Rathole reverse tunnel${C_0}"
  echo "${C_B}   Iran ${IP_IRAN}  <=======  ESP  =======>  Kharej ${IP_KHAREJ}${C_0}"
  echo "${C_B}   rathole: Iran = client  ->  Kharej = server (${RH_SRV_IP}:${DEFAULT_RH_PORT})${C_0}"
  echo "${C_B}==============================================================${C_0}"
  if load_config 2>/dev/null; then
    echo " Installed role: $ROLE (rathole $(rh_role_name))   |   service: $(systemctl is-active "$APP" 2>/dev/null)"
  else
    echo " Not installed yet."
  fi
  echo
}

menu() {
  local ch
  while true; do
    banner
    echo "  1) Tunnel Set Iran Server  (rathole client -> dials ${IP_KHAREJ})"
    echo "  2) Tunnel Set Client (Kharej)  (rathole server, opens the public ports)"
    echo "  3) Status Tunnel"
    echo "  4) Live Log"
    echo "  5) Uninstall Full Tunnel"
    echo "  ------------------------------------"
    echo "  6) Change forwarded ports / protocol (run on both servers)"
    echo "  7) Restart tunnel"
    echo "  8) Show / change token"
    echo "  9) Watchdog / preventive-rebuild settings"
    echo " 10) Update rathole core"
    echo "  0) Exit"
    echo
    read -r -p "Select: " ch || exit 0
    echo
    case $ch in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; echo; pause ;;
      4) live_log ;;
      5) uninstall_all; echo; pause ;;
      6) change_ports; echo; pause ;;
      7) restart_tunnel; echo; pause ;;
      8) show_token; echo; pause ;;
      9) change_watchdog; echo; pause ;;
      10) update_rathole; echo; pause ;;
      0|q|Q) exit 0 ;;
      *) warn "Invalid choice."; sleep 1 ;;
    esac
  done
}

usage() {
  echo "Usage: $0 [menu|status|daemon|teardown|fw|rh-run]"
}

main() {
  case "${1:-menu}" in
    menu)     need_root; menu ;;
    status)   need_root; cmd_status ;;
    daemon)   need_root; cmd_daemon ;;
    rh-run)   need_root; cmd_rh_run ;;
    teardown) need_root; cmd_teardown ;;
    fw)       need_root; cmd_fw ;;
    *)        usage; exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
