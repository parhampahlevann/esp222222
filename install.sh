#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager v1.4
#   * Optional clock-synchronized UDP port hopping (new outer-flow identity every 10 min)
#   * Clock-aligned "quiet windows" in outage mode (lets stale NAT / ISP flow state expire)
#   * Backoff watchdog (no more full-rebuild storms) + evidence lines in the journal
#   * `diag` command: shows exactly where packets die
#   * Tunnel's own outer UDP flow is excluded from DNAT + stale conntrack entries flushed
#  Key/SPI derivation is identical to v1.3, so v1.3 <-> v1.4 peers interoperate
#  as long as port hopping is off.
# ==============================================================================

APP="esp-tunnel"
VERSION="1.4"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"
UDP_ERR_FILE="${RUN_DIR}/udp.err"
XFRM_STAT="/proc/net/xfrm_stat"
CT_FILE="/proc/net/nf_conntrack"

# ---- Shared default secret. Anyone holding this script can derive the keys, ----
# ---- so set your own secret during setup if privacy matters.                ----
STATIC_MASTER="e7d8f3c1a4b92850d6e1749c3b8a1052f9c4e7b8a1d2e3f4c5b6a78901234567"
DEFAULT_UDP_PORT=39540
DEFAULT_MODE="udp"
DEFAULT_PORTS="443,80,2053,2083,2087,2096,8443"
DEFAULT_HOP=0
DEFAULT_FORCE_REBUILD_SEC=0        # 0 = off. e.g. 43200 = full rebuild every 12h
HOP_MIN=20000                      # port-hopping range (both servers must allow it)
HOP_MAX=60000
HOP_LEN=600                        # seconds per hop (= key epoch length while hopping)

IF_NAME="espt0"
IF_ID=42
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30
EPOCH_LEN=3600
EPOCH_SLACK=2                      # accept peer clocks up to +-2 epochs away
MTU_ESP=1400
MTU_UDP=1360

FAIL_THRESHOLD=5                   # failed probes (~6s each) before a recovery step
QUIET_CYCLE=600                    # outage mode: every 10 min ...
QUIET_LEN=180                      # ... stay silent for the first 3 min (clock-aligned)

ROLE=""; MASTER="$STATIC_MASTER"; IRAN_IP=""; KHAREJ_IP=""; MODE="$DEFAULT_MODE"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"; HOP="$DEFAULT_HOP"; FORCE_REBUILD_SEC="$DEFAULT_FORCE_REBUILD_SEC"
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_UDP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0

# watchdog state
FAILS=0; OUTAGE_START=0; HEAL_STAGE=0; NEXT_HEAL_AT=0; OUTAGE_MODE=0; QUIET=0
LAST_FULL=0; PRX_PREV=0; XSTAT_PREV=""; XSTAT_DELTA="n/a"; QUIET_SINCE=0

# Helper that keeps UDP-encap sockets open (kernel needs them to decapsulate ESP-in-UDP).
PY_UDP='
import socket, sys, time, select
socks = []
for a in sys.argv[1:]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", int(a)))
        s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP_ESPINUDP
        s.setblocking(False)
        socks.append(s)
    except Exception as e:
        sys.stderr.write("port %s: %s\n" % (a, e))
if not socks:
    sys.exit(1)
while True:
    try:
        r, _, _ = select.select(socks, [], [], 5)
        for s in r:
            try:
                s.recvfrom(65535)
            except Exception:
                pass
    except Exception:
        time.sleep(0.5)
'

if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'; C_G=$'\e[1;32m'; C_Y=$'\e[1;33m'; C_B=$'\e[1;36m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
fi
info() { echo "${C_B}[*]${C_0} $*"; }
ok()   { echo "${C_G}[+]${C_0} $*"; }
warn() { echo "${C_Y}[!]${C_0} $*" >&2; }
err()  { echo "${C_R}[x]${C_0} $*" >&2; }
log()  { echo "[${APP}] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Please run as root (sudo -i)."
    exit 1
  fi
}

confirm() {
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
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
  return 0
}

is_private_ip() {
  [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]
}

valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

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

ports_include() {
  local spec a b
  local -a specs=()
  IFS=',' read -ra specs <<< "$1"
  for spec in "${specs[@]}"; do
    if [[ $spec == *-* ]]; then a=${spec%-*}; b=${spec#*-}; else a=$spec; b=$spec; fi
    (( $2 >= a && $2 <= b )) && return 0
  done
  return 1
}

ssh_ports() {
  local p
  p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
  [[ -n $p ]] || p=$(ss -Hltnp 2>/dev/null | awk '/sshd/{n=split($4,a,":"); print a[n]}')
  [[ -n $p ]] || p=22
  echo "$p ${SSH_CONNECTION##* }"
}

kdf() { printf '%s' "$1" | sha512sum | awk '{print $1}'; }

route_info() {
  local out
  out=$(ip -4 route get "$1" 2>/dev/null | head -n1)
  LOCAL_ADDR=$(awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")
  WAN_DEV=$(awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")
  [[ -n $LOCAL_ADDR && -n $WAN_DEV ]]
}

detect_public_ip() {
  local addr pub
  addr=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')
  if [[ -z $addr ]] || is_private_ip "$addr"; then
    if have curl; then
      pub=$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null)
      valid_ip "$pub" && addr=$pub
    fi
  fi
  echo "$addr"
}

hop_on() { [[ $MODE == udp && $HOP == 1 ]]; }

load_config() {
  [[ -r $CONF ]] || return 1
  # shellcheck disable=SC1090
  source "$CONF"
  MASTER=${MASTER:-$STATIC_MASTER}
  MODE=${MODE:-$DEFAULT_MODE}; UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}; FWD_PROTO=${FWD_PROTO:-both}
  HOP=${HOP:-$DEFAULT_HOP}
  FORCE_REBUILD_SEC=${FORCE_REBUILD_SEC:-$DEFAULT_FORCE_REBUILD_SEC}
  case $ROLE in
    iran)   LOCAL_INNER=$IP_IRAN;   PEER_INNER=$IP_KHAREJ; PEER_PUB=$KHAREJ_IP; OUT_LABEL=i2k; IN_LABEL=k2i ;;
    kharej) LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN;   PEER_PUB=$IRAN_IP;   OUT_LABEL=k2i; IN_LABEL=i2k ;;
    *) return 1 ;;
  esac
  [[ -n $MASTER && -n $PEER_PUB ]] || return 1
  if [[ $MODE == udp ]]; then MTU=$MTU_UDP; else MTU=$MTU_ESP; fi
  if hop_on; then EPOCH_LEN=$HOP_LEN; else EPOCH_LEN=3600; fi
  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      echo "# ${APP} config"
      printf 'ROLE=%q\n'      "$ROLE"
      printf 'MASTER=%q\n'    "$MASTER"
      printf 'IRAN_IP=%q\n'   "$IRAN_IP"
      printf 'KHAREJ_IP=%q\n' "$KHAREJ_IP"
      printf 'MODE=%q\n'      "$MODE"
      printf 'UDP_PORT=%q\n'  "$UDP_PORT"
      printf 'PORTS=%q\n'     "$PORTS"
      printf 'FWD_PROTO=%q\n' "$FWD_PROTO"
      printf 'HOP=%q\n'       "$HOP"
      printf 'FORCE_REBUILD_SEC=%q\n' "$FORCE_REBUILD_SEC"
    } > "$CONF"
  )
  chmod 600 "$CONF"
}

ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()
  have systemctl || { err "systemd is required."; return 1; }
  for c in ip iptables ping ss sha256sum sha512sum base64 awk od head python3; do
    have "$c" || missing+=("$c")
  done
  (( ${#missing[@]} == 0 )) && return 0

  if   have apt-get; then pm=apt
  elif have dnf;     then pm=dnf
  elif have yum;     then pm=yum
  fi
  [[ -n $pm ]] || { err "Missing: ${missing[*]}"; return 1; }

  for c in "${missing[@]}"; do
    case $c in
      ip|ss)   [[ $pm == apt ]] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      ping)    [[ $pm == apt ]] && pkgs+=(iputils-ping) || pkgs+=(iputils) ;;
      iptables|python3) pkgs+=("$c") ;;
      *)       pkgs+=(coreutils) ;;
    esac
  done
  info "Installing dependencies: ${pkgs[*]}"
  if [[ $pm == apt ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
  else
    timeout 300 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1
  fi
  return 0
}

# Optional tools (never fatal): conntrack = flush stale outer-flow entries, tcpdump = `diag` wire capture.
ensure_opt_deps() {
  local pm=""
  local -a pkgs=()
  have conntrack || pkgs+=(conntrack)
  have tcpdump   || pkgs+=(tcpdump)
  (( ${#pkgs[@]} == 0 )) && return 0
  if   have apt-get; then pm=apt
  elif have dnf;     then pm=dnf
  elif have yum;     then pm=yum
  fi
  [[ -n $pm ]] || return 0
  [[ $pm != apt ]] && pkgs=("${pkgs[@]/conntrack/conntrack-tools}")
  info "Installing optional tools: ${pkgs[*]}"
  if [[ $pm == apt ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 120 apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
  else
    timeout 240 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1
  fi
  return 0
}

load_modules() {
  local m
  for m in xfrm_interface xfrm_user esp4 gcm aesni_intel nf_conntrack xt_TCPMSS iptable_nat; do
    modprobe -q "$m" 2>/dev/null
  done
  return 0
}

check_kernel() {
  local t="espchk0" out
  load_modules
  ip link del "$t" 2>/dev/null
  if ! out=$(ip link add "$t" type xfrm dev lo if_id 4242 2>&1); then
    err "Kernel lacks XFRM-interface support: $out"
    return 1
  fi
  ip link del "$t" 2>/dev/null
  return 0
}

# ---------------------------------------------------------------- port / epoch
# Outer UDP port used by SAs of a given epoch. Without hopping it is simply UDP_PORT.
port_for_epoch() {
  local e=$1 h
  if hop_on; then
    h=$(kdf "${MASTER}|port|${e}" | cut -c1-8)
    echo $(( HOP_MIN + 0x$h % (HOP_MAX - HOP_MIN + 1) ))
  else
    echo "$UDP_PORT"
  fi
}

# All ports we must be listening on (peer clock may be a few epochs off).
helper_ports() {
  local x
  for (( x = CUR_EPOCH - EPOCH_SLACK; x <= CUR_EPOCH + EPOCH_SLACK; x++ )); do
    port_for_epoch "$x"
  done | sort -un | tr '\n' ' '
}

# ---------------------------------------------------------------- firewall
ipt() { iptables -w 5 "$@"; }

fw_chain_reset() {
  local t=$1 c=$2 h=$3
  while ipt -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  ipt -t "$t" -N "$c" 2>/dev/null || ipt -t "$t" -F "$c"
  ipt -t "$t" -I "$h" 1 -j "$c"
}

fw_chain_remove() {
  local t=$1 c=$2 h=$3
  while ipt -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  ipt -t "$t" -F "$c" 2>/dev/null
  ipt -t "$t" -X "$c" 2>/dev/null
}

fw_remove() {
  have iptables || return 0
  fw_chain_remove filter ESPT_IN   INPUT
  fw_chain_remove filter ESPT_FWD  FORWARD
  fw_chain_remove mangle ESPT_MSS  POSTROUTING
  fw_chain_remove nat    ESPT_PRE  PREROUTING
  fw_chain_remove nat    ESPT_POST POSTROUTING
}

fw_apply() {
  local spec d pr dp=""
  local -a specs=() protos=()

  if [[ $MODE == udp ]]; then
    if hop_on; then dp="${HOP_MIN}:${HOP_MAX}"; else dp="$UDP_PORT"; fi
  fi

  fw_chain_reset filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT
  if [[ $MODE == udp ]]; then
    ipt -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$dp" -j ACCEPT
  else
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
  fi

  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  local target_mss=$(( MTU - 40 ))
  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$target_mss"

  if [[ $ROLE == iran ]]; then
    fw_chain_reset nat ESPT_PRE  PREROUTING
    fw_chain_reset nat ESPT_POST POSTROUTING
    # Never DNAT anything coming from the peer's public IP: this protects the tunnel's own
    # outer UDP flow even when the forwarded PORTS range happens to cover the tunnel port.
    ipt -t nat -A ESPT_PRE -s "$PEER_PUB" -j RETURN
    case $FWD_PROTO in
      tcp) protos=(tcp) ;;
      udp) protos=(udp) ;;
      *)   protos=(tcp udp) ;;
    esac
    IFS=',' read -ra specs <<< "$PORTS"
    for spec in "${specs[@]}"; do
      [[ -z $spec ]] && continue
      d=${spec/-/:}
      for pr in "${protos[@]}"; do
        ipt -t nat -A ESPT_PRE ! -i "$IF_NAME" -p "$pr" --dport "$d" -j DNAT --to-destination "$IP_KHAREJ"
      done
    done
    ipt -t nat -A ESPT_POST -o "$IF_NAME" -d "$IP_KHAREJ" -j SNAT --to-source "$IP_IRAN"
  fi
  return 0
}

fw_ok() {
  ipt -C INPUT   -j ESPT_IN  2>/dev/null || return 1
  ipt -C FORWARD -j ESPT_FWD 2>/dev/null || return 1
  if [[ $ROLE == iran ]]; then
    ipt -t nat -C PREROUTING  -j ESPT_PRE  2>/dev/null || return 1
    ipt -t nat -C POSTROUTING -j ESPT_POST 2>/dev/null || return 1
  fi
  return 0
}

# Drop conntrack entries of the outer flow. A stale entry created in the wrong direction
# (e.g. peer packet arrived first and got DNAT'ed) would otherwise survive restarts as long
# as the peer keeps sending.
ct_flush_outer() {
  have conntrack || return 0
  conntrack -D -p udp -s "$PEER_PUB" >/dev/null 2>&1
  conntrack -D -p udp -d "$PEER_PUB" >/dev/null 2>&1
  return 0
}

sysctl_apply() {
  cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.rp_filter = 0
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
EOF
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

# ---------------------------------------------------------------- xfrm
iface_setup() {
  local out
  ip link del "$IF_NAME" 2>/dev/null
  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
    log "ERROR: cannot create $IF_NAME: $out"; return 1
  fi
  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || return 1
  ip link set "$IF_NAME" mtu "$MTU" up || return 1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
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
  policies_remove
  ip xfrm policy add src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
     tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp reqid "$IF_ID" mode tunnel >/dev/null 2>&1 || return 1
  ip xfrm policy add src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
     tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel >/dev/null 2>&1 || return 1
  ip xfrm policy add src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
     tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel >/dev/null 2>&1 || return 1
  return 0
}

sa_add() {
  local dir=$1 e=$2 src dst label spi key out port
  local -a args=()
  if [[ $dir == out ]]; then src=$LOCAL_ADDR; dst=$PEER_PUB;  label=$OUT_LABEL
  else                       src=$PEER_PUB;   dst=$LOCAL_ADDR; label=$IN_LABEL
  fi
  grep -q "^$dir $e " "$REG" 2>/dev/null && return 0

  spi="0x1$(kdf "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
  key=$(kdf "${MASTER}|key|${label}|${e}" | cut -c1-72)
  port=$(port_for_epoch "$e")

  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        replay-window 0
        aead 'rfc4106(gcm(aes))' "0x${key}" 128)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$port" "$port" 0.0.0.0); fi
  args+=(if_id "$IF_ID")

  ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
  if ! out=$(ip xfrm state add "${args[@]}" 2>&1); then
    log "ERROR: cannot add SA: $out"; return 1
  fi
  echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

prune_sa() {
  local e=$1 dir ep spi src dst keep tmp
  [[ -f $REG ]] || return 0
  tmp=$(mktemp)
  while read -r dir ep spi src dst; do
    [[ -n $spi ]] || continue
    keep=1
    if [[ $dir == out ]]; then
      (( ep != e )) && keep=0
    else
      (( ep < e - EPOCH_SLACK || ep > e + EPOCH_SLACK )) && keep=0
    fi
    if (( keep )); then
      echo "$dir $ep $spi $src $dst" >> "$tmp"
    else
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    fi
  done < "$REG"
  cat "$tmp" > "$REG"
  rm -f "$tmp"
}

install_epoch() {
  local e=$1 x
  sa_add out "$e" || return 1
  for (( x = e - EPOCH_SLACK; x <= e + EPOCH_SLACK; x++ )); do
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

# Are all SAs we think we installed really in the kernel?
sa_all_present() {
  local dir ep spi src dst
  [[ -s $REG ]] || return 1
  while read -r dir ep spi src dst; do
    [[ -n $spi ]] || continue
    ip xfrm state get src "$src" dst "$dst" proto esp spi "$spi" >/dev/null 2>&1 || return 1
  done < "$REG"
  return 0
}

# ---------------------------------------------------------------- udp helper
helper_alive() {
  [[ -f $UDP_PID_FILE ]] && kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null
}

udp_helper_stop() {
  if [[ -f $UDP_PID_FILE ]]; then
    kill "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null
    rm -f "$UDP_PID_FILE"
  fi
}

# New helper is started BEFORE the old one is stopped (no receive gap when ports change).
udp_helper_start() {
  local old="" new
  local -a plist=()
  read -ra plist <<< "$(helper_ports)"
  [[ -f $UDP_PID_FILE ]] && old=$(cat "$UDP_PID_FILE" 2>/dev/null)
  python3 -c "$PY_UDP" "${plist[@]}" >/dev/null 2>"$UDP_ERR_FILE" &
  new=$!
  sleep 0.5
  if ! kill -0 "$new" 2>/dev/null; then
    log "ERROR: cannot open UDP port(s) ${plist[*]}: $(head -c 200 "$UDP_ERR_FILE" 2>/dev/null)"
    return 1
  fi
  echo "$new" > "$UDP_PID_FILE"
  [[ -n $old && $old != "$new" ]] && kill "$old" 2>/dev/null
  return 0
}

# ---------------------------------------------------------------- lifecycle
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
  ct_flush_outer
  if [[ $MODE == udp ]]; then udp_helper_start || return 1; fi
  sysctl_apply
  fw_apply
  log "tunnel up: $LOCAL_INNER <-> $PEER_INNER mode=$MODE port=$(port_for_epoch "$CUR_EPOCH") hop=$HOP epoch=$CUR_EPOCH"
  return 0
}

# Non-destructive repair. Returns 0 = did what it could, 2 = local state is broken -> needs full rebuild.
soft_heal() {
  log "soft-heal: re-checking helper, SAs, policies, firewall (interface stays up)"
  route_info "$PEER_PUB" || return 2
  ip link show "$IF_NAME" >/dev/null 2>&1 || return 2
  sa_all_present || { log "soft-heal: SA missing in kernel"; return 2; }
  install_epoch "$CUR_EPOCH" || return 2
  if [[ $MODE == udp ]]; then
    helper_alive || udp_helper_start || return 2
  fi
  policies_setup || return 2
  ct_flush_outer
  fw_ok || fw_apply
  sysctl_apply
  return 0
}

# ---------------------------------------------------------------- evidence
if_counters() {
  local r t
  r=$(cat "/sys/class/net/${IF_NAME}/statistics/rx_bytes" 2>/dev/null) || r=0
  t=$(cat "/sys/class/net/${IF_NAME}/statistics/tx_bytes" 2>/dev/null) || t=0
  echo "${r:-0} ${t:-0}"
}

# UDP/ESP packets from the peer that reached this host's INPUT chain (counter of our accept rule).
peer_rx_pkts() {
  iptables -w 5 -nvxL ESPT_IN 2>/dev/null | awk -v p="$PEER_PUB" '
    $8==p && ($4=="udp" || $4=="50" || $4=="esp") {s+=$1}
    END{print s+0}'
}

# Sets XSTAT_DELTA to the xfrm_stat counters that changed since the last call.
xstat_delta() {
  local cur out
  cur=$(cat "$XFRM_STAT" 2>/dev/null)
  if [[ -z $XSTAT_PREV ]]; then XSTAT_PREV=$cur; XSTAT_DELTA="n/a"; return 0; fi
  out=$(awk 'NR==FNR{p[$1]=$2; next} ($1 in p) && $2!=p[$1]{printf "%s+%d ", $1, $2-p[$1]}' \
        <(printf '%s\n' "$XSTAT_PREV") <(printf '%s\n' "$cur"))
  XSTAT_PREV=$cur
  XSTAT_DELTA=${out:-none}
}

# "<packets encrypted by our out-SAs> <packets decrypted by our in-SAs>"
sa_counters() {
  ip -s xfrm state 2>/dev/null | awk -v L="$LOCAL_ADDR" -v P="$PEER_PUB" '
    /^src /{s=$2; d=$4; next}
    /lifetime current:/{getline; split($2,a,"("); pk=a[1]+0
      if (s==L && d==P) o+=pk; else if (s==P && d==L) i+=pk}
    END{print o+0, i+0}'
}

sync_counters() {
  PRX_PREV=$(peer_rx_pkts)
  XSTAT_PREV=$(cat "$XFRM_STAT" 2>/dev/null)
}

evidence() {
  local rx tx prx d
  read -r rx tx <<< "$(if_counters)"
  prx=$(peer_rx_pkts)
  if (( prx >= PRX_PREV )); then d=$(( prx - PRX_PREV )); else d=$prx; fi
  PRX_PREV=$prx
  xstat_delta
  log "evidence: from-peer pkts +${d} (0 = nothing reaches us) | ${IF_NAME} rx=${rx}B tx=${tx}B | xfrm_stat: ${XSTAT_DELTA}"
}

probe_peer() { ping -c 2 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; }

cron_find() {
  { crontab -l 2>/dev/null; cat /etc/crontab /etc/cron.d/* 2>/dev/null
    cat /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null; } \
    | grep -E "${APP}" | grep -vE '^[[:space:]]*#'
}

cron_warn() {
  local l
  l=$(cron_find | head -3 | tr '\n' ';')
  [[ -n $l ]] && log "WARN: cron entry touches ${APP}: ${l} - periodic restarts keep the outer UDP flow busy and defeat the quiet-window recovery; remove it"
  return 0
}

ntp_warn() {
  have timedatectl || return 0
  if [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == no ]]; then
    log "WARN: system clock is NOT NTP-synchronized; keys/ports are derived from the clock, keep both servers in sync"
  fi
  return 0
}

# ---------------------------------------------------------------- watchdog
outage_clear() { FAILS=0; OUTAGE_START=0; HEAL_STAGE=0; NEXT_HEAL_AT=0; OUTAGE_MODE=0; }

quiet_enter() {
  evidence
  log "QUIET window: no tunnel traffic until the clock-aligned window ends (lets stale NAT/ISP flow state expire)"
  policies_remove
  sa_flush
  ip link del "$IF_NAME" 2>/dev/null
  QUIET=1; QUIET_SINCE=$1
}

quiet_exit() {
  local now=$1
  log "QUIET window over: rebuilding tunnel"
  setup_all || log "ERROR: rebuild failed"
  QUIET=0; FAILS=0; NEXT_HEAL_AT=0; LAST_FULL=$now
  sync_counters
}

recover_step() {
  local reason=$1 now=$2 rc
  HEAL_STAGE=$(( HEAL_STAGE + 1 ))
  evidence
  case $HEAL_STAGE in
    1)
      log "recovery step 1 (soft, no teardown): $reason"
      soft_heal; rc=$?
      if (( rc == 0 )) && probe_peer; then
        log "soft-heal restored the tunnel"; outage_clear; return 0
      fi
      if (( rc == 2 )); then
        log "local state is broken -> full rebuild now"
        setup_all || log "ERROR: rebuild failed"
        HEAL_STAGE=2; LAST_FULL=$now; NEXT_HEAL_AT=$(( now + 60 ))
        sync_counters
      else
        NEXT_HEAL_AT=$(( now + 45 ))
      fi
      ;;
    2)
      log "recovery step 2 (full rebuild): $reason"
      setup_all || log "ERROR: rebuild failed"
      LAST_FULL=$now; NEXT_HEAL_AT=$(( now + 60 ))
      sync_counters
      ;;
    *)
      log "still down after soft-heal + rebuild -> OUTAGE MODE: silent ${QUIET_LEN}s window every ${QUIET_CYCLE}s (aligned to the clock, so both servers go quiet together)"
      OUTAGE_MODE=1
      ;;
  esac
  FAILS=0
}

watchdog_tick() {
  local now=$1 e phase

  # 0. outage mode: clock-aligned silent windows
  if (( OUTAGE_MODE )); then
    phase=$(( now % QUIET_CYCLE ))
    if (( ! QUIET && phase < 30 )); then
      quiet_enter "$now"
    elif (( QUIET && (phase >= QUIET_LEN || now - QUIET_SINCE >= QUIET_LEN + 60) )); then
      quiet_exit "$now"
    fi
    (( QUIET )) && return 0
  fi

  # 1. key rotation (and port hop)
  e=$(( now / EPOCH_LEN ))
  if (( e != CUR_EPOCH )); then
    log "key rotation: epoch $CUR_EPOCH -> $e (port $(port_for_epoch "$e"))"
    if install_epoch "$e"; then
      CUR_EPOCH=$e
      if [[ $MODE == udp ]]; then udp_helper_start; fi
    fi
  fi

  # 2. optional scheduled full rebuild
  if (( FORCE_REBUILD_SEC > 0 && now - LAST_FULL >= FORCE_REBUILD_SEC )); then
    log "scheduled full rebuild (every ${FORCE_REBUILD_SEC}s)"
    setup_all; LAST_FULL=$now; outage_clear; sync_counters
    return 0
  fi

  # 3. UDP helper alive?
  if [[ $MODE == udp ]] && ! helper_alive; then
    log "WARN: UDP helper died - restarting"
    udp_helper_start
  fi

  # 4. interface present?
  if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
    log "interface $IF_NAME vanished - full rebuild"
    setup_all; LAST_FULL=$now; outage_clear; sync_counters
    return 0
  fi

  # 5. end-to-end probe through the tunnel
  if probe_peer; then
    if (( OUTAGE_START )); then log "peer reachable again after $(( now - OUTAGE_START ))s"; fi
    outage_clear
  else
    (( FAILS == 0 )) && OUTAGE_START=$now
    FAILS=$(( FAILS + 1 ))
    if (( ! OUTAGE_MODE && FAILS >= FAIL_THRESHOLD && now >= NEXT_HEAL_AT )); then
      recover_step "peer unreachable for $(( now - OUTAGE_START ))s ($FAILS probes)" "$now"
    fi
  fi
  return 0
}

cmd_daemon() {
  local tries=0
  load_config || { log "ERROR: missing config"; exit 1; }
  mkdir -p "$RUN_DIR"
  trap 'log "stop signal received"; exit 0' TERM INT

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && { log "ERROR: no route to $PEER_PUB"; exit 1; }
    sleep 2
  done
  setup_all || { log "ERROR: setup failed"; exit 1; }
  LAST_FULL=$(date +%s)
  outage_clear; QUIET=0
  sync_counters
  ntp_warn; cron_warn
  log "watchdog armed: v${VERSION} hop=${HOP} epoch_len=${EPOCH_LEN}s recovery after ${FAIL_THRESHOLD} failed probes"

  while true; do
    sleep 5 &
    wait $!
    watchdog_tick "$(date +%s)"
  done
}

cmd_teardown() { teardown_all; log "tunnel torn down"; }
cmd_fw() { load_config || exit 1; route_info "$PEER_PUB" || exit 1; fw_apply; }

# ---------------------------------------------------------------- diagnostics
cmd_diag() {
  local now tmp cap_pid="" t0 peer_re o1 i1 o2 i2 r1 r2 pingok=0 cap_out=0 cap_in=0 have_cap=0
  local d_out d_in d_fw sent recv nfc nfm l
  load_config || { warn "Not installed."; return 1; }
  route_info "$PEER_PUB" || warn "no route to peer $PEER_PUB"
  now=$(date +%s); CUR_EPOCH=$(( now / EPOCH_LEN ))
  peer_re=${PEER_PUB//./\\.}

  echo "===== ${APP} v${VERSION} diagnostics ====="
  echo "role=$ROLE mode=$MODE hop=$HOP peer=$PEER_PUB local=$LOCAL_ADDR dev=$WAN_DEV"
  echo "udp ports now: $(port_for_epoch "$CUR_EPOCH") | listening set: $(helper_ports)"
  [[ $ROLE == iran ]] && echo "forwarding: PORTS=$PORTS proto=$FWD_PROTO"
  echo "utc=$(date -u +%FT%TZ) epoch=$CUR_EPOCH (+$(( now % EPOCH_LEN ))s into it) ntp_sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo n/a)"
  echo "service=$(systemctl is-active "$APP" 2>/dev/null) since=$(systemctl show -p ActiveEnterTimestamp --value "$APP" 2>/dev/null)"
  l=$(cron_find | head -3)
  [[ -n $l ]] && echo "!! cron entry touching ${APP} (periodic restarts defeat recovery): $l"

  echo "-- interface"
  ip -br addr show "$IF_NAME" 2>&1
  ip -s link show "$IF_NAME" 2>/dev/null | sed -n '3,6p'
  echo "xfrm policies (want 3): $(ip xfrm policy 2>/dev/null | grep -c "if_id $(printf '0x%x' "$IF_ID")")"

  echo "-- SAs (packets handled by each SA)"
  ip -s xfrm state 2>/dev/null | awk '
    /^src /{s=$2; d=$4; next}
    /proto esp spi/{spi=$4; next}
    /lifetime current:/{getline; printf "  %s -> %s spi=%s %s %s\n", s, d, spi, $1, $2}'

  echo "-- xfrm_stat (non-zero)"
  awk '$2 != 0 {printf "  %s=%s\n", $1, $2}' "$XFRM_STAT" 2>/dev/null

  echo "-- firewall counters (ESPT_IN)"
  iptables -w 5 -nvxL ESPT_IN 2>/dev/null | sed 's/^/  /'
  if [[ $ROLE == iran ]]; then
    echo "-- NAT (ESPT_PRE)"
    iptables -w 5 -t nat -nvxL ESPT_PRE 2>/dev/null | sed 's/^/  /'
    if [[ -n $PORTS ]] && ports_include "$PORTS" "$(port_for_epoch "$CUR_EPOCH")"; then
      echo "  note: forwarded PORTS covers the tunnel port (outer flow is protected by a RETURN rule in v1.4)"
    fi
  fi

  echo "-- UDP sockets"
  ss -uanp 2>/dev/null | grep -E "python3" | sed 's/^/  /' | head -6

  nfc=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)
  nfm=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
  echo "-- conntrack ${nfc:-n/a}/${nfm:-n/a}"
  if [[ -r $CT_FILE ]]; then
    grep -E "udp .*(src|dst)=${peer_re} " "$CT_FILE" 2>/dev/null | head -4 | sed 's/^/  /'
    if grep -E "udp .*src=${peer_re} dst=.* src=10\.10\.10\." "$CT_FILE" >/dev/null 2>&1; then
      echo "  !! outer flow is stuck in a DNAT'ed conntrack entry -> run: conntrack -D -p udp -s $PEER_PUB  (v1.4 does this automatically)"
    fi
  fi

  echo "-- live check (12s): pinging through the tunnel while counting packets"
  read -r o1 i1 <<< "$(sa_counters)"
  r1=$(peer_rx_pkts)
  tmp=$(mktemp)
  if have tcpdump && [[ -n $WAN_DEV ]]; then
    have_cap=1
    timeout 12 tcpdump -nn -l -i "$WAN_DEV" "udp and host $PEER_PUB" >"$tmp" 2>/dev/null &
    cap_pid=$!
  fi
  t0=$SECONDS
  ping -c 4 -i 1 -W 2 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1 && pingok=1
  while (( SECONDS - t0 < 12 )); do sleep 1; done
  [[ -n $cap_pid ]] && wait "$cap_pid" 2>/dev/null
  read -r o2 i2 <<< "$(sa_counters)"
  r2=$(peer_rx_pkts)
  if (( have_cap )); then
    cap_out=$(grep -cE " > ${peer_re}\.[0-9]+:" "$tmp")
    cap_in=$(grep -cE "IP ${peer_re}\.[0-9]+ > " "$tmp")
  fi
  rm -f "$tmp"

  d_out=$(( o2 - o1 )); d_in=$(( i2 - i1 )); d_fw=$(( r2 - r1 ))
  sent=$d_out; (( cap_out > sent )) && sent=$cap_out
  recv=$d_fw; (( cap_in > recv )) && recv=$cap_in
  echo "  ping through tunnel : $( (( pingok )) && echo OK || echo FAIL )"
  echo "  encrypted by out-SA : +$d_out"
  echo "  decrypted by in-SA  : +$d_in"
  echo "  UDP from peer at INPUT: +$d_fw"
  if (( have_cap )); then echo "  wire capture        : to_peer=$cap_out from_peer=$cap_in"
  else echo "  wire capture        : (tcpdump not installed: apt install tcpdump)"; fi

  echo "-- hint"
  if (( pingok )); then
    echo "  tunnel works right now."
  elif (( sent == 0 )); then
    echo "  nothing is encrypted locally -> local xfrm/policy/route problem (look at xfrm_stat Out* counters above)."
  elif (( recv == 0 )); then
    echo "  packets leave but NOTHING arrives from the peer -> dropped in the network path (ISP/DPI/provider firewall) or the peer sends nothing."
    echo "  try: '${APP} port <new-port>' or '${APP} hop on' on BOTH servers; also compare this output with the peer's."
  elif (( cap_in > 0 && d_fw == 0 )); then
    echo "  packets reach the NIC but not our INPUT rule -> another firewall (ufw/provider/raw table) drops them first."
  elif (( d_in == 0 )); then
    echo "  packets arrive but are not accepted -> key/time/policy mismatch: compare utc+epoch+secret on both servers, see xfrm_stat In* counters."
  else
    echo "  inconclusive - send this whole output (both servers)."
  fi

  echo "-- last journal lines"
  journalctl -u "$APP" -n 12 --no-pager -o cat 2>/dev/null | sed 's/^/  /'
}

# ---------------------------------------------------------------- install / service
install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  [[ -f $src ]] || return 1
  [[ $src != "$BIN" ]] && install -m 755 "$src" "$BIN"
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP Tunnel Service (${APP})
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BIN} daemon
ExecStopPost=${BIN} teardown
Restart=always
RestartSec=3
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  write_unit
  systemctl daemon-reload
  systemctl enable "$APP" >/dev/null 2>&1
  systemctl restart "$APP"
  sleep 2
  if systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; then
    ok "Tunnel service started successfully."
    return 0
  fi
  err "Service failed to start."
  return 1
}

ask_ports() {
  local raw norm p
  while true; do
    read -r -p "Ports to forward [${DEFAULT_PORTS}]: " raw
    raw=${raw:-$DEFAULT_PORTS}
    if ! norm=$(norm_ports "$raw"); then
      err "Invalid list format."
      continue
    fi
    for p in $(ssh_ports); do
      if ports_include "$norm" "$p"; then
        err "Port $p is SSH! Forwarding it will lock you out."
        continue 2
      fi
    done
    PORTS=$norm; break
  done
}

ask_fwd_proto() {
  local c
  echo "Forwarding Protocol: 1) TCP + UDP (default)  2) TCP only  3) UDP only"
  read -r -p "Select [1]: " c
  case $c in 2) FWD_PROTO=tcp ;; 3) FWD_PROTO=udp ;; *) FWD_PROTO=both ;; esac
}

ask_udp_port() {
  local p
  while true; do
    read -r -p "Tunnel UDP port [${DEFAULT_UDP_PORT}] (must be identical on both servers): " p
    p=${p:-$DEFAULT_UDP_PORT}
    valid_port "$p" && break
    err "Invalid port."
  done
  UDP_PORT=$((10#$p))
}

ask_secret() {
  local s
  read -r -s -p "Shared secret (identical on both servers; Enter = built-in default): " s; echo
  if [[ -n $s ]]; then
    MASTER=$(kdf "${APP}-master|${s}")
  else
    MASTER="$STATIC_MASTER"
    warn "Using the built-in default secret: anyone who has this script can decrypt/forge the tunnel traffic."
  fi
}

confirm_reinstall() {
  if load_config 2>/dev/null; then
    warn "Already configured as $ROLE."
    confirm "Overwrite?" n || return 1
  fi
  return 0
}

setup_iran() {
  confirm_reinstall || return
  install_self || return
  info "Configuring IRAN Server side (10.10.10.2)"
  ensure_deps || return
  ensure_opt_deps
  check_kernel || return

  local det
  det=$(detect_public_ip)
  read -r -p "Iran Public IP [$det]: " IRAN_IP; IRAN_IP=${IRAN_IP:-$det}
  while true; do
    read -r -p "Kharej (foreign) Server Public IP: " KHAREJ_IP
    valid_ip "$KHAREJ_IP" && break
    err "Invalid IPv4 address."
  done

  ask_ports
  ask_fwd_proto
  ask_udp_port
  ask_secret

  ROLE=iran
  MODE="$DEFAULT_MODE"
  HOP="$DEFAULT_HOP"

  write_config; load_config; start_service || return
  echo
  ok "Iran server setup complete!"
  echo "Now run option 2 on the Kharej server and enter this Iran IP: ${C_Y}${IRAN_IP}${C_0}"
  echo "(use the same UDP port ${UDP_PORT} and the same secret there)"
  echo
  pause
}

setup_kharej() {
  confirm_reinstall || return
  install_self || return
  info "Configuring KHAREJ Client side (10.10.10.1)"
  ensure_deps || return
  ensure_opt_deps
  check_kernel || return

  local det
  det=$(detect_public_ip)
  read -r -p "Kharej Public IP [$det]: " KHAREJ_IP; KHAREJ_IP=${KHAREJ_IP:-$det}
  while true; do
    read -r -p "Iran Server Public IP: " IRAN_IP
    valid_ip "$IRAN_IP" && break
    err "Invalid IPv4 address."
  done

  ask_udp_port
  ask_secret

  ROLE=kharej
  MODE="$DEFAULT_MODE"
  PORTS=""
  FWD_PROTO="both"
  HOP="$DEFAULT_HOP"

  write_config; load_config; start_service || return
  echo
  info "Testing ping to Iran (${PEER_INNER})..."
  if ping -c 4 -W 1 -I "$IF_NAME" "$PEER_INNER"; then
    ok "Kharej client connected."
  else
    warn "No reply yet. Make sure the Iran side is configured with the same UDP port/secret, then run: ${APP} diag"
  fi
  pause
}

cmd_status() {
  load_config || { warn "Not installed."; return; }
  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  echo "Role: $ROLE | Mode: $MODE | UDP port(s): $(helper_ports)| Hop: $HOP | v${VERSION}"
  echo "Service: $(systemctl is-active "$APP")"
  ip -br addr show "$IF_NAME" 2>/dev/null
  echo "Ping test:"
  ping -c 4 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 2
  echo "Tip: '${APP} diag' shows where packets die."
}

cmd_port() {
  local p=${1:-}
  load_config || { err "Not installed."; return 1; }
  if ! valid_port "$p"; then err "Usage: ${APP} port <1-65535>"; return 1; fi
  p=$((10#$p))
  if [[ $ROLE == iran && -n $PORTS ]] && ports_include "$PORTS" "$p"; then
    warn "Port $p is inside the forwarded PORTS list - consider another port."
  fi
  UDP_PORT=$p; HOP=0
  write_config
  systemctl restart "$APP" && ok "UDP port set to $p (hopping off). Run the SAME command on the other server."
}

cmd_hop() {
  local v=${1:-}
  load_config || { err "Not installed."; return 1; }
  [[ $MODE == udp ]] || { err "Port hopping needs UDP mode."; return 1; }
  case $v in
    on|1)  HOP=1 ;;
    off|0) HOP=0 ;;
    *) err "Usage: ${APP} hop on|off"; return 1 ;;
  esac
  write_config
  systemctl restart "$APP" && ok "Port hopping: $v. Run the SAME command on the other server (within ~1 minute)."
}

cmd_rebuild_every() {
  local s=${1:-}
  load_config || { err "Not installed."; return 1; }
  [[ $s =~ ^[0-9]+$ ]] || { err "Usage: ${APP} rebuild-every <seconds|0>   (43200 = 12h, 0 = off)"; return 1; }
  FORCE_REBUILD_SEC=$s
  write_config
  systemctl restart "$APP" && ok "Scheduled full rebuild every ${s}s (0 = off)."
}

cmd_upgrade() {
  load_config || { err "Not installed - use the menu to set up first."; return 1; }
  install_self || { err "Run this from the script file itself (not through a pipe)."; return 1; }
  ensure_opt_deps
  start_service
}

uninstall_all() {
  confirm "Remove tunnel completely?" n || return
  systemctl disable --now "$APP" >/dev/null 2>&1
  teardown_all
  rm -f "$UNIT_FILE" "$SYSCTL_FILE" "$BIN"
  rm -rf "$CONF_DIR" "$RUN_DIR"
  systemctl daemon-reload
  ok "Tunnel fully removed."
}

menu() {
  local ch p
  while true; do
    echo
    echo "${C_B}======================================================${C_0}"
    echo "${C_B}   ESP Tunnel Manager v${VERSION}                          ${C_0}"
    echo "${C_B}======================================================${C_0}"
    echo "  1) Setup Iran Server"
    echo "  2) Setup Kharej Client"
    echo "  3) Status & Ping"
    echo "  4) Live Journal Log"
    echo "  5) Uninstall"
    echo "  6) Diagnostics (send this output when it breaks)"
    echo "  7) Change UDP port   (run on BOTH servers)"
    echo "  8) Port hopping on/off (run on BOTH servers)"
    echo "  0) Exit"
    echo
    read -r -p "Select: " ch
    case $ch in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; pause ;;
      4) journalctl -u "$APP" -f -n 30 ;;
      5) uninstall_all; pause ;;
      6) cmd_diag; pause ;;
      7) read -r -p "New UDP port: " p; cmd_port "$p"; pause ;;
      8) read -r -p "Port hopping [on/off]: " p; cmd_hop "$p"; pause ;;
      0|q|Q) exit 0 ;;
    esac
  done
}

main() {
  case "${1:-menu}" in
    menu)          need_root; menu ;;
    status)        need_root; cmd_status ;;
    daemon)        need_root; cmd_daemon ;;
    teardown)      need_root; cmd_teardown ;;
    fw)            need_root; cmd_fw ;;
    diag)          need_root; cmd_diag ;;
    port)          need_root; cmd_port "${2:-}" ;;
    hop)           need_root; cmd_hop "${2:-}" ;;
    rebuild-every) need_root; cmd_rebuild_every "${2:-}" ;;
    rebuild)       need_root; systemctl restart "$APP" && ok "Rebuilt (config unchanged)." ;;
    upgrade|install) need_root; cmd_upgrade ;;
    *) echo "usage: $0 {menu|status|diag|port N|hop on|off|rebuild|rebuild-every SEC|upgrade}"; exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
