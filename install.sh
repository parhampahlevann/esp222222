#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager v1.6 - Zero-Drop Edition
#
#  Wire-compatible with v1.5 (same keys / SPIs / UDP port / inner IPs), so you
#  can upgrade one server at a time without a key mismatch.
#
#  Root causes fixed compared with v1.5
#  -----------------------------------------------------------------------------
#   1. Silent "tunnel up but ports dead": soft-heal never re-applied iptables.
#      If ufw / docker / fail2ban / netfilter-persistent flushed or re-ordered
#      the ESPT_* chains, DNAT/SNAT/ACCEPT were gone while ping still worked.
#      -> firewall drift is now detected (signature) and healed atomically.
#   2. policies_ensure() grepped "if_id 42" but iproute2 prints "if_id 0x2a":
#      the check never matched, so every soft-heal DELETED and re-added the XFRM
#      policies (a real drop window). -> hex/dec aware, per-policy, atomic update.
#   3. SA registry (/run/.../sa.list) could disagree with the kernel; a missing
#      SA was never re-created by soft-heal. -> SAs are verified against the
#      kernel every tick; stale/conflicting SAs are removed after new ones are in.
#   4. fw_sync compared `iptables -S` text with hand-written rules (-d x vs
#      -d x/32, option order) so it always "differed" and flushed the chain.
#      -> atomic iptables-restore of each table (no empty-chain window).
#   5. conntrack established timeout was 7200s: idle long-lived TCP flows
#      (xray/v2ray, ssh, websockets) were cut every ~2h.  -> 86400s,
#      + tcp_be_liberal, larger UDP timeouts, bigger hash table.
#   6. Full rebuild on 30s of ping loss.  The ISP link flaps often; a rebuild
#      cannot fix the ISP but it does reset flows.  -> the daemon only repairs
#      what is actually broken; a full rebuild is a last resort after 10 min.
#   7. Restart/teardown on every crash (ExecStopPost).  -> teardown only on a
#      real `systemctl stop`; after a crash the daemon adopts the live state.
#   8. Outer ESP/UDP flow went through conntrack (CPU + table pressure).
#      -> optional NOTRACK for the outer flow only.
#   9. Wider key window (e-3..e+3), clock-sync guard (keys are time based).
#  10. Legacy cron/timer "healthcheck" watchers that restart the service are
#      detected and can be removed.
#  11. MTU 1360 was needlessly low for UDP on some links and too high on others;
#      default 1380 (safe on >=1450 underlays) + built-in path-MTU tester and
#      an editable MTU override (no restart needed).
#  12. Better diagnostics: when the peer is silent the log tells you WHY
#      (SPI mismatch / decrypt errors / nothing arriving).
# ==============================================================================

export LC_ALL=C

APP="esp-tunnel"
VERSION="1.6"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
UDP_PID_FILE="${RUN_DIR}/udp.pid"
UDP_ERR_FILE="${RUN_DIR}/udp.err"

# ---- Shared static secret / defaults (MUST stay identical on both servers) ----
STATIC_MASTER="e7d8f3c1a4b92850d6e1749c3b8a1052f9c4e7b8a1d2e3f4c5b6a78901234567"
DEFAULT_UDP_PORT=39540
DEFAULT_MODE="udp"
DEFAULT_PORTS="443,80,2053,2083,2087,2096,8443"

IF_NAME="espt0"
IF_ID=42
IF_HEX=$(printf '%x' "$IF_ID")
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30
EPOCH_LEN=3600            # key-derivation input: never change (must match peer)
IN_BACK=3                 # accept peer keys from epoch e-3 ...
IN_FWD=3                  # ... to e+3  (clock skew / rotation lag tolerance)
MTU_ESP=1400              # raw ESP  : worst-case overhead 57  -> fits underlay >= 1457
MTU_UDP=1380              # ESP/UDP  : worst-case overhead 65  -> fits underlay >= 1445

# ---- watchdog tuning ----
TICK=5                    # seconds between reconcile + probe cycles
FAIL_WARN=3               # consecutive failed probes before logging "peer silent"
DOWN_REBUILD_SEC=600      # last-resort full rebuild after this long without peer
REBUILD_COOLDOWN=900      # min seconds between full rebuilds
FW_EVERY=3                # verify firewall every N ticks (~15s)
PROBE_W=3                 # per-ping timeout (adapted to measured RTT)

ROLE=""; MASTER="$STATIC_MASTER"; IRAN_IP=""; KHAREJ_IP=""; MODE="$DEFAULT_MODE"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"; MTU_OVERRIDE=""; NOTRACK=1
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_UDP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0; NOW=0
LAST_REBUILD=0; FAILS=0; PEER_STATE="unknown"; DOWN_SINCE=0; RELOAD=0
POL_SIG=""; FW_SIG=""; POL_FAIL_TS=0
D_SRC=""; D_DST=""; D_SPI=""; D_KEY=""

declare -A SPI_C=() KEY_C=() LOG_LAST=() XS_PREV=()
FW_SPECS=()

FW_ALL=("filter ESPT_IN INPUT" "filter ESPT_FWD FORWARD" "mangle ESPT_MSS POSTROUTING"
        "nat ESPT_PRE PREROUTING" "nat ESPT_POST POSTROUTING"
        "raw ESPT_RAWP PREROUTING" "raw ESPT_RAWO OUTPUT")

SYSCTL_LIST=(
  "net.ipv4.ip_forward=1"
  "net.ipv4.conf.all.rp_filter=0"
  "net.ipv4.conf.default.rp_filter=0"
  "net.ipv4.conf.lo.rp_filter=0"
  "net.netfilter.nf_conntrack_max=1048576"
  "net.netfilter.nf_conntrack_tcp_timeout_established=86400"
  "net.netfilter.nf_conntrack_tcp_be_liberal=1"
  "net.netfilter.nf_conntrack_udp_timeout=60"
  "net.netfilter.nf_conntrack_udp_timeout_stream=300"
  "net.core.rmem_max=33554432"
  "net.core.wmem_max=33554432"
  "net.core.netdev_max_backlog=250000"
  "net.core.netdev_budget=600"
  "net.core.default_qdisc=fq"
  "net.ipv4.tcp_congestion_control=bbr"
  "net.ipv4.tcp_rmem=4096 131072 33554432"
  "net.ipv4.tcp_wmem=4096 65536 33554432"
  "net.ipv4.tcp_mtu_probing=1"
  "net.ipv4.tcp_slow_start_after_idle=0"
)

LEGACY_RE='esp-tunnel-health|systemctl[[:space:]]+(re)?start[[:space:]]+esp-tunnel|service[[:space:]]+esp-tunnel[[:space:]]+(re)?start'

PY_UDP='
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
except Exception:
    pass
s.bind(("0.0.0.0", port))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP = UDP_ENCAP_ESPINUDP
while True:
    try:
        s.recvfrom(65535)
    except Exception:
        time.sleep(0.2)
'

# ------------------------------------------------------------------------------
#  Basic helpers
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
log()  { echo "[${APP}] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if printf -v _t '%(%s)T' -1 2>/dev/null; then
  now_s() { printf -v NOW '%(%s)T' -1; }
else
  now_s() { NOW=$(date +%s); }
fi

# log at most once per 60s per key (keeps the journal readable in a flap loop)
rlog() {
  local k=$1; shift
  now_s
  (( NOW - ${LOG_LAST[$k]:-0} >= 60 )) || return 0
  LOG_LAST[$k]=$NOW
  log "$*"
}

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

kdf() { local o; o=$(printf '%s' "$1" | sha512sum); printf '%s' "${o%% *}"; }

route_info() {
  local out a d
  out=$(ip -4 route get "$1" 2>/dev/null | head -n1)
  a=$(awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")
  d=$(awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")
  [[ -n $a && -n $d ]] || return 1       # keep last good values on failure
  LOCAL_ADDR=$a; WAN_DEV=$d
  return 0
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

xfrm_stat() { awk -v k="$1" '$1==k{print $2; exit}' /proc/net/xfrm_stat 2>/dev/null; }

# ------------------------------------------------------------------------------
#  Config
# ------------------------------------------------------------------------------
load_config() {
  [[ -r $CONF ]] || return 1
  MTU_OVERRIDE=""; NOTRACK=""
  # shellcheck disable=SC1090
  source "$CONF"
  MASTER=${MASTER:-$STATIC_MASTER}
  MODE=${MODE:-$DEFAULT_MODE}; UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}; FWD_PROTO=${FWD_PROTO:-both}
  NOTRACK=${NOTRACK:-1}
  case $ROLE in
    iran)   LOCAL_INNER=$IP_IRAN;   PEER_INNER=$IP_KHAREJ; PEER_PUB=$KHAREJ_IP; OUT_LABEL=i2k; IN_LABEL=k2i ;;
    kharej) LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN;   PEER_PUB=$IRAN_IP;   OUT_LABEL=k2i; IN_LABEL=i2k ;;
    *) return 1 ;;
  esac
  [[ -n $MASTER && -n $PEER_PUB ]] || return 1
  if [[ $MTU_OVERRIDE =~ ^[0-9]+$ ]] && (( 10#$MTU_OVERRIDE >= 1200 && 10#$MTU_OVERRIDE <= 1500 )); then
    MTU=$((10#$MTU_OVERRIDE))
  elif [[ $MODE == udp ]]; then
    MTU=$MTU_UDP
  else
    MTU=$MTU_ESP
  fi
  SPI_C=(); KEY_C=()
  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      echo "# ${APP} config"
      printf 'ROLE=%q\n'         "$ROLE"
      printf 'MASTER=%q\n'       "$MASTER"
      printf 'IRAN_IP=%q\n'      "$IRAN_IP"
      printf 'KHAREJ_IP=%q\n'    "$KHAREJ_IP"
      printf 'MODE=%q\n'         "$MODE"
      printf 'UDP_PORT=%q\n'     "$UDP_PORT"
      printf 'PORTS=%q\n'        "$PORTS"
      printf 'FWD_PROTO=%q\n'    "$FWD_PROTO"
      printf 'MTU_OVERRIDE=%q\n' "$MTU_OVERRIDE"
      printf 'NOTRACK=%q\n'      "$NOTRACK"
    } > "$CONF"
  )
  chmod 600 "$CONF"
}

reload_daemon() {
  if systemctl is-active --quiet "$APP"; then
    systemctl kill -s HUP --kill-whom=main "$APP" 2>/dev/null \
      && ok "Settings applied live (no restart, no downtime)." \
      || warn "Could not signal the service; run: systemctl restart $APP"
  fi
}

# ------------------------------------------------------------------------------
#  Dependencies / kernel / clock / legacy watchers
# ------------------------------------------------------------------------------
ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()
  have systemctl || { err "systemd is required."; return 1; }
  for c in ip iptables iptables-restore ping ss sha512sum awk python3 cksum sed grep; do
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
      ip|ss)                    [[ $pm == apt ]] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      ping)                     [[ $pm == apt ]] && pkgs+=(iputils-ping) || pkgs+=(iputils) ;;
      iptables|iptables-restore) pkgs+=(iptables) ;;
      python3)                  pkgs+=(python3) ;;
      awk)                      pkgs+=(gawk) ;;
      sed)                      pkgs+=(sed) ;;
      grep)                     pkgs+=(grep) ;;
      *)                        pkgs+=(coreutils) ;;
    esac
  done
  info "Installing dependencies: ${pkgs[*]}"
  if [[ $pm == apt ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
  else
    timeout 300 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1
  fi
  for c in "${missing[@]}"; do
    have "$c" || { err "Dependency still missing: $c"; return 1; }
  done
  return 0
}

load_modules() {
  local m
  for m in xfrm_interface xfrm_user esp4 gcm aesni_intel nf_conntrack xt_conntrack xt_TCPMSS \
           xt_CT iptable_nat iptable_raw tcp_bbr sch_fq; do
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

time_synced() { timedatectl status 2>/dev/null | grep -qiE 'synchronized: *yes'; }

# Keys are derived from the wall clock: both servers must agree on the hour.
ensure_time_sync() {
  have timedatectl || { warn "timedatectl not found: make sure both servers keep correct time (NTP)."; return 0; }
  time_synced && return 0
  warn "System clock is NOT NTP-synchronized (tunnel keys are time-based)."
  timedatectl set-ntp true >/dev/null 2>&1
  sleep 3
  if time_synced; then ok "NTP synchronization enabled."; return 0; fi
  warn "Still not synchronized. Check 'timedatectl status' and your NTP service on this server."
  return 0
}

legacy_files()  { grep -lsE "$LEGACY_RE" /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/* 2>/dev/null; }
legacy_units()  { systemctl list-unit-files --no-legend 2>/dev/null | awk '$1 ~ /^esp-tunnel-.+\.(timer|service)$/ {print $1}'; }
legacy_found() {
  [[ -n $(legacy_files) ]] && return 0
  [[ -e /usr/local/bin/esp-tunnel-healthcheck.sh ]] && return 0
  [[ -n $(legacy_units) ]] && return 0
  return 1
}

# Old health-check cron jobs / timers restart the service behind the daemon's
# back; every restart tears the tunnel down = periodic outage.
legacy_clean() {
  local f u bak="/root/${APP}-legacy-backup"
  legacy_found || { ok "No legacy watchers found."; return 0; }
  warn "Found external watchers that can restart the tunnel service:"
  for f in $(legacy_files); do
    echo "  $f"
    grep -nE "$LEGACY_RE" "$f" | sed 's/^/      /'
  done
  [[ -e /usr/local/bin/esp-tunnel-healthcheck.sh ]] && echo "  /usr/local/bin/esp-tunnel-healthcheck.sh"
  for u in $(legacy_units); do echo "  systemd unit: $u"; done
  if [[ ! -t 0 ]]; then
    warn "Non-interactive run: not removing automatically. Run: $BIN cleanup"
    return 0
  fi
  confirm "Remove them now? (backups go to $bak)" y || return 0
  mkdir -p "$bak"
  for f in $(legacy_files); do
    cp -a "$f" "$bak/$(tr '/' '_' <<<"$f")"
    sed -i -E "/$LEGACY_RE/d" "$f"
  done
  rm -f /usr/local/bin/esp-tunnel-healthcheck.sh
  for u in $(legacy_units); do
    systemctl disable --now "$u" >/dev/null 2>&1
    rm -f "/etc/systemd/system/$u"
  done
  systemctl daemon-reload
  ok "Legacy watchers removed."
}

# ------------------------------------------------------------------------------
#  Firewall (atomic, drift-aware)
# ------------------------------------------------------------------------------
ipt() { iptables -w 5 "$@"; }

ipt_restore() {
  local payload=$1
  printf '%s\n' "$payload" | iptables-restore -w 5 --noflush 2>/dev/null && return 0
  printf '%s\n' "$payload" | iptables-restore --noflush
}

raw_ok() { iptables -w 5 -t raw -S >/dev/null 2>&1; }

fw_define() {
  FW_SPECS=("filter ESPT_IN INPUT" "filter ESPT_FWD FORWARD" "mangle ESPT_MSS POSTROUTING")
  if [[ $ROLE == iran ]]; then
    FW_SPECS+=("nat ESPT_PRE PREROUTING" "nat ESPT_POST POSTROUTING")
  fi
  if (( NOTRACK )) && raw_ok; then
    FW_SPECS+=("raw ESPT_RAWP PREROUTING" "raw ESPT_RAWO OUTPUT")
  fi
}

fw_rules_of() {
  local c=$1 spec d pr
  local -a specs=() protos=()
  case $c in
    ESPT_IN)
      echo "-A ESPT_IN -i $IF_NAME -j ACCEPT"
      if [[ $MODE == udp ]]; then
        echo "-A ESPT_IN -p udp -m udp --dport $UDP_PORT -j ACCEPT"
      else
        echo "-A ESPT_IN -p 50 -s $PEER_PUB -j ACCEPT"
      fi ;;
    ESPT_FWD)
      echo "-A ESPT_FWD -i $IF_NAME -j ACCEPT"
      echo "-A ESPT_FWD -o $IF_NAME -j ACCEPT" ;;
    ESPT_MSS)
      echo "-A ESPT_MSS -o $IF_NAME -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $(( MTU - 40 ))" ;;
    ESPT_PRE)
      case $FWD_PROTO in tcp) protos=(tcp) ;; udp) protos=(udp) ;; *) protos=(tcp udp) ;; esac
      IFS=',' read -ra specs <<< "$PORTS"
      for spec in "${specs[@]}"; do
        [[ -z $spec ]] && continue
        d=${spec/-/:}
        for pr in "${protos[@]}"; do
          echo "-A ESPT_PRE ! -i $IF_NAME -p $pr -m $pr --dport $d -j DNAT --to-destination $IP_KHAREJ"
        done
      done ;;
    ESPT_POST)
      echo "-A ESPT_POST -o $IF_NAME -d $IP_KHAREJ -j SNAT --to-source $IP_IRAN" ;;
    ESPT_RAWP)
      if [[ $MODE == udp ]]; then
        echo "-A ESPT_RAWP -p udp -m udp --dport $UDP_PORT -j CT --notrack"
      else
        echo "-A ESPT_RAWP -p 50 -s $PEER_PUB -j CT --notrack"
      fi ;;
    ESPT_RAWO)
      if [[ $MODE == udp ]]; then
        echo "-A ESPT_RAWO -p udp -m udp --sport $UDP_PORT -j CT --notrack"
      else
        echo "-A ESPT_RAWO -p 50 -d $PEER_PUB -j CT --notrack"
      fi ;;
  esac
}

fw_chain_remove() {
  local t=$1 c=$2 h=$3
  while ipt -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  ipt -t "$t" -F "$c" 2>/dev/null
  ipt -t "$t" -X "$c" 2>/dev/null
}

# Make sure exactly one `-j CHAIN` exists in HOOK and that it is rule #1.
# The new jump is inserted BEFORE duplicates are removed (no unprotected moment).
fw_hook_ensure() {
  local t=$1 c=$2 h=$3 dump first cnt i
  local -a nums=()
  dump=$(iptables -w 5 -t "$t" -S "$h" 2>/dev/null) || return 1
  first=$(sed -n 2p <<<"$dump")
  cnt=$(grep -cxF -- "-A $h -j $c" <<<"$dump")
  [[ $first == "-A $h -j $c" && $cnt -eq 1 ]] && return 0
  if [[ $first != "-A $h -j $c" ]]; then
    ipt -t "$t" -I "$h" 1 -j "$c" || return 1
  fi
  mapfile -t nums < <(iptables -w 5 -t "$t" -L "$h" -n --line-numbers 2>/dev/null \
                      | awk -v c="$c" 'NR>2 && $2==c && $3=="all" {print $1}')
  for (( i=${#nums[@]}-1; i>=1; i-- )); do
    ipt -t "$t" -D "$h" "${nums[i]}" 2>/dev/null
  done
  return 0
}

# Signature of everything we own (chain contents + position of our jumps).
fw_sig() {
  local spec t c h s=""
  for spec in "${FW_SPECS[@]}"; do
    read -r t c h <<<"$spec"
    s+=$(iptables -w 5 -t "$t" -S "$c" 2>&1)
    s+=$(iptables -w 5 -t "$t" -S "$h" 2>&1 | sed -n 2p)
  done
  printf '%s' "$s" | cksum
}

fw_apply() {
  local spec t st c h payload rules rc=0
  local -A inset=()
  fw_define
  for spec in "${FW_SPECS[@]}"; do inset[$spec]=1; done

  for t in filter mangle nat raw; do
    payload=""
    for spec in "${FW_SPECS[@]}"; do
      read -r st c h <<<"$spec"
      [[ $st == "$t" ]] || continue
      rules=$(fw_rules_of "$c")
      payload+=":$c - [0:0]"$'\n'"-F $c"$'\n'
      [[ -n $rules ]] && payload+="$rules"$'\n'
    done
    [[ -n $payload ]] || continue
    ipt_restore "*${t}"$'\n'"${payload}COMMIT" || { log "ERROR: iptables-restore failed (table $t)"; rc=1; }
  done

  for spec in "${FW_SPECS[@]}"; do
    read -r t c h <<<"$spec"
    fw_hook_ensure "$t" "$c" "$h" || rc=1
  done

  for spec in "${FW_ALL[@]}"; do
    [[ -n ${inset[$spec]:-} ]] && continue
    read -r t c h <<<"$spec"
    fw_chain_remove "$t" "$c" "$h"
  done
  FW_SIG=$(fw_sig)
  return $rc
}

fw_verify() {
  [[ $(fw_sig) == "$FW_SIG" ]] && return 0
  log "firewall drift detected (flushed/reordered by another tool) -> re-applying"
  fw_apply
}

fw_remove() {
  local spec t c h
  have iptables || return 0
  for spec in "${FW_ALL[@]}"; do
    read -r t c h <<<"$spec"
    fw_chain_remove "$t" "$c" "$h"
  done
}

# ------------------------------------------------------------------------------
#  sysctl
# ------------------------------------------------------------------------------
sysctl_apply() {
  local kv body="" cur hs
  for kv in "${SYSCTL_LIST[@]}"; do body+="${kv/=/ = }"$'\n'; done
  cur=$(cat "$SYSCTL_FILE" 2>/dev/null)
  [[ "$cur" == "${body%$'\n'}" ]] || printf '%s' "$body" > "$SYSCTL_FILE"
  for kv in "${SYSCTL_LIST[@]}"; do sysctl -qw "$kv" >/dev/null 2>&1; done
  if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]]; then
    read -r hs < /sys/module/nf_conntrack/parameters/hashsize
    [[ $hs =~ ^[0-9]+$ ]] && (( hs < 131072 )) && echo 131072 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null
  fi
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

# cheap guard: other tools (ufw, sysctl --system, cloud-init) like to reset these
sysctl_verify() {
  local f p
  if [[ $(< /proc/sys/net/ipv4/ip_forward) != 1 ]]; then
    echo 1 > /proc/sys/net/ipv4/ip_forward
    rlog fwd "ip_forward had been reset to 0 -> restored"
  fi
  for f in all default lo "$IF_NAME"; do
    p=/proc/sys/net/ipv4/conf/$f/rp_filter
    if [[ -e $p && $(< "$p") != 0 ]]; then
      echo 0 > "$p"
      rlog rpf "rp_filter on $f had been changed -> restored"
    fi
  done
}

# ------------------------------------------------------------------------------
#  Interface
# ------------------------------------------------------------------------------
iface_create() {
  local out
  ip link del "$IF_NAME" 2>/dev/null
  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
    rlog ifc "ERROR: cannot create $IF_NAME: $out"; return 1
  fi
  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || return 1
  ip link set "$IF_NAME" mtu "$MTU" up || return 1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

ensure_iface() {
  local cur flags
  if [[ ! -d /sys/class/net/$IF_NAME ]]; then
    log "interface $IF_NAME missing -> creating"
    iface_create; return
  fi
  if ! ip -4 -o addr show dev "$IF_NAME" 2>/dev/null | grep -qF "${LOCAL_INNER}/${NET_PREFIX}"; then
    log "address ${LOCAL_INNER}/${NET_PREFIX} missing on $IF_NAME -> re-adding"
    ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" 2>/dev/null
  fi
  read -r cur < "/sys/class/net/$IF_NAME/mtu"
  if [[ $cur != "$MTU" ]]; then
    log "MTU on $IF_NAME is $cur, expected $MTU -> fixing"
    ip link set "$IF_NAME" mtu "$MTU"
  fi
  read -r flags < "/sys/class/net/$IF_NAME/flags"
  if (( (flags & 1) == 0 )); then
    log "$IF_NAME was down -> bringing up"
    ip link set "$IF_NAME" up
  fi
  return 0
}

# ------------------------------------------------------------------------------
#  XFRM policies (idempotent; never delete+add while traffic flows)
# ------------------------------------------------------------------------------
policies_remove() {
  local a b
  for a in "$IP_IRAN" "$IP_KHAREJ"; do
    if [[ $a == "$IP_IRAN" ]]; then b=$IP_KHAREJ; else b=$IP_IRAN; fi
    ip xfrm policy delete src "$a/32" dst "$b/32" dir out if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst "$b/32" dir in  if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" 2>/dev/null
  done
}

# `update` = atomic add-or-replace (no gap between delete and add)
pol_apply() {
  local out rc=0
  out=$(ip xfrm policy update src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
        tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
        || { log "ERROR: policy out: $out"; rc=1; }
  out=$(ip xfrm policy update src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
        || { log "ERROR: policy in: $out"; rc=1; }
  out=$(ip xfrm policy update src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
        || { log "ERROR: policy fwd: $out"; rc=1; }
  return $rc
}

ensure_policies() {
  local sig="$LOCAL_ADDR|$PEER_PUB" n
  # iproute2 prints if_id in hex (0x2a); accept both notations
  n=$(ip xfrm policy 2>/dev/null | grep -Ec "if_id (0x0*${IF_HEX}|${IF_ID})([^0-9a-fA-F]|$)")
  if [[ $POL_SIG == "$sig" ]] && (( n >= 3 )); then return 0; fi
  now_s
  # if the count method itself is unreliable on some iproute2, do not hammer the kernel
  if [[ $POL_SIG == "$sig" ]] && (( NOW - POL_FAIL_TS < 60 )); then return 0; fi
  POL_FAIL_TS=$NOW
  log "XFRM policies incomplete/outdated (found $n/3) -> atomic refresh"
  pol_apply || return 1
  POL_SIG=$sig
  return 0
}

# ------------------------------------------------------------------------------
#  XFRM states (SAs): verified against the kernel, not a text registry
# ------------------------------------------------------------------------------
kernel_sas() {      # prints: "src dst spi" for every SA that belongs to us
  ip xfrm state 2>/dev/null | awk -v rq="$IF_ID" '
    /^src /  { src=$2; dst=$4; next }
    /^[ \t]+proto esp/ {
      spi=""; r=""
      for (i=1;i<=NF;i++) { if ($i=="spi") spi=$(i+1); if ($i=="reqid") r=$(i+1) }
      sub(/\(.*/, "", spi); sub(/\(.*/, "", r)
      if (r==rq) print src, dst, spi
    }'
}

derive() {          # derive DIR EPOCH -> D_SRC D_DST D_SPI D_KEY  (same math as v1.5)
  local dir=$1 e=$2 label h k
  if [[ $dir == out ]]; then label=$OUT_LABEL; D_SRC=$LOCAL_ADDR; D_DST=$PEER_PUB
  else                       label=$IN_LABEL;  D_SRC=$PEER_PUB;   D_DST=$LOCAL_ADDR
  fi
  k="${label}|${e}"
  if [[ -z ${SPI_C[$k]:-} ]]; then
    h=$(kdf "${MASTER}|spi|${label}|${e}"); SPI_C[$k]="0x1${h:0:7}"
    h=$(kdf "${MASTER}|key|${label}|${e}"); KEY_C[$k]=${h:0:72}
  fi
  D_SPI=${SPI_C[$k]}; D_KEY=${KEY_C[$k]}
}

sa_install() {      # uses D_* ; args: dir epoch
  local out
  local -a args=(src "$D_SRC" dst "$D_DST" proto esp spi "$D_SPI" reqid "$IF_ID" mode tunnel
                 replay-window 0
                 aead 'rfc4106(gcm(aes))' "0x${D_KEY}" 128)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" 0.0.0.0); fi
  args+=(if_id "$IF_ID")
  if ! out=$(ip xfrm state add "${args[@]}" 2>&1); then
    rlog sa "ERROR: cannot add SA ($1 epoch $2): $out"
    return 1
  fi
  return 0
}

sa_delete() {       # "src dst spi"
  local s d p
  read -r s d p <<<"$1"
  ip xfrm state delete src "$s" dst "$d" proto esp spi "$p" 2>/dev/null
}

ensure_sas() {
  local e x item dir ep line rc=0 prev=$CUR_EPOCH
  local -a plan=()
  local -A want=() have=() wspi=()

  now_s; e=$(( NOW / EPOCH_LEN ))
  plan=("out $e")
  for (( x = e - IN_BACK; x <= e + IN_FWD; x++ )); do plan+=("in $x"); done

  while read -r line; do [[ -n $line ]] && have[$line]=1; done < <(kernel_sas)

  for item in "${plan[@]}"; do
    read -r dir ep <<<"$item"
    derive "$dir" "$ep"
    want["$D_SRC $D_DST $D_SPI"]=1
    wspi[$D_SPI]=1
  done

  # 1) same SPI but wrong addresses (public IP changed) -> remove first
  for line in "${!have[@]}"; do
    read -r _ _ x <<<"$line"
    if [[ -n ${wspi[$x]:-} && -z ${want[$line]:-} ]]; then
      log "removing SA with outdated addresses: $line"
      sa_delete "$line"
    fi
  done

  # 2) add whatever is missing (new keys go in BEFORE old ones are removed)
  for item in "${plan[@]}"; do
    read -r dir ep <<<"$item"
    derive "$dir" "$ep"
    [[ -n ${have["$D_SRC $D_DST $D_SPI"]:-} ]] && continue
    sa_install "$dir" "$ep" || rc=1
  done

  # 3) drop SAs of expired epochs
  for line in "${!have[@]}"; do
    read -r _ _ x <<<"$line"
    [[ -z ${wspi[$x]:-} ]] && sa_delete "$line"
  done

  if (( rc == 0 )); then
    if (( prev != 0 && prev != e )); then log "key rotation: epoch $prev -> $e"; fi
    CUR_EPOCH=$e
  fi
  return $rc
}

sa_flush() {
  local line
  while read -r line; do
    [[ -n $line ]] && sa_delete "$line"
  done < <(kernel_sas)
}

# ------------------------------------------------------------------------------
#  UDP encapsulation helper (socket that arms UDP_ENCAP_ESPINUDP)
# ------------------------------------------------------------------------------
udp_port_bound() {
  ss -uln 2>/dev/null | awk -v p=":${UDP_PORT}" '$4 ~ (p "$") {f=1} END{exit !f}'
}

udp_helper_alive() {
  [[ -f $UDP_PID_FILE ]] && kill -0 "$(< "$UDP_PID_FILE")" 2>/dev/null
}

udp_helper_stop() {
  if [[ -f $UDP_PID_FILE ]]; then
    kill "$(< "$UDP_PID_FILE")" 2>/dev/null
    rm -f "$UDP_PID_FILE"
  fi
}

udp_helper_start() {
  local i
  udp_helper_stop
  mkdir -p "$RUN_DIR"
  python3 -c "$PY_UDP" "$UDP_PORT" >/dev/null 2>"$UDP_ERR_FILE" &
  echo $! > "$UDP_PID_FILE"
  for i in 1 2 3 4 5 6 7 8; do
    sleep 0.25
    if udp_helper_alive && udp_port_bound; then return 0; fi
  done
  log "ERROR: cannot open UDP port $UDP_PORT: $(tail -n 1 "$UDP_ERR_FILE" 2>/dev/null)"
  return 1
}

ensure_udp() {
  [[ $MODE == udp ]] || return 0
  if udp_helper_alive && udp_port_bound; then return 0; fi
  rlog udp "UDP helper not healthy -> restarting"
  udp_helper_start
}

# ------------------------------------------------------------------------------
#  Reconcile / setup / teardown
# ------------------------------------------------------------------------------
ensure_all() {
  local rc=0 old=$LOCAL_ADDR
  if ! route_info "$PEER_PUB"; then
    rlog route "WARN: no route to peer $PEER_PUB (keeping current state)"
    [[ -n $LOCAL_ADDR ]] || return 1
  elif [[ -n $old && $old != "$LOCAL_ADDR" ]]; then
    log "local source address changed $old -> $LOCAL_ADDR (policies/SAs will follow)"
  fi
  ensure_iface    || rc=1
  ensure_policies || rc=1
  ensure_sas      || rc=1
  ensure_udp      || rc=1
  return $rc
}

teardown_all() {
  fw_remove
  udp_helper_stop
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null
  POL_SIG=""; FW_SIG=""
  return 0
}

setup_all() {
  teardown_all
  mkdir -p "$RUN_DIR"
  load_modules
  route_info "$PEER_PUB" || { log "ERROR: no route to peer $PEER_PUB"; return 1; }
  CUR_EPOCH=0
  sysctl_apply
  ensure_all || log "WARN: setup incomplete, reconcile loop will keep repairing"
  fw_apply
  log "tunnel up: $LOCAL_INNER <-> $PEER_INNER mode=$MODE port=$UDP_PORT mtu=$MTU epoch=$CUR_EPOCH"
  return 0
}

# ------------------------------------------------------------------------------
#  Probing / diagnostics
# ------------------------------------------------------------------------------
measure_rtt() {
  local avg ms
  avg=$(ping -c 4 -W 3 -I "$IF_NAME" "$PEER_INNER" 2>/dev/null | awk -F'/' '/rtt|round-trip/{print $5}')
  [[ -n $avg ]] || return 0
  ms=${avg%%.*}
  [[ $ms =~ ^[0-9]+$ ]] || return 0
  PROBE_W=$(( ms * 2 / 1000 + 3 ))
  (( PROBE_W < 3 )) && PROBE_W=3
  (( PROBE_W > 10 )) && PROBE_W=10
  log "adaptive probe timeout ${PROBE_W}s (baseline RTT ${ms}ms)"
}

peer_probe_ok() {
  local out rcv
  out=$(ping -c 2 -i 0.2 -W "$PROBE_W" -I "$IF_NAME" "$PEER_INNER" 2>/dev/null)
  rcv=$(awk -F'[, ]+' '/packets transmitted/{for(i=1;i<=NF;i++) if($i=="received"){print $(i-1); exit}}' <<<"$out")
  [[ ${rcv:-0} -ge 1 ]]
}

diag_log() {
  local k v d out=""
  now_s
  if [[ ! -r /proc/net/xfrm_stat ]]; then
    log "diag: epoch=$(( NOW / EPOCH_LEN )) utc=$(date -u +%H:%M:%S) (kernel has no xfrm_stat)"
    return 0
  fi
  for k in XfrmInNoStates XfrmInStateProtoError XfrmInStateMismatch XfrmInError XfrmInNoPols \
           XfrmInPolBlock XfrmInPolError XfrmOutNoStates XfrmOutPolBlock XfrmOutPolError XfrmOutStateSeqError; do
    v=$(xfrm_stat "$k"); v=${v:-0}
    d=$(( v - ${XS_PREV[$k]:-0} ))
    XS_PREV[$k]=$v
    (( d > 0 )) && out+=" $k+$d"
  done
  log "diag: epoch=$(( NOW / EPOCH_LEN )) utc=$(date -u +%H:%M:%S) xfrm_delta:${out:- none}"
  if   [[ $out == *XfrmInNoStates* ]]; then
    log "diag: peer sends ESP with SPIs we do not hold -> clock/epoch mismatch or different MASTER. Compare 'date -u' and NTP on BOTH servers."
  elif [[ $out == *XfrmInStateProtoError* || $out == *XfrmInError* ]]; then
    log "diag: ESP decrypt errors -> wrong key or damaged packets (MTU / fragmentation on the path?)."
  elif [[ $out == *XfrmInNoPols* || $out == *XfrmInPolBlock* ]]; then
    log "diag: inbound policy problem (policies are verified every ${TICK}s)."
  elif [[ $out == *XfrmOutNoStates* ]]; then
    log "diag: no outbound SA at the moment (SAs are verified every ${TICK}s)."
  elif [[ -z $out ]]; then
    log "diag: nothing arrives from the peer -> ISP/underlay drop, peer service down, or UDP $UDP_PORT blocked."
  fi
}

# ------------------------------------------------------------------------------
#  Daemon
# ------------------------------------------------------------------------------
cmd_daemon() {
  local tries=0 tick=0
  load_config || { log "ERROR: missing config"; exit 1; }
  mkdir -p "$RUN_DIR"
  trap 'log "stop signal received"; exit 0' TERM INT
  trap 'RELOAD=1' HUP

  until route_info "$PEER_PUB"; do
    (( ++tries > 60 )) && { log "ERROR: no route to $PEER_PUB"; exit 1; }
    sleep 2
  done
  load_modules
  log "starting v${VERSION} role=$ROLE mode=$MODE mtu=$MTU peer=$PEER_PUB notrack=$NOTRACK"
  time_synced || log "WARN: system clock is not NTP-synchronized (keys are time based!)"
  legacy_found && log "WARN: legacy watcher (cron/timer) found - it may restart this service. Run: $BIN cleanup"

  sysctl_apply
  ensure_all || log "WARN: initial setup incomplete; reconcile loop will retry"
  fw_apply
  now_s; LAST_REBUILD=$NOW
  log "tunnel up: $LOCAL_INNER <-> $PEER_INNER epoch=$CUR_EPOCH"
  measure_rtt

  while true; do
    sleep "$TICK" &
    wait $!

    if (( RELOAD )); then
      RELOAD=0
      log "reload requested (SIGHUP)"
      if load_config; then
        sysctl_apply; ensure_all; fw_apply
        log "reloaded: mtu=$MTU ports=${PORTS:-n/a} notrack=$NOTRACK"
      else
        log "WARN: reload failed, keeping previous settings"
      fi
    fi

    # --- 1. reconcile local state (cheap, silent when healthy) ---
    ensure_all
    sysctl_verify
    (( ++tick % FW_EVERY == 0 )) && fw_verify

    # --- 2. peer probe (also acts as NAT / conntrack keepalive) ---
    now_s
    if peer_probe_ok; then
      if [[ $PEER_STATE != up ]]; then
        if (( DOWN_SINCE > 0 )); then log "peer reachable again (silent for $(( NOW - DOWN_SINCE ))s)"
        else log "peer reachable"; fi
      fi
      PEER_STATE=up; FAILS=0; DOWN_SINCE=0
    else
      FAILS=$(( FAILS + 1 ))
      (( DOWN_SINCE == 0 )) && DOWN_SINCE=$NOW
      if (( FAILS == FAIL_WARN )); then
        PEER_STATE=down
        log "peer silent for ~$(( NOW - DOWN_SINCE ))s; local state verified OK, waiting (no teardown)"
        diag_log
      elif (( FAILS > FAIL_WARN && FAILS % 12 == 0 )); then
        diag_log
      fi
      if (( NOW - DOWN_SINCE >= DOWN_REBUILD_SEC && NOW - LAST_REBUILD >= REBUILD_COOLDOWN )); then
        log "peer silent for $(( NOW - DOWN_SINCE ))s -> last-resort full rebuild"
        setup_all
        now_s; LAST_REBUILD=$NOW; DOWN_SINCE=$NOW
      fi
    fi
  done
}

cmd_teardown() { teardown_all; log "tunnel torn down"; }

# systemd ExecStopPost: tear down only on a deliberate stop/restart. After a crash
# (SERVICE_RESULT != success) keep the live state so the new daemon adopts it.
cmd_stoppost() {
  if [[ ${SERVICE_RESULT:-success} == success ]]; then
    teardown_all
  fi
}

cmd_fw() { load_config || exit 1; route_info "$PEER_PUB" || exit 1; fw_apply; }

# ------------------------------------------------------------------------------
#  Install / service
# ------------------------------------------------------------------------------
install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  if [[ ! -f $src ]]; then
    err "Cannot read the script file (piped execution?). Save it first, e.g.:"
    err "  curl -fsSL <URL> -o esp-tunnel.sh && bash esp-tunnel.sh"
    return 1
  fi
  [[ $src != "$BIN" ]] && install -m 755 "$src" "$BIN"
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP Tunnel Service (${APP})
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BIN} daemon
ExecStopPost=${BIN} stoppost
Restart=always
RestartSec=2
TimeoutStopSec=20
Nice=-5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  local i
  write_unit
  systemctl daemon-reload
  systemctl enable "$APP" >/dev/null 2>&1
  systemctl restart "$APP"
  for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; then
      ok "Tunnel service started successfully."
      return 0
    fi
  done
  err "Service failed to start. Check: journalctl -u $APP -n 50"
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

  ROLE=iran
  MASTER="$STATIC_MASTER"
  MODE="$DEFAULT_MODE"
  UDP_PORT="$DEFAULT_UDP_PORT"
  MTU_OVERRIDE=""
  NOTRACK=1

  write_config; load_config
  legacy_clean
  ensure_time_sync
  start_service || return
  echo
  ok "Iran server setup complete!"
  echo "${C_G}No token copy-paste needed!${C_0}"
  echo "Now run option 2 on Kharej server and just enter this Iran IP: ${C_Y}${IRAN_IP}${C_0}"
  echo
  pause
}

setup_kharej() {
  confirm_reinstall || return
  install_self || return
  info "Configuring KHAREJ Client side (10.10.10.1)"
  ensure_deps || return
  check_kernel || return

  local det
  det=$(detect_public_ip)
  read -r -p "Kharej Public IP [$det]: " KHAREJ_IP; KHAREJ_IP=${KHAREJ_IP:-$det}
  while true; do
    read -r -p "Iran Server Public IP: " IRAN_IP
    valid_ip "$IRAN_IP" && break
    err "Invalid IPv4 address."
  done

  ROLE=kharej
  MASTER="$STATIC_MASTER"
  MODE="$DEFAULT_MODE"
  UDP_PORT="$DEFAULT_UDP_PORT"
  PORTS=""
  FWD_PROTO="both"
  MTU_OVERRIDE=""
  NOTRACK=1

  write_config; load_config
  legacy_clean
  ensure_time_sync
  start_service || return
  echo
  info "Testing ping to Iran (${PEER_INNER})..."
  ping -c 4 -W 2 -I "$IF_NAME" "$PEER_INNER"
  echo
  ok "Kharej client connected using static auto-token!"
  pause
}

cmd_upgrade() {
  load_config || { err "Not installed yet: use option 1 or 2 first."; return 1; }
  install_self || return 1
  legacy_clean
  ensure_time_sync
  start_service
}

# ------------------------------------------------------------------------------
#  Status / tools
# ------------------------------------------------------------------------------
cmd_status() {
  local k v
  load_config || { warn "Not installed."; return; }
  now_s; fw_define
  echo "Version: v${VERSION} | Role: $ROLE | Mode: $MODE | UDP Port: $UDP_PORT | MTU: $MTU${MTU_OVERRIDE:+ (override)} | Epoch: $(( NOW / EPOCH_LEN )) | NOTRACK: $NOTRACK"
  echo "Service: $(systemctl is-active "$APP") | Clock NTP-synced: $(time_synced && echo yes || echo NO)"
  ip -br addr show "$IF_NAME" 2>/dev/null
  echo "SAs in kernel: $(kernel_sas | wc -l) (expected $(( IN_BACK + IN_FWD + 2 )))"
  if [[ -r /proc/net/xfrm_stat ]]; then
    for k in XfrmInNoStates XfrmInStateProtoError XfrmInError XfrmInNoPols XfrmOutNoStates XfrmOutPolBlock; do
      v=$(xfrm_stat "$k"); [[ ${v:-0} -gt 0 ]] && echo "  counter $k = $v"
    done
  fi
  local spec ft fc fwmiss=0
  for spec in "${FW_SPECS[@]}"; do
    read -r ft fc _ <<<"$spec"
    iptables -w 5 -t "$ft" -S "$fc" >/dev/null 2>&1 || { echo "  firewall chain missing: $ft/$fc"; fwmiss=1; }
  done
  (( fwmiss )) || echo "Firewall chains: OK"
  legacy_found && warn "Legacy watcher found (may restart the tunnel). Run: $BIN cleanup"
  echo "Ping test:"
  ping -c 4 -W 2 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 2
}

mtu_try() { ping -M 'do' -s "$1" -c 3 -i 0.3 -W 2 "$PEER_PUB" >/dev/null 2>&1; }

cmd_mtu_test() {
  load_config || { warn "Not installed."; return 1; }
  local lo=1200 hi=1472 mid pmtu rec ovh
  info "Measuring underlay path MTU to $PEER_PUB (ICMP, DF bit set) ..."
  if ! ping -c 3 -W 2 "$PEER_PUB" >/dev/null 2>&1; then
    warn "Peer does not answer ICMP, cannot measure. Keep the default MTU ($MTU) or set one manually."
    return 1
  fi
  if mtu_try "$hi"; then
    lo=$hi
  elif mtu_try "$lo"; then
    hi=$(( hi - 1 ))
    while (( lo < hi )); do
      mid=$(( (lo + hi + 1) / 2 ))
      if mtu_try "$mid"; then lo=$mid; else hi=$(( mid - 1 )); fi
    done
  else
    warn "Even a ${lo}-byte payload fails (ICMP size filtering?). Result would be unreliable; keeping default."
    return 1
  fi
  pmtu=$(( lo + 28 ))
  if [[ $MODE == udp ]]; then ovh=65; else ovh=57; fi
  rec=$(( (pmtu - ovh) / 4 * 4 ))
  (( rec < 1200 )) && rec=1200
  (( rec > 1500 )) && rec=1500
  echo "Path MTU (this -> peer): $pmtu | max tunnel MTU for $MODE mode: $rec | current: $MTU"
  echo "Run this on BOTH servers and use the smaller value. ICMP filtering can under-report."
  if (( rec != MTU )) && confirm "Apply MTU $rec on this server?" n; then
    MTU_OVERRIDE=$rec
    write_config
    reload_daemon
  fi
}

cmd_edit() {
  load_config || { warn "Not installed."; return; }
  local c v
  while true; do
    echo
    echo "Current: MTU=$MTU (${MTU_OVERRIDE:-auto}) | NOTRACK=$NOTRACK | ports=${PORTS:-n/a} | proto=$FWD_PROTO"
    echo "  1) Set MTU manually (1200-1500)"
    echo "  2) Reset MTU to default (auto: $([[ $MODE == udp ]] && echo $MTU_UDP || echo $MTU_ESP))"
    echo "  3) Toggle NOTRACK for the outer tunnel flow (on = less CPU)"
    echo "  4) Change forwarded ports        (Iran only)"
    echo "  5) Change forwarding protocol    (Iran only)"
    echo "  0) Back"
    read -r -p "Select: " c
    case $c in
      1) read -r -p "MTU: " v
         if [[ $v =~ ^[0-9]+$ ]] && (( 10#$v >= 1200 && 10#$v <= 1500 )); then
           MTU_OVERRIDE=$((10#$v)); write_config; load_config; reload_daemon
         else err "Invalid MTU."; fi ;;
      2) MTU_OVERRIDE=""; write_config; load_config; reload_daemon ;;
      3) if (( NOTRACK )); then NOTRACK=0; else NOTRACK=1; fi
         write_config; load_config; reload_daemon ;;
      4) if [[ $ROLE == iran ]]; then ask_ports; write_config; load_config; reload_daemon
         else warn "Ports are configured on the Iran server."; fi ;;
      5) if [[ $ROLE == iran ]]; then ask_fwd_proto; write_config; load_config; reload_daemon
         else warn "Forwarding protocol is configured on the Iran server."; fi ;;
      0|q|Q) return ;;
    esac
  done
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
  local ch
  while true; do
    echo
    echo "${C_B}======================================================${C_0}"
    echo "${C_B}   ESP Tunnel Manager v${VERSION} (Zero-Drop Edition)     ${C_0}"
    echo "${C_B}======================================================${C_0}"
    echo "  1) Setup Iran Server"
    echo "  2) Setup Kharej Client"
    echo "  3) Status & Ping"
    echo "  4) Live Journal Log"
    echo "  5) Edit Settings (MTU / ports / ...)"
    echo "  6) MTU Test (find the best MTU)"
    echo "  7) Upgrade script & restart (keep config)"
    echo "  8) Remove legacy watchers (old cron/healthcheck)"
    echo "  9) Uninstall"
    echo "  0) Exit"
    echo
    read -r -p "Select: " ch
    case $ch in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; pause ;;
      4) journalctl -u "$APP" -f -n 30 ;;
      5) cmd_edit ;;
      6) cmd_mtu_test; pause ;;
      7) cmd_upgrade; pause ;;
      8) legacy_clean; pause ;;
      9) uninstall_all; pause ;;
      0|q|Q) exit 0 ;;
    esac
  done
}

main() {
  case "${1:-menu}" in
    menu)              need_root; menu ;;
    status)            need_root; cmd_status ;;
    daemon)            need_root; cmd_daemon ;;
    teardown)          need_root; cmd_teardown ;;
    stoppost)          need_root; cmd_stoppost ;;
    fw)                need_root; cmd_fw ;;
    upgrade)           need_root; cmd_upgrade ;;
    mtu-test)          need_root; cmd_mtu_test ;;
    cleanup)           need_root; legacy_clean ;;
    version|-v|--version) echo "${APP} v${VERSION}" ;;
    *) echo "Usage: $0 {menu|status|upgrade|mtu-test|cleanup|version}"; exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
