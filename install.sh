#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager v2.0
#   - Manual config editor (MTU, ports, mode, secret, watchdog ...)
#   - Scanner: best outgoing UDP port + real Path-MTU probing, applied live
#   - Faster self-healing (1s keepalive, exponential backoff), kernel tuning,
#     warm-up burst at start, safer SA registry handling
# ==============================================================================

APP="esp-tunnel"
VERSION="2.0"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"
UDP_PORTS_FILE="${RUN_DIR}/udp.ports"
SCAN_LOCK="${RUN_DIR}/scan.lock"

# ---- توکن و تنظیمات پیش‌فرض (Shared Static Secret) ----
# هشدار: این کلید داخل اسکریپت عمومی است. برای امنیت واقعی از منوی Edit ->
# Shared secret یک کلید اختصاصی بسازید و روی هر دو سرور یکسان بگذارید.
STATIC_MASTER="e7d8f3c1a4b92850d6e1749c3b8a1052f9c4e7b8a1d2e3f4c5b6a78901234567"
DEFAULT_UDP_PORT=39540
DEFAULT_MODE="udp"
DEFAULT_PORTS="443,80,2053,2083,2087,2096,8443"
# پورت‌های کاندید برای اسکنر (هر دو سرور باید روی این‌ها گوش بدهند)
DEFAULT_EXTRA_PORTS="4500,500,1194,5060,3478,51820"
DEFAULT_TICK=1              # فاصله چک سلامت (ثانیه)
DEFAULT_FAIL_LIMIT=5        # تعداد شکست پشت‌سرهم قبل از self-heal
DEFAULT_RX_STALL_SEC=45     # قطع یک‌طرفه: چند ثانیه قبل از بررسی

IF_NAME="espt0"
IF_ID=42
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30
EPOCH_LEN=3600
MTU_ESP=1400
MTU_UDP=1360
MTU_SEARCH_MIN=1000         # کف جستجوی MTU در اسکنر
MTU_MARGIN=8                # حاشیه امن روی MTU پیدا شده

ROLE=""; MASTER="$STATIC_MASTER"; IRAN_IP=""; KHAREJ_IP=""; MODE="$DEFAULT_MODE"; UDP_PORT="$DEFAULT_UDP_PORT"
PEER_UDP_PORT="$DEFAULT_UDP_PORT"; EXTRA_PORTS="$DEFAULT_EXTRA_PORTS"; MTU_OVERRIDE=0
TICK="$DEFAULT_TICK"; FAIL_LIMIT="$DEFAULT_FAIL_LIMIT"; RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"
PORTS=""; FWD_PROTO="both"
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_UDP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0

RX0=0; TX0=0; RX_STALL_START=0; FAILS=0; RELOAD=0
REB_BACKOFF=0; REB_NEXT=0; OK_STREAK=0
Q_LOSS=100; Q_MIN=0; Q_AVG=9999; Q_MAX=0; Q_MDEV=0
M_LOSS=100; M_AVG=9999; M_BIG=9999; M_JIT=0; M_SCORE=99999
PMTU_FOUND=0; SCAN_ABORT=0

# هلپر UDP: روی چند پورت گوش می‌دهد و سوکت‌ها را ESPINUDP می‌کند.
# argv[1]=فایل خروجی (لیست پورت‌های باز شده)  argv[2]=پورت اصلی  بقیه=پورت‌های اضافه
PY_UDP='
import socket, sys, select, time
out = sys.argv[1]
ports = [int(p) for p in sys.argv[2:]]
socks, bound = [], []
for i, p in enumerate(ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP_ESPINUDP
        s.setblocking(False)
        socks.append(s)
        bound.append(p)
    except OSError:
        if i == 0:
            sys.exit(1)
if not socks:
    sys.exit(1)
with open(out, "w") as f:
    f.write(",".join(str(p) for p in bound))
while True:
    try:
        r, _, _ = select.select(socks, [], [], 5)
        for s in r:
            try:
                s.recvfrom(65535)
            except OSError:
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

# ------------------------------------------------------------------------------
#  Validation helpers
# ------------------------------------------------------------------------------
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
valid_mtu()  { [[ $1 =~ ^[0-9]{3,4}$ ]] && (( 10#$1 >= 576 && 10#$1 <= 1500 )); }
valid_uint_range() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }

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

# لیست پورت‌های تکی (بدون رنج)، یکتا، حداکثر ۱۴ عدد؛ خالی مجاز است
norm_port_list() {
  local raw=${1//[[:space:]]/} p
  local -a out=() specs=()
  raw=${raw//،/,}
  if [[ -z $raw ]]; then echo ""; return 0; fi
  IFS=',' read -ra specs <<< "$raw"
  for p in "${specs[@]}"; do
    [[ -z $p ]] && continue
    valid_port "$p" || return 1
    p=$((10#$p))
    [[ " ${out[*]} " == *" $p "* ]] || out+=("$p")
  done
  (( ${#out[@]} <= 14 )) || return 1
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

# پورت اصلی + پورت‌های اضافه (یکتا، با فاصله جدا شده)
listen_ports() {
  local p res="$UDP_PORT"
  local -a ex=()
  IFS=',' read -ra ex <<< "$EXTRA_PORTS"
  for p in "${ex[@]}"; do
    [[ -z $p || $p == "$UDP_PORT" ]] && continue
    [[ " $res " == *" $p "* ]] || res+=" $p"
  done
  echo "$res"
}

flt_lt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 < b+0)}'; }

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

# ------------------------------------------------------------------------------
#  Config
# ------------------------------------------------------------------------------
load_config() {
  [[ -r $CONF ]] || return 1
  unset PEER_UDP_PORT EXTRA_PORTS MTU_OVERRIDE TICK FAIL_LIMIT RX_STALL_SEC
  # shellcheck disable=SC1090
  source "$CONF"
  MASTER=${MASTER:-$STATIC_MASTER}
  MODE=${MODE:-$DEFAULT_MODE}; UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}; FWD_PROTO=${FWD_PROTO:-both}
  PEER_UDP_PORT=${PEER_UDP_PORT:-$UDP_PORT}
  EXTRA_PORTS=${EXTRA_PORTS-$DEFAULT_EXTRA_PORTS}
  MTU_OVERRIDE=${MTU_OVERRIDE:-0}
  TICK=${TICK:-$DEFAULT_TICK}
  FAIL_LIMIT=${FAIL_LIMIT:-$DEFAULT_FAIL_LIMIT}
  RX_STALL_SEC=${RX_STALL_SEC:-$DEFAULT_RX_STALL_SEC}
  case $ROLE in
    iran)   LOCAL_INNER=$IP_IRAN;   PEER_INNER=$IP_KHAREJ; PEER_PUB=$KHAREJ_IP; OUT_LABEL=i2k; IN_LABEL=k2i ;;
    kharej) LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN;   PEER_PUB=$IRAN_IP;   OUT_LABEL=k2i; IN_LABEL=i2k ;;
    *) return 1 ;;
  esac
  [[ -n $MASTER && -n $PEER_PUB ]] || return 1
  if [[ $MODE == udp ]]; then MTU=$MTU_UDP; else MTU=$MTU_ESP; fi
  if valid_mtu "$MTU_OVERRIDE"; then MTU=$((10#$MTU_OVERRIDE)); fi
  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      echo "# ${APP} config"
      printf 'ROLE=%q\n'          "$ROLE"
      printf 'MASTER=%q\n'        "$MASTER"
      printf 'IRAN_IP=%q\n'       "$IRAN_IP"
      printf 'KHAREJ_IP=%q\n'     "$KHAREJ_IP"
      printf 'MODE=%q\n'          "$MODE"
      printf 'UDP_PORT=%q\n'      "$UDP_PORT"
      printf 'PEER_UDP_PORT=%q\n' "$PEER_UDP_PORT"
      printf 'EXTRA_PORTS=%q\n'   "$EXTRA_PORTS"
      printf 'PORTS=%q\n'         "$PORTS"
      printf 'FWD_PROTO=%q\n'     "$FWD_PROTO"
      printf 'MTU_OVERRIDE=%q\n'  "$MTU_OVERRIDE"
      printf 'TICK=%q\n'          "$TICK"
      printf 'FAIL_LIMIT=%q\n'    "$FAIL_LIMIT"
      printf 'RX_STALL_SEC=%q\n'  "$RX_STALL_SEC"
    } > "$CONF"
  )
  chmod 600 "$CONF"
}

init_defaults() {
  MODE="$DEFAULT_MODE"; UDP_PORT="$DEFAULT_UDP_PORT"; PEER_UDP_PORT="$DEFAULT_UDP_PORT"
  EXTRA_PORTS="$DEFAULT_EXTRA_PORTS"; MTU_OVERRIDE=0
  TICK="$DEFAULT_TICK"; FAIL_LIMIT="$DEFAULT_FAIL_LIMIT"; RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"
}

# ------------------------------------------------------------------------------
#  Dependencies / kernel
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
#  Firewall
# ------------------------------------------------------------------------------
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

fw_apply_filter() {
  local p
  fw_chain_reset filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT
  if [[ $MODE == udp ]]; then
    # پذیرش از هر مبدا (پشتیبانی IP داینامیک/CGNAT)؛ امنیت با احراز هویت ESP در هسته
    for p in $(listen_ports); do
      ipt -A ESPT_IN -p udp --dport "$p" -j ACCEPT
    done
  else
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
  fi
  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT
}

fw_apply_mss() {
  local target_mss=$(( MTU - 40 ))
  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$target_mss"
}

fw_apply_nat() {
  local spec d pr p
  local -a specs=() protos=()
  [[ $ROLE == iran ]] || return 0
  fw_chain_reset nat ESPT_PRE  PREROUTING
  fw_chain_reset nat ESPT_POST POSTROUTING
  # پورت‌های خود تونل هرگز DNAT نشوند (وگرنه پکت‌های ESP-in-UDP به هلپر نمی‌رسند)
  if [[ $MODE == udp ]]; then
    for p in $(listen_ports); do
      ipt -t nat -A ESPT_PRE -p udp --dport "$p" -j RETURN
    done
  fi
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
}

fw_apply() {
  fw_apply_filter
  fw_apply_mss
  fw_apply_nat
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
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180
net.core.netdev_max_backlog = 16384
net.core.netdev_budget = 600
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
EOF
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

# ------------------------------------------------------------------------------
#  Interface / XFRM policies / SAs
# ------------------------------------------------------------------------------
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

# فرمت رجیستری: dir epoch spi src dst dport
sa_add() {
  local dir=$1 e=$2 src dst label spi key out op=add dport
  local old_line old_src old_dst old_spi old_port
  local -a args=()
  if [[ $dir == out ]]; then src=$LOCAL_ADDR; dst=$PEER_PUB;  label=$OUT_LABEL; dport=$PEER_UDP_PORT
  else                       src=$PEER_PUB;   dst=$LOCAL_ADDR; label=$IN_LABEL;  dport=$UDP_PORT
  fi

  old_line=$(grep "^$dir $e " "$REG" 2>/dev/null)
  if [[ -n $old_line ]]; then
    read -r _ _ old_spi old_src old_dst old_port <<< "$old_line"
    old_port=${old_port:-$dport}
    if [[ $old_src == "$src" && $old_dst == "$dst" ]]; then
      [[ $old_port == "$dport" ]] && return 0      # بدون تغییر
      op=update                                    # فقط پورت عوض شده
    else
      # IP عوض شده: SA قدیمی پاک شود
      ip xfrm state delete src "$old_src" dst "$old_dst" proto esp spi "$old_spi" 2>/dev/null
    fi
    grep -v "^$dir $e " "$REG" > "${REG}.tmp" 2>/dev/null
    mv -f "${REG}.tmp" "$REG"
  fi

  spi="0x1$(kdf "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
  key=$(kdf "${MASTER}|key|${label}|${e}" | cut -c1-72)

  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        replay-window 0
        aead 'rfc4106(gcm(aes))' "0x${key}" 128)
  if [[ $MODE == udp ]]; then
    if [[ $dir == out ]]; then args+=(encap espinudp "$UDP_PORT" "$dport" 0.0.0.0)
    else                       args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" 0.0.0.0); fi
  fi
  args+=(if_id "$IF_ID")

  if ! out=$(ip xfrm state "$op" "${args[@]}" 2>&1); then
    if [[ $op == update ]]; then
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
      out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
    else
      log "ERROR: cannot add SA: $out"; return 1
    fi
  fi
  echo "$dir $e $spi $src $dst $dport" >> "$REG"
  return 0
}

prune_sa() {
  local e=$1 dir ep spi src dst dport keep tmp
  [[ -f $REG ]] || return 0
  tmp=$(mktemp)
  while read -r dir ep spi src dst dport; do
    [[ -n $spi ]] || continue
    keep=1
    if [[ $dir == out ]]; then
      (( ep != e )) && keep=0
    else
      # پنجره تحمل ±۲ ساعت برای اختلاف ساعت سرورها
      (( ep < e - 2 || ep > e + 2 )) && keep=0
    fi
    if (( keep )); then
      echo "$dir $ep $spi $src $dst $dport" >> "$tmp"
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
  for x in $((e - 2)) $((e - 1)) "$e" $((e + 1)) $((e + 2)); do
    sa_add in "$x" || return 1
  done
  prune_sa "$e"
  return 0
}

sa_flush() {
  local dir ep spi src dst dport
  if [[ -f $REG ]]; then
    while read -r dir ep spi src dst dport; do
      [[ -n $spi ]] && ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    done < "$REG"
  fi
  rm -f "$REG"
}

# ------------------------------------------------------------------------------
#  UDP helper
# ------------------------------------------------------------------------------
udp_helper_stop() {
  if [[ -f $UDP_PID_FILE ]]; then
    kill "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null
    rm -f "$UDP_PID_FILE"
  fi
}

udp_helper_start() {
  udp_helper_stop
  rm -f "$UDP_PORTS_FILE"
  # shellcheck disable=SC2046
  python3 -c "$PY_UDP" "$UDP_PORTS_FILE" $(listen_ports) >/dev/null 2>&1 &
  echo $! > "$UDP_PID_FILE"
  for _ in {1..30}; do
    [[ -s $UDP_PORTS_FILE ]] && return 0
    kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null || break
    sleep 0.1
  done
  log "ERROR: cannot open UDP port $UDP_PORT"
  return 1
}

# ------------------------------------------------------------------------------
#  Tunnel lifecycle
# ------------------------------------------------------------------------------
teardown_all() {
  fw_remove
  udp_helper_stop
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null
  return 0
}

setup_all() {
  load_config || { log "ERROR: bad config"; return 1; }
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
  # warm-up: چند پینگ سریع برای باز کردن NAT/pinhole و شروع سریع‌تر ارتباط
  ( ping -c 4 -i 0.2 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1 & )
  log "tunnel up: $LOCAL_INNER <-> $PEER_INNER mode=$MODE mtu=$MTU port=$UDP_PORT->$PEER_UDP_PORT epoch=$CUR_EPOCH"
  return 0
}

soft_heal() {
  local old_dev=$WAN_DEV
  log "running soft self-healing..."
  route_info "$PEER_PUB" || return 1
  if [[ $WAN_DEV != "$old_dev" ]]; then
    log "WAN device changed ($old_dev -> $WAN_DEV): full rebuild needed"
    return 1
  fi
  if [[ $MODE == udp ]]; then
    if [[ ! -f $UDP_PID_FILE ]] || ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; then
      udp_helper_start
    fi
  fi
  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  install_epoch "$CUR_EPOCH"
  policies_setup
  sysctl_apply
  return 0
}

if_counters() {
  local r t
  r=$(cat "/sys/class/net/${IF_NAME}/statistics/rx_bytes" 2>/dev/null) || r=0
  t=$(cat "/sys/class/net/${IF_NAME}/statistics/tx_bytes" 2>/dev/null) || t=0
  echo "${r:-0} ${t:-0}"
}

watchdog_rebuild() {
  local reason=$1
  log "watchdog triggering rebuild: $reason"
  if ! soft_heal || ! ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
    log "soft-heal failed, performing full rebuild..."
    setup_all
  else
    log "soft-heal succeeded, tunnel restored without tearing down interface."
  fi
  RX_STALL_START=0
  FAILS=0
  read -r RX0 TX0 <<< "$(if_counters)"
}

# rebuild با backoff نمایی (۵،۱۰،۲۰،۴۰،۶۰ ثانیه) تا وقتی پیر واقعاً قطع است حلقه‌ی بی‌پایان نسازد
maybe_rebuild() {
  local now
  now=$(date +%s)
  (( now < REB_NEXT )) && return 0
  watchdog_rebuild "$1"
  if (( REB_BACKOFF == 0 )); then REB_BACKOFF=5; else REB_BACKOFF=$(( REB_BACKOFF * 2 )); fi
  (( REB_BACKOFF > 60 )) && REB_BACKOFF=60
  REB_NEXT=$(( $(date +%s) + REB_BACKOFF ))
  OK_STREAK=0
}

# قفل مشترک: وقتی اسکنر/ادیتور در حال تغییر تونل است، دیمون دخالت نمی‌کند
lock_touch()   { mkdir -p "$RUN_DIR"; : > "$SCAN_LOCK"; }
lock_release() { rm -f "$SCAN_LOCK"; }
scan_active() {
  local t
  [[ -f $SCAN_LOCK ]] || return 1
  t=$(stat -c %Y "$SCAN_LOCK" 2>/dev/null) || return 1
  (( $(date +%s) - t < 120 ))
}

cmd_daemon() {
  local tries=0 e now rx tx
  trap 'log "stop signal received"; exit 0' TERM INT
  trap 'RELOAD=1' HUP
  load_config || { log "ERROR: missing config"; exit 1; }
  mkdir -p "$RUN_DIR"

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && { log "ERROR: no route to $PEER_PUB"; exit 1; }
    sleep 2
  done
  setup_all || { log "ERROR: setup failed"; exit 1; }
  read -r RX0 TX0 <<< "$(if_counters)"

  while true; do
    sleep "$TICK" &
    wait $!
    now=$(date +%s)

    if (( RELOAD )); then
      RELOAD=0
      load_config && log "config reloaded"
    fi
    scan_active && continue

    # 1. Hourly key rotation
    e=$(( now / EPOCH_LEN ))
    if (( e != CUR_EPOCH )); then
      log "key rotation: epoch $CUR_EPOCH -> $e"
      if install_epoch "$e"; then CUR_EPOCH=$e; fi
    fi

    # 2. UDP helper check
    if [[ $MODE == udp ]]; then
      if [[ ! -f $UDP_PID_FILE ]] || ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; then
        log "WARN: UDP helper died! Reviving..."
        udp_helper_start
      fi
    fi

    # 3. Interface check
    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      maybe_rebuild "interface $IF_NAME vanished"
      continue
    fi

    # 4. Asymmetric blackout check (verified by ping)
    read -r rx tx <<< "$(if_counters)"
    if (( tx > TX0 && rx == RX0 )); then
      (( RX_STALL_START == 0 )) && RX_STALL_START=$now
      if (( now - RX_STALL_START >= RX_STALL_SEC )); then
        if ! ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
          maybe_rebuild "asymmetric blackout confirmed by ping"
          continue
        else
          RX_STALL_START=0
        fi
      fi
    else
      RX_STALL_START=0; RX0=$rx; TX0=$tx
    fi

    # 5. Continuous keepalive ping (also keeps NAT/UDP mapping alive)
    if ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
      FAILS=0
      (( ++OK_STREAK >= 30 )) && REB_BACKOFF=0
    else
      OK_STREAK=0
      FAILS=$(( FAILS + 1 ))
      if (( FAILS >= FAIL_LIMIT )); then
        maybe_rebuild "peer unreachable (ping) x${FAILS}"
      fi
    fi
  done
}

cmd_teardown() { teardown_all; log "tunnel torn down"; }
cmd_fw() { load_config || exit 1; route_info "$PEER_PUB" || exit 1; fw_apply; }

# ------------------------------------------------------------------------------
#  Install / service
# ------------------------------------------------------------------------------
install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  if [[ ! -f $src ]]; then
    err "Cannot locate the script file to install (run it from a saved file, not a pipe)."
    return 1
  fi
  [[ $src != "$BIN" ]] && install -m 755 "$src" "$BIN"
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP Tunnel Service (${APP})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN} daemon
ExecReload=/bin/kill -HUP \$MAINPID
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
  sleep 2
  if systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; then
    ok "Tunnel service started successfully."
    return 0
  fi
  err "Service failed to start."
  return 1
}

svc_running() { systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; }
daemon_reload() { systemctl kill -s HUP --kill-who=main "$APP" 2>/dev/null; }

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
  init_defaults

  write_config; load_config; start_service || return
  echo
  ok "Iran server setup complete!"
  echo "Now run option 2 on Kharej server and just enter this Iran IP: ${C_Y}${IRAN_IP}${C_0}"
  warn "The built-in shared secret is public. Set your own via option 5 (Edit) -> Shared secret, identical on both servers."
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
  init_defaults
  PORTS=""
  FWD_PROTO="both"

  write_config; load_config; start_service || return
  echo
  info "Testing ping to Iran (${PEER_INNER})..."
  ping -c 4 -W 1 -I "$IF_NAME" "$PEER_INNER"
  echo
  ok "Kharej client connected successfully!"
  warn "The built-in shared secret is public. Set your own via option 5 (Edit) -> Shared secret, identical on both servers."
  pause
}

cmd_upgrade() {
  load_config || { warn "Not installed."; return; }
  install_self || return
  write_config          # کانفیگ با کلیدهای جدید بازنویسی می‌شود (مقادیر فعلی حفظ می‌شود)
  start_service
}

# ------------------------------------------------------------------------------
#  Measurement helpers (used by status, editor, scanner)
# ------------------------------------------------------------------------------
# probe_quality COUNT INTERVAL SIZE  ->  Q_LOSS Q_MIN Q_AVG Q_MAX Q_MDEV
probe_quality() {
  local count=$1 iv=$2 size=$3 out st
  Q_LOSS=100; Q_MIN=0; Q_AVG=9999; Q_MAX=0; Q_MDEV=0
  out=$(ping -q -c "$count" -i "$iv" -W 1 -s "$size" -I "$IF_NAME" "$PEER_INNER" 2>&1) || true
  st=$(grep -oE '[0-9.]+% packet loss' <<<"$out" | head -n1 | grep -oE '^[0-9.]+')
  [[ -n $st ]] && Q_LOSS=$st
  st=$(awk -F'[ =/]+' '/^(rtt|round-trip) /{print $6" "$7" "$8" "$9}' <<<"$out")
  [[ -n $st ]] && read -r Q_MIN Q_AVG Q_MAX Q_MDEV <<<"$st"
  return 0
}

# آیا پکت DF با اندازه‌ی MTU داده‌شده از داخل تونل رد می‌شود؟ (۲ از ۳)
pmtu_ok() {
  local m=$1 got
  got=$(ping -q -c 3 -i 0.2 -W 1 -M "do" -s $(( m - 28 )) -I "$IF_NAME" "$PEER_INNER" 2>/dev/null \
        | awk '/packets transmitted/{print $4}')
  (( ${got:-0} >= 2 ))
}

# جستجوی دودویی بزرگ‌ترین MTU سالم؛ نتیجه در PMTU_FOUND (0 = ناموفق)
probe_pmtu() {
  local lo=$MTU_SEARCH_MIN hi=$1 mid
  PMTU_FOUND=0
  ip link set "$IF_NAME" mtu "$hi" || return 1
  while (( lo <= hi )); do
    (( SCAN_ABORT )) && return 1
    lock_touch
    mid=$(( (lo + hi) / 2 ))
    if pmtu_ok "$mid"; then PMTU_FOUND=$mid; lo=$(( mid + 1 )); else hi=$(( mid - 1 )); fi
  done
  return 0
}

# امتیاز اتصال فعلی: پینگ کوچک + پینگ بزرگ (نزدیک MTU)  ->  M_*
measure_conn() {
  local cur sz sl sa sm ll la lm
  cur=$(cat "/sys/class/net/${IF_NAME}/mtu" 2>/dev/null || echo "$MTU")
  sz=$(( cur - 28 )); (( sz > 1200 )) && sz=1200; (( sz < 56 )) && sz=56
  probe_quality 20 0.2 56;    sl=$Q_LOSS; sa=$Q_AVG; sm=$Q_MDEV
  probe_quality 10 0.2 "$sz"; ll=$Q_LOSS; la=$Q_AVG; lm=$Q_MDEV
  M_LOSS=$(awk -v a="$sl" -v b="$ll" 'BEGIN{print (a>b)?a:b}')
  M_JIT=$(awk -v a="$sm" -v b="$lm" 'BEGIN{print (a>b)?a:b}')
  M_AVG=$sa; M_BIG=$la
  M_SCORE=$(awk -v s="$sa" -v l2="$la" -v j="$M_JIT" -v l="$M_LOSS" 'BEGIN{printf "%.1f", (s+l2)/2 + 2*j + 30*l}')
}

print_row() {
  if awk -v l="$M_LOSS" 'BEGIN{exit !(l>=100)}'; then
    printf '  %-8s %-8s %s\n' "$1" "100" "no reply"
  else
    printf '  %-8s %-8s %-10s %-9s %-10s %s\n' "$1" "$M_LOSS" "$M_AVG" "$M_JIT" "$M_BIG" "$M_SCORE"
  fi
}

# ------------------------------------------------------------------------------
#  Apply changes to a running tunnel without restarting it
# ------------------------------------------------------------------------------
set_peer_port_live() {
  local e
  PEER_UDP_PORT=$1
  route_info "$PEER_PUB" || return 1
  e=$(( $(date +%s) / EPOCH_LEN ))
  install_epoch "$e"
}

apply_live() {
  if ! svc_running; then
    warn "Service is not running; saved to config only."
    return 0
  fi
  lock_touch
  if route_info "$PEER_PUB"; then
    ip link set "$IF_NAME" mtu "$MTU"
    fw_apply
    install_epoch "$(( $(date +%s) / EPOCH_LEN ))"
  else
    warn "No route to peer; could not apply live."
  fi
  lock_release
  daemon_reload
  ok "Applied live (no restart)."
}

test_mtu_now() {
  svc_running || return 0
  info "Testing full-size DF ping at MTU $MTU ..."
  if pmtu_ok "$MTU"; then
    ok "MTU $MTU passes through the tunnel."
  else
    warn "Full-size DF pings failed at MTU $MTU (or the peer is unreachable). MTU is probably too high for this path -> run the scanner."
  fi
}

# ------------------------------------------------------------------------------
#  Scanner
# ------------------------------------------------------------------------------
scan_restore() {   # $1=port $2=mtu
  set_peer_port_live "$1"
  ip link set "$IF_NAME" mtu "$2" 2>/dev/null
  MTU=$2
  fw_apply_mss
}

cmd_scan() {
  local orig_port orig_mtu orig_override p wan_mtu overhead hi new_mtu
  local best_port="" best_score="" b_loss b_avg b_jit
  local -a cand=()

  load_config || { warn "Not installed."; return 1; }
  svc_running || { err "Tunnel service is not running. Start it first."; return 1; }
  route_info "$PEER_PUB" || { err "No route to peer $PEER_PUB."; return 1; }

  orig_port=$PEER_UDP_PORT
  orig_override=$MTU_OVERRIDE
  orig_mtu=$(cat "/sys/class/net/${IF_NAME}/mtu" 2>/dev/null || echo "$MTU")

  if [[ $MODE == udp ]]; then
    read -r -a cand <<< "$(listen_ports)"
    [[ " ${cand[*]} " == *" $orig_port "* ]] || cand=("$orig_port" "${cand[@]}")
  else
    cand=("$orig_port")
    warn "Mode is 'esp' (raw protocol 50): no ports to scan, only MTU will be probed."
  fi

  SCAN_ABORT=0
  trap 'SCAN_ABORT=1' INT
  lock_touch

  echo
  info "Baseline: peer port $orig_port, MTU $orig_mtu"
  measure_conn
  b_loss=$M_LOSS; b_avg=$M_AVG; b_jit=$M_JIT
  echo "    loss ${M_LOSS}% | rtt ${M_AVG} ms | jitter ${M_JIT} ms | score ${M_SCORE}"
  if awk -v l="$M_LOSS" 'BEGIN{exit !(l>=100)}'; then
    warn "Baseline shows no replies. Scanning may still find a working path."
  fi

  if (( ${#cand[@]} > 1 )); then
    echo
    info "Step 1/2: testing ${#cand[@]} outgoing UDP ports (the peer must listen on them: same EXTRA ports on both servers)"
    printf '  %-8s %-8s %-10s %-9s %-10s %s\n' "PORT" "LOSS%" "RTT(ms)" "JITTER" "BIG-RTT" "SCORE"
    for p in "${cand[@]}"; do
      (( SCAN_ABORT )) && break
      lock_touch
      if [[ $p != "$PEER_UDP_PORT" ]]; then
        if ! set_peer_port_live "$p"; then warn "port $p: cannot switch"; continue; fi
        sleep 1
      fi
      measure_conn
      print_row "$p"
      if [[ -z $best_score ]] || flt_lt "$M_SCORE" "$best_score"; then
        best_score=$M_SCORE; best_port=$p
      fi
    done
  else
    best_port=$orig_port
  fi

  if (( SCAN_ABORT )); then
    warn "Aborted. Restoring previous settings."
    scan_restore "$orig_port" "$orig_mtu"
    trap - INT; lock_release; return 1
  fi

  if [[ -z $best_port ]] || { [[ -n $best_score ]] && ! flt_lt "$best_score" 3000; }; then
    err "No port produced replies. Check firewalls/security-groups for UDP ports on both servers."
    scan_restore "$orig_port" "$orig_mtu"
    trap - INT; lock_release; return 1
  fi
  set_peer_port_live "$best_port"
  ok "Best outgoing port: $best_port"

  echo
  info "Step 2/2: Path-MTU probing (DF pings through the tunnel)"
  wan_mtu=$(cat "/sys/class/net/${WAN_DEV}/mtu" 2>/dev/null || echo 1500)
  overhead=54; [[ $MODE == udp ]] && overhead=62
  hi=$(( wan_mtu - overhead )); (( hi > 1500 )) && hi=1500; (( hi < MTU_SEARCH_MIN )) && hi=$MTU_SEARCH_MIN
  probe_pmtu "$hi"
  if (( SCAN_ABORT )); then
    warn "Aborted. Restoring previous settings."
    scan_restore "$orig_port" "$orig_mtu"
    trap - INT; lock_release; return 1
  fi
  if (( PMTU_FOUND == 0 )); then
    warn "MTU probing failed (no DF reply even at ${MTU_SEARCH_MIN}). Keeping MTU $orig_mtu."
    new_mtu=$orig_mtu
  else
    new_mtu=$(( PMTU_FOUND - MTU_MARGIN ))
    (( new_mtu > 1500 )) && new_mtu=1500
    echo "    largest working MTU: $PMTU_FOUND  ->  using $new_mtu (safety margin $MTU_MARGIN)"
  fi
  ip link set "$IF_NAME" mtu "$new_mtu"; MTU=$new_mtu
  fw_apply_mss

  echo
  info "Verifying final settings..."
  measure_conn
  echo "    Before: port $orig_port  MTU $orig_mtu | loss ${b_loss}% | rtt ${b_avg} ms | jitter ${b_jit} ms"
  echo "    After : port $best_port  MTU $new_mtu | loss ${M_LOSS}% | rtt ${M_AVG} ms | jitter ${M_JIT} ms"

  if confirm "Keep and save these settings?" y; then
    PEER_UDP_PORT=$best_port
    MTU_OVERRIDE=$new_mtu
    write_config
    daemon_reload
    ok "Saved. Run the scanner on the OTHER server too (each side optimizes its own outgoing direction)."
  else
    scan_restore "$orig_port" "$orig_mtu"
    MTU_OVERRIDE=$orig_override
    warn "Reverted to previous settings."
  fi
  trap - INT
  lock_release
  return 0
}

# ------------------------------------------------------------------------------
#  Status
# ------------------------------------------------------------------------------
cmd_status() {
  local rx tx
  load_config || { warn "Not installed."; return; }
  echo "Role: $ROLE | Mode: $MODE | MTU: $MTU | Local UDP: $UDP_PORT | Peer UDP: $PEER_UDP_PORT"
  echo "Listening UDP ports: $(cat "$UDP_PORTS_FILE" 2>/dev/null || echo n/a)"
  echo "Service: $(systemctl is-active "$APP")"
  ip -br addr show "$IF_NAME" 2>/dev/null
  read -r rx tx <<< "$(if_counters)"
  echo "RX bytes: $rx | TX bytes: $tx"
  info "Measuring 20 pings to ${PEER_INNER} ..."
  probe_quality 20 0.2 56
  echo "Loss: ${Q_LOSS}% | RTT min/avg/max/mdev: ${Q_MIN}/${Q_AVG}/${Q_MAX}/${Q_MDEV} ms"
}

# ------------------------------------------------------------------------------
#  Manual config editor
# ------------------------------------------------------------------------------
mask_secret() { local s=$1; echo "${s:0:6}...${s: -4}"; }

commit_change() {   # $1 = live | restart
  write_config; load_config
  if [[ $1 == restart ]]; then
    if confirm "Restart tunnel service now to apply? (apply the same change on the OTHER server too)" y; then
      start_service
    else
      warn "Saved to config only; it takes effect at next restart."
    fi
  else
    apply_live
  fi
}

edit_secret() {
  local c new
  echo "  1) Enter secret manually   2) Generate random secret   3) Show current   4) Reset to built-in (public!)"
  read -r -p "Select: " c
  case $c in
    1) read -r -p "New secret (>=32 chars, letters/digits): " new
       if [[ ${#new} -ge 32 && $new =~ ^[A-Za-z0-9]+$ ]]; then
         warn "The SAME secret must be set on the other server, otherwise the tunnel will not come up."
         confirm "Apply?" n && { MASTER=$new; commit_change restart; }
       else err "Too short or invalid characters."; fi ;;
    2) new=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
       echo "Generated: ${C_Y}${new}${C_0}"
       warn "Copy it to the other server (same menu). Applying it here alone breaks the tunnel until both match."
       confirm "Apply on this server?" n && { MASTER=$new; commit_change restart; } ;;
    3) echo "$MASTER" ;;
    4) warn "The built-in secret is visible to anyone who has this script."
       confirm "Reset to built-in?" n && { MASTER=$STATIC_MASTER; commit_change restart; } ;;
  esac
}

edit_config() {
  local ch v old
  load_config || { warn "Not installed. Run setup first."; pause; return; }
  while true; do
    load_config
    echo
    echo "${C_B}==================== Manual Config Editor ====================${C_0}"
    echo " Role: $ROLE | Mode: $MODE | Effective MTU: $MTU"
    echo " -- Link, LOCAL only (applied live, no restart) --"
    echo "  1) MTU override (0 = auto default)      : $MTU_OVERRIDE"
    echo "  2) Peer UDP port (outgoing)             : $PEER_UDP_PORT"
    echo " -- Link, must MATCH on both servers (restart) --"
    echo "  3) Tunnel mode (udp | esp)              : $MODE"
    echo "  4) Local UDP port (listen)              : $UDP_PORT"
    echo "  5) Extra listen ports (scanner)         : ${EXTRA_PORTS:-<none>}"
    echo "  6) Shared secret                        : $(mask_secret "$MASTER")"
    echo "  7) Iran public IP                       : $IRAN_IP"
    echo "  8) Kharej public IP                     : $KHAREJ_IP"
    if [[ $ROLE == iran ]]; then
      echo " -- Forwarding (Iran only) --"
      echo "  9) Forwarded ports                      : $PORTS"
      echo " 10) Forward protocol                     : $FWD_PROTO"
    fi
    echo " -- Watchdog, LOCAL --"
    echo " 11) Health-check interval (sec)          : $TICK"
    echo " 12) Failures before self-heal            : $FAIL_LIMIT"
    echo " 13) RX-stall threshold (sec)             : $RX_STALL_SEC"
    echo " 14) Reset link/watchdog tuning to defaults"
    echo "  0) Back"
    read -r -p "Select: " ch
    case $ch in
      1) read -r -p "MTU (576-1500, 0 = auto) [$MTU_OVERRIDE]: " v; v=${v:-$MTU_OVERRIDE}
         if [[ $v == 0 ]] || valid_mtu "$v"; then
           MTU_OVERRIDE=$((10#$v)); commit_change live; test_mtu_now
         else err "Invalid MTU."; fi ;;
      2) read -r -p "Peer UDP port [$PEER_UDP_PORT]: " v; v=${v:-$PEER_UDP_PORT}
         if valid_port "$v"; then
           warn "The peer must be listening on this port (its main or extra ports)."
           PEER_UDP_PORT=$((10#$v)); commit_change live
         else err "Invalid port."; fi ;;
      3) read -r -p "Mode (udp|esp) [$MODE]: " v; v=${v:-$MODE}
         if [[ $v == udp || $v == esp ]]; then
           if [[ $v != "$MODE" ]]; then
             warn "Mode must be identical on BOTH servers. 'esp' = raw protocol 50 (often filtered), 'udp' = ESP-in-UDP."
             confirm "Apply?" n && { MODE=$v; commit_change restart; }
           fi
         else err "Use udp or esp."; fi ;;
      4) read -r -p "Local UDP port [$UDP_PORT]: " v; v=${v:-$UDP_PORT}
         if valid_port "$v"; then
           if [[ $v != "$UDP_PORT" ]]; then
             warn "Must be identical on BOTH servers."
             if confirm "Apply?" n; then
               old=$UDP_PORT; UDP_PORT=$((10#$v))
               [[ $PEER_UDP_PORT == "$old" ]] && PEER_UDP_PORT=$UDP_PORT
               commit_change restart
             fi
           fi
         else err "Invalid port."; fi ;;
      5) read -r -p "Extra ports, comma separated, max 14 (empty = none) [${EXTRA_PORTS}]: " v
         v=${v:-$EXTRA_PORTS}
         if v=$(norm_port_list "$v"); then
           warn "Use the same list on BOTH servers. Avoid ports of real services on these hosts (they will be skipped if busy)."
           EXTRA_PORTS=$v; commit_change restart
         else err "Invalid list."; fi ;;
      6) edit_secret ;;
      7) read -r -p "Iran public IP [$IRAN_IP]: " v; v=${v:-$IRAN_IP}
         if valid_ip "$v"; then IRAN_IP=$v; commit_change restart; else err "Invalid IPv4."; fi ;;
      8) read -r -p "Kharej public IP [$KHAREJ_IP]: " v; v=${v:-$KHAREJ_IP}
         if valid_ip "$v"; then KHAREJ_IP=$v; commit_change restart; else err "Invalid IPv4."; fi ;;
      9) if [[ $ROLE == iran ]]; then ask_ports; commit_change live; else warn "Only on the Iran server."; fi ;;
     10) if [[ $ROLE == iran ]]; then ask_fwd_proto; commit_change live; else warn "Only on the Iran server."; fi ;;
     11) read -r -p "Interval 1-30 sec [$TICK]: " v; v=${v:-$TICK}
         if valid_uint_range "$v" 1 30; then TICK=$((10#$v)); commit_change live; else err "Invalid."; fi ;;
     12) read -r -p "Failures 2-60 [$FAIL_LIMIT]: " v; v=${v:-$FAIL_LIMIT}
         if valid_uint_range "$v" 2 60; then FAIL_LIMIT=$((10#$v)); commit_change live; else err "Invalid."; fi ;;
     13) read -r -p "Seconds 10-600 [$RX_STALL_SEC]: " v; v=${v:-$RX_STALL_SEC}
         if valid_uint_range "$v" 10 600; then RX_STALL_SEC=$((10#$v)); commit_change live; else err "Invalid."; fi ;;
     14) if confirm "Reset MTU, peer port, extra ports and watchdog values to defaults?" n; then
           old=$EXTRA_PORTS
           init_defaults
           PEER_UDP_PORT=$UDP_PORT
           [[ $old != "$EXTRA_PORTS" ]] && warn "Extra ports changed: restart needed."
           commit_change restart
         fi ;;
      0|q|Q) return ;;
    esac
  done
}

# ------------------------------------------------------------------------------
#  Uninstall / menu / main
# ------------------------------------------------------------------------------
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
    echo "${C_B}   ESP Tunnel Manager v${VERSION}                      ${C_0}"
    echo "${C_B}======================================================${C_0}"
    echo "  1) Setup Iran Server"
    echo "  2) Setup Kharej Client"
    echo "  3) Status & Ping quality"
    echo "  4) Live Journal Log"
    echo "  5) Edit config manually (MTU, ports, mode, secret, ...)"
    echo "  6) Scanner: find & apply best connection (port + MTU)"
    echo "  7) Update script (keep config) & restart"
    echo "  8) Uninstall"
    echo "  0) Exit"
    echo
    read -r -p "Select: " ch
    case $ch in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; pause ;;
      4) journalctl -u "$APP" -f -n 30 ;;
      5) edit_config ;;
      6) cmd_scan; pause ;;
      7) cmd_upgrade; pause ;;
      8) uninstall_all; pause ;;
      0|q|Q) exit 0 ;;
    esac
  done
}

main() {
  case "${1:-menu}" in
    menu)     need_root; menu ;;
    status)   need_root; cmd_status ;;
    scan)     need_root; cmd_scan ;;
    edit)     need_root; edit_config ;;
    daemon)   need_root; cmd_daemon ;;
    teardown) need_root; cmd_teardown ;;
    fw)       need_root; cmd_fw ;;
    *)        exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
