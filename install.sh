#!/usr/bin/env bash
#
# install.sh - installs the IoT-Honeypot from scratch and runs it in the background.
#
# What it does:
#   1. checks the system (Linux, root, free disk space)
#   2. installs Docker Engine + Compose plugin if missing (Debian/Ubuntu: official Docker apt repo)
#   3. asks for the Telegram bot token and chat ID (or detects the chat ID), validates them
#      against the Telegram API and sends a test message
#   4. optionally asks for a free AbuseIPDB API key and validates it; with a key the sensor
#      reports confirmed attackers to AbuseIPDB automatically (leave empty to skip)
#   5. copies the project to /opt/iot-honeypot, writes a private .env (mode 600)
#   6. checks that the host ports are free (offers alternatives)
#   7. builds the image and starts the container detached; Docker restarts it on failure
#      and on reboot (restart: unless-stopped)
#
# Usage:
#   sudo ./install.sh                         interactive install / update
#   sudo ./install.sh --uninstall [--purge]   stop and remove (--purge also deletes all data)
#
# Options:
#   --token TOKEN        Telegram bot token (prefer the prompt or TELEGRAM_BOT_TOKEN env var:
#                        command-line arguments are visible to other users via `ps`)
#   --chat-id ID         Telegram chat ID (e.g. 123456789, -1001234567890 or @channelname)
#   --abuseipdb-key KEY  AbuseIPDB API key (prefer the prompt or the ABUSEIPDB_API_KEY env var:
#                        command-line arguments are visible to other users via `ps`)
#   --no-abuseipdb       do not ask about AbuseIPDB and leave any saved key untouched
#   --dir DIR            install directory (default /opt/iot-honeypot, or $HP_INSTALL_DIR)
#   --yes                non-interactive: accept defaults, never prompt (needs token + chat ID);
#                        an AbuseIPDB key already saved in .env is reused
#   --skip-telegram-check   do not contact Telegram during installation
#   --skip-abuseipdb-check  do not contact AbuseIPDB to validate the API key
#   --skip-docker-install   fail instead of installing Docker when it is missing
#   --no-start           install and configure, but do not start the container
#   -h, --help           show this help
#
# Security: install ONLY on a dedicated, disposable VPS/VM that holds no secrets and has no
# route to your internal networks (see docs/TECHNICAL_REPORT.md, section 8).

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
INSTALL_DIR="${HP_INSTALL_DIR:-/opt/iot-honeypot}"
CONTAINER="iot-honeypot"

TG_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TG_CHAT="${TELEGRAM_CHAT_ID:-}"
ABUSE_KEY="${ABUSEIPDB_API_KEY:-}"
ABUSE_API="${HP_ABUSEIPDB_API_BASE:-https://api.abuseipdb.com}"
NO_ABUSE=0
SKIP_ABUSE_CHECK=0
ASSUME_YES=0
SKIP_TG_CHECK=0
SKIP_DOCKER_INSTALL=0
NO_START=0
DO_UNINSTALL=0
PURGE=0

declare -A HOST_PORT_OVERRIDE=()

# ----------------------------------------------------------------------------- output
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_BLU=$'\033[34m'; C_BLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_RED=''; C_GRN=''; C_YLW=''; C_BLU=''; C_BLD=''; C_OFF=''
fi
info() { printf '%s[*]%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YLW" "$C_OFF" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; exit 1; }
trap 'printf "%s[x]%s installer failed at line %s: %s\n" "$C_RED" "$C_OFF" "$LINENO" "$BASH_COMMAND" >&2' ERR

usage() { sed -n '2,/^set -Eeuo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }

# ----------------------------------------------------------------------------- helpers
interactive() { [[ $ASSUME_YES -eq 0 && -t 0 ]]; }

# confirm "question" [default y|n]
confirm() {
  local q=$1 def=${2:-y} ans hint='[Y/n]'
  [[ $def == n ]] && hint='[y/N]'
  if [[ $ASSUME_YES -eq 1 ]]; then return 0; fi
  [[ -t 0 ]] || die "'$q' needs an answer but there is no terminal; re-run with --yes"
  read -r -p "$q $hint " ans || true
  ans=${ans:-$def}
  [[ $ans =~ ^[Yy] ]]
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# set_env FILE KEY VALUE - replace "KEY=..." (or append) without sed escaping problems
set_env() {
  local file=$1 key=$2 val=$3 tmp found=0 line
  tmp=$(mktemp)
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line == "$key="* ]]; then
      printf '%s=%s\n' "$key" "$val"; found=1
    else
      printf '%s\n' "$line"
    fi
  done <"$file" >"$tmp"
  [[ $found -eq 1 ]] || printf '%s=%s\n' "$key" "$val" >>"$tmp"
  cat "$tmp" >"$file"
  rm -f "$tmp"
}

get_env() { # FILE KEY
  [[ -f $1 ]] || return 0
  grep -m1 "^$2=" "$1" 2>/dev/null | cut -d= -f2- || true
}

valid_token() { [[ $1 =~ ^[0-9]{5,15}:[A-Za-z0-9_-]{30,}$ ]]; }
valid_chat()  { [[ $1 =~ ^-?[0-9]{3,20}$ || $1 =~ ^@[A-Za-z][A-Za-z0-9_]{3,}$ ]]; }
valid_abuse_key() { [[ $1 =~ ^[A-Za-z0-9]{20,128}$ ]]; }

port_busy() {
  local p=$1
  if need_cmd ss; then
    [[ -n "$(ss -H -ltn "sport = :$p" 2>/dev/null)" ]]
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null
  fi
}

# ----------------------------------------------------------------------------- args
# Accept both "--chat-id VALUE" and "--chat-id=VALUE" (group chat IDs start with '-').
norm_args=()
for a in "$@"; do
  case $a in
    --token=*|--chat-id=*|--dir=*|--abuseipdb-key=*) norm_args+=("${a%%=*}" "${a#*=}") ;;
    *) norm_args+=("$a") ;;
  esac
done
if [[ ${#norm_args[@]} -gt 0 ]]; then set -- "${norm_args[@]}"; fi

while [[ $# -gt 0 ]]; do
  case $1 in
    --token)               [[ $# -ge 2 ]] || die "--token needs a value"; TG_TOKEN=$2; shift 2 ;;
    --chat-id)             [[ $# -ge 2 ]] || die "--chat-id needs a value"; TG_CHAT=$2; shift 2 ;;
    --abuseipdb-key)       [[ $# -ge 2 ]] || die "--abuseipdb-key needs a value"; ABUSE_KEY=$2; shift 2 ;;
    --no-abuseipdb)        NO_ABUSE=1; shift ;;
    --skip-abuseipdb-check) SKIP_ABUSE_CHECK=1; shift ;;
    --dir)                 [[ $# -ge 2 ]] || die "--dir needs a value"; INSTALL_DIR=$2; shift 2 ;;
    --yes|--non-interactive) ASSUME_YES=1; shift ;;
    --skip-telegram-check) SKIP_TG_CHECK=1; shift ;;
    --skip-docker-install) SKIP_DOCKER_INSTALL=1; shift ;;
    --no-start)            NO_START=1; shift ;;
    --uninstall)           DO_UNINSTALL=1; shift ;;
    --purge)               PURGE=1; shift ;;
    -h|--help)             usage; exit 0 ;;
    *)                     die "unknown option: $1 (see --help)" ;;
  esac
done

# Fail fast on malformed credentials passed via flags/env, before anything is installed.
[[ -z $TG_TOKEN ]] || valid_token "$TG_TOKEN" || die "invalid Telegram bot token format (expected 123456789:AA...)"
[[ -z $TG_CHAT ]]  || valid_chat "$TG_CHAT"  || die "invalid Telegram chat ID format (digits, optional leading '-', or @channelname)"
[[ -z $ABUSE_KEY ]] || valid_abuse_key "$ABUSE_KEY" || die "invalid AbuseIPDB API key format (20-128 letters and digits)"

# ----------------------------------------------------------------------------- root
if [[ $EUID -ne 0 ]]; then
  need_cmd sudo || die "run as root (sudo is not installed)"
  info "re-running with sudo..."
  exec sudo -E bash "${BASH_SOURCE[0]}" "$@"
fi
[[ $(uname -s) == Linux ]] || die "Linux only"
INSTALL_DIR=$(realpath -m -- "$INSTALL_DIR")
[[ $INSTALL_DIR != / && $INSTALL_DIR != /usr && $INSTALL_DIR != /etc ]] || die "refusing to use $INSTALL_DIR as install directory"

# ----------------------------------------------------------------------------- uninstall
do_uninstall() {
  [[ -d $INSTALL_DIR ]] || die "nothing installed at $INSTALL_DIR"
  confirm "Stop and remove the honeypot container and image ($INSTALL_DIR)?" y || die "aborted"
  if need_cmd docker && [[ -f $INSTALL_DIR/docker-compose.yml ]]; then
    (cd "$INSTALL_DIR" && docker compose down --rmi all --remove-orphans) || warn "docker compose down reported an error"
  fi
  if [[ $PURGE -eq 1 ]]; then
    warn "--purge deletes ALL collected telemetry and captured malware samples in $INSTALL_DIR"
    if [[ $ASSUME_YES -eq 1 ]] || { [[ -t 0 ]] && read -r -p "Type DELETE to confirm: " a && [[ ${a:-} == DELETE ]]; }; then
      rm -rf -- "$INSTALL_DIR"
      ok "removed $INSTALL_DIR"
    else
      die "purge not confirmed; data kept"
    fi
  else
    ok "stopped. Configuration and data kept in $INSTALL_DIR (use --uninstall --purge to delete)"
  fi
}
if [[ $DO_UNINSTALL -eq 1 ]]; then do_uninstall; exit 0; fi

# ----------------------------------------------------------------------------- banner
cat <<EOF

${C_BLD}IoT-Honeypot installer${C_OFF}
  install dir : $INSTALL_DIR
  This exposes intentionally vulnerable-looking services to the Internet.
  Install it only on a dedicated, disposable VPS/VM with no secrets and no
  route to your internal network. Your real SSH port is not touched.

EOF
confirm "Continue?" y || die "aborted"

# ----------------------------------------------------------------------------- preflight
for f in Dockerfile docker-compose.yml go.mod cmd/honeypot/main.go .env.example; do
  [[ -e $SCRIPT_DIR/$f ]] || die "project file missing next to install.sh: $f (run the script from the unpacked project)"
done
parent=$INSTALL_DIR; while [[ ! -d $parent ]]; do parent=$(dirname "$parent"); done
avail_kb=$(df -Pk "$parent" | awk 'NR==2 {print $4}')
if [[ ${avail_kb:-0} -lt 2097152 ]]; then
  warn "less than 2 GB free on $parent; the Docker build needs about 1 GB"
fi

# ----------------------------------------------------------------------------- docker
docker_ready() { need_cmd docker && docker compose version >/dev/null 2>&1; }

install_docker_apt() {
  # shellcheck disable=SC1091
  . /etc/os-release
  local distro codename
  case ${ID:-} in
    ubuntu|debian) distro=$ID; codename=${VERSION_CODENAME:-} ;;
    *) case " ${ID_LIKE:-} " in
         *" ubuntu "*) distro=ubuntu; codename=${UBUNTU_CODENAME:-${VERSION_CODENAME:-}} ;;
         *" debian "*) distro=debian; codename=${VERSION_CODENAME:-} ;;
         *) die "automatic Docker install supports Debian/Ubuntu only; install Docker Engine + the compose plugin manually and re-run" ;;
       esac ;;
  esac
  [[ -n $codename ]] || die "cannot determine the distribution codename from /etc/os-release"

  info "installing Docker Engine from the official Docker apt repository ($distro $codename)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$distro" "$codename" >/etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

if docker_ready; then
  ok "Docker and the compose plugin are already installed"
else
  [[ $SKIP_DOCKER_INSTALL -eq 0 ]] || die "Docker / compose plugin missing and --skip-docker-install given"
  need_cmd apt-get || die "Docker is missing and automatic install supports Debian/Ubuntu only"
  install_docker_apt
  docker_ready || die "Docker installation finished but 'docker compose' is not available"
  ok "Docker installed"
fi
if ! docker info >/dev/null 2>&1; then
  if need_cmd systemctl; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    sleep 2
  fi
  docker info >/dev/null 2>&1 || die "the Docker daemon is not running"
fi
if need_cmd systemctl; then systemctl enable docker >/dev/null 2>&1 || true; fi   # start on boot

# ----------------------------------------------------------------------------- telegram
tg_get() { # METHOD
  curl -fsS --max-time 15 -K - 2>/dev/null <<<"url = \"https://api.telegram.org/bot${TG_TOKEN}/$1\""
}
tg_send() { # TEXT (must not contain double quotes or backslashes)
  curl -sS --max-time 15 -K - 2>/dev/null <<EOF
url = "https://api.telegram.org/bot${TG_TOKEN}/sendMessage"
data-urlencode = "chat_id=${TG_CHAT}"
data-urlencode = "text=$1"
EOF
}

ENV_FILE="$INSTALL_DIR/.env"
if [[ -z $TG_TOKEN && -z $TG_CHAT && -f $ENV_FILE ]]; then
  old_tok=$(get_env "$ENV_FILE" TELEGRAM_BOT_TOKEN); old_chat=$(get_env "$ENV_FILE" TELEGRAM_CHAT_ID)
  if [[ -n $old_tok && -n $old_chat ]] && confirm "Existing Telegram configuration found in $ENV_FILE. Reuse it?" y; then
    TG_TOKEN=$old_tok; TG_CHAT=$old_chat
  fi
fi

if [[ -z $TG_TOKEN ]]; then
  interactive || die "no Telegram bot token: set TELEGRAM_BOT_TOKEN or use --token (or run interactively)"
  cat <<EOF

${C_BLD}Telegram bot${C_OFF}
  1. In Telegram open @BotFather, send /newbot and copy the token it gives you
     (looks like 123456789:AAE...).
  2. Open your new bot and press Start (a bot cannot write to you first).

EOF
  while :; do
    read -r -s -p "Bot token (input hidden): " TG_TOKEN; echo
    valid_token "$TG_TOKEN" && break
    warn "that does not look like a bot token (expected 123456789:AA...). Try again."
    TG_TOKEN=""
  done
fi
valid_token "$TG_TOKEN" || die "invalid Telegram bot token format"

if [[ $SKIP_TG_CHECK -eq 0 ]]; then
  info "checking the token with Telegram..."
  if resp=$(tg_get getMe) && [[ $resp == *'"ok":true'* ]]; then
    bot_name=$(grep -o '"username":"[^"]*"' <<<"$resp" | head -1 | cut -d'"' -f4 || true)
    ok "token accepted${bot_name:+ (bot @$bot_name)}"
  else
    warn "Telegram rejected the token or api.telegram.org is unreachable from this server."
    if ! { interactive && confirm "Continue anyway?" n; }; then
      die "aborting (use --skip-telegram-check to bypass)"
    fi
  fi
fi

if [[ -z $TG_CHAT ]]; then
  interactive || die "no Telegram chat ID: set TELEGRAM_CHAT_ID or use --chat-id"
  cat <<EOF

${C_BLD}Telegram chat ID${C_OFF}
  Enter the numeric chat ID (e.g. 123456789; groups/channels look like -1001234567890)
  or @channelname. Leave empty to detect it automatically: send any message to your
  bot (or to the group where you added it), then press Enter here.

EOF
  while :; do
    read -r -p "Chat ID (empty = auto-detect): " TG_CHAT
    if [[ -z $TG_CHAT ]]; then
      read -r -p "Send a message to the bot now, then press Enter... " _ || true
      if resp=$(tg_get getUpdates) ; then
        TG_CHAT=$(grep -o '"chat":{"id":-\{0,1\}[0-9]*' <<<"$resp" | tail -1 | grep -o -- '-\{0,1\}[0-9]*$' || true)
      fi
      if [[ -n $TG_CHAT ]]; then ok "detected chat ID: $TG_CHAT"; else warn "no messages found for this bot; try again"; continue; fi
    fi
    valid_chat "$TG_CHAT" && break
    warn "invalid chat ID. Use digits (optionally with a leading minus) or @channelname."
    TG_CHAT=""
  done
fi
valid_chat "$TG_CHAT" || die "invalid Telegram chat ID format"

if [[ $SKIP_TG_CHECK -eq 0 ]]; then
  info "sending a test message..."
  if resp=$(tg_send "Honeypot installer: Telegram alerts are configured for host $(hostname)") && [[ $resp == *'"ok":true'* ]]; then
    ok "test message delivered - check your Telegram"
  else
    warn "could not deliver the test message (wrong chat ID, bot not started/added, or network blocked)."
    if ! { interactive && confirm "Continue anyway?" n; }; then
      die "aborting (use --skip-telegram-check to bypass)"
    fi
  fi
fi

# ----------------------------------------------------------------------------- abuseipdb
# HTTP status of a harmless read-only call that proves the key works ("000" = no answer).
abuse_check() { # KEY
  local code
  code=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' -K - 2>/dev/null <<EOF || true
url = "${ABUSE_API}/api/v2/check?ipAddress=127.0.0.1"
header = "Key: $1"
header = "Accept: application/json"
EOF
  )
  printf '%s' "${code:-000}"
}

# verify_abuse_key KEY -> 0 usable, 1 rejected, 2 could not be checked
verify_abuse_key() {
  case $(abuse_check "$1") in
    200|429) return 0 ;;     # 429 = valid key whose daily quota is spent
    401|403) return 1 ;;
    *)       return 2 ;;
  esac
}

if [[ $NO_ABUSE -eq 1 ]]; then
  ABUSE_KEY=""
else
  if [[ -z $ABUSE_KEY && -f $ENV_FILE ]]; then
    old_key=$(get_env "$ENV_FILE" ABUSEIPDB_API_KEY)
    if [[ -n $old_key ]] && valid_abuse_key "$old_key" && confirm "Existing AbuseIPDB key found in $ENV_FILE. Reuse it?" y; then
      ABUSE_KEY=$old_key
    fi
  fi

  if [[ -z $ABUSE_KEY ]] && interactive; then
    cat <<EOF

${C_BLD}AbuseIPDB reporting (optional)${C_OFF}
  With a free API key the sensor reports confirmed attackers (exploit attempts, shell
  commands, malware downloads) to AbuseIPDB.com so other operators can block them.
    - same address at most once per 24 h; password guessing is reported too
    - the comment holds the technique, port and a defanged dropper URL, never your
      server address or any personal data
    - free plan: 1000 reports/day. Get a key: https://www.abuseipdb.com/account/api
  Leave empty to skip; you can add ABUSEIPDB_API_KEY to $ENV_FILE later.

EOF
    while :; do
      read -r -s -p "AbuseIPDB API key (input hidden, Enter = skip): " ABUSE_KEY; echo
      [[ -n $ABUSE_KEY ]] || break
      if ! valid_abuse_key "$ABUSE_KEY"; then
        warn "that does not look like an AbuseIPDB key (20-128 letters and digits). Try again or press Enter to skip."
        ABUSE_KEY=""; continue
      fi
      [[ $SKIP_ABUSE_CHECK -eq 0 ]] || break
      info "checking the key with AbuseIPDB..."
      rc=0; verify_abuse_key "$ABUSE_KEY" || rc=$?
      case $rc in
        0) ok "AbuseIPDB key accepted"; break ;;
        1) warn "AbuseIPDB rejected this key. Try again or press Enter to skip."; ABUSE_KEY="" ;;
        *) warn "could not reach api.abuseipdb.com from this server."
           if confirm "Keep the key anyway?" n; then break; fi
           ABUSE_KEY="" ;;
      esac
    done
  elif [[ -n $ABUSE_KEY && $SKIP_ABUSE_CHECK -eq 0 ]]; then
    info "checking the AbuseIPDB key..."
    rc=0; verify_abuse_key "$ABUSE_KEY" || rc=$?
    case $rc in
      0) ok "AbuseIPDB key accepted" ;;
      1) die "AbuseIPDB rejected the API key (use --no-abuseipdb to install without it)" ;;
      *) warn "could not verify the AbuseIPDB key (network); saving it anyway - the sensor retries on its own" ;;
    esac
  fi
  [[ -n $ABUSE_KEY ]] || info "AbuseIPDB reporting is off (no key). Enable it later: set ABUSEIPDB_API_KEY in $ENV_FILE, then docker compose restart honeypot"
fi

# ----------------------------------------------------------------------------- copy project
info "installing files to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
if [[ $(realpath -- "$SCRIPT_DIR") != "$(realpath -- "$INSTALL_DIR")" ]]; then
  tar -C "$SCRIPT_DIR" \
      --exclude='./.git' --exclude='./data' --exclude='./captured_payloads' --exclude='./.env' \
      --exclude='./analysis/.venv' --exclude='./bin' --exclude='*.zip' -cf - . | tar -C "$INSTALL_DIR" -xf -
fi
chown -R root:root "$INSTALL_DIR"/{Dockerfile,docker-compose.yml,go.mod,cmd,internal,.env.example} 2>/dev/null || true

# ----------------------------------------------------------------------------- stop old, check ports
if [[ -f $INSTALL_DIR/docker-compose.yml ]] && docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  info "stopping the previous honeypot container for the update..."
  (cd "$INSTALL_DIR" && docker compose down --remove-orphans) || true
fi

choose_port() { # LABEL DEFAULT VARNAME
  local label=$1 port=$2 var=$3 new
  while port_busy "$port"; do
    warn "host port $port ($label) is already in use by another process."
    interactive || die "port $port is busy; free it or set $var in $ENV_FILE and re-run"
    read -r -p "Use a different host port for $label: " new
    if [[ $new =~ ^[0-9]+$ && $new -ge 1 && $new -le 65535 ]]; then port=$new; else warn "invalid port"; fi
  done
  [[ $port == "$2" ]] || HOST_PORT_OVERRIDE[$var]=$port
  ok "host port $port ($label) is free"
}
choose_port "ADB"         "$(get_env "$ENV_FILE" HP_HOST_PORT_ADB | grep . || echo 5555)"    HP_HOST_PORT_ADB
choose_port "TR-069/CWMP" "$(get_env "$ENV_FILE" HP_HOST_PORT_TR069 | grep . || echo 7547)"  HP_HOST_PORT_TR069
choose_port "Telnet"       "$(get_env "$ENV_FILE" HP_HOST_PORT_TELNET | grep . || echo 23)"   HP_HOST_PORT_TELNET
choose_port "Hikvision web" "$(get_env "$ENV_FILE" HP_HOST_PORT_HIKVISION | grep . || echo 80)" HP_HOST_PORT_HIKVISION
choose_port "TVT web"       "$(get_env "$ENV_FILE" HP_HOST_PORT_TVT | grep . || echo 81)"       HP_HOST_PORT_TVT
choose_port "Dahua web"     "$(get_env "$ENV_FILE" HP_HOST_PORT_DAHUA | grep . || echo 8080)"   HP_HOST_PORT_DAHUA

# ----------------------------------------------------------------------------- configuration
info "writing $ENV_FILE (mode 600) ..."
umask 077
[[ -f $ENV_FILE ]] || cp "$INSTALL_DIR/.env.example" "$ENV_FILE"
set_env "$ENV_FILE" TELEGRAM_BOT_TOKEN "$TG_TOKEN"
set_env "$ENV_FILE" TELEGRAM_CHAT_ID "$TG_CHAT"
[[ -z $ABUSE_KEY ]] || set_env "$ENV_FILE" ABUSEIPDB_API_KEY "$ABUSE_KEY"
for var in "${!HOST_PORT_OVERRIDE[@]}"; do set_env "$ENV_FILE" "$var" "${HOST_PORT_OVERRIDE[$var]}"; done
case "$(get_env "$ENV_FILE" HP_PORTS)" in
  5555,8080,2323|5555,7547,2323)
    info "upgrading HP_PORTS in $ENV_FILE to include the camera/DVR web personas"
    set_env "$ENV_FILE" HP_PORTS "5555,7547,2323,8088,8081,8080"
    if [[ -z $(get_env "$ENV_FILE" HP_WEB_PORTS) ]]; then
      set_env "$ENV_FILE" HP_WEB_PORTS "8088=hikvision,8081=tvt,8080=dahua"
      set_env "$ENV_FILE" HP_PORT_LABELS "2323:23,8088:80,8081:81"
    fi
    ;;
esac
if [[ "$(get_env "$ENV_FILE" HP_PORTS)" == "5555,7547,2323,8088,8081,8080,8082" ]]; then
  info "removing the discontinued GPON persona (port 8082) from $ENV_FILE"
  set_env "$ENV_FILE" HP_PORTS "5555,7547,2323,8088,8081,8080"
  [[ "$(get_env "$ENV_FILE" HP_WEB_PORTS)" == "8088=hikvision,8081=tvt,8080=dahua,8082=gpon" ]] &&
    set_env "$ENV_FILE" HP_WEB_PORTS "8088=hikvision,8081=tvt,8080=dahua"
  [[ "$(get_env "$ENV_FILE" HP_PORT_LABELS)" == "2323:23,8088:80,8081:81,8082:82" ]] &&
    set_env "$ENV_FILE" HP_PORT_LABELS "2323:23,8088:80,8081:81"
fi
case "$(get_env "$ENV_FILE" HP_ALERT_COOLDOWN)" in
  10m|"10m "*)
    info "raising HP_ALERT_COOLDOWN from the old 10m default to 6h (fewer repeated alerts)"
    set_env "$ENV_FILE" HP_ALERT_COOLDOWN "6h"
    ;;
esac
chmod 600 "$ENV_FILE"
umask 022

mkdir -p "$INSTALL_DIR/captured_payloads" "$INSTALL_DIR/data"
chown -R 10001:10001 "$INSTALL_DIR/captured_payloads" "$INSTALL_DIR/data"
chmod 750 "$INSTALL_DIR/captured_payloads" "$INSTALL_DIR/data"

# ----------------------------------------------------------------------------- start
if [[ $NO_START -eq 1 ]]; then
  ok "configured. Start later with: cd $INSTALL_DIR && docker compose up -d --build"
  exit 0
fi

info "building the image and starting the container (first build takes a few minutes)..."
(cd "$INSTALL_DIR" && docker compose up -d --build)

info "waiting for the container to become healthy..."
status=starting
for _ in $(seq 1 40); do
  status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing)
  case $status in
    healthy) break ;;
    exited|dead|restarting|missing|unhealthy)
      sleep 3
      status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing)
      [[ $status == healthy ]] && break
      (cd "$INSTALL_DIR" && docker compose logs --tail 40 honeypot) >&2 || true
      die "the container is '$status'. See the log above (docker compose logs honeypot)."
      ;;
  esac
  sleep 3
done
[[ $status == healthy ]] || warn "container status is '$status' after 2 minutes; check: docker compose logs honeypot"

ip=$(hostname -I 2>/dev/null | awk '{print $1}')
p_adb=${HOST_PORT_OVERRIDE[HP_HOST_PORT_ADB]:-$(get_env "$ENV_FILE" HP_HOST_PORT_ADB | grep . || echo 5555)}
p_tr069=${HOST_PORT_OVERRIDE[HP_HOST_PORT_TR069]:-$(get_env "$ENV_FILE" HP_HOST_PORT_TR069 | grep . || echo 7547)}
p_tel=${HOST_PORT_OVERRIDE[HP_HOST_PORT_TELNET]:-$(get_env "$ENV_FILE" HP_HOST_PORT_TELNET | grep . || echo 23)}
p_hik=${HOST_PORT_OVERRIDE[HP_HOST_PORT_HIKVISION]:-$(get_env "$ENV_FILE" HP_HOST_PORT_HIKVISION | grep . || echo 80)}
p_tvt=${HOST_PORT_OVERRIDE[HP_HOST_PORT_TVT]:-$(get_env "$ENV_FILE" HP_HOST_PORT_TVT | grep . || echo 81)}
p_dah=${HOST_PORT_OVERRIDE[HP_HOST_PORT_DAHUA]:-$(get_env "$ENV_FILE" HP_HOST_PORT_DAHUA | grep . || echo 8080)}

if [[ -n $(get_env "$ENV_FILE" ABUSEIPDB_API_KEY) ]]; then
  abuse_state="automatic reporting ON (confirmed attackers, once per IP per 24 h)"
else
  abuse_state="off (add ABUSEIPDB_API_KEY to .env to enable)"
fi

cat <<EOF

${C_GRN}${C_BLD}IoT-Honeypot is running in the background${C_OFF} (status: $status)

  Listening on ${ip:-this host}:  ${p_adb} (ADB)   ${p_tr069} (TR-069/CWMP)   ${p_tel} (Telnet)
                       ${p_hik} (Hikvision)   ${p_tvt} (TVT)   ${p_dah} (Dahua)
  Install dir  : $INSTALL_DIR
  Telemetry    : $INSTALL_DIR/data/events-YYYY-MM-DD.jsonl
  Malware      : $INSTALL_DIR/captured_payloads/   (live samples - never open or execute them)
  Config       : $ENV_FILE   (contains your bot token and API keys; mode 600)
  AbuseIPDB    : $abuse_state

  Manage it:
    cd $INSTALL_DIR
    docker compose ps                  # state
    docker compose logs -f honeypot    # live log
    docker compose restart honeypot    # after editing .env
    docker compose down                # stop
    sudo $INSTALL_DIR/install.sh       # update / reconfigure
    sudo $INSTALL_DIR/install.sh --uninstall [--purge]

  Make sure your cloud firewall allows inbound TCP ${p_adb}, ${p_tr069}, ${p_tel}, ${p_hik}, ${p_tvt} and ${p_dah}.
  Recommended hardening (egress filtering, noexec payload mount): docs/TECHNICAL_REPORT.md, section 8.

EOF
