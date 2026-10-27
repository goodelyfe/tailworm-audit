#!/usr/bin/env bash
# tailworm-audit / fleet.sh: audit, probe and toggle Tailscale SSH hardening across
# every Tailscale SSH server in your tailnet, from one admin machine.
#
# Run it as YOU, from a device that has root SSH to your nodes in the tailnet policy
# (typically an untagged admin laptop/WSL). Linux, WSL (Windows Tailscale client),
# macOS (bash >= 4.3 + coreutils from Homebrew) and Git Bash are supported.
#
#   ./fleet.sh                                     read-only audit + report
#   ./fleet.sh --only n1,n2 | --tag tag:x | --skip n3
#   ./fleet.sh --policy path/to/policy.hujson      + policy audit, per-node cross-ref
#   ./fleet.sh --probe                             + active forwarding test (read-only)
#   ./fleet.sh --api                               + Tailscale API audit (TS_API_KEY / OAuth)
#   ./fleet.sh --set forwarding=off --only n1,n2   change settings, then re-verify
#   ./fleet.sh --set webclient=off,autoupdate=on --tag tag:managed-host
#   ./fleet.sh --set forwarding=on --only n1       revert (a node you tunnel through)
#   ./fleet.sh --status                            settings table only (fast)
#   ./fleet.sh --apply n1,n2 | --apply flagged     shorthand for --set forwarding=off
#
# Settings: forwarding|webclient|autoupdate = on|off; ssh=off needs --i-have-another-way.
# Tailscale CLI: TS_CLI=/path, else remembered choice, else auto-detected, else asked.
# Output: ~/tailworm-out/<timestamp>/{raw/*, report.md, report.json}  (TW_OUT_DIR to change)
set -uo pipefail
TW_VERSION=8

[ "${BASH_VERSINFO[0]}" -gt 4 ] || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -ge 3 ]; } \
  || { echo "fleet: needs bash >= 4.3 (macOS: brew install bash, then run with that bash)" >&2; exit 3; }

HERE=$(cd "$(dirname "$0")" && pwd)
PY=${PYTHON:-python3}
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/tailworm-audit/config"
OUT=""; PAR=6
ONLY=""; SKIP=""; TAG=""
SELF=0; PROBE=0; API=0; YES=0; K8S=0; STATUS_ONLY=0; ANOTHER=0
SET=""; APPLY=""; POLICY=""
TIMEOUT=${TW_TIMEOUT:-600}
TRY_USERS=${TW_TRY_USERS:-"root ubuntu dietpi pi"}
RESTART_IN=15

usage() { sed -n '2,22p' "$0"; exit "${1:-0}"; }
die() { echo "fleet: $*" >&2; exit 3; }

while [ $# -gt 0 ]; do
  case "$1" in
    --only) ONLY=$2; shift ;;
    --skip) SKIP=$2; shift ;;
    --tag) TAG=$2; shift ;;
    --self) SELF=1 ;;
    --probe) PROBE=1 ;;
    --api) API=1 ;;
    --k8s) K8S=1 ;;
    --status) STATUS_ONLY=1 ;;
    --policy) POLICY=$2; shift ;;
    --set) SET=$2; shift ;;
    --apply) APPLY=$2; shift ;;
    --i-have-another-way) ANOTHER=1 ;;
    --restart-in) RESTART_IN=$2; shift ;;
    --par) PAR=$2; shift ;;
    --out) OUT=$2; shift ;;
    --yes|-y) YES=1 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 3 ;;
  esac
  shift
done

# ------------------------------------------------------------------ portability
# timeout: GNU coreutils; macOS Homebrew installs it as gtimeout.
if command -v timeout >/dev/null 2>&1; then TMO=timeout
elif command -v gtimeout >/dev/null 2>&1; then TMO=gtimeout
else die "needs 'timeout' (macOS: brew install coreutils)"; fi

find_tailscale() {
  local c
  [ -n "${TS_CLI:-}" ] && { echo "$TS_CLI"; return; }
  if [ -r "$CONF" ]; then
    c=$(sed -n 's/^TS_CLI=//p' "$CONF" | head -n 1)
    [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return; }
  fi
  command -v tailscale >/dev/null 2>&1 && { command -v tailscale; return; }
  for c in /mnt/*/"Program Files"/Tailscale/tailscale.exe \
           "/c/Program Files/Tailscale/tailscale.exe" \
           /Applications/Tailscale.app/Contents/MacOS/Tailscale \
           "$(command -v tailscale.exe 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return; }
  done
  return 1
}
if ! TS=$(find_tailscale); then
  if [ -t 0 ]; then
    echo "Couldn't find the Tailscale CLI." >&2
    echo "  WSL:   /mnt/c/Program Files/Tailscale/tailscale.exe" >&2
    echo "  macOS: /Applications/Tailscale.app/Contents/MacOS/Tailscale" >&2
    read -r -p "Path to tailscale (or tailscale.exe): " TS
    [ -x "$TS" ] || die "not executable: $TS"
    read -r -p "Remember this in $CONF? [Y/n] " ans
    if [[ ! "$ans" =~ ^[Nn] ]]; then mkdir -p "$(dirname "$CONF")"; printf 'TS_CLI=%s\n' "$TS" > "$CONF"; fi
  else
    die "tailscale CLI not found; set TS_CLI=/path/to/tailscale"
  fi
fi
# Transport: 'tailscale' = tailscale ssh; 'ssh' = plain OpenSSH to the node's 100.x IP.
# Tailscale SSH answers on :22 of the tailnet IP, so both reach the same server and policy.
# Windows and macOS GUI clients default to ssh (their 'tailscale ssh' wraps a different ssh).
case "$TS" in
  *.exe|*/Tailscale.app/*) TRANSPORT=${TW_TRANSPORT:-ssh} ;;
  *) TRANSPORT=${TW_TRANSPORT:-tailscale} ;;
esac
[ "$TRANSPORT" = ssh ] && { command -v ssh >/dev/null || die "needs the OpenSSH client (apt install openssh-client)"; }
command -v "$PY" >/dev/null || die "python3 not found"
[ -n "$POLICY" ] && [ ! -r "$POLICY" ] && die "policy file not readable: $POLICY"
KNOWN="$HOME/.ssh/known_hosts_tailnet"; mkdir -p "$HOME/.ssh"

# rssh <timeout> <user> <dns> <ip> <remote command...>   (stdin is passed through)
rssh() {
  local t=$1 u=$2 dns=$3 ip=$4; shift 4
  if [ "$TRANSPORT" = ssh ]; then
    "$TMO" "$t" ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile="$KNOWN" -o LogLevel=ERROR "$u@$ip" "$@"
  else
    "$TMO" "$t" "$TS" ssh "$u@$dns" "$@"
  fi
}

# Reports live OUTSIDE the tool folder, so re-extracting the tarball doesn't delete them.
OUT_BASE=${TW_OUT_DIR:-"$HOME/tailworm-out"}
OUT=${OUT:-"$OUT_BASE/$(date +%Y%m%d-%H%M%S)"}
mkdir -p "$OUT/raw"
"$TS" status --json 2>/dev/null | tr -d '\r' > "$OUT/_status.json"
[ -s "$OUT/_status.json" ] || die "tailscale status failed (are you logged in?)"
echo "tailworm-audit v$TW_VERSION | using: $TS (transport: $TRANSPORT)"
"$PY" "$HERE/tailworm_audit.py" peers "$OUT/_status.json" > "$OUT/_peers.tsv"

in_list() { local needle=$1 list=$2; [[ ",$list," == *",$needle,"* ]]; }

# columns: dns short ip tags os online ssh sharee
select_targets() {
  while IFS=$'\t' read -r dns short ip tags _os online ssh sharee; do
    [ "$ssh" = 1 ] || continue
    [ "$sharee" = 1 ] && continue
    [ -n "$ONLY" ] && ! in_list "$short" "$ONLY" && continue
    [ -n "$SKIP" ] && in_list "$short" "$SKIP" && continue
    [ -n "$TAG" ] && ! in_list "$TAG" "$tags" && continue
    if [ "$online" != 1 ]; then echo "skip   $short (offline)" >&2; continue; fi
    printf '%s\t%s\t%s\n' "$dns" "$short" "$ip"
  done < "$OUT/_peers.tsv"
}
write_scope() { if [ -n "$ONLY$SKIP$TAG" ]; then printf '%s\n' "${TARGETS[@]}" | cut -f2 > "$OUT/_scope.txt"; else rm -f "$OUT/_scope.txt"; fi; }

collect_one() {
  local dns=$1 short=$2 out=$3 ip=$4 u cmd envs
  envs="TW_K8S=$K8S TW_SKIP_SECRETS=${TW_SKIP_SECRETS:-0}"
  [ -n "${TW_SECRET_PATHS:-}" ] && envs="$envs TW_SECRET_PATHS='$TW_SECRET_PATHS'"
  [ -n "${TW_USERS:-}" ] && envs="$envs TW_USERS='$TW_USERS'"
  for u in $TRY_USERS; do
    if [ "$u" = root ]; then cmd="env $envs sh -s"; else cmd="sudo -n env $envs sh -s"; fi
    if rssh "$TIMEOUT" "$u" "$dns" "$ip" "$cmd" < "$HERE/collect.sh" > "$out/raw/$short.txt" 2> "$out/raw/$short.err" \
       && grep -q '=====TW:DONE=====' "$out/raw/$short.txt"; then
      echo "ok     $short (as $u)"
      return 0
    fi
  done
  mv -f "$out/raw/$short.txt" "$out/raw/$short.failed" 2>/dev/null
  if grep -q 'does not permit' "$out/raw/$short.err" 2>/dev/null; then
    : > "$out/raw/$short.denied"
    echo "denied $short (tailnet policy doesn't let you SSH here)"
  else
    echo "FAILED $short (see raw/$short.err; raise TW_TIMEOUT if it's a slow device)"
  fi
  return 1
}

# One forwarding attempt; classify by what the SERVER said, not by silence.
#   "connect failed" or an HTTP answer -> server dialed for us: forwarding is ON
#   "administratively prohibited" / "unknown channel type" -> server refused: blocked
# fwd_try <ip> <local> <remote> <client cmd...>  -> prints "<client output>|<ssh channel messages>"
fwd_try() {
  local ip=$1 lspec=$2 rspec=$3; shift 3
  local err pid out msg
  err=$(mktemp)
  ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="$KNOWN" -o LogLevel=INFO -o ExitOnForwardFailure=yes \
      -N -L "$lspec:$rspec" "root@$ip" 2>"$err" &
  pid=$!
  for _ in $(seq 1 20); do
    if [[ $lspec == /* ]]; then [ -S "$lspec" ] && break
    else (exec 3<>"/dev/tcp/127.0.0.1/${lspec##*:}") 2>/dev/null && break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  out=$("$@" 2>/dev/null)
  sleep 1
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  msg=$(tr -d '\r' < "$err" | grep -iE 'open failed|administratively|connect failed|unknown channel|forward' | sort -u | head -n 2 | tr '\n' ' ')
  if [ -z "$msg" ] && [ -s "$err" ]; then msg="ssh: $(tr -d '\r' < "$err" | head -c 150 | tr '\n' ' ')"; fi
  rm -f "$err"
  printf '%s|%s\n' "$out" "$msg"
}

# What did the SERVER do with one forward request?
#   reached    it dialed the target (HTTP answer, or "connect failed"/"no such file": it tried)
#   allowlist  refused with "not in an allowed directory": forwarding is ON, path-restricted
#   disabled   any other "administratively prohibited" / "unknown channel type"
classify() { # <client out> <msgs>
  case "$2" in
    *"allowed director"*) echo allowlist; return ;;
    *"connect failed"*|*"no such file"*|*"dial unix"*|*"connection refused"*) echo reached; return ;;
    *"administratively prohibited"*|*"unknown channel type"*|*"unsupported channel"*) echo disabled; return ;;
  esac
  case "$1" in ""|000|"<nc-fail>") echo inconclusive ;; *) echo reached ;; esac
}

# Remote unix-socket bind (Tailworm F2's mechanism) at a NEW random /tmp path; removed after.
rfwd_try() {
  local ip=$1 rpath=$2 err rc msg
  err=$(mktemp)
  "$TMO" 15 ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="$KNOWN" -o LogLevel=INFO -o ExitOnForwardFailure=yes \
      -N -R "$rpath:127.0.0.1:9" "root@$ip" 2>"$err"
  rc=$?
  msg=$(tr -d '\r' < "$err" | grep -iE 'forward|refused|denied|prohibit|allowed' | sort -u | head -n 2 | tr '\n' ' ')
  rm -f "$err"
  if [ "$rc" = 124 ]; then
    echo "accepted|bound $rpath on the node"
    ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$KNOWN" \
        -o LogLevel=ERROR "root@$ip" "rm -f '$rpath'" >/dev/null 2>&1
  elif [ -n "$msg" ]; then echo "refused|$msg"
  else echo "inconclusive|ssh exited $rc with no forwarding message"; fi
}

probe_one() {
  local ip=$1 short=$2 out=$3 d r o m c port tag rr rv
  local -a parts=()
  local direct=0 allowed=0 allowlisted=0 disabled=0 total=0
  d=$(mktemp -d)
  # unix -L targets: two root sockets (harmless reads) + two probe paths that don't exist,
  # to learn which directories the server's allowlist lets through.
  local targets="tailscaled.sock=/var/run/tailscale/tailscaled.sock|http://local-tailscaled.sock/localapi/v0/status
docker.sock=/var/run/docker.sock|http://localhost/_ping
/tmp=/tmp/tailworm-probe-$RANDOM.sock|http://localhost/
/root=/root/tailworm-probe-$RANDOM.sock|http://localhost/"
  while IFS= read -r line; do
    tag=${line%%=*}; r=${line#*=}; local path=${r%%|*} url=${r#*|}
    rm -f "$d/l.sock"
    r=$(fwd_try "$ip" "$d/l.sock" "$path" curl -s --max-time 6 --unix-socket "$d/l.sock" -o /dev/null -w '%{http_code}' "$url")
    o=${r%%|*}; m=${r#*|}; c=$(classify "$o" "$m")
    total=$((total + 1))
    case "$c" in
      reached) [ -n "$o" ] && [ "$o" != 000 ] && case "$tag" in *.sock) direct=1 ;; esac; allowed=1 ;;
      allowlist) allowlisted=1 ;;
      disabled) disabled=$((disabled + 1)) ;;
    esac
    parts+=("$tag: $c${o:+ (http=$o)}${m:+ [${m% }]}")
  done <<< "$targets"
  rr=$(rfwd_try "$ip" "/tmp/tailworm-probe-$$-$RANDOM.sock"); rv=${rr%%|*}
  parts+=("-R /tmp: $rv [${rr#*|}]")
  port=$((20000 + RANDOM % 20000))
  r=$(fwd_try "$ip" "127.0.0.1:$port" 127.0.0.1:9 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port && \"$TMO\" 4 cat <&3; echo '<nc-fail>'")
  parts+=("tcp: $(classify "${r%%|*}" "${r#*|}")")
  rm -rf "$d"
  local detail; detail=$(printf '%s; ' "${parts[@]}")
  if [ "$direct" = 1 ]; then echo "probe=UNIX_DIRECT_ROOT_SOCKET $detail"
  elif [ "$allowed" = 1 ] || [ "$rv" = accepted ] || [ "$allowlisted" = 1 ]; then echo "probe=UNIX_FORWARDING_ALLOWLISTED $detail"
  elif [ "$disabled" = "$total" ] && [ "$rv" = refused ]; then echo "probe=forwarding_blocked $detail"
  else echo "probe=inconclusive $detail"; fi > "$out/raw/$short.probe"
}


set_one() { # <dns> <short> <out> <ip> <settings...>
  local dns=$1 short=$2 out=$3 ip=$4; shift 4
  local extra=""; [ "$ANOTHER" = 1 ] && extra="--i-have-another-way"
  rssh 60 root "$dns" "$ip" "sh -s -- --restart-in $RESTART_IN $extra $*" < "$HERE/tsctl.sh" > "$out/raw/$short.set" 2>&1
  grep '^RESULT=' "$out/raw/$short.set" | sed "s/^RESULT=/set    $short: /" || echo "set    $short: no result (see raw/$short.set)"
}

mapfile -t TARGETS < <(select_targets)
[ ${#TARGETS[@]} -gt 0 ] || [ "$SELF" = 1 ] || die "no reachable Tailscale SSH servers matched"

# ------------------------------------------------------------------ status only
if [ "$STATUS_ONLY" = 1 ]; then
  printf '%-18s %s\n' NODE SETTINGS
  for t in "${TARGETS[@]}"; do
    IFS=$'\t' read -r dns short ip <<<"$t"
    r=$(rssh 30 root "$dns" "$ip" "sh -s -- status" < "$HERE/tsctl.sh" 2>/dev/null | sed -n 's/^RESULT=status|ok|//p')
    printf '%-18s %s\n' "$short" "${r:-unreachable or not root}"
  done
  exit 0
fi

# ------------------------------------------------------------------ change settings
if [ -n "$APPLY" ]; then
  if [ "$APPLY" = flagged ]; then
    last=$(ls -1dt "$OUT_BASE"/*/report.json 2>/dev/null | head -n 1)
    [ -n "$last" ] || die "--apply flagged needs a previous run's report.json"
    APPLY=$("$PY" - "$last" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
out = []
for name, h in r["hosts"].items():
    if h["facts"].get("init") != "systemd":
        continue
    if any(f["id"] in ("TW03", "TW03P") and f["sev"] in ("CRIT", "HIGH", "WARN") and "read" not in f["title"] for f in h["findings"]):
        out.append(name)
print(",".join(sorted(out)))
PY
)
    [ -n "$APPLY" ] || { echo "nothing flagged in $last"; exit 0; }
  fi
  ONLY=$APPLY; SET="forwarding=off${SET:+,$SET}"
  mapfile -t TARGETS < <(select_targets)
fi

if [ -n "$SET" ]; then
  [ -n "$ONLY$TAG" ] || [ "$YES" = 1 ] || die "--set changes nodes: narrow it with --only/--tag (or add --yes to target every SSH server)"
  set_args=${SET//,/ }
  for kv in $set_args; do
    case "$kv" in forwarding=on|forwarding=off|webclient=on|webclient=off|autoupdate=on|autoupdate=off|ssh=on|ssh=off) ;;
      *) die "unknown setting '$kv' (forwarding|webclient|autoupdate|ssh = on|off)" ;; esac
  done
  names=$(printf '%s\n' "${TARGETS[@]}" | cut -f2 | paste -sd, -)
  echo "About to set [$set_args] on: $names"
  [[ " $set_args " == *" forwarding="* ]] && echo "  forwarding changes restart tailscaled ${RESTART_IN}s later (sessions on those nodes drop; shells reconnect fine)."
  [[ " $set_args " == *" forwarding=off "* ]] && echo "  forwarding=off stops ssh -L/-R/-D and VS Code Remote-SSH over Tailscale SSH on those nodes."
  [[ " $set_args " == *" ssh=off "* ]] && echo "  ssh=off ends Tailscale SSH access to those nodes (fleet.sh can't reach them afterwards)."
  if [ "$YES" != 1 ]; then read -r -p "Proceed? [y/N] " ans; [[ "$ans" =~ ^[Yy] ]] || exit 0; fi
  for t in "${TARGETS[@]}"; do
    IFS=$'\t' read -r dns short ip <<<"$t"
    # shellcheck disable=SC2086  # word-splitting the settings list is intended
    set_one "$dns" "$short" "$OUT" "$ip" $set_args
  done
  if [[ " $set_args " == *" forwarding="* ]]; then
    wait_s=$((RESTART_IN + 25)); echo "waiting ${wait_s}s for tailscaled restarts, then re-verifying..."; sleep "$wait_s"
  fi
  [[ " $set_args " == *" ssh=off "* ]] && { echo "ssh=off applied; skipping re-verification (no Tailscale SSH left to verify with)."; exit 0; }
  mapfile -t TARGETS < <(select_targets)
fi
write_scope

# ------------------------------------------------------------------ collect
echo "collecting from ${#TARGETS[@]} node(s), $PAR at a time -> $OUT"
running=0
for t in "${TARGETS[@]}"; do
  IFS=$'\t' read -r dns short ip <<<"$t"
  collect_one "$dns" "$short" "$OUT" "$ip" &
  running=$((running + 1))
  if [ "$running" -ge "$PAR" ]; then wait -n; running=$((running - 1)); fi
done
wait
if [ "$SELF" = 1 ]; then
  me=$(hostname -s 2>/dev/null || hostname)
  # shellcheck disable=SC2024  # redirect as the invoking user is intended
  if sudo -n true 2>/dev/null; then sudo -n env TW_K8S="$K8S" sh "$HERE/collect.sh" > "$OUT/raw/$me.txt"
  else TW_K8S="$K8S" sh "$HERE/collect.sh" > "$OUT/raw/$me.txt"; fi
  echo "ok     $me (local)"
fi

if [ "$PROBE" = 1 ]; then
  command -v ssh >/dev/null && command -v curl >/dev/null || die "--probe needs ssh and curl"
  echo "probing Tailscale SSH forwarding (read-only GETs; one throwaway /tmp socket, removed after)..."
  for t in "${TARGETS[@]}"; do
    IFS=$'\t' read -r dns short ip <<<"$t"
    [ -e "$OUT/raw/$short.denied" ] && { echo "probe  $short: skipped (policy denies you)"; continue; }
    probe_one "$ip" "$short" "$OUT"
    echo "probe  $short: $(cut -d' ' -f1 "$OUT/raw/$short.probe")"
  done
fi

# ------------------------------------------------------------------ analyze
args=(analyze "$OUT/raw" --status "$OUT/_status.json" --md "$OUT/report.md" --json "$OUT/report.json")
[ -n "$POLICY" ] && args+=(--policy "$POLICY")
[ -s "$OUT/_scope.txt" ] && args+=(--scope "$OUT/_scope.txt")
[ "$API" = 1 ] && args+=(--api)
echo
"$PY" "$HERE/tailworm_audit.py" "${args[@]}"
rc=$?
echo "(exit $rc: 0 = nothing above WARN, 1 = HIGH, 2 = CRIT)"
exit $rc
