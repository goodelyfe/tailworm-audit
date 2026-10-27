#!/bin/sh
# tailworm-audit / collect.sh
#
# READ-ONLY evidence collector for the Tailworm (Oct 2026) Tailscale findings,
# plus the adjacent risks the public write-ups don't cover. Runs on the node
# being audited: Debian/Ubuntu/DietPi/Proxmox/LXC/OpenWrt (BusyBox ash OK).
#
#   sudo sh collect.sh > node.txt                 # local
#   tailscale ssh root@node 'sh -s' < collect.sh  # remote (what fleet.sh does)
#
# It changes nothing. All interpretation happens in tailworm_audit.py, so this
# file stays small enough to read before you run it (please do).
#
# Privacy: every line of output passes through redact(): Tailscale keys are
# masked to their type prefix (tskey-auth-****), and env values whose names
# look like secrets are replaced with <redacted>. Non-Tailscale container env
# vars are never emitted at all.
#
# Knobs (environment):
#   TW_USERS          local users to inspect for privilege (default below)
#   TW_SECRET_PATHS   dirs scanned for stray tskey-* material
#   TW_SKIP_SECRETS=1 skip the secret scan (fast mode)
#   TW_K8S=1          also inspect Tailscale containers via kubectl (if present)

set -u
TW_COLLECTOR_VERSION=1
TW_USERS=${TW_USERS:-"ubuntu dietpi pi git deploy scout ansible admin"}
TW_SECRET_PATHS=${TW_SECRET_PATHS:-"/etc /root /home /opt /srv"}
TW_SKIP_SECRETS=${TW_SKIP_SECRETS:-0}
TW_K8S=${TW_K8S:-0}

# Root-only "crown jewel" sockets. With Tailscale SSH forwarding enabled,
# tailscaled (running as root) will connect to these on an SSH user's behalf.
JEWELS="/var/run/docker.sock /run/docker.sock
/run/containerd/containerd.sock /run/k3s/containerd/containerd.sock
/run/podman/podman.sock /run/crio/crio.sock
/run/systemd/private /run/dbus/system_bus_socket /var/run/dbus/system_bus_socket
/var/run/libvirt/libvirt-sock /run/libvirt/libvirt-sock
/var/snap/lxd/common/lxd/unix.socket /var/lib/lxd/unix.socket /var/lib/incus/unix.socket
/run/tailscale/tailscaled.sock /var/run/tailscale/tailscaled.sock"

have() { command -v "$1" >/dev/null 2>&1; }

# Portable timeout: GNU/new BusyBox take "timeout N", old BusyBox "timeout -t N".
if timeout 1 true >/dev/null 2>&1; then
  T() { timeout "$@"; }
elif timeout -t 1 true >/dev/null 2>&1; then
  T() { _tw_s=$1; shift; timeout -t "$_tw_s" "$@"; }
else
  T() { shift; "$@"; }
fi

sec() { echo "=====TW:BEGIN:$1====="; }
endsec() { echo "=====TW:END:$1====="; }

# Mask Tailscale secrets anywhere in the stream (keeps the type prefix).
redact() { sed -e 's/\(tskey-[a-z]*-\)[A-Za-z0-9_-]*/\1****/g'; }

# NAME=value lines -> blank out values whose names look secret.
sanitize_kv() {
  awk '{
    i = index($0, "="); if (i == 0) { print; next }
    n = substr($0, 1, i - 1); v = substr($0, i + 1)
    if (n ~ /KEY|SECRET|TOKEN|PASSW|CREDENTIAL/ && n != "TS_SSH_DISABLE_FORWARDING") v = "<redacted>"
    print n "=" v
  }'
}

TS=$(command -v tailscale 2>/dev/null || true)
for _p in /usr/sbin/tailscale /usr/bin/tailscale /usr/local/bin/tailscale; do
  [ -z "$TS" ] && [ -x "$_p" ] && TS=$_p
done
IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
SELF_MNT=$(readlink "/proc/$$/ns/mnt" 2>/dev/null)

# PIDs of every tailscaled on this kernel. From a Proxmox host this includes
# tailscaled inside each LXC; from a Docker host, inside each container.
ts_pids() {
  for _d in /proc/[0-9]*; do
    [ "$(cat "$_d/comm" 2>/dev/null)" = tailscaled ] && echo "${_d#/proc/}"
  done
}

s_meta() {
  sec meta
  echo "collector_version=$TW_COLLECTOR_VERSION"
  echo "hostname=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)"
  echo "uid=$(id -u)"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname=$(uname -srm 2>/dev/null)"
  [ -r /etc/os-release ] && grep -E '^(PRETTY_NAME|ID|VERSION_ID)=' /etc/os-release
  [ -r /etc/openwrt_release ] && grep -E '^DISTRIB_(ID|RELEASE)=' /etc/openwrt_release
  if [ -d /run/systemd/system ]; then echo "init=systemd"
  elif [ -r /etc/openwrt_release ] || [ -x /sbin/procd ]; then echo "init=procd"
  else echo "init=other"; fi
  if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then echo "container=yes"; fi
  have systemd-detect-virt && echo "virt=$(systemd-detect-virt 2>/dev/null)"
  for _t in ss netstat docker kubectl sudo journalctl logread pct stat systemctl systemd-run; do
    have "$_t" && echo "have_$_t=1"
  done
  echo "tailscale_cli=${TS:-none}"
  endsec meta
}

s_ts() {
  sec ts_version;  [ -n "$TS" ] && T 10 "$TS" version 2>&1 | head -n 5; endsec ts_version
  sec ts_status
  if [ -n "$TS" ]; then
    T 15 "$TS" status --json --peers=false 2>/dev/null || T 15 "$TS" status --json 2>/dev/null
  fi
  endsec ts_status
  sec ts_prefs;    [ -n "$TS" ] && T 10 "$TS" debug prefs 2>/dev/null; endsec ts_prefs
  sec ts_serve;    [ -n "$TS" ] && T 10 "$TS" serve status --json 2>/dev/null; endsec ts_serve
  sec ts_lock;     [ -n "$TS" ] && T 10 "$TS" lock status 2>&1 | head -n 20; endsec ts_lock
  sec ts_drive;    [ -n "$TS" ] && T 10 "$TS" drive list 2>&1 | head -n 40; endsec ts_drive
}

# The mitigation only counts if the RUNNING daemon has it, so read the live
# environment of every tailscaled, not just the config files.
s_procs() {
  sec ts_procs
  for _pid in $(ts_pids); do
    _cg=$(head -n 1 "/proc/$_pid/cgroup" 2>/dev/null | cut -d: -f3-)
    if [ -r "/proc/$_pid/environ" ]; then
      _er=1
      _env=$(tr '\0' '\n' < "/proc/$_pid/environ" 2>/dev/null | grep '^TS_' | sanitize_kv | tr '\n' ' ')
    else
      _er=0; _env=""
    fi
    _cmd=$(tr '\0' ' ' < "/proc/$_pid/cmdline" 2>/dev/null)
    _start=$(stat -c '%Y' "/proc/$_pid" 2>/dev/null)
    _mns=$(readlink "/proc/$_pid/ns/mnt" 2>/dev/null)
    _same=0; [ -n "$_mns" ] && [ "$_mns" = "$SELF_MNT" ] && _same=1
    [ -z "$_mns" ] && _same=1
    # Ask THIS instance (via its own LocalAPI socket) whether it runs Tailscale SSH.
    _sock=$(printf '%s\n' "$_cmd" | tr ' ' '\n' | sed -n 's/^--*socket=//p' | head -n 1)
    [ -n "$_sock" ] || _sock=/var/run/tailscale/tailscaled.sock
    _ssh=""
    if [ -n "$TS" ] && [ -S "/proc/$_pid/root$_sock" ]; then
      _ssh=$(T 5 "$TS" --socket="/proc/$_pid/root$_sock" debug prefs 2>/dev/null | tr -d '\n' | grep -o '"RunSSH": *[a-z]*' | sed 's/.*: *//')
    fi
    echo "pid=$_pid|cgroup=$_cg|samens=$_same|env_readable=$_er|start_epoch=$_start|socket=$_sock|ssh=$_ssh|env=$_env|cmd=$_cmd"
  done
  endsec ts_procs
}

s_persist() {
  sec ts_persist
  if have systemctl; then
    systemctl show tailscaled.service -p Environment -p EnvironmentFiles \
      -p FragmentPath -p DropInPaths -p ActiveState -p MainPID 2>/dev/null
    for _f in /etc/default/tailscaled /etc/sysconfig/tailscaled; do
      [ -r "$_f" ] && { echo "file=$_f"; grep -E '^[[:space:]]*[A-Za-z_]+=' "$_f" | sanitize_kv; }
    done
    for _f in /etc/systemd/system/tailscaled.service.d/*.conf /run/systemd/system/tailscaled.service.d/*.conf; do
      [ -r "$_f" ] && { echo "file=$_f"; grep -E 'Environment|TS_' "$_f" | sanitize_kv; }
    done
  fi
  for _f in /etc/init.d/tailscale /etc/init.d/tailscaled; do
    [ -r "$_f" ] && { echo "file=$_f"; grep -nE 'TS_|procd_set_param env' "$_f"; }
  done
  endsec ts_persist
}

s_listen() {
  sec unix_listen
  if have ss; then ss -xlpn 2>/dev/null; elif have netstat; then netstat -xlpn 2>/dev/null; fi
  endsec unix_listen
  sec tcp_listen
  if have ss; then ss -tlnp 2>/dev/null; elif have netstat; then netstat -tlnp 2>/dev/null; fi
  endsec tcp_listen
}

# stat every jewel, every listening unix socket, and every unix: serve target,
# plus the parent directory (who can rename/replace the path).
s_socks() {
  sec sock_stat
  for _p in $JEWELS; do
    if [ -e "$_p" ] || [ -L "$_p" ]; then echo "jewel=$_p|present=1"; else echo "jewel=$_p|present=0"; fi
  done
  {
    for _p in $JEWELS; do echo "$_p"; done
    if have ss; then ss -xlpn 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^\//) print $i}'; fi
    [ -n "$TS" ] && T 10 "$TS" serve status --json 2>/dev/null | grep -o 'unix:[^"]*' | sed 's/^unix://'
  } | sort -u | while read -r _p; do
    { [ -e "$_p" ] || [ -L "$_p" ]; } || continue
    _d=$(dirname "$_p")
    echo "path=$_p|stat=$(stat -c '%a %u %g %F' "$_p" 2>/dev/null)|parent=$_d|pstat=$(stat -L -c '%a %u %g %F' "$_d" 2>/dev/null)"
  done
  endsec sock_stat
}

s_kernel() {
  sec kernel
  for _k in protected_symlinks protected_hardlinks protected_regular; do
    echo "$_k=$(cat /proc/sys/fs/$_k 2>/dev/null)"
  done
  endsec kernel
}

# Process names in OUR mount namespace only (so a Proxmox host doesn't report
# the dockerd that lives inside an LXC as its own).
s_comms() {
  sec proc_comms
  for _d in /proc/[0-9]*; do
    _m=$(readlink "$_d/ns/mnt" 2>/dev/null)
    [ -n "$SELF_MNT" ] && [ -n "$_m" ] && [ "$_m" != "$SELF_MNT" ] && continue
    cat "$_d/comm" 2>/dev/null
  done | sort -u
  endsec proc_comms
}

# Which local users would an SSH grant land on, and are they already root?
s_users() {
  sec users
  {
    for _u in $TW_USERS; do echo "$_u"; done
    awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null
  } | sort -u | while read -r _u; do
    _id=$(id "$_u" 2>/dev/null) || continue
    _np=""; _sa=""
    if [ "$IS_ROOT" = 1 ] && have sudo; then
      _sl=$(T 5 sudo -n -l -U "$_u" 2>/dev/null)
      _np=$(printf '%s\n' "$_sl" | grep -c NOPASSWD)
      _sa=$(printf '%s\n' "$_sl" | grep -cE '\(ALL(:ALL| : ALL)?\)')
    fi
    _sh=$(awk -F: -v u="$_u" '$1 == u {print $7}' /etc/passwd 2>/dev/null)
    echo "user=$_u|shell=$_sh|id=$_id|nopasswd=$_np|sudo_all=$_sa"
  done
  endsec users
}

# Node identity on disk. Root on a box (or a copy of its backups) can clone it.
s_state() {
  sec state
  for _pid in $(ts_pids); do
    _root="/proc/$_pid/root"
    {
      echo /var/lib/tailscale/tailscaled.state
      echo /etc/tailscale/tailscaled.state
      tr '\0' '\n' < "/proc/$_pid/cmdline" 2>/dev/null | sed -n \
        -e 's/^--*state=//p' -e 's/^--*statedir=\(.*\)/\1\/tailscaled.state/p'
    } | sort -u | while read -r _f; do
      case "$_f" in kube:*|arn:*|mem:*) echo "pid=$_pid|path=$_f|nonfile=1"; continue ;; esac
      [ -f "$_root$_f" ] || continue
      _fb=$(head -c 1 "$_root$_f" 2>/dev/null)
      _pt=0; [ "$_fb" = "{" ] && _pt=1
      echo "pid=$_pid|path=$_f|stat=$(stat -c '%a %u %g' "$_root$_f" 2>/dev/null)|plaintext_json=$_pt"
    done
  done
  endsec state
}

# Stray auth keys make the report's TOCTOU authkey capture unnecessary.
s_secrets() {
  sec secrets
  if [ "$TW_SKIP_SECRETS" = 1 ]; then echo "skipped=1"; endsec secrets; return; fi
  [ "$IS_ROOT" = 1 ] || echo "partial=not_root"
  _gi=""; echo x | grep -I x >/dev/null 2>&1 && _gi="-I"
  _dirs=""
  for _p in $TW_SECRET_PATHS; do [ -d "$_p" ] && _dirs="$_dirs $_p"; done
  if [ -n "$_dirs" ]; then
    # shellcheck disable=SC2086
    T 120 grep -rls $_gi 'tskey-' $_dirs 2>/dev/null | head -n 200 | while read -r _f; do
      _ty=$(grep -o 'tskey-[a-z]*-' "$_f" 2>/dev/null | sort -u | tr '\n' ' ')
      echo "file=$_f|types=$_ty"
    done
  fi
  endsec secrets
}

# Tailscale containers: each one with --ssh is its OWN SSH server that the
# host-level mitigation does not cover. Only TS_*/TAILSCALE* env is emitted.
s_docker() {
  sec docker
  if ! have docker; then echo "absent=1"; endsec docker; return; fi
  _ids=$(T 15 docker ps -aq 2>/dev/null) || { echo "no_access=1"; endsec docker; return; }
  if [ -n "$_ids" ]; then
    # shellcheck disable=SC2086
    T 60 docker inspect --format '{{printf "@@C|%s|%s|%s|%s|%v|%s|" .Name .Config.Image .State.Status .Created .HostConfig.Privileged .HostConfig.NetworkMode}}{{range .Mounts}}{{printf "%s>%s," .Source .Destination}}{{end}}{{println}}{{print "@@A "}}{{range .Args}}{{print . " "}}{{end}}{{println}}{{range .Config.Env}}{{println "@@E" .}}{{end}}' $_ids 2>/dev/null |
      awk '/^@@C\|/ || /^@@A / { print; next }
           /^@@E (TS_|TAILSCALE)/ {
             s = substr($0, 5); i = index(s, "="); n = substr(s, 1, i - 1); v = substr(s, i + 1)
             if (n ~ /KEY|SECRET|TOKEN|PASSW|CREDENTIAL/ && n != "TS_SSH_DISABLE_FORWARDING") v = "<redacted>"
             print "@@E " n "=" v }'
  fi
  endsec docker
  sec docker_events
  _now=$(date +%s)
  T 20 docker events --since "$((_now - 259200))" --until "$_now" \
    --filter type=container --filter event=create --filter event=exec_create \
    --format '{{.Time}} {{.Action}} {{.Actor.Attributes.name}} {{.Actor.Attributes.image}}' 2>/dev/null | tail -n 60
  endsec docker_events
}

# What already uses SSH forwarding (so you know what the mitigation breaks).
s_logs() {
  sec ts_logs
  if have journalctl; then
    T 30 journalctl -u tailscaled --since "7 days ago" --no-pager 2>/dev/null |
      grep -iE 'direct-tcpip|streamlocal|tcpip-forward|port.?forward|forwarding' | tail -n 40
  elif have logread; then
    logread 2>/dev/null | grep -i tailscale | grep -iE 'forward|streamlocal|direct-tcpip' | tail -n 40
  fi
  endsec ts_logs
}

s_k8s() {
  sec k8s
  if have kubectl && T 10 kubectl get ns >/dev/null 2>&1; then
    T 60 kubectl get pods -A -o go-template='{{range .items}}{{$ns := .metadata.namespace}}{{$n := .metadata.name}}{{range .spec.containers}}{{printf "@@P|%s/%s|%s|%s\n" $ns $n .name .image}}{{range .env}}{{printf "@@E %s=%v\n" .name .value}}{{end}}{{end}}{{end}}' 2>/dev/null |
      awk '/^@@P\|/ { print; next }
           /^@@E (TS_|TAILSCALE)/ {
             s = substr($0, 5); i = index(s, "="); n = substr(s, 1, i - 1); v = substr(s, i + 1)
             if (n ~ /KEY|SECRET|TOKEN|PASSW|CREDENTIAL/ && n != "TS_SSH_DISABLE_FORWARDING") v = "<redacted>"
             print "@@E " n "=" v }'
    echo "@@PROXYCLASS"
    T 20 kubectl get proxyclasses.tailscale.com -o yaml 2>/dev/null | grep -E 'name: TS_|value:' | head -n 80
  else
    echo "unavailable=1"
  fi
  endsec k8s
}

main() {
  s_meta; s_ts; s_procs; s_persist; s_listen; s_socks; s_kernel; s_comms
  s_users; s_state; s_secrets; s_docker; s_logs
  [ "$TW_K8S" = 1 ] && s_k8s
  echo "=====TW:DONE====="
}

main 2>/dev/null | redact
