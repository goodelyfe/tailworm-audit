#!/bin/sh
# tailworm-audit / tsctl.sh: show or change Tailscale hardening settings on ONE node.
#
#   sudo sh tsctl.sh status
#   sudo sh tsctl.sh forwarding=off                  # Tailworm mitigation (restart in 15s)
#   sudo sh tsctl.sh forwarding=on                   # revert, e.g. on a node you tunnel through
#   sudo sh tsctl.sh webclient=off autoupdate=on     # several at once
#   sudo sh tsctl.sh ssh=off --i-have-another-way    # turn Tailscale SSH off entirely
#
# Options: --restart-in N (default 15)  --no-restart  --dry-run
#
# Settings
#   forwarding=off|on  TS_SSH_DISABLE_FORWARDING=1 via a systemd drop-in (survives package
#                      upgrades). Off blocks ssh -L/-R/-D, unix-socket forwards and VS Code
#                      Remote-SSH over Tailscale SSH. Shells, scp, sftp, Ansible keep working.
#                      Needs a tailscaled restart; it is DETACHED so the SSH session that ran
#                      this lives long enough to report. Non-systemd: prints manual steps.
#   webclient=off|on   tailscale set --webclient      (immediate)
#   autoupdate=on|off  tailscale set --auto-update    (immediate; not every install supports it)
#   ssh=off|on         tailscale set --ssh            (immediate; off ends Tailscale SSH access,
#                      so it needs --i-have-another-way, e.g. console, LAN sshd, pct enter)
#
# One machine-readable line per setting: RESULT=<setting>|<applied|already|manual|error|dry-run>|<detail>

set -u
DELAY=15; RESTART=1; DRY=0; ANOTHER=0
DROPDIR=/etc/systemd/system/tailscaled.service.d
DROP=$DROPDIR/50-tailworm-mitigation.conf
NEED_RESTART=0
SETTINGS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --restart-in) DELAY=${2:?seconds}; shift ;;
    --no-restart) RESTART=0 ;;
    --dry-run) DRY=1 ;;
    --i-have-another-way) ANOTHER=1 ;;
    -h|--help) sed -n '2,24p' "$0" 2>/dev/null; exit 0 ;;
    status|*=*) SETTINGS="$SETTINGS $1" ;;
    *) echo "RESULT=args|error|unknown argument $1"; exit 2 ;;
  esac
  shift
done
[ -n "$SETTINGS" ] || SETTINGS=status
[ "$(id -u)" = 0 ] || { echo "RESULT=args|error|must run as root"; exit 2; }

TS=$(command -v tailscale 2>/dev/null || true)
for _p in /usr/sbin/tailscale /usr/bin/tailscale /usr/local/bin/tailscale; do
  [ -z "$TS" ] && [ -x "$_p" ] && TS=$_p
done
SYSTEMD=0; [ -d /run/systemd/system ] && SYSTEMD=1

res() { echo "RESULT=$1|$2|$3"; }

prefs() { [ -n "$TS" ] && "$TS" debug prefs 2>/dev/null | tr -d '\n' | tr -s ' '; }
pref_bool() { # <prefs-json> <key>  -> true|false|unknown
  _v=$(printf '%s' "$1" | grep -o "\"$2\": *[a-z]*" | head -n 1 | sed 's/.*: *//')
  echo "${_v:-unknown}"
}
autoupdate_state() {
  _v=$(printf '%s' "$1" | grep -o '"AutoUpdate": *{[^}]*}' | grep -o '"Apply": *[a-z]*' | sed 's/.*: *//')
  case "$_v" in true) echo on ;; false|null) echo off ;; *) echo unknown ;; esac
}
live_forwarding_off() {
  _pid=""
  [ "$SYSTEMD" = 1 ] && _pid=$(systemctl show -p MainPID tailscaled.service 2>/dev/null | cut -d= -f2)
  if [ -z "$_pid" ] || [ "$_pid" = 0 ]; then
    for _d in /proc/[0-9]*; do
      [ "$(cat "$_d/comm" 2>/dev/null)" = tailscaled ] || continue
      tr '\0' ' ' < "$_d/cmdline" 2>/dev/null | grep -q be-child && continue
      _pid=${_d#/proc/}; break
    done
  fi
  [ -n "$_pid" ] && tr '\0' '\n' < "/proc/$_pid/environ" 2>/dev/null | grep -qE '^TS_SSH_DISABLE_FORWARDING=(1|true)$'
}

do_status() {
  _p=$(prefs)
  if live_forwarding_off; then _f="off (live)"
  elif [ -f "$DROP" ]; then _f="off (configured, NOT live until restart)"
  else _f="on"; fi
  _ver=$([ -n "$TS" ] && "$TS" version 2>/dev/null | head -n 1)
  res status ok "ssh=$(pref_bool "$_p" RunSSH) forwarding=$_f webclient=$(pref_bool "$_p" RunWebClient) autoupdate=$(autoupdate_state "$_p") init=$([ "$SYSTEMD" = 1 ] && echo systemd || echo other) version=${_ver:-unknown}"
}

ts_set() { # <setting> <flag> <value> <current>
  if [ -z "$TS" ]; then res "$1" error "tailscale CLI not found"; return; fi
  if [ "$4" = "$3" ]; then res "$1" already "$3"; return; fi
  if [ "$DRY" = 1 ]; then res "$1" dry-run "would run: tailscale set $2=$3"; return; fi
  if _o=$("$TS" set "$2=$3" 2>&1); then res "$1" applied "$2=$3"
  else res "$1" error "$(printf '%s' "$_o" | tr '\n' ' ' | head -c 200)"; fi
}

do_forwarding() { # off|on
  if [ "$SYSTEMD" != 1 ]; then
    if [ -r /etc/openwrt_release ] || [ -x /sbin/procd ]; then
      res forwarding manual "OpenWrt/procd: add 'procd_set_param env TS_SSH_DISABLE_FORWARDING=1' after procd_open_instance in /etc/init.d/tailscale, then restart it (re-check after firmware updates). Or: tsctl.sh ssh=off"
    elif [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then
      res forwarding manual "container: set TS_SSH_DISABLE_FORWARDING=1 in its environment and recreate it, or drop --ssh from TS_EXTRA_ARGS"
    else
      res forwarding manual "no systemd: set TS_SSH_DISABLE_FORWARDING=1 in tailscaled's environment and restart it"
    fi
    return
  fi
  systemctl cat tailscaled.service >/dev/null 2>&1 || { res forwarding error "no tailscaled.service unit"; return; }
  if [ "$1" = off ]; then
    if [ -f "$DROP" ]; then
      if live_forwarding_off; then res forwarding already "off (live)"; return; fi
      [ "$DRY" = 1 ] && { res forwarding dry-run "drop-in present, would restart to make it live"; return; }
      NEED_RESTART=1; res forwarding applied "drop-in present; restart scheduled to make it live"; return
    fi
    [ "$DRY" = 1 ] && { res forwarding dry-run "would write $DROP and restart"; return; }
    mkdir -p "$DROPDIR"
    printf '%s\n' "# Added by tailworm-audit/tsctl.sh. Disables Tailscale SSH TCP/unix-socket forwarding" \
      "# (Tailworm mitigation). Remove with: tsctl.sh forwarding=on" "[Service]" \
      "Environment=TS_SSH_DISABLE_FORWARDING=1" > "$DROP"
    chmod 0644 "$DROP"
    systemctl daemon-reload
    systemctl show tailscaled.service -p Environment | grep -q 'TS_SSH_DISABLE_FORWARDING=1' \
      || { res forwarding error "systemd did not pick up the drop-in"; return; }
    NEED_RESTART=1; res forwarding applied "drop-in written; restart scheduled"
  else
    if [ ! -f "$DROP" ] && ! live_forwarding_off; then res forwarding already "on"; return; fi
    [ "$DRY" = 1 ] && { res forwarding dry-run "would remove $DROP and restart"; return; }
    rm -f "$DROP"; systemctl daemon-reload
    if grep -rqs 'TS_SSH_DISABLE_FORWARDING' /etc/default/tailscaled "$DROPDIR" 2>/dev/null; then
      res forwarding error "removed our drop-in, but TS_SSH_DISABLE_FORWARDING is still set elsewhere (/etc/default/tailscaled or another drop-in)"; return
    fi
    NEED_RESTART=1; res forwarding applied "drop-in removed; restart scheduled"
  fi
}

schedule_restart() {
  [ "$NEED_RESTART" = 1 ] || return 0
  if [ "$RESTART" != 1 ]; then res restart skipped "--no-restart: the forwarding change is NOT live until tailscaled restarts"; return; fi
  _sc=$(command -v systemctl)
  if command -v systemd-run >/dev/null 2>&1 &&
     { systemd-run --quiet --collect --on-active="${DELAY}s" --unit="tailworm-restart-$$" "$_sc" restart tailscaled.service 2>/dev/null ||
       systemd-run --quiet --on-active="${DELAY}s" --unit="tailworm-restart-$$" "$_sc" restart tailscaled.service 2>/dev/null; }; then
    res restart scheduled "tailscaled restarts in ${DELAY}s (systemd-run); this session will drop"
  else
    nohup sh -c "sleep $DELAY; $_sc restart tailscaled.service" >/dev/null 2>&1 &
    res restart scheduled "tailscaled restarts in ${DELAY}s (nohup); this session will drop"
  fi
}

P=$(prefs)
for s in $SETTINGS; do
  k=${s%%=*}; v=${s#*=}
  case "$k=$v" in
    status=status) do_status ;;
    forwarding=off|forwarding=on) do_forwarding "$v" ;;
    webclient=off) ts_set webclient --webclient false "$(pref_bool "$P" RunWebClient)" ;;
    webclient=on)  ts_set webclient --webclient true  "$(pref_bool "$P" RunWebClient)" ;;
    autoupdate=on)  ts_set autoupdate --auto-update true  "$(autoupdate_state "$P" | sed 's/^on$/true/;s/^off$/false/')" ;;
    autoupdate=off) ts_set autoupdate --auto-update false "$(autoupdate_state "$P" | sed 's/^on$/true/;s/^off$/false/')" ;;
    ssh=on) ts_set ssh --ssh true "$(pref_bool "$P" RunSSH)" ;;
    ssh=off)
      if [ "$ANOTHER" != 1 ]; then res ssh error "refusing: this ends Tailscale SSH access to the node. Re-run with --i-have-another-way"
      else ts_set ssh --ssh false "$(pref_bool "$P" RunSSH)"; fi ;;
    *) res "$k" error "unknown setting '$s' (forwarding|webclient|autoupdate|ssh = on|off, or status)" ;;
  esac
done
schedule_restart
