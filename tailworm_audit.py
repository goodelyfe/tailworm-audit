#!/usr/bin/env python3
"""tailworm-audit: analyze Tailworm (Oct 2026) exposure across a Tailscale fleet.

Subcommands
  peers   <status.json>                 list SSH-capable peers (used by fleet.sh)
  analyze <dir> [--status F] [--policy F] [--md F] [--json F]
  policy  <policy.hujson> [--md F]      offline tailnet policy audit
  api     [--tailnet T] [--from-dir D] [--md F]   Tailscale API audit

Stdlib only. Never needs network access except `api`.
Exit codes: 0 nothing above WARN, 1 HIGH present, 2 CRIT present, 3 usage/input error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ----------------------------------------------------------------------------- config
# Last release that fixed the *earlier* instance of this bug class (TS-2026-004/005,
# per the tailslop write-up). Tailworm itself was demonstrated on 1.104.2, so being
# above this floor is necessary, not sufficient.
FLOOR = os.environ.get("TW_FLOOR", "1.98.9")
# Set when Tailscale ships a Tailworm fix (e.g. TW_PATCHED=1.106.1). Empty = no fix yet.
PATCHED = os.environ.get("TW_PATCHED", "")
RECENT_DAYS = int(os.environ.get("TW_RECENT_DAYS", "14"))

SEV_ORDER = {"CRIT": 0, "HIGH": 1, "WARN": 2, "INFO": 3, "OK": 4}

# Expected listeners for root-only sockets. Anything else listening there is an IOC
# (Tailworm F2 "BindUnlink" makes tailscaled itself the listener).
JEWELS = {
    "/run/docker.sock": {"dockerd", "systemd"},
    "/run/containerd/containerd.sock": {"containerd", "systemd"},
    "/run/k3s/containerd/containerd.sock": {"containerd", "k3s", "k3s-server", "k3s-agent"},
    "/run/podman/podman.sock": {"podman", "systemd"},
    "/run/crio/crio.sock": {"crio", "systemd"},
    "/run/systemd/private": {"systemd"},
    "/run/dbus/system_bus_socket": {"dbus-daemon", "dbus-broker", "dbus-broker-lau", "systemd"},
    "/run/libvirt/libvirt-sock": {"libvirtd", "virtqemud", "systemd"},
    "/var/snap/lxd/common/lxd/unix.socket": {"lxd", "systemd"},
    "/var/lib/lxd/unix.socket": {"lxd", "systemd"},
    "/var/lib/incus/unix.socket": {"incusd", "systemd"},
    "/run/tailscale/tailscaled.sock": {"tailscaled"},
}
# daemon comm -> jewel paths it should own (detects "daemon running, socket gone")
DAEMON_SOCKETS = {"dockerd": ["/run/docker.sock"], "containerd": ["/run/containerd/containerd.sock", "/run/k3s/containerd/containerd.sock"]}


def norm_run(p):
    return "/run/" + p[len("/var/run/"):] if p.startswith("/var/run/") else p


# TCP services that are root-equivalent to reach, with no SSH bug required.
DANGER_PORTS = {
    2375: "Docker Engine API, plaintext and unauthenticated",
    2376: "Docker Engine API (TLS)",
    4243: "Docker Engine API (alt port)",
    9001: "Portainer agent (Docker control plane)",
    3552: "Arcane agent (Docker control plane)",
    3553: "Arcane agent (Docker control plane)",
    8006: "Proxmox VE web UI/API",
    10250: "kubelet API",
    6443: "Kubernetes API server",
    2379: "etcd",
    5252: "Tailscale web client",
}
PRIV_GROUPS_ROOT = {"docker", "lxd", "incus-admin", "libvirt", "disk"}
PRIV_GROUPS_SUDO = {"sudo", "wheel", "admin"}
OWN_SOCKETS = ("/run/tailscale/tailscaled.sock", "/var/run/tailscale/tailscaled.sock")


@dataclass
class Finding:
    host: str
    id: str
    sev: str
    title: str
    detail: str = ""
    fix: str = ""


@dataclass
class Host:
    name: str
    sections: dict = field(default_factory=dict)
    meta: dict = field(default_factory=dict)
    complete: bool = False
    findings: list = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    def add(self, fid, sev, title, detail="", fix=""):
        if any(f.id == fid and f.title == title for f in self.findings):
            return
        self.findings.append(Finding(self.name, fid, sev, title, detail, fix))

    def worst(self):
        if not self.findings:
            return "OK"
        return min((f.sev for f in self.findings), key=lambda s: SEV_ORDER[s])


# ----------------------------------------------------------------------------- helpers
def vtuple(s):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None


def first_json(text):
    """Parse the first JSON object/array in text; None if there isn't one."""
    if not text:
        return None
    for i, ch in enumerate(text):
        if ch in "{[":
            try:
                obj, _ = json.JSONDecoder().raw_decode(text[i:])
                return obj
            except ValueError:
                continue
    return None


def kv_lines(text, sep="="):
    out = {}
    for line in (text or "").splitlines():
        if sep in line:
            k, v = line.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


def pipe_records(text, prefix=None):
    """Parse 'a=1|b=2' lines into dicts."""
    recs = []
    for line in (text or "").splitlines():
        if prefix and not line.startswith(prefix):
            continue
        rec = {}
        for part in line.split("|"):
            if "=" in part:
                k, v = part.split("=", 1)
                rec[k] = v
        if rec:
            recs.append(rec)
    return recs


def parse_env(s):
    env = {}
    for tok in (s or "").split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            env[k] = v
    return env


def truthy(v):
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def parse_listeners(text):
    """ss -xlpn / -tlnp or netstat output -> list of (address, [process comms])."""
    out = []
    for line in (text or "").splitlines():
        toks = line.split()
        if not toks or toks[0] in ("Netid", "State", "Proto", "Active"):
            continue
        procs = re.findall(r'\(\("([^"]+)"', line)               # ss: users:(("name",pid=..
        if not procs:                                               # netstat: 123/name token
            procs = [t.split("/", 1)[1] for t in toks if re.match(r"^\d+/[\w.-]+$", t)]
        addr = None
        for t in toks:
            if t.startswith("/") or re.match(r"^[\[\]\w.:*%-]+:\d+$", t):
                addr = t
                break
        if addr:
            out.append((addr, procs))
    return out


def bind_class(addr):
    host = addr.rsplit(":", 1)[0].strip("[]")
    if host in ("0.0.0.0", "*", "::", ""):
        return "all"
    if host in ("127.0.0.1", "::1", "localhost") or host.startswith("127."):
        return "loopback"
    if host.startswith("100.") or host.lower().startswith("fd7a:115c:a1e0"):
        return "tailnet"
    return "specific"


def parse_mode(stat):
    """'1777 0 0 directory' -> (mode int, uid, gid, type)."""
    parts = (stat or "").split(None, 3)
    if len(parts) < 4:
        return None
    try:
        return int(parts[0], 8), int(parts[1]), int(parts[2]), parts[3]
    except ValueError:
        return None


def walk_serve(obj, path=""):
    """Yield (path, key, value) for every leaf in a serve config."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_serve(v, f"{path}/{k}")
            if not isinstance(v, (dict, list)):
                yield path, k, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_serve(v, f"{path}[{i}]")


# ----------------------------------------------------------------------------- load
SEC_RE = re.compile(r"^=====TW:(BEGIN|END):([\w-]+)=====$")


def load_host(path: Path) -> Host:
    h = Host(name=path.stem)
    cur, buf = None, []
    for line in path.read_text(errors="replace").splitlines():
        if line == "=====TW:DONE=====":
            h.complete = True
            continue
        m = SEC_RE.match(line)
        if m:
            if m.group(1) == "BEGIN":
                cur, buf = m.group(2), []
            else:
                h.sections[cur] = "\n".join(buf)
                cur = None
            continue
        if cur:
            buf.append(line)
    h.meta = kv_lines(h.sections.get("meta"))
    probe = path.with_suffix(".probe")
    if probe.exists():
        h.facts["probe"] = probe.read_text().strip()
    return h


# ----------------------------------------------------------------------------- policy
def load_hujson(text):
    """HuJSON (JSON + comments + trailing commas) -> Python object. No deps."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    s = "".join(out)
    s = re.sub(r",(\s*[}\]])", r"\1", s)
    return json.loads(s)


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def is_userish(sel):
    return sel.startswith(("group:", "autogroup:member", "autogroup:admin", "autogroup:owner")) or "@" in sel


def dst_matches(dst, tags, untagged):
    """Does an SSH/grant dst selector plausibly match a node with these tags?"""
    for d in as_list(dst):
        if d == "*" or (d in tags) or (d == "autogroup:tagged" and tags):
            return True
        if untagged and (d in ("autogroup:self", "autogroup:member") or is_userish(d)):
            return True
    return False


def policy_ssh_users_for(policy, tags):
    """Union of local users any SSH rule can land on for a node with these tags."""
    users = set()
    for r in (policy or {}).get("ssh", []):
        if dst_matches(r.get("dst"), set(tags), not tags):
            users.update(as_list(r.get("users")))
    return users


def audit_policy(policy) -> list:
    F = []

    def add(fid, sev, title, detail="", fix=""):
        F.append(Finding("policy", fid, sev, title, detail, fix))

    tag_owners = policy.get("tagOwners", {})
    ssh = policy.get("ssh", [])
    for i, r in enumerate(ssh):
        src, dst, users = as_list(r.get("src")), as_list(r.get("dst")), as_list(r.get("users"))
        label = f"ssh[{i}] {src} -> {dst} as {users}"
        nonroot = [u for u in users if u != "root"]
        if nonroot and "root" not in users:   # rules that already grant root gain nothing new
            add("PA01", "HIGH", "Non-root SSH grant is root-equivalent while forwarding is enabled",
                f"{label}. Tailworm F1-F3: forwarding runs inside root tailscaled, so '{', '.join(nonroot)}' can reach root-only sockets (docker.sock, systemd private bus, tailscaled.sock).",
                "Set TS_SSH_DISABLE_FORWARDING=1 on every dst node (fleet.sh --set forwarding=off), then verify with fleet.sh --probe. Until then, treat this rule as a root grant.")
        if "root" in users and any(is_userish(s) for s in src) and r.get("action") == "accept":
            add("PA02", "WARN", "Root SSH from user-owned devices with action=accept",
                f"{label}. Every device those users own (laptops, phones, WSL boxes running AI agents) is a root foothold on {dst}.",
                "Consider action: check with a short checkPeriod for root, and keep agent-running dev boxes out of group:admins.")
        if r.get("recorder"):
            note = " enforceRecorder is false, so sessions proceed if the recorder is down." if not r.get("enforceRecorder") else ""
            add("PA03", "INFO", "Session recording does not cover forwarded channels (likely)",
                f"{label}. tsrecorder captures the terminal stream; -L/-R/unix-socket forwards are separate SSH channels.{note}",
                "Verify on a test node: forward a socket, then check whether anything shows up in the recording. Don't count recording as a Tailworm control.")
        env = as_list(r.get("acceptEnv"))
        if env:
            risky = [e for e in env if e == "*" or e.startswith(("LD_", "PATH", "PYTHON", "PERL", "BASH_ENV", "ENV"))]
            add("PA04", "WARN" if risky else "INFO", "SSH rule accepts client environment variables",
                f"{label} acceptEnv={env}" + (f"; risky: {risky}" if risky else ""),
                "Remove acceptEnv or narrow it to explicit, inert names.")
        if "autogroup:self" in dst and "root" in users:
            add("PA11", "INFO", "Members get root on all of their own devices",
                f"{label}. One compromised personal device can root every other device the same person owns.",
                "Drop root from this rule if you don't need it; personal devices rarely do.")

    for g in policy.get("grants", []):
        src, dst, ip = as_list(g.get("src")), as_list(g.get("dst")), as_list(g.get("ip"))
        if "*" in ip and ("autogroup:tagged" in dst or "*" in dst):
            if src == ["group:admins"] or src == ["autogroup:admin"]:
                continue
            add("PA05", "WARN", "Any-port mesh grant to every tagged node",
                f"src={src} dst={dst} ip=*. A foothold on any of these sources can reach docker-equivalent APIs on every server (Arcane/Portainer agents, Docker TCP, kubelet, Proxmox) without any SSH bug.",
                "Split into per-service grants (port + tag) for anything that controls containers or hypervisors.")
        app = g.get("app") or {}
        for cap in app.get("tailscale.com/cap/webui", []) or []:
            if "ssh" in as_list(cap.get("canEdit")):
                add("PA09", "WARN", "Web client (port 5252) can toggle Tailscale SSH",
                    f"src={src} dst={dst}: webui canEdit includes 'ssh'. A browser session on an admin device can re-enable SSH on nodes you've locked down.",
                    "Drop 'ssh' from canEdit, or remove the webui grant if you don't use the web client.")
        for cap in app.get("tailscale.com/cap/drive", []) or []:
            if cap.get("access") == "rw" and ("autogroup:tagged" in dst or "*" in dst):
                add("PA07", "WARN", "Taildrive read-write to every tagged node",
                    f"src={src} dst={dst} shares={cap.get('shares')}. If any process gets LocalAPI access on a server (Tailworm F1/F7), 'tailscale drive share x /' turns into read-write root filesystem access for these sources.",
                    "Restrict drive:share in nodeAttrs to the nodes that actually share, and grant drive per node/tag.")

    for na in policy.get("nodeAttrs", []):
        attrs, tgt = as_list(na.get("attr")), as_list(na.get("target"))
        if "funnel" in attrs:
            add("PA06", "INFO", "Funnel attribute granted",
                f"targets={tgt}. Tailworm F9: Funnel entitlement is enforced by the client, so inventory actual Funnel state on every node rather than trusting this attribute.",
                "fleet.sh reports live AllowFunnel per node (TW10).")
        if ("drive:share" in attrs) and "autogroup:tagged" in tgt:
            add("PA07", "INFO", "Every tagged node may create Taildrive shares", f"targets={tgt}",
                "Scope drive:share to the nodes that need it.")
        if "tailscale.com/app-connectors" in (na.get("app") or {}):
            add("PA10", "WARN", "App connectors configured (Tailworm F4)",
                f"targets={tgt}. Per the report, entitled users can pick arbitrary egress destinations through the connector.",
                "Restrict entitlements, apply a kernel-level destination allowlist on connector hosts, or pause the connector until patched.")

    aa = policy.get("autoApprovers", {})
    for kind, approvers in [("exitNode", aa.get("exitNode", []))] + [(f"route {r}", v) for r, v in (aa.get("routes") or {}).items()]:
        for t in as_list(approvers):
            owners = as_list(tag_owners.get(t))
            via = [o for o in owners if o.startswith("tag:")]
            if via:
                add("PA08", "WARN", "Auto-approved routing reachable through tag-owns-tag",
                    f"{kind} is auto-approved for {t}, and {t} is owned by {via}. Root on any {via} node can mint new {t} nodes that are auto-approved for {kind}.",
                    "Keep auto-approval for this, but alert on new devices with this tag (api audit AP02).")

    for t in policy.get("sshTests", []):
        if "root" in as_list(t.get("deny")) and t.get("accept"):
            add("PA12", "INFO", "sshTest asserts 'no root' for a principal that holds a non-root grant",
                f"src={t.get('src')} dst={t.get('dst')} accept={t.get('accept')} deny=root. The test still passes, but under Tailworm the accepted user can reach root.",
                "Keep the test, and add a comment that it holds only once forwarding is disabled fleet-wide.")
    return F


# ----------------------------------------------------------------------------- node checks
def analyze_host(h: Host, policy=None):
    if not h.sections:
        h.add("TW00", "HIGH", "No collection data", "Collector output was empty or unreadable.",
              "Re-run collection; check the .err file next to it.")
        return
    if not h.complete:
        h.add("TW27", "WARN", "Collection incomplete", "The collector did not finish (timeout or lost session). Results below may be partial.")
    if h.meta.get("uid") not in (None, "0"):
        h.add("TW27", "WARN", "Collected as non-root",
              "Can't read other processes' environment or run sudo -l. Forwarding status and privilege checks may be incomplete.",
              "Re-run as root (fleet.sh tries root first).")

    status = first_json(h.sections.get("ts_status")) or {}
    prefs = first_json(h.sections.get("ts_prefs")) or {}
    serve = first_json(h.sections.get("ts_serve")) or {}
    self_ = status.get("Self") or {}
    tags = self_.get("Tags") or []
    h.facts.update(dns=(self_.get("DNSName") or "").rstrip("."), tags=tags, os=self_.get("OS"),
                   init=h.meta.get("init"))

    # TW01 version
    ver = status.get("Version") or (h.sections.get("ts_version") or "").split("\n")[0]
    vt = vtuple(ver)
    h.facts["version"] = ver.split("-")[0] if ver else "?"
    if not vt:
        if h.sections.get("ts_procs", "").strip():
            h.add("TW01", "INFO", "Tailscale version unknown", "tailscaled is running but the CLI wasn't found or didn't answer.")
    elif vt < vtuple(FLOOR):
        h.add("TW01", "WARN", f"Tailscale {h.facts['version']} is below {FLOOR}",
              "This predates the fix for the earlier instance of this bug class (TS-2026-004/005).",
              "Update tailscale. Static and vendor builds (GL-iNet and other router firmware) need a manual binary update.")
    elif PATCHED and vt < vtuple(PATCHED):
        h.add("TW01", "HIGH", f"Tailscale {h.facts['version']} is below the Tailworm fix {PATCHED}", "", "Update tailscale.")
    else:
        h.add("TW01", "OK", f"Tailscale {h.facts['version']}" + ("" if PATCHED else " (no Tailworm fix released yet; mitigation still required)"))

    run_ssh = prefs.get("RunSSH")
    h.facts["ssh"] = run_ssh
    h.facts["webclient"] = prefs.get("RunWebClient")
    h.facts["autoupdate"] = (prefs.get("AutoUpdate") or {}).get("Apply") if prefs else None

    # TW03 live forwarding mitigation, per tailscaled instance on this kernel
    # Skip per-session helpers ("tailscaled be-child ssh ..."): Tailscale SSH forks one per
    # session (including the session that ran the collector). Forwarding happens in the
    # daemon itself, and the children never carry the daemon's TS_* environment.
    procs = [p for p in pipe_records(h.sections.get("ts_procs"), prefix="pid=") if "be-child" not in p.get("cmd", "")]
    persist = h.sections.get("ts_persist") or ""
    persisted = bool(re.search(r"TS_SSH_DISABLE_FORWARDING=(1|true)", persist, re.I))
    h.facts["instances"] = []
    default_socks = {"/var/run/tailscale/tailscaled.sock", "/run/tailscale/tailscaled.sock", ""}
    host_insts = [p for p in procs if p.get("samens", "1") == "1"]
    # The main daemon is the one on the default socket; any other host-namespace tailscaled is a
    # separate tailnet node (tsidp, a second identity, ...) that tailscaled.service's drop-in doesn't cover.
    main_pid = next((p.get("pid") for p in host_insts if p.get("socket", "") in default_socks), host_insts[0].get("pid") if host_insts else None)
    for p in procs:
        env = parse_env(p.get("env"))
        cg = p.get("cgroup", "")
        inst_ssh = {"true": True, "false": False}.get(p.get("ssh", ""))
        where = "host" if p.get("samens", "1") == "1" else "other namespace"
        m = re.search(r"/lxc(?:\.payload)?[./](\d+)", cg) or re.search(r"/lxc/(\d+)", cg)
        if m:
            where = f"LXC {m.group(1)}"
        elif re.search(r"docker[-/]([0-9a-f]{12})", cg):
            where = f"container {re.search(r'docker[-/]([0-9a-f]{12})', cg).group(1)}"
        elif "kubepods" in cg:
            where = "k8s pod"
        if p.get("samens") == "1":
            where = "host"
        is_main = where == "host" and p.get("pid") == main_pid
        if where == "host" and not is_main:
            where = f"host, second instance on {p.get('socket') or '?'}"
        live = truthy(env.get("TS_SSH_DISABLE_FORWARDING"))
        allow_all = truthy(env.get("TS_SERVE_ALLOW_ALL_INTERFACES"))
        h.facts["instances"].append({"pid": p.get("pid"), "where": where, "live": live, "ssh": inst_ssh,
                                     "readable": p.get("env_readable") == "1", "main": is_main})
        if allow_all:
            h.add("TW12", "CRIT", f"TS_SERVE_ALLOW_ALL_INTERFACES set ({where}, pid {p.get('pid')})",
                  "Tailworm F10: serve listeners are reachable from any network that can route to this node's Tailscale IP, with no WireGuard, no ACL, and no identity headers.",
                  "Unset it. The Kubernetes operator's experimental cluster-traffic ingress sets it; check ProxyClass/env.")
        if p.get("env_readable") != "1":
            h.add("TW03", "WARN", f"Can't read tailscaled environment ({where}, pid {p.get('pid')})", "", "Run as root.")
            continue
        if not is_main:
            if live:
                continue
            if inst_ssh is False:
                h.add("TW03", "INFO", f"tailscaled in {where} runs without Tailscale SSH",
                      "No forwarding mitigation in its environment, but its SSH server is off, so Tailworm F1-F3 don't apply to it.")
            elif inst_ssh is True:
                h.add("TW03", "HIGH", f"tailscaled in {where} runs Tailscale SSH with forwarding enabled",
                      f"It's a separate tailnet node with its own SSH server; the host's mitigation doesn't cover it. Command: {p.get('cmd', '')[:160]}",
                      "Set TS_SSH_DISABLE_FORWARDING=1 in that instance's own environment (its service unit or container), or turn its SSH off.")
            else:
                h.add("TW03", "INFO", f"tailscaled in {where} lacks the forwarding mitigation",
                      f"Couldn't ask it whether it runs Tailscale SSH. Only matters if it does. Command: {p.get('cmd', '')[:160]}",
                      f"Check: tailscale --socket=<its socket> debug prefs | grep RunSSH")
            continue
        node_ssh = run_ssh if run_ssh is not None else inst_ssh
        if node_ssh is False:
            h.add("TW03", "OK", "Tailscale SSH server is off on this node", "Findings 1-3 and 5 need the SSH server.")
        elif live:
            h.add("TW03", "OK", "Forwarding disabled in the running tailscaled (TS_SSH_DISABLE_FORWARDING=1)",
                  "Confirm it actually takes effect with fleet.sh --probe.")
        elif persisted:
            h.add("TW03", "WARN", "Mitigation is configured but NOT live",
                  "TS_SSH_DISABLE_FORWARDING is in the unit/env file, but the running tailscaled was started without it.",
                  "Restart tailscaled: ./fleet.sh --set forwarding=off --only <host> schedules a detached restart.")
        else:
            sev = "HIGH" if node_ssh else "WARN"
            h.add("TW03", sev, "Tailscale SSH forwarding is enabled" if node_ssh else "Forwarding mitigation absent (SSH state unknown)",
                  "Any SSH grant to this node can be turned into root via root-run unix-socket forwarding (Tailworm F1-F3).",
                  "./fleet.sh --set forwarding=off --only <host>  (or on the node: sudo sh tsctl.sh forwarding=off)")
    if not procs and h.sections.get("ts_procs") is not None:
        h.add("TW03", "INFO", "No tailscaled process found", "Nothing to mitigate on this kernel (or the collector couldn't see /proc).")

    probe = h.facts.get("probe", "")
    if "UNIX_DIRECT_ROOT_SOCKET" in probe:
        h.add("TW03P", "CRIT", "Active probe: a root-only socket answered through SSH forwarding", probe,
              "Any SSH grant here is root, no race needed (Tailworm F1). Mitigate now: fleet.sh --set forwarding=off, or ssh=off.")
    elif "UNIX_FORWARDING_ALLOWLISTED" in probe:
        h.add("TW03P", "HIGH", "Active probe: unix-socket forwarding is ON, limited by a directory allowlist", probe,
              "Tailworm F3 is a TOCTOU race that defeats exactly this allowlist (symlink swap inside an allowed directory), and F2 binds sockets there. Mitigate: fleet.sh --set forwarding=off, then re-probe; a working mitigation should turn every line into a non-allowlist refusal.")
    elif "forwarding_blocked" in probe:
        h.add("TW03P", "OK", "Active probe: the SSH server refuses unix-socket forwarding (-L and -R)", probe)
        for f in h.findings:
            if f.id == "TW03" and f.sev == "HIGH":
                f.sev = "INFO"
                f.title += " (refused in practice per probe)"
                f.detail = "The env-var mitigation isn't visible in the environment, but the server refused every unix-socket forward. Re-probe after every tailscale upgrade."
    elif "inconclusive" in probe:
        h.add("TW03P", "WARN", "Active probe was inconclusive", probe,
              "The server neither forwarded nor clearly refused. Don't treat this as proof the node is safe.")

    # Sockets: listeners, jewels, parent directories
    ulisten = parse_listeners(h.sections.get("unix_listen"))
    listeners = {}
    for addr, procs_ in ulisten:
        listeners.setdefault(addr, set()).update(procs_)
    own = set(OWN_SOCKETS)
    for p in procs:
        m = re.search(r"--socket[= ](\S+)", p.get("cmd", ""))
        if m:
            own.add(m.group(1))
    for addr, comms in listeners.items():
        if "tailscaled" in comms and norm_run(addr) not in {norm_run(o) for o in own} and not addr.endswith("tailscaled.sock"):
            h.add("TW04", "CRIT", f"tailscaled is LISTENING on {addr}",
                  "This is what Tailworm F2 (BindUnlink via ssh -R) looks like while active: tailscaled took over another daemon's socket path. Point-in-time IOC.",
                  "Treat as a live compromise: capture `ss -xlpn`, the tailscaled journal, and active SSH sessions, then isolate the node.")

    socks = pipe_records(h.sections.get("sock_stat"), prefix="path=")
    jewel_lines = pipe_records(h.sections.get("sock_stat"), prefix="jewel=")
    comms_running = set((h.sections.get("proc_comms") or "").split())
    nlisteners = {}
    for addr, comms in listeners.items():
        nlisteners.setdefault(norm_run(addr), set()).update(comms)
    present_jewels = []
    seen_paths = set()
    for s in socks:
        path = s.get("path", "")
        npath = norm_run(path)
        if npath in seen_paths:
            continue
        seen_paths.add(npath)
        st, ps = parse_mode(s.get("stat")), parse_mode(s.get("pstat"))
        if npath in JEWELS and st:
            if st[3] == "symbolic link":
                h.add("TW05", "INFO", f"Root socket path {path} is a symlink",
                      "Usually benign (podman-docker links docker.sock to podman.sock; appliance builds link tailscaled.sock into a container). It matters if a non-root user can change the link or its directory: that is the swap Tailworm F8 abuses.",
                      f"ls -l {path}  and confirm the target and its directory are root-owned.")
            elif st[3] == "socket":
                if npath not in [norm_run(p) for p in present_jewels]:
                    present_jewels.append(path)
                ls = nlisteners.get(npath)
                if ls and not (ls & JEWELS[npath]):
                    h.add("TW05", "CRIT" if "tailscaled" in ls else "WARN",
                          f"Unexpected listener on {path}: {sorted(ls)}",
                          f"Expected one of {sorted(JEWELS[npath])}.",
                          "Investigate. An unexpected owner of a root socket is a takeover indicator.")
        if st and ps and st[1] == 0 and st[3] in ("socket", "symbolic link"):
            pmode, puid, _, _ = ps
            sticky = bool(pmode & 0o1000)
            group_w, other_w = bool(pmode & 0o020), bool(pmode & 0o002)
            if puid != 0 or ((group_w or other_w) and not sticky):
                h.add("TW07", "WARN", f"Root-owned socket {path} sits in a directory non-root can modify",
                      f"{s.get('parent')} is mode {oct(pmode)[2:]} owned by uid {puid}. Someone other than root can rename or replace the path, which is the race and swap primitive behind Tailworm F3/F8.",
                      "Move the socket into a root-owned 0755 directory, or tighten the directory.")
            elif other_w and sticky and path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                h.add("TW07", "INFO", f"Root socket {path} in a world-writable sticky dir",
                      "Safe only while fs.protected_symlinks=1 (see TW08).")
    h.facts["jewels"] = present_jewels
    present_n = {norm_run(p) for p in present_jewels} | {norm_run(j.get("jewel", "")) for j in jewel_lines if j.get("present") == "1"}
    known_absent = {norm_run(j.get("jewel", "")) for j in jewel_lines if j.get("present") == "0"}
    for daemon, paths in DAEMON_SOCKETS.items():
        # Only flag with positive evidence: the collector looked and the path wasn't there.
        if daemon in comms_running and not (present_n & set(paths)) and (known_absent & set(paths)):
            h.add("TW05", "WARN", f"{daemon} is running but its socket is missing",
                  f"Expected one of {paths}. After Tailworm F2 (BindUnlink) the original socket is unlinked; once the attacker disconnects, the daemon is left without its socket. A custom socket path also triggers this.",
                  f"Run `docker info` or `ctr version` locally. If it can't connect, restart {daemon} and investigate how the socket disappeared.")

    if present_jewels and any(f.id == "TW03" and f.sev == "HIGH" for f in h.findings):
        names = ", ".join(sorted({os.path.basename(p) for p in present_jewels}))
        h.add("TW06", "INFO", "Root sockets reachable via forwarding on this node", names,
              "These become reachable from any SSH grant until forwarding is disabled. docker.sock or containerd.sock means root on the host.")

    kern = kv_lines(h.sections.get("kernel"))
    if "kernel" in h.sections and kern.get("protected_symlinks", "") == "":
        h.add("TW08", "INFO", "fs.protected_symlinks unknown", "Couldn't read /proc/sys/fs/protected_symlinks (old or embedded kernel?).",
              "Check by hand: cat /proc/sys/fs/protected_symlinks (want 1).")
    elif kern.get("protected_symlinks") not in (None, "", "1"):
        h.add("TW08", "WARN", f"fs.protected_symlinks={kern.get('protected_symlinks')}",
              "Without it, symlink swaps in /tmp-style dirs work. The report relies on this protection to call some swaps blocked.",
              "sysctl -w fs.protected_symlinks=1 (persist in /etc/sysctl.d).")

    # TW09 privileged local users (cross-ref with policy if given)
    ssh_users = policy_ssh_users_for(policy, tags) if policy else None
    for u in pipe_records(h.sections.get("users"), prefix="user="):
        name = u.get("user")
        groups = set(re.findall(r"\d+\(([^)]+)\)", u.get("id", "").split("groups=", 1)[-1])) if "groups=" in u.get("id", "") else set()
        rootish = sorted(groups & PRIV_GROUPS_ROOT - {name})
        nopw = (u.get("nopasswd") or "0") not in ("", "0")
        if not (rootish or nopw):
            continue
        reach = ""
        if ssh_users is not None:
            if name in ssh_users or "autogroup:nonroot" in ssh_users:
                reach = " The policy lets SSH land on this user here."
            else:
                continue
        why = []
        if rootish:
            why.append(f"groups {rootish}")
        if nopw:
            why.append("passwordless sudo")
        h.add("TW09", "WARN", f"SSH-target user '{name}' is already root-equivalent",
              f"{', '.join(why)}.{reach} A 'non-root' SSH grant to this user was never a privilege boundary, with or without Tailworm.",
              "Give agent/CI users their own accounts with no docker group and no NOPASSWD sudo, or accept that the grant is a root grant.")

    # Serve / Funnel (F7-F11 + header spoofing)
    tcp = parse_listeners(h.sections.get("tcp_listen"))
    tcp_by_port = {}
    for addr, pr in tcp:
        try:
            port = int(addr.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue
        tcp_by_port.setdefault(port, []).append((bind_class(addr), addr, pr))
    funnels = []
    for path, k, v in walk_serve(serve):
        sv = str(v)
        if k == "AllowFunnel" or "AllowFunnel" in path:
            if v is True:
                funnels.append(path.rsplit("/", 1)[-1] if k == "AllowFunnel" else k)
        if k in ("Proxy", "TCPForward", "Path"):
            if "tailscaled.sock" in sv or "localapi" in sv:
                h.add("TW10", "CRIT", f"Serve forwards to Tailscale's own LocalAPI ({sv})",
                      "Tailworm F7: a remote peer gets admin control of this node's tailscaled.",
                      "Remove that serve handler now: tailscale serve reset (or remove the specific mount).")
            elif sv.startswith("unix:"):
                h.add("TW10", "WARN", f"Serve proxies to a unix socket: {sv}",
                      "Tailworm F8: the guard is checked at config time only; if that path's directory is writable by non-root, it can be swapped for docker.sock.",
                      "Make sure the socket's directory is root-owned and 0755 (see TW07 for this path).")
            elif k == "Path":
                h.add("TW10", "INFO", f"Serve publishes files from {sv}", "Served by root tailscaled; anything that can write there can replace what's published.")
            m = re.match(r"^(?:https?://|https\+insecure://)?(127\.0\.0\.1|localhost|\[::1\])?:?(\d+)", sv.replace("tcp://", ""))
            if m and m.group(2):
                port = int(m.group(2))
                exposed = [a for c, a, _ in tcp_by_port.get(port, []) if c in ("all", "specific", "tailnet")]
                if exposed:
                    h.add("TW11", "WARN", f"Serve backend :{port} also listens on {exposed}",
                          "Clients can skip serve and talk to the backend directly, forging the Tailscale-User-* identity headers serve would inject. If the app authorizes on those headers, auth is bypassed. This is separate from Tailworm F11, which races those same headers.",
                          f"Bind the backend to 127.0.0.1:{port} only.")
    if funnels:
        h.add("TW10", "WARN", f"Funnel is ON: {sorted(set(funnels))}",
              "Publicly reachable from the internet. Tailworm F9: the attribute is enforced client-side, so don't assume policy limits where this can be turned on.",
              "Confirm each one is intentional; `tailscale funnel reset` for the rest.")

    # Prefs-based exposure
    if prefs.get("OperatorUser"):
        h.add("TW13", "WARN", f"Tailscale operator user set: {prefs['OperatorUser']}",
              "The operator can change serve/funnel config without root. That is exactly the precondition for Tailworm F7/F8, held by a non-root account.",
              "Clear it (`tailscale set --operator=`) unless you need it.")
    if prefs.get("RunWebClient"):
        h.add("TW14", "WARN", "Tailscale web client is running (port 5252)",
              "If policy grants webui canEdit ssh, a browser session can re-enable SSH here.", "./fleet.sh --set webclient=off --only <host>")
    shares = prefs.get("DriveShares") or []
    drive_txt = h.sections.get("ts_drive") or ""
    if shares or re.search(r"^\S+\s+/\S*", drive_txt, re.M):
        h.add("TW15", "WARN", "Taildrive shares exist on this node",
              f"{[s.get('Name') for s in shares] if shares else drive_txt.strip()[:200]}. Check each one is intentional; a planted share is a quiet persistence and exfil channel.",
              "`tailscale drive unshare <name>`")
    if (prefs.get("AppConnector") or {}).get("Advertise"):
        h.add("TW16", "HIGH", "This node is an app connector (Tailworm F4)",
              "Entitled users can choose arbitrary egress destinations through it, including metadata services, the LAN, and in k8s the API server.",
              "Restrict entitlements and enforce a kernel destination allowlist, or stop advertising until patched.")
    routes = prefs.get("AdvertiseRoutes") or []
    if routes:
        exit_ = any(r in ("0.0.0.0/0", "::/0") for r in routes)
        h.add("TW17", "INFO", ("Exit node + " if exit_ else "") + "subnet router",
              f"Advertises {routes}. Root here means a pivot into those networks, so this node deserves the tightest SSH policy.")
    au = prefs.get("AutoUpdate") or {}
    if au and not au.get("Apply"):
        h.add("TW18", "INFO", "Auto-update is off", "When Tailscale ships the fix, this node won't pick it up on its own.",
              "./fleet.sh --set autoupdate=on --only <host> (where the install supports it).")

    lock = h.sections.get("ts_lock") or ""
    if re.search(r"not enabled", lock, re.I):
        h.facts["lock"] = "off"
    elif re.search(r"is enabled", lock, re.I):
        h.facts["lock"] = "on"

    for s in pipe_records(h.sections.get("state"), prefix="pid="):
        if s.get("nonfile"):
            continue
        st = (s.get("stat") or "").split()
        if st and st[0] not in ("600", "400"):
            h.add("TW20", "WARN", f"Node state file {s.get('path')} has mode {st[0]}",
                  "It contains the node's private keys.", f"chmod 600 {s.get('path')}")
        if s.get("plaintext_json") == "1":
            h.facts["plaintext_state"] = True

    for s in pipe_records(h.sections.get("secrets"), prefix="file="):
        types = [t.replace("*", "") for t in s.get("types", "").split()]
        if not types:
            continue
        sev = "HIGH" if any(t in ("tskey-auth-", "tskey-client-", "tskey-api-") for t in types) else "WARN"
        h.add("TW21", sev, f"Tailscale credential material in {s.get('file')}",
              f"Types: {types}. Root on this node (or anyone who has its backups) can enroll devices or call the API without the race the report describes.",
              "Revoke the key in the admin console, delete the file or line, and use ephemeral, single-use, or OAuth-scoped credentials instead.")

    analyze_docker(h)

    for addr, pr in tcp:
        try:
            port = int(addr.rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue
        if port in DANGER_PORTS and bind_class(addr) != "loopback":
            if port == 5252 and any(f.id == "TW14" for f in h.findings):
                continue
            h.add("TW25", "WARN", f"{DANGER_PORTS[port]} listening on {addr}",
                  f"Process {pr or '?'}. Anyone the tailnet policy lets reach this port gets container or host control, with no Tailscale bug needed.",
                  "Bind to loopback or a socket, or limit the policy grant to the one source that needs it.")

    # Tailworm is escalation beyond the local user you SSH in as. If every SSH grant that can
    # reach this node lands as root, there is nothing to escalate to.
    if policy is not None and "users" in h.sections:
        local = {u.get("user") for u in pipe_records(h.sections.get("users"), prefix="user=")} - {None}
        allowed = policy_ssh_users_for(policy, tags)
        nonroot = ((allowed - {"root", "autogroup:nonroot"}) & local) | (local if "autogroup:nonroot" in allowed else set())
        h.facts["ssh_nonroot_users"] = sorted(nonroot)
        if allowed and not nonroot:
            for f in h.findings:
                if f.id in ("TW03", "TW03P") and f.sev == "HIGH":
                    f.sev = "INFO"
                    f.title += " (root-only access: nothing to escalate to)"
                    f.detail = ("Every SSH rule that reaches this node logs in as root, and none of the other users it allows exist here, "
                                "so Tailworm's escalation adds nothing. The risk is who holds those root grants. "
                                "Still update tailscale when the fix ships. " + f.detail)

    logs = (h.sections.get("ts_logs") or "").strip()
    if logs:
        n = len(logs.splitlines())
        h.add("TW26", "INFO", f"{n} forwarding-related tailscaled log line(s) in the last 7 days",
              "Something may depend on Tailscale SSH forwarding (VS Code Remote-SSH, ssh -L). Check before disabling, and look for anything unexpected.\n" + "\n".join(logs.splitlines()[-5:]))


def parse_iso(s):
    try:
        s = re.sub(r"(\.\d{6})\d+", r"\1", s.strip()).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, AttributeError):
        return None


def analyze_docker(h: Host):
    text = h.sections.get("docker") or ""
    recs, cur = [], None
    for line in text.splitlines():
        if line.startswith("@@C|"):
            parts = line.split("|")
            cur = {"name": parts[1].lstrip("/"), "image": parts[2], "status": parts[3], "created": parts[4],
                   "privileged": parts[5] == "true", "netmode": parts[6],
                   "mounts": [m for m in (parts[7] if len(parts) > 7 else "").split(",") if m], "args": "", "env": {}}
            recs.append(cur)
        elif cur and line.startswith("@@A "):
            cur["args"] = line[4:]
        elif cur and line.startswith("@@E "):
            k, _, v = line[4:].partition("=")
            cur["env"][k] = v
    now = datetime.now(timezone.utc)
    for c in recs:
        sources = [m.split(">", 1)[0] for m in c["mounts"]]
        is_ts = "tailscale" in c["image"].lower() or any(k.startswith("TS_") for k in c["env"])
        if is_ts:
            extra = c["env"].get("TS_EXTRA_ARGS", "") + " " + c["args"]
            ssh_on = "--ssh" in extra and "--ssh=false" not in extra
            mitig = truthy(c["env"].get("TS_SSH_DISABLE_FORWARDING"))
            dsock = any(s.endswith("docker.sock") for s in sources)
            if ssh_on and not mitig:
                h.add("TW22", "CRIT" if dsock else "HIGH",
                      f"Container '{c['name']}' runs its own Tailscale SSH server with forwarding enabled",
                      "It's a separate tailnet node; the host-level mitigation does not cover it." + (" It also mounts docker.sock, so an SSH grant to it is root on the HOST." if dsock else ""),
                      "Add TS_SSH_DISABLE_FORWARDING=1 to its environment (compose: environment:) and recreate it; or drop --ssh from TS_EXTRA_ARGS.")
            if truthy(c["env"].get("TS_SERVE_ALLOW_ALL_INTERFACES")):
                h.add("TW12", "CRIT", f"Container '{c['name']}' sets TS_SERVE_ALLOW_ALL_INTERFACES", "Tailworm F10.", "Remove it and recreate the container.")
            if any(k in c["env"] for k in ("TS_AUTHKEY", "TS_AUTH_KEY", "TAILSCALE_AUTHKEY")):
                h.add("TW21", "WARN", f"Container '{c['name']}' has an auth key in its runtime environment",
                      "Read from the running container's config, not from your files. Anything with docker access sees it via `docker inspect`, and it's also stored wherever the stack's env lives (Portainer/Arcane database, .env) and in their backups. With `env_file: stack.env`, every service in the stack gets it, even ones that never use Tailscale.",
                      "Once the container has enrolled, its identity is in the state volume: remove TS_AUTHKEY from the stack env, redeploy, then revoke the key.")
        created = parse_iso(c["created"])
        if created and now - created < timedelta(days=7) and ("/" in sources or c["privileged"]):
            h.add("TW23", "WARN", f"Recently created container '{c['name']}' has host-root access",
                  f"created {c['created'][:19]}, privileged={c['privileged']}, mounts '/'={'/' in sources}, image {c['image']}. `docker run -v /:/host` is the usual payload after reaching docker.sock (Tailworm F1).",
                  "Confirm you created it. If not, treat the host as compromised.")
    ev = [l for l in (h.sections.get("docker_events") or "").splitlines() if l.strip()]
    if ev:
        h.add("TW24", "INFO", f"{len(ev)} container create/exec events in the last 72h",
              "Review for anything you didn't do:\n" + "\n".join(ev[-8:]))


def fleet_checks(hosts, status, scope=None, denied=None):
    F = []
    denied = set(denied or ())
    collected = {h.facts.get("dns") for h in hosts if h.facts.get("dns")}
    collected_names = {h.name for h in hosts}
    if status:
        missing = []
        for p in (status.get("Peer") or {}).values():
            if not p.get("sshHostKeys") or p.get("ShareeNode"):
                continue
            dns = (p.get("DNSName") or "").rstrip(".")
            short = dns.split(".")[0]
            if scope is not None and short not in scope:
                continue
            if short in denied:
                continue
            if dns not in collected and short not in collected_names:
                missing.append(f"{short} ({'online' if p.get('Online') else 'offline'}; {', '.join(p.get('Tags') or ['untagged'])})")
        if missing:
            F.append(Finding("fleet", "TW90", "WARN", f"{len(missing)} Tailscale SSH server(s) not audited",
                             "These peers advertise SSH host keys in your netmap, so they run a Tailscale SSH server, but no collection exists for them. Sidecar containers, k8s proxies, and routers usually end up here:\n- " + "\n- ".join(sorted(missing)),
                             "Collect them, or confirm they're covered by a host-level collection (TW03 lists instances by LXC/container)."))
    if denied:
        F.append(Finding("fleet", "TW91", "INFO", f"{len(denied)} SSH server(s) the tailnet policy doesn't let you into",
                         "These belong to someone else, or no SSH rule covers them for you: " + ", ".join(sorted(denied)) + ". Confirm the owner in the admin console; you can't audit what you can't reach."))
    locks = {h.facts.get("lock") for h in hosts} - {None}
    if "off" in locks:
        F.append(Finding("fleet", "TW19", "WARN", "Tailnet Lock is not enabled",
                         "Report outcome #3 (captured auth key, then rogue node enrollment) and any stray key from TW21 are accepted by the control plane without a signature from a trusted node. Tailnet Lock blocks that. It does NOT stop node-key theft (TW20).",
                         "Plan Tailnet Lock: it needs pre-signed keys for the k8s operator and any automation that enrolls nodes."))
    if any(h.facts.get("plaintext_state") for h in hosts):
        names = sorted(h.name for h in hosts if h.facts.get("plaintext_state"))
        F.append(Finding("fleet", "TW20", "INFO", "Node identities are stored as plaintext on disk",
                         f"{', '.join(names)}. Root (or a copy of a backup: vzdump, restic, Arcane, Syncthing) can clone a node's identity, and no new device appears in the console. Neither the Tailworm report nor Tailnet Lock covers this.",
                         "Exclude /var/lib/tailscale from file-level backups or treat those backups as secrets; rotate (logout/login) any node you suspect."))
    return F


# ----------------------------------------------------------------------------- API audit
API = "https://api.tailscale.com/api/v2"


def api_get(path, token):
    req = urllib.request.Request(f"{API}{path}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def api_token():
    if os.environ.get("TS_API_KEY"):
        return os.environ["TS_API_KEY"]
    cid, sec = os.environ.get("TS_OAUTH_CLIENT_ID"), os.environ.get("TS_OAUTH_CLIENT_SECRET")
    if cid and sec:
        data = urllib.parse.urlencode({"client_id": cid, "client_secret": sec}).encode()
        with urllib.request.urlopen(urllib.request.Request(f"{API}/oauth/token", data=data), timeout=30) as r:
            return json.loads(r.read().decode())["access_token"]
    return None


def audit_api(tailnet="-", from_dir=None):
    F = []

    def add(fid, sev, title, detail="", fix=""):
        F.append(Finding("api", fid, sev, title, detail, fix))

    if from_dir:
        d = Path(from_dir)
        devices = json.loads((d / "devices.json").read_text()).get("devices", [])
        keys = json.loads((d / "keys.json").read_text()) if (d / "keys.json").exists() else []
        settings = json.loads((d / "settings.json").read_text()) if (d / "settings.json").exists() else {}
    else:
        tok = api_token()
        if not tok:
            add("AP00", "WARN", "API audit skipped", "Set TS_API_KEY, or TS_OAUTH_CLIENT_ID and TS_OAUTH_CLIENT_SECRET (scopes: devices:core:read, auth_keys:read, feature_settings:read).")
            return F
        t = urllib.parse.quote(tailnet)
        devices = api_get(f"/tailnet/{t}/devices?fields=all", tok).get("devices", [])
        keys = []
        try:
            for k in api_get(f"/tailnet/{t}/keys?all=true", tok).get("keys", []):
                try:
                    keys.append(api_get(f"/tailnet/{t}/keys/{k['id']}", tok))
                except Exception:  # noqa: BLE001
                    keys.append(k)
        except Exception as e:  # noqa: BLE001
            add("AP06", "INFO", "Could not list auth keys", str(e))
        try:
            settings = api_get(f"/tailnet/{t}/settings", tok)
        except Exception:  # noqa: BLE001
            settings = {}

    now = datetime.now(timezone.utc)
    old, recent, untagged_linux, pending, lockerr, upd = [], [], [], [], [], []
    for dv in devices:
        name = (dv.get("name") or dv.get("hostname") or "?").split(".")[0]
        v = vtuple(dv.get("clientVersion", ""))
        if v and v < vtuple(FLOOR):
            old.append(f"{name} {dv.get('clientVersion', '').split('-')[0]}")
        if dv.get("updateAvailable"):
            upd.append(name)
        c = parse_iso(dv.get("created", ""))
        if c and now - c < timedelta(days=RECENT_DAYS):
            recent.append(f"{name} (created {dv['created'][:10]}, user {dv.get('user')}, tags {dv.get('tags') or '-'}, os {dv.get('os')})")
        if not dv.get("tags") and dv.get("os") == "linux" and not dv.get("isExternal"):
            untagged_linux.append(f"{name} (user {dv.get('user')})")
        if dv.get("authorized") is False:
            pending.append(name)
        if dv.get("tailnetLockError"):
            lockerr.append(f"{name}: {dv['tailnetLockError']}")
    if old:
        add("AP01", "WARN", f"{len(old)} device(s) below {FLOOR}", "\n".join(old), "Update. Routers and static binaries won't self-update.")
    if upd:
        add("AP01", "INFO", f"{len(upd)} device(s) report an update available", ", ".join(sorted(upd)))
    if recent:
        add("AP02", "WARN", f"{len(recent)} device(s) enrolled in the last {RECENT_DAYS} days: confirm each one",
            "SANS: 'investigate unexpected device enrollment'. Report outcome #3 is a rogue node enrolled with a captured auth key.\n" + "\n".join(recent))
    if untagged_linux:
        add("AP08", "WARN", f"{len(untagged_linux)} untagged Linux device(s) carry a user's identity",
            "An untagged server acts as its owner (often an admin) for ACLs, Tailscale SSH and tsidp. One compromised container on it inherits that identity, which is exactly what tags exist to prevent.\n" + "\n".join(untagged_linux),
            "Tag servers (with grants written first), and keep untagged devices to the laptops and phones people actually use.")
    if pending:
        add("AP03", "WARN", "Devices awaiting approval", ", ".join(pending), "Approve only the ones you recognize.")
    if lockerr:
        add("AP04", "INFO", "Tailnet Lock errors", "\n".join(lockerr))
    if settings:
        if settings.get("devicesApprovalOn") is False:
            add("AP05", "WARN", "Device approval is off", "New devices (including ones enrolled with a stolen key) join immediately.",
                "Turn on device approval (Settings > Device management), or use Tailnet Lock.")
        if settings.get("devicesAutoUpdatesOn") is False:
            add("AP05", "INFO", "Auto-updates for new devices are off")
        if settings.get("networkFlowLoggingOn") is False:
            add("AP05", "INFO", "Network flow logs are off", "You'd have no connection history to investigate lateral movement with.")
    for k in keys:
        caps = ((k.get("capabilities") or {}).get("devices") or {}).get("create") or {}
        if k.get("invalid") or k.get("revoked"):
            continue
        if caps.get("reusable") and caps.get("preauthorized"):
            add("AP06", "WARN", f"Reusable, pre-authorized auth key {k.get('id')}",
                f"tags={caps.get('tags')} ephemeral={caps.get('ephemeral')} expires={k.get('expires', '')[:10]} description={k.get('description', '')!r}. Anyone who finds this key enrolls trusted devices at will.",
                "Revoke it if unused; otherwise prefer single-use or OAuth-minted keys.")
    return F


# ----------------------------------------------------------------------------- output
def render_md(hosts, extra, title="Tailworm fleet audit"):
    allf = [f for h in hosts for f in h.findings] + extra
    real = [f for f in allf if f.sev != "OK"]
    counts = {s: sum(1 for f in real if f.sev == s) for s in ("CRIT", "HIGH", "WARN", "INFO")}
    L = [f"# {title}", "", f"_Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC. Floor {FLOOR}; Tailworm fix: {PATCHED or 'none released yet'}._", "",
         "| CRIT | HIGH | WARN | INFO |", "|---|---|---|---|", f"| {counts['CRIT']} | {counts['HIGH']} | {counts['WARN']} | {counts['INFO']} |", ""]
    if hosts:
        L += ["## Nodes", "", "| Node | Worst | Version | SSH | Forwarding off (live) | Probe | Web client | Auto-update | Tags | Init |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for h in sorted(hosts, key=lambda x: (SEV_ORDER[x.worst()], x.name)):
            inst = [i for i in h.facts.get("instances", []) if i["where"] == "host"]
            fwd = "yes" if inst and all(i["live"] for i in inst) else ("n/a" if not inst else "NO")
            onoff = lambda v: {True: "on", False: "off"}.get(v, "?")
            pr = (h.facts.get("probe") or "").split(" ", 1)[0].replace("probe=", "") or "-"
            L.append(f"| {h.name} | {h.worst()} | {h.facts.get('version', '?')} | {onoff(h.facts.get('ssh'))} | {fwd} | {pr} | "
                     f"{onoff(h.facts.get('webclient'))} | {onoff(h.facts.get('autoupdate'))} | {', '.join(h.facts.get('tags') or []) or 'untagged'} | {h.facts.get('init', '?')} |")
        L.append("")
        apply_hosts = sorted(h.name for h in hosts if any(f.id == "TW03" and f.sev in ("HIGH", "WARN") and "NOT live" not in f.title and "read" not in f.title for f in h.findings) and h.facts.get("init") == "systemd")
        probed_ok = sorted(h.name for h in hosts if any(f.id == "TW03P" and f.sev == "OK" for f in h.findings))
        restart_hosts = sorted(h.name for h in hosts if any(f.id == "TW03" and "NOT live" in f.title for f in h.findings))
        manual = sorted(h.name for h in hosts if any(f.id == "TW03" and f.sev == "HIGH" for f in h.findings) and h.facts.get("init") != "systemd")
        L += ["## Remediation plan", ""]
        steps = []
        if apply_hosts:
            steps.append(f"**Disable forwarding (systemd):** `./fleet.sh --set forwarding=off --only {','.join(apply_hosts)}` (skip any node you tunnel through)")
        if restart_hosts:
            steps.append(f"**Restart to make it live:** `./fleet.sh --set forwarding=off --only {','.join(restart_hosts)}` (idempotent; it just schedules the restart)")
        if manual:
            steps.append(f"**Manual (non-systemd: OpenWrt/containers):** {', '.join(manual)} (see README > Manual mitigation)")
        if probed_ok:
            steps.append(f"**Already refusing unix-socket forwarding (no action):** {', '.join(probed_ok)}")
        steps.append("**Verify:** `./fleet.sh --probe`, then confirm every TW03P is OK")
        steps.append("Work through the CRIT/HIGH findings below, then the WARNs.")
        L += [f"{i}. {t}" for i, t in enumerate(steps, 1)]
        L.append("")
    groups = {}
    for f in allf:
        groups.setdefault(f.host, []).append(f)
    for host in sorted(groups, key=lambda x: (x in ("fleet", "policy", "api"), x)):
        fs = sorted([f for f in groups[host] if f.sev != "OK"], key=lambda f: (SEV_ORDER[f.sev], f.id))
        oks = [f for f in groups[host] if f.sev == "OK"]
        if not fs and not oks:
            continue
        L += [f"## {host}", ""]
        for f in fs:
            L.append(f"- **[{f.sev}] {f.id}: {f.title}**")
            if f.detail:
                L.append("  " + f.detail.replace("\n", "\n  "))
            if f.fix:
                L.append(f"  - Fix: {f.fix}")
        for f in oks:
            L.append(f"- [OK] {f.id}: {f.title}")
        L.append("")
    L += ["## What this audit can't see", "",
          "- Tailscale SSH servers it couldn't log into (TW90), and tsnet apps (tsidp, tsrecorder, golink) that embed their own Tailscale.",
          "- Anything on a node's disk outside TW_SECRET_PATHS.",
          "- `--probe` tests unix -L (core sockets plus allowlist mapping), unix -R and TCP -L. It doesn't attempt the F3 race itself.",
          "- Activity before the last 72h (docker events) or 7 days (journal)."]
    return "\n".join(L) + "\n"


def print_console(hosts, extra):
    allf = [f for h in hosts for f in h.findings] + extra
    for f in sorted(allf, key=lambda f: (SEV_ORDER[f.sev], f.host, f.id)):
        if f.sev in ("OK", "INFO"):
            continue
        print(f"[{f.sev:4}] {f.host:20} {f.id:5} {f.title}")


def exit_code(findings):
    sevs = {f.sev for f in findings}
    return 2 if "CRIT" in sevs else 1 if "HIGH" in sevs else 0


# ----------------------------------------------------------------------------- CLI
def cmd_peers(a):
    st = json.loads(Path(a.status).read_text())
    for p in (st.get("Peer") or {}).values():
        dns = (p.get("DNSName") or "").rstrip(".")
        if not dns:
            continue
        ip = (p.get("TailscaleIPs") or [""])[0]
        print("\t".join([dns, dns.split(".")[0], ip, ",".join(p.get("Tags") or []) or "-", p.get("OS") or "?",
                         "1" if p.get("Online") else "0", "1" if p.get("sshHostKeys") else "0",
                         "1" if p.get("ShareeNode") else "0"]))
    return 0


def cmd_analyze(a):
    d = Path(a.dir)
    files = sorted(d.glob("*.txt"))
    if not files:
        print(f"no *.txt collections in {d}", file=sys.stderr)
        return 3
    policy = load_hujson(Path(a.policy).read_text()) if a.policy else None
    status = json.loads(Path(a.status).read_text()) if a.status and Path(a.status).exists() else None
    hosts = [load_host(f) for f in files]
    for h in hosts:
        analyze_host(h, policy)
    scope = set(Path(a.scope).read_text().split()) if a.scope and Path(a.scope).exists() else None
    denied = {f.stem for f in d.glob("*.denied")}
    extra = fleet_checks(hosts, status, scope, denied)
    if policy:
        extra += audit_policy(policy)
    if a.api_dir or a.api:
        extra += audit_api(a.tailnet, a.api_dir)
    print_console(hosts, extra)
    md = render_md(hosts, extra)
    if a.md:
        Path(a.md).write_text(md)
        print(f"\nreport: {a.md}")
    if a.json:
        Path(a.json).write_text(json.dumps({"hosts": {h.name: {"facts": h.facts, "findings": [asdict(f) for f in h.findings]} for h in hosts},
                                            "extra": [asdict(f) for f in extra]}, indent=2, default=str))
    return exit_code([f for h in hosts for f in h.findings] + extra)


def cmd_policy(a):
    F = audit_policy(load_hujson(Path(a.file).read_text()))
    print_console([], F)
    md = render_md([], F, "Tailnet policy audit (Tailworm lens)")
    if a.md:
        Path(a.md).write_text(md)
    else:
        print(md)
    return exit_code(F)


def cmd_api(a):
    F = audit_api(a.tailnet, a.from_dir)
    print_console([], F)
    md = render_md([], F, "Tailscale API audit")
    if a.md:
        Path(a.md).write_text(md)
    else:
        print(md)
    return exit_code(F)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("peers"); p.add_argument("status"); p.set_defaults(fn=cmd_peers)
    p = sp.add_parser("analyze"); p.add_argument("dir"); p.add_argument("--status"); p.add_argument("--policy")
    p.add_argument("--api", action="store_true"); p.add_argument("--api-dir"); p.add_argument("--tailnet", default="-")
    p.add_argument("--md"); p.add_argument("--json"); p.add_argument("--scope"); p.set_defaults(fn=cmd_analyze)
    p = sp.add_parser("policy"); p.add_argument("file"); p.add_argument("--md"); p.set_defaults(fn=cmd_policy)
    p = sp.add_parser("api"); p.add_argument("--tailnet", default="-"); p.add_argument("--from-dir"); p.add_argument("--md"); p.set_defaults(fn=cmd_api)
    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
