# Tailworm fleet audit

_Generated 2026-10-27 17:38 UTC. Floor 1.98.9; Tailworm fix: none released yet._

| CRIT | HIGH | WARN | INFO |
|---|---|---|---|
| 2 | 4 | 26 | 19 |

## Nodes

| Node | Worst | Version | SSH | Forwarding off (live) | Probe | Web client | Auto-update | Tags | Init |
|---|---|---|---|---|---|---|---|---|---|
| dockerhost-01 | CRIT | 1.104.2 | off | NO | - | ? | on | tag:docker-host | systemd |
| pve-01 | HIGH | 1.100.1 | on | NO | - | ? | off | untagged | systemd |
| router-01 | HIGH | 1.92.5 | on | NO | - | ? | off | tag:router | procd |
| staged-02 | WARN | 1.104.2 | on | NO | - | off | on | tag:managed-host | systemd |
| mitigated-01 | OK | 1.104.2 | on | yes | - | off | on | tag:managed-host | systemd |

## Remediation plan

1. **Disable forwarding (systemd):** `./fleet.sh --set forwarding=off --only pve-01` (skip any node you tunnel through)
2. **Restart to make it live:** `./fleet.sh --set forwarding=off --only staged-02` (idempotent; it just schedules the restart)
3. **Verify:** `./fleet.sh --probe`, then confirm every TW03P is OK
4. Work through the CRIT/HIGH findings below, then the WARNs.

## dockerhost-01

- **[CRIT] TW10: Serve forwards to Tailscale's own LocalAPI (unix:/run/tailscale/tailscaled.sock)**
  Tailworm F7: a remote peer gets admin control of this node's tailscaled.
  - Fix: Remove that serve handler now: tailscale serve reset (or remove the specific mount).
- **[CRIT] TW22: Container 'ts-forgejo' runs its own Tailscale SSH server with forwarding enabled**
  It's a separate tailnet node; the host-level mitigation does not cover it. It also mounts docker.sock, so an SSH grant to it is root on the HOST.
  - Fix: Add TS_SSH_DISABLE_FORWARDING=1 to its environment (compose: environment:) and recreate it; or drop --ssh from TS_EXTRA_ARGS.
- **[WARN] TW05: dockerd is running but its socket is missing**
  Expected one of ['/run/docker.sock']. After Tailworm F2 (BindUnlink) the original socket is unlinked; once the attacker disconnects, the daemon is left without its socket. A custom socket path also triggers this.
  - Fix: Run `docker info` or `ctr version` locally. If it can't connect, restart dockerd and investigate how the socket disappeared.
- **[WARN] TW11: Serve backend :3000 also listens on ['0.0.0.0:3000']**
  Clients can skip serve and talk to the backend directly, forging the Tailscale-User-* identity headers serve would inject. If the app authorizes on those headers, auth is bypassed. This is separate from Tailworm F11, which races those same headers.
  - Fix: Bind the backend to 127.0.0.1:3000 only.
- **[WARN] TW21: Container 'ts-forgejo' has an auth key in its runtime environment**
  Read from the running container's config, not from your files. Anything with docker access sees it via `docker inspect`, and it's also stored wherever the stack's env lives (Portainer/Arcane database, .env) and in their backups. With `env_file: stack.env`, every service in the stack gets it, even ones that never use Tailscale.
  - Fix: Once the container has enrolled, its identity is in the state volume: remove TS_AUTHKEY from the stack env, redeploy, then revoke the key.
- **[WARN] TW25: Arcane agent (Docker control plane) listening on 0.0.0.0:3552**
  Process ['arcane-agent']. Anyone the tailnet policy lets reach this port gets container or host control, with no Tailscale bug needed.
  - Fix: Bind to loopback or a socket, or limit the policy grant to the one source that needs it.
- **[INFO] TW03: tailscaled in container 3f9a1c2b4d5e lacks the forwarding mitigation**
  Couldn't ask it whether it runs Tailscale SSH. Only matters if it does. Command: tailscaled --statedir=/var/lib/tailscale
  - Fix: Check: tailscale --socket=<its socket> debug prefs | grep RunSSH
- **[INFO] TW24: 2 container create/exec events in the last 72h**
  Review for anything you didn't do:
  1793030000 create helper alpine:3.20
  1793030001 exec_create: sh helper alpine:3.20
- **[INFO] TW26: 1 forwarding-related tailscaled log line(s) in the last 7 days**
  Something may depend on Tailscale SSH forwarding (VS Code Remote-SSH, ssh -L). Check before disabling, and look for anything unexpected.
  Oct 25 03:12:01 dockerhost-01 tailscaled[500]: ssh-session(sess-1): direct-tcpip channel to 127.0.0.1:5432
- [OK] TW01: Tailscale 1.104.2 (no Tailworm fix released yet; mitigation still required)
- [OK] TW03: Tailscale SSH server is off on this node

## mitigated-01

- [OK] TW01: Tailscale 1.104.2 (no Tailworm fix released yet; mitigation still required)
- [OK] TW03: Forwarding disabled in the running tailscaled (TS_SSH_DISABLE_FORWARDING=1)

## pve-01

- **[HIGH] TW03: Tailscale SSH forwarding is enabled**
  Any SSH grant to this node can be turned into root via root-run unix-socket forwarding (Tailworm F1-F3).
  - Fix: ./fleet.sh --set forwarding=off --only <host>  (or on the node: sudo sh tsctl.sh forwarding=off)
- **[WARN] TW09: SSH-target user 'pi' is already root-equivalent**
  passwordless sudo. The policy lets SSH land on this user here. A 'non-root' SSH grant to this user was never a privilege boundary, with or without Tailworm.
  - Fix: Give agent/CI users their own accounts with no docker group and no NOPASSWD sudo, or accept that the grant is a root grant.
- **[WARN] TW25: Proxmox VE web UI/API listening on *:8006**
  Process ['pveproxy']. Anyone the tailnet policy lets reach this port gets container or host control, with no Tailscale bug needed.
  - Fix: Bind to loopback or a socket, or limit the policy grant to the one source that needs it.
- **[INFO] TW03: tailscaled in LXC 105 lacks the forwarding mitigation**
  Couldn't ask it whether it runs Tailscale SSH. Only matters if it does. Command: /usr/sbin/tailscaled
  - Fix: Check: tailscale --socket=<its socket> debug prefs | grep RunSSH
- **[INFO] TW18: Auto-update is off**
  When Tailscale ships the fix, this node won't pick it up on its own.
  - Fix: ./fleet.sh --set autoupdate=on --only <host> (where the install supports it).
- [OK] TW01: Tailscale 1.100.1 (no Tailworm fix released yet; mitigation still required)

## router-01

- **[HIGH] TW21: Tailscale credential material in /etc/tailscale/up.sh**
  Types: ['tskey-auth-']. Root on this node (or anyone who has its backups) can enroll devices or call the API without the race the report describes.
  - Fix: Revoke the key in the admin console, delete the file or line, and use ephemeral, single-use, or OAuth-scoped credentials instead.
- **[WARN] TW01: Tailscale 1.92.5 is below 1.98.9**
  This predates the fix for the earlier instance of this bug class (TS-2026-004/005).
  - Fix: Update tailscale. Static and vendor builds (GL-iNet and other router firmware) need a manual binary update.
- **[WARN] TW20: Node state file /etc/tailscale/tailscaled.state has mode 644**
  It contains the node's private keys.
  - Fix: chmod 600 /etc/tailscale/tailscaled.state
- **[WARN] TW25: Tailscale web client listening on 100.64.0.3:5252**
  Process ['tailscaled']. Anyone the tailnet policy lets reach this port gets container or host control, with no Tailscale bug needed.
  - Fix: Bind to loopback or a socket, or limit the policy grant to the one source that needs it.
- **[INFO] TW03: Tailscale SSH forwarding is enabled (root-only access: nothing to escalate to)**
  Every SSH rule that reaches this node logs in as root, and none of the other users it allows exist here, so Tailworm's escalation adds nothing. The risk is who holds those root grants. Still update tailscale when the fix ships. Any SSH grant to this node can be turned into root via root-run unix-socket forwarding (Tailworm F1-F3).
  - Fix: ./fleet.sh --set forwarding=off --only <host>  (or on the node: sudo sh tsctl.sh forwarding=off)
- **[INFO] TW06: Root sockets reachable via forwarding on this node**
  tailscaled.sock
  - Fix: These become reachable from any SSH grant until forwarding is disabled. docker.sock or containerd.sock means root on the host.
- **[INFO] TW08: fs.protected_symlinks unknown**
  Couldn't read /proc/sys/fs/protected_symlinks (old or embedded kernel?).
  - Fix: Check by hand: cat /proc/sys/fs/protected_symlinks (want 1).
- **[INFO] TW17: Exit node + subnet router**
  Advertises ['192.168.8.0/24', '0.0.0.0/0', '::/0']. Root here means a pivot into those networks, so this node deserves the tightest SSH policy.
- **[INFO] TW18: Auto-update is off**
  When Tailscale ships the fix, this node won't pick it up on its own.
  - Fix: ./fleet.sh --set autoupdate=on --only <host> (where the install supports it).

## staged-02

- **[WARN] TW03: Mitigation is configured but NOT live**
  TS_SSH_DISABLE_FORWARDING is in the unit/env file, but the running tailscaled was started without it.
  - Fix: Restart tailscaled: ./fleet.sh --set forwarding=off --only <host> schedules a detached restart.
- [OK] TW01: Tailscale 1.104.2 (no Tailworm fix released yet; mitigation still required)

## api

- **[WARN] AP01: 1 device(s) below 1.98.9**
  old-router 1.90.1
  - Fix: Update. Routers and static binaries won't self-update.
- **[WARN] AP03: Devices awaiting approval**
  pending
  - Fix: Approve only the ones you recognize.
- **[WARN] AP05: Device approval is off**
  New devices (including ones enrolled with a stolen key) join immediately.
  - Fix: Turn on device approval (Settings > Device management), or use Tailnet Lock.
- **[WARN] AP06: Reusable, pre-authorized auth key kAbc123**
  tags=['tag:docker-host'] ephemeral=False expires=2027-01-01 description='compose stacks'. Anyone who finds this key enrolls trusted devices at will.
  - Fix: Revoke it if unused; otherwise prefer single-use or OAuth-minted keys.
- **[WARN] AP08: 1 untagged Linux device(s) carry a user's identity**
  An untagged server acts as its owner (often an admin) for ACLs, Tailscale SSH and tsidp. One compromised container on it inherits that identity, which is exactly what tags exist to prevent.
  dockerbox (user admin@example.com)
  - Fix: Tag servers (with grants written first), and keep untagged devices to the laptops and phones people actually use.
- **[INFO] AP01: 1 device(s) report an update available**
  old-router
- **[INFO] AP05: Auto-updates for new devices are off**
- **[INFO] AP05: Network flow logs are off**
  You'd have no connection history to investigate lateral movement with.

## fleet

- **[WARN] TW19: Tailnet Lock is not enabled**
  Report outcome #3 (captured auth key, then rogue node enrollment) and any stray key from TW21 are accepted by the control plane without a signature from a trusted node. Tailnet Lock blocks that. It does NOT stop node-key theft (TW20).
  - Fix: Plan Tailnet Lock: it needs pre-signed keys for the k8s operator and any automation that enrolls nodes.
- **[WARN] TW90: 1 Tailscale SSH server(s) not audited**
  These peers advertise SSH host keys in your netmap, so they run a Tailscale SSH server, but no collection exists for them. Sidecar containers, k8s proxies, and routers usually end up here:
  - ts-sidecar (online; tag:forgejo)
  - Fix: Collect them, or confirm they're covered by a host-level collection (TW03 lists instances by LXC/container).
- **[INFO] TW20: Node identities are stored as plaintext on disk**
  mitigated-01, router-01, staged-02. Root (or a copy of a backup: vzdump, restic, Arcane, Syncthing) can clone a node's identity, and no new device appears in the console. Neither the Tailworm report nor Tailnet Lock covers this.
  - Fix: Exclude /var/lib/tailscale from file-level backups or treat those backups as secrets; rotate (logout/login) any node you suspect.

## policy

- **[HIGH] PA01: Non-root SSH grant is root-equivalent while forwarding is enabled**
  ssh[1] ['tag:agent-scout'] -> ['tag:managed-host'] as ['scout']. Tailworm F1-F3: forwarding runs inside root tailscaled, so 'scout' can reach root-only sockets (docker.sock, systemd private bus, tailscaled.sock).
  - Fix: Set TS_SSH_DISABLE_FORWARDING=1 on every dst node (fleet.sh --set forwarding=off), then verify with fleet.sh --probe. Until then, treat this rule as a root grant.
- **[HIGH] PA01: Non-root SSH grant is root-equivalent while forwarding is enabled**
  ssh[3] ['tag:ci-runner'] -> ['tag:managed-host'] as ['deploy']. Tailworm F1-F3: forwarding runs inside root tailscaled, so 'deploy' can reach root-only sockets (docker.sock, systemd private bus, tailscaled.sock).
  - Fix: Set TS_SSH_DISABLE_FORWARDING=1 on every dst node (fleet.sh --set forwarding=off), then verify with fleet.sh --probe. Until then, treat this rule as a root grant.
- **[WARN] PA02: Root SSH from user-owned devices with action=accept**
  ssh[0] ['group:admins'] -> ['autogroup:tagged'] as ['root']. Every device those users own (laptops, phones, WSL boxes running AI agents) is a root foothold on ['autogroup:tagged'].
  - Fix: Consider action: check with a short checkPeriod for root, and keep agent-running dev boxes out of group:admins.
- **[WARN] PA02: Root SSH from user-owned devices with action=accept**
  ssh[2] ['autogroup:member'] -> ['autogroup:self'] as ['root', 'autogroup:nonroot']. Every device those users own (laptops, phones, WSL boxes running AI agents) is a root foothold on ['autogroup:self'].
  - Fix: Consider action: check with a short checkPeriod for root, and keep agent-running dev boxes out of group:admins.
- **[WARN] PA04: SSH rule accepts client environment variables**
  ssh[3] ['tag:ci-runner'] -> ['tag:managed-host'] as ['deploy'] acceptEnv=['LD_PRELOAD', 'GIT_*']; risky: ['LD_PRELOAD']
  - Fix: Remove acceptEnv or narrow it to explicit, inert names.
- **[WARN] PA05: Any-port mesh grant to every tagged node**
  src=['tag:managed-host', 'tag:k8s'] dst=['autogroup:tagged'] ip=*. A foothold on any of these sources can reach docker-equivalent APIs on every server (Arcane/Portainer agents, Docker TCP, kubelet, Proxmox) without any SSH bug.
  - Fix: Split into per-service grants (port + tag) for anything that controls containers or hypervisors.
- **[WARN] PA07: Taildrive read-write to every tagged node**
  src=['autogroup:member'] dst=['autogroup:member', 'autogroup:tagged'] shares=['*']. If any process gets LocalAPI access on a server (Tailworm F1/F7), 'tailscale drive share x /' turns into read-write root filesystem access for these sources.
  - Fix: Restrict drive:share in nodeAttrs to the nodes that actually share, and grant drive per node/tag.
- **[WARN] PA08: Auto-approved routing reachable through tag-owns-tag**
  exitNode is auto-approved for tag:k8s, and tag:k8s is owned by ['tag:k8s-operator']. Root on any ['tag:k8s-operator'] node can mint new tag:k8s nodes that are auto-approved for exitNode.
  - Fix: Keep auto-approval for this, but alert on new devices with this tag (api audit AP02).
- **[WARN] PA08: Auto-approved routing reachable through tag-owns-tag**
  route 10.42.0.0/16 is auto-approved for tag:k8s, and tag:k8s is owned by ['tag:k8s-operator']. Root on any ['tag:k8s-operator'] node can mint new tag:k8s nodes that are auto-approved for route 10.42.0.0/16.
  - Fix: Keep auto-approval for this, but alert on new devices with this tag (api audit AP02).
- **[WARN] PA09: Web client (port 5252) can toggle Tailscale SSH**
  src=['group:admins'] dst=['autogroup:tagged']: webui canEdit includes 'ssh'. A browser session on an admin device can re-enable SSH on nodes you've locked down.
  - Fix: Drop 'ssh' from canEdit, or remove the webui grant if you don't use the web client.
- **[WARN] PA10: App connectors configured (Tailworm F4)**
  targets=['tag:connector']. Per the report, entitled users can pick arbitrary egress destinations through the connector.
  - Fix: Restrict entitlements, apply a kernel-level destination allowlist on connector hosts, or pause the connector until patched.
- **[INFO] PA03: Session recording does not cover forwarded channels (likely)**
  ssh[1] ['tag:agent-scout'] -> ['tag:managed-host'] as ['scout']. tsrecorder captures the terminal stream; -L/-R/unix-socket forwards are separate SSH channels. enforceRecorder is false, so sessions proceed if the recorder is down.
  - Fix: Verify on a test node: forward a socket, then check whether anything shows up in the recording. Don't count recording as a Tailworm control.
- **[INFO] PA06: Funnel attribute granted**
  targets=['group:admins']. Tailworm F9: Funnel entitlement is enforced by the client, so inventory actual Funnel state on every node rather than trusting this attribute.
  - Fix: fleet.sh reports live AllowFunnel per node (TW10).
- **[INFO] PA07: Every tagged node may create Taildrive shares**
  targets=['autogroup:member', 'autogroup:tagged']
  - Fix: Scope drive:share to the nodes that need it.
- **[INFO] PA11: Members get root on all of their own devices**
  ssh[2] ['autogroup:member'] -> ['autogroup:self'] as ['root', 'autogroup:nonroot']. One compromised personal device can root every other device the same person owns.
  - Fix: Drop root from this rule if you don't need it; personal devices rarely do.
- **[INFO] PA12: sshTest asserts 'no root' for a principal that holds a non-root grant**
  src=tag:agent-scout dst=['tag:managed-host'] accept=['scout'] deny=root. The test still passes, but under Tailworm the accepted user can reach root.
  - Fix: Keep the test, and add a comment that it holds only once forwarding is disabled fleet-wide.

## What this audit can't see

- Tailscale SSH servers it couldn't log into (TW90), and tsnet apps (tsidp, tsrecorder, golink) that embed their own Tailscale.
- Anything on a node's disk outside TW_SECRET_PATHS.
- `--probe` tests unix -L (core sockets plus allowlist mapping), unix -R and TCP -L. It doesn't attempt the F3 race itself.
- Activity before the last 72h (docker events) or 7 days (journal).
