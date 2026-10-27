# tailworm-audit

Fleet-wide audit, active probe and hardening toggles for the **Tailworm** Tailscale findings (Oct 2026), plus the adjacent exposures the public write-ups don't cover.

Tailworm's headline: Tailscale SSH forwarding runs inside the root `tailscaled`. That makes **any** SSH grant to a node, including "non-root" ones, a path to root-only unix sockets like `docker.sock`. Tailscale SSH does restrict unix-socket forwards to an allowlist of directories (`/tmp` and the user's home, in our tests), and Tailworm F3 is a race that defeats exactly that allowlist. When this was published there was no fix. The mitigation is `TS_SSH_DISABLE_FORWARDING=1` in tailscaled's environment, and this tool checks that it's actually in effect.

## Quick start

```bash
./fleet.sh                                         # read-only audit + report
./fleet.sh --probe                                 # + ask each SSH server what it will forward
./fleet.sh --set forwarding=off --only node1,node2 # mitigate, then re-verify
./fleet.sh --status                                # settings table, fast
```

Run it **as you**, from a device that has root SSH to your nodes in the tailnet policy (usually an untagged admin laptop). Output goes to `~/tailworm-out/<timestamp>/` (`report.md`, `report.json`, `raw/`), outside the tool folder, so updating the tool never deletes past reports. `TW_OUT_DIR` changes it. Exit code: `0` nothing above WARN, `1` HIGH, `2` CRIT, so it works as a CI job.

### Where it runs

| Platform | Notes |
|---|---|
| Linux | Uses `tailscale ssh`. Needs bash 4.3+, python3, coreutils. |
| WSL (Windows Tailscale client) | Finds `tailscale.exe` on any mounted drive and connects with OpenSSH to each node's 100.x IP. Tailscale SSH answers on port 22 there, under the same policy. Needs `openssh-client`. Don't install a second Tailscale inside WSL. |
| macOS | Finds `/Applications/Tailscale.app/...`. Needs `brew install bash coreutils` (Apple's bash is 3.2, and `timeout` ships as `gtimeout`). |
| Git Bash | Finds `/c/Program Files/Tailscale/tailscale.exe`. |

If it can't find the CLI it asks for the path once and remembers it in `~/.config/tailworm-audit/config`. You can override with `TS_CLI=/path/to/tailscale` and `TW_TRANSPORT=ssh|tailscale`.

## Pieces

| File | Runs on | What it does |
|---|---|---|
| `collect.sh` | each node | **Read-only** evidence collector. POSIX `sh` (dash, BusyBox/OpenWrt). Redacts every `tskey-*` and secret-looking value before output. Read it first. |
| `tsctl.sh` | each node | Shows or changes: `forwarding`, `webclient`, `autoupdate`, `ssh` (on/off). The forwarding change uses a systemd drop-in plus a **detached** restart, so the SSH session that made the change survives long enough to report. |
| `fleet.sh` | admin box | Discovers every peer advertising Tailscale SSH host keys, collects in parallel, probes, toggles, re-verifies, reports. |
| `tailworm_audit.py` | admin box | All the analysis (stdlib only): `analyze`, `policy`, `api`, `peers`. |
| `tests/` | anywhere | `python3 -m unittest discover -s tests` (synthetic fixtures). |
| `examples/sample-report.md` | - | What a report looks like, generated from the test fixtures (made-up hosts). |

## Toggles

```bash
./fleet.sh --set forwarding=off --only n1,n2            # Tailworm mitigation
./fleet.sh --set forwarding=on  --only n1               # revert one node (e.g. you tunnel through it)
./fleet.sh --set webclient=off,autoupdate=on --tag tag:managed-host
./fleet.sh --set ssh=off --only router1 --i-have-another-way
./fleet.sh --apply flagged                              # forwarding=off on every systemd node the last report flagged
```

On a single node: `sudo sh tsctl.sh status`, or `sudo sh tsctl.sh forwarding=off webclient=off`.

- `--set` refuses to run without `--only` or `--tag` (or an explicit `--yes`).
- `forwarding` changes restart tailscaled after `--restart-in` seconds (default 15). Existing Tailscale SSH sessions on those nodes drop; new ones work right away.
- `ssh=off` needs `--i-have-another-way` (console, LAN `sshd`, `pct enter`). After it, Tailscale SSH can't reach that node, including this tool.
- `webclient` and `autoupdate` take effect immediately with no restart. `autoupdate` isn't supported on every install (static binaries, some containers); the tool reports that instead of failing silently.

**What `forwarding=off` breaks:** in testing, `TS_SSH_DISABLE_FORWARDING=1` disables **all** forwarding, TCP included. That covers `ssh -L/-R/-D`, socket forwards and VS Code Remote-SSH over Tailscale SSH. Shells, remote commands, `scp`/`sftp` and Ansible keep working.

## If you rely on SSH tunnels

Use one of these instead of leaving forwarding on fleet-wide:

1. **Don't tunnel at all.** Most `ssh -L` use is for something bound to localhost. Publish it tailnet-only instead, e.g. `tailscale serve --bg --https=8443 http://127.0.0.1:12000`, or a Tailscale operator Ingress in Kubernetes. The tailnet policy then decides who can reach it, and no SSH is involved.
2. **Tunnel over OpenSSH instead.** Tailworm is specific to Tailscale's SSH server. OpenSSH's `sshd` handles forwarding as the logged-in user. Run `sshd` on another port bound to the tailnet IP, with key auth, and grant that port only to your admin device in the policy.
3. **Leave forwarding on for that one node** (`--set forwarding=on --only n1`) and keep its SSH policy tight: no non-root grants and no agent sources. Re-probe after every Tailscale upgrade.

## Check catalog

**From the Tailworm report**

| ID | Check | Finding |
|---|---|---|
| TW03 | Mitigation present **in the running tailscaled**, per instance (host, each LXC, each container) | F1–F3, F5 |
| TW03P | Active probe: unix `-L` to `tailscaled.sock` and `docker.sock` (read-only GETs), allowlist mapping (`/tmp`, `/root`), unix `-R` bind at a throwaway `/tmp` path, TCP `-L`. Verdicts: `UNIX_DIRECT_ROOT_SOCKET` (CRIT), `UNIX_FORWARDING_ALLOWLISTED` (HIGH), `forwarding_blocked` (OK) | F1, F2, F3 |
| TW04 | `tailscaled` **listening** on a socket path that isn't its own (live IOC) | F2 |
| TW10 | Serve to LocalAPI (CRIT); serve to unix sockets; Funnel actually on | F7, F8, F9 |
| TW12 | `TS_SERVE_ALLOW_ALL_INTERFACES` set (process env, container env, k8s) | F10 |
| TW16 | Node advertises an app connector | F4 |
| TW01 | Version vs floor (`TW_FLOOR`) and the eventual fix (`TW_PATCHED`) | all |
| PA01, PA12 | Policy: non-root SSH grants that are root-equivalent; sshTests that pass but no longer hold | F1–F3 |
| PA10 | Policy: app connectors | F4 |

**Beyond the report**

| ID | Check |
|---|---|
| TW05 | Root sockets with an unexpected listener; a daemon running with its socket **gone** (what F2 leaves behind) |
| TW06 | Which root sockets forwarding exposes on each node |
| TW07/TW08 | Root sockets in directories non-root can modify; `fs.protected_symlinks` |
| TW09 | SSH-target users that are **already** root (docker group, NOPASSWD sudo), cross-referenced with the policy |
| TW11 | Serve backends also bound to `0.0.0.0` (identity-header bypass) |
| TW13/14/15 | Operator user, web client, Taildrive shares (LocalAPI persistence surfaces) |
| TW17/18 | Subnet routers and exit nodes (pivot points); auto-update off |
| TW19/TW20 | Tailnet Lock off; plaintext node identity on disk |
| TW21 | Stray `tskey-auth/client/api` material in files, shell history, container config |
| TW22 | Tailscale **containers** running their own SSH server (worse if they mount `docker.sock`) |
| TW23/24 | Recent privileged or `/`-mounting containers; recent container create/exec events |
| TW25 | Docker/Portainer/Arcane/kubelet/Proxmox APIs reachable over the tailnet |
| TW26 | Log evidence that something uses forwarding (know what you'll break) |
| TW90 | SSH servers in your netmap that nobody audited |
| PA02–PA11 | Policy: root from user devices, recording gaps, acceptEnv, any-port mesh grants, Taildrive rw, tag-owns-tag auto-approval, web client `canEdit ssh` |
| AP01–AP08 | API: versions, **recent enrollments**, pending devices, approval/flow-log settings, reusable pre-auth keys, **untagged Linux servers** |

## What the public analysis misses

1. **The allowlist is the attack surface, not a defense.** Tailscale SSH refuses unix forwards outside an allowlist (`… is not in an allowed directory`) but dials paths inside it (`/tmp`, `~`). A probe that only targets `docker.sock` sees a refusal and wrongly concludes forwarding is off. TW03P maps the allowlist explicitly.
2. **The fix must be live, not just configured.** An env file without a restart does nothing. TW03 reads the running process's environment, and the probe checks behavior.
3. **Every containerized `tailscaled` is its own SSH server.** A sidecar with `TS_EXTRA_ARGS=--ssh` isn't covered by the host's mitigation, and if it mounts `docker.sock`, an SSH grant to that sidecar is root on the host. The netmap's `sshHostKeys` field lists every SSH server, including forgotten ones (TW90).
4. **"Non-root" grants were often never non-root.** Default `ubuntu`, `dietpi` and `pi` users have passwordless sudo; `ansible`/`deploy` users usually do too, or sit in `docker`. TW09 shows which.
5. **Recording is likely not a control here.** tsrecorder captures the terminal stream; forwarded channels are separate. With `enforceRecorder: false`, sessions also proceed when the recorder is down.
6. **F2 leaves a durable artifact.** After `ssh -R` unlinks and rebinds a daemon's socket, the daemon is left socketless (TW05). While the session is live, TW04 sees `tailscaled` as the listener.
7. **LocalAPI access is persistence.** Root on `tailscaled.sock` can add a Taildrive share of `/`, arm Serve or Funnel, advertise routes, or turn on the web client. Inventory these after mitigating (TW10/13/14/15/17).
8. **Node identity theft is quieter than rogue enrollment.** The state file holds the node's private key. Root, or a vzdump/restic/Syncthing copy of it, can clone the node, and no new device appears. Tailnet Lock blocks rogue *enrollment*, not this.
9. **Stray auth keys make the race unnecessary.** Compose `.env` files, `docker inspect` output, setup scripts and shell history (TW21, AP06).
10. **The Funnel attribute isn't a boundary (F9).** Inventory actual `AllowFunnel` state.
11. **Serve identity headers are only as good as the backend's bind address** (TW11).
12. **The operator user is a privilege boundary** (TW13).
13. **The "already in the tailnet" premise is where most real risk lives.** Any-port mesh grants reach Docker through Arcane/Portainer agents, kubelet or the Proxmox API with no Tailscale bug at all (TW25, PA05).
14. **Applying the fix over Tailscale SSH cuts the branch you're sitting on.** Hence the detached restart and re-verification. Keep a non-Tailscale path to every node.
15. **Vendor and static builds lag**, and firmware updates overwrite init-script edits (TW01, TW18, AP01).
16. **Untagged servers carry a person's identity** for ACLs, SSH and tsidp (AP08).

## Manual mitigation (non-systemd)

- **OpenWrt / GL-iNet:** in `/etc/init.d/tailscale`, inside `start_service()` after `procd_open_instance`, add `procd_set_param env TS_SSH_DISABLE_FORWARDING=1`, then restart. Re-check after firmware updates. Or skip Tailscale SSH on routers: `--set ssh=off`.
- **Docker sidecars:** add `TS_SSH_DISABLE_FORWARDING=1` under `environment:` and recreate, or drop `--ssh` from `TS_EXTRA_ARGS`.
- **Kubernetes operator:** set it in the ProxyClass `tailscaleContainer.env` (and make sure `TS_SERVE_ALLOW_ALL_INTERFACES` isn't set).
- **Proxmox:** the host and each LXC run their own `tailscaled`; mitigate each one that's a tailnet node.

## When Tailscale ships the fix

```bash
TW_PATCHED=<version> ./fleet.sh --probe     # nodes below that version become HIGH (TW01)
```

Keep forwarding off where you don't use it, even after patching. If nothing tunnels through a node, it doesn't need the capability. Turn it back on per node with `--set forwarding=on`.

## Knobs

`TW_FLOOR` (default 1.98.9), `TW_PATCHED`, `TW_RECENT_DAYS` (14), `TW_TRY_USERS` ("root ubuntu dietpi pi"), `TW_TIMEOUT` (600s per node), `TS_CLI`, `TW_TRANSPORT`. For the collector: `TW_USERS`, `TW_SECRET_PATHS` (add your stack dirs), `TW_SKIP_SECRETS=1`, `TW_K8S=1`. For the API audit: `TS_API_KEY`, or `TS_OAUTH_CLIENT_ID` + `TS_OAUTH_CLIENT_SECRET` (scopes `devices:core:read`, `auth_keys:read`, `feature_settings:read`).

## Limits

It can't log into SSH servers it has no grant for (TW90). It doesn't look inside tsnet apps (tsidp, tsrecorder, golink). It doesn't attempt the F3 race. Secret scanning is bounded to `TW_SECRET_PATHS`. Docker events cover 72h and the journal 7 days. It's a point-in-time audit, not monitoring.

## License

MIT
