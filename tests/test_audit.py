"""Unit tests for tailworm_audit.py against synthetic fixtures.

Run: python3 -m unittest discover -s tests -v
"""
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import tailworm_audit as ta  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
RECENT = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


def stage(src: Path) -> Path:
    """Copy a fixture dir to tmp, substituting {RECENT} with a timestamp from yesterday."""
    d = Path(tempfile.mkdtemp())
    for f in src.iterdir():
        (d / f.name).write_text(f.read_text().replace("{RECENT}", RECENT))
    return d


def ids(findings, sev=None):
    return {f.id for f in findings if sev is None or f.sev == sev}


def by(findings, fid):
    return [f for f in findings if f.id == fid]


class HelpersTest(unittest.TestCase):
    def test_vtuple(self):
        self.assertEqual(ta.vtuple("1.104.2-t123abc"), (1, 104, 2))
        self.assertLess(ta.vtuple("1.98.8"), ta.vtuple("1.98.9"))
        self.assertIsNone(ta.vtuple("unknown"))

    def test_hujson(self):
        obj = ta.load_hujson('{\n // c\n "a": "x // not a comment", /* b */ "b": [1, 2,],\n}')
        self.assertEqual(obj, {"a": "x // not a comment", "b": [1, 2]})

    def test_listeners_ss_and_netstat(self):
        ss = 'u_str LISTEN 0 4096 /run/docker.sock 23456 * 0 users:(("dockerd",pid=700,fd=4))\n' \
             'u_str LISTEN 0 4096 /run/user/1000/bus 1 * 0 users:(("dbus",pid=9,fd=1))'
        ls = dict(ta.parse_listeners(ss))
        self.assertEqual(ls["/run/docker.sock"], ["dockerd"])
        self.assertEqual(ls["/run/user/1000/bus"], ["dbus"])      # not "bus" from a path fragment
        ns = "unix  2 [ ACC ] STREAM LISTENING 4410 2201/tailscaled /var/run/tailscale/tailscaled.sock"
        self.assertEqual(dict(ta.parse_listeners(ns))["/var/run/tailscale/tailscaled.sock"], ["tailscaled"])
        tcp = "tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 1900/nginx"
        self.assertEqual(ta.parse_listeners(tcp), [("0.0.0.0:80", ["nginx"])])

    def test_bind_class(self):
        self.assertEqual(ta.bind_class("0.0.0.0:2375"), "all")
        self.assertEqual(ta.bind_class("[::]:22"), "all")
        self.assertEqual(ta.bind_class("*:8006"), "all")
        self.assertEqual(ta.bind_class("127.0.0.1:8080"), "loopback")
        self.assertEqual(ta.bind_class("100.64.0.3:5252"), "tailnet")


class FleetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = stage(FIX / "fleet")
        cls.policy = ta.load_hujson((FIX / "policy.hujson").read_text())
        cls.hosts = {}
        for f in sorted(cls.dir.glob("*.txt")):
            h = ta.load_host(f)
            ta.analyze_host(h, cls.policy)
            cls.hosts[h.name] = h
        import json
        cls.fleet = ta.fleet_checks(list(cls.hosts.values()), json.loads((FIX / "status.json").read_text()))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def test_mitigated_host_is_clean(self):
        h = self.hosts["mitigated-01"]
        self.assertIn("TW03", ids(h.findings, "OK"))
        self.assertFalse(ids(h.findings, "CRIT") | ids(h.findings, "HIGH"), [f.title for f in h.findings])
        self.assertNotIn("TW07", ids(h.findings))  # root-owned 0755 dirs are fine
        self.assertNotIn("TW05", ids(h.findings))  # dockerd owns docker.sock

    def test_staged_not_live(self):
        h = self.hosts["staged-02"]
        tw03 = by(h.findings, "TW03")
        self.assertEqual(tw03[0].sev, "WARN")
        self.assertIn("NOT live", tw03[0].title)

    def test_router(self):
        h = self.hosts["router-01"]
        self.assertEqual(by(h.findings, "TW01")[0].sev, "WARN")   # below floor
        tw03 = by(h.findings, "TW03")[0]
        self.assertEqual(tw03.sev, "INFO")                        # SSH on, no mitigation, but root-only per policy
        self.assertIn("root-only", tw03.title)
        self.assertEqual(by(h.findings, "TW20")[0].sev, "WARN")   # state file 644
        self.assertEqual(by(h.findings, "TW21")[0].sev, "HIGH")   # authkey in up.sh
        self.assertIn("TW08", ids(h.findings))                    # protected_symlinks unknown/empty -> flagged
        self.assertIn("TW17", ids(h.findings))                    # exit node + subnet router
        self.assertNotIn("TW04", ids(h.findings))                 # netstat format: own socket recognized

    def test_docker_host(self):
        h = self.hosts["dockerhost-01"]
        self.assertEqual(by(h.findings, "TW03")[0].sev, "OK")     # host SSH is off...
        tw22 = by(h.findings, "TW22")
        self.assertEqual(tw22[0].sev, "CRIT")                     # ...but the sidecar runs SSH + docker.sock
        self.assertIn("TW10", ids(h.findings, "CRIT"))            # serve -> tailscaled.sock (F7)
        self.assertIn("TW11", ids(h.findings))                    # backend :3000 on 0.0.0.0
        self.assertIn("TW23", ids(h.findings))                    # recent privileged container with /
        self.assertIn("TW25", ids(h.findings))                    # arcane agent on 0.0.0.0
        self.assertTrue(any("socket is missing" in f.title for f in by(h.findings, "TW05")))
        self.assertTrue(any(f.sev == "WARN" and "auth key" in f.title for f in by(h.findings, "TW21")))
        self.assertIn("TW26", ids(h.findings))
        inst = h.facts["instances"]
        self.assertEqual([i["where"] for i in inst], ["host", "container 3f9a1c2b4d5e"])

    def test_proxmox_with_lxc(self):
        h = self.hosts["pve-01"]
        self.assertEqual(by(h.findings, "TW03")[0].sev, "HIGH")
        self.assertTrue(any("LXC 105" in f.title for f in by(h.findings, "TW03")))
        self.assertIn("TW25", ids(h.findings))                    # Proxmox UI on *:8006
        self.assertIn("TW09", ids(h.findings))                    # pi has NOPASSWD sudo, policy reaches it
        self.assertIn("TW18", ids(h.findings))

    def test_fleet_unaudited_ssh_servers(self):
        tw90 = by(self.fleet, "TW90")
        self.assertEqual(len(tw90), 1)
        self.assertIn("ts-sidecar", tw90[0].detail)
        self.assertNotIn("shared-laptop", tw90[0].detail)            # shared-in nodes aren't ours to audit
        self.assertNotIn("phone", tw90[0].detail)                 # no SSH host keys
        self.assertIn("TW19", ids(self.fleet))                    # lock off somewhere
        self.assertIn("TW20", ids(self.fleet))                    # plaintext state

    def test_markdown_renders(self):
        md = ta.render_md(list(self.hosts.values()), self.fleet)
        self.assertIn("## Remediation plan", md)
        self.assertIn("--set forwarding=off --only pve-01", md)
        self.assertIn("staged-02", md)
        self.assertIn("root-only access", md)
        self.assertTrue(md.split("## Remediation plan")[1].lstrip().startswith("1."))


class RootOnlyTest(unittest.TestCase):
    def test_router_without_policy_stays_high(self):
        d = stage(FIX / "fleet")
        try:
            h = ta.load_host(d / "router-01.txt")
            ta.analyze_host(h, None)
            self.assertEqual(by(h.findings, "TW03")[0].sev, "HIGH")
        finally:
            shutil.rmtree(d)

    def test_nonroot_user_present_blocks_downgrade(self):
        d = stage(FIX / "fleet")
        try:
            txt = (d / "router-01.txt").read_text().replace(
                "=====TW:BEGIN:users=====\n", "=====TW:BEGIN:users=====\nuser=pi|shell=/bin/sh|id=uid=1000(pi) gid=1000(pi) groups=1000(pi)|nopasswd=0|sudo_all=0\n")
            (d / "router-01.txt").write_text(txt)
            h = ta.load_host(d / "router-01.txt")
            ta.analyze_host(h, ta.load_hujson((FIX / "policy.hujson").read_text()))
            # synthetic policy's admin rule allows root only, so 'pi' isn't reachable -> still root-only
            self.assertEqual(by(h.findings, "TW03")[0].sev, "INFO")
            pol = ta.load_hujson((FIX / "policy.hujson").read_text())
            pol["ssh"][0]["users"] = ["root", "pi"]
            h = ta.load_host(d / "router-01.txt")
            ta.analyze_host(h, pol)
            self.assertEqual(by(h.findings, "TW03")[0].sev, "HIGH")   # now a non-root user is reachable
        finally:
            shutil.rmtree(d)


class InstanceTest(unittest.TestCase):
    def _run(self, procs):
        d = Path(tempfile.mkdtemp())
        try:
            txt = (FIX / "fleet" / "mitigated-01.txt").read_text()
            a, b = txt.index("=====TW:BEGIN:ts_procs=====\n") + len("=====TW:BEGIN:ts_procs=====\n"), txt.index("=====TW:END:ts_procs=====")
            (d / "x.txt").write_text(txt[:a] + procs + txt[b:])
            h = ta.load_host(d / "x.txt")
            ta.analyze_host(h)
            return [(f.sev, f.title) for f in h.findings if f.id == "TW03"]
        finally:
            shutil.rmtree(d)

    MAIN = "pid=812|cgroup=/system.slice/tailscaled.service|samens=1|env_readable=1|socket=/var/run/tailscale/tailscaled.sock|ssh=true|env=TS_SSH_DISABLE_FORWARDING=1 |cmd=/usr/sbin/tailscaled\n"

    def test_second_instance_without_ssh_is_info(self):
        got = self._run(self.MAIN + "pid=900|cgroup=/system.slice/tsidp.service|samens=1|env_readable=1|socket=/run/tsidp/tailscaled.sock|ssh=false|env=|cmd=/usr/sbin/tailscaled --socket=/run/tsidp/tailscaled.sock\n")
        self.assertIn(("OK", "Forwarding disabled in the running tailscaled (TS_SSH_DISABLE_FORWARDING=1)"), got)
        self.assertTrue(any(sev == "INFO" and "second instance" in t and "without Tailscale SSH" in t for sev, t in got))
        self.assertFalse(any("NOT live" in t for _, t in got))

    def test_second_instance_with_ssh_is_high(self):
        got = self._run(self.MAIN + "pid=900|cgroup=/system.slice/x.service|samens=1|env_readable=1|socket=/run/x.sock|ssh=true|env=|cmd=/usr/sbin/tailscaled --socket=/run/x.sock\n")
        self.assertTrue(any(sev == "HIGH" and "second instance" in t for sev, t in got))


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.F = ta.audit_policy(ta.load_hujson((FIX / "policy.hujson").read_text()))

    def test_ids(self):
        got = ids(self.F)
        for want in ("PA01", "PA02", "PA03", "PA04", "PA05", "PA06", "PA07", "PA08", "PA09", "PA10", "PA11", "PA12"):
            self.assertIn(want, got)

    def test_nonroot_rules(self):
        msgs = " ".join(f.detail for f in by(self.F, "PA01"))
        self.assertIn("scout", msgs)
        self.assertIn("deploy", msgs)

    def test_admin_any_grant_not_flagged_as_mesh(self):
        self.assertTrue(all("group:admins" not in f.detail.split("dst=")[0] for f in by(self.F, "PA05")))

    def test_acceptenv_risky(self):
        self.assertEqual(by(self.F, "PA04")[0].sev, "WARN")


class ApiTest(unittest.TestCase):
    def test_offline(self):
        d = stage(FIX / "api")
        try:
            F = ta.audit_api(from_dir=str(d))
        finally:
            shutil.rmtree(d)
        got = ids(F)
        for want in ("AP01", "AP02", "AP03", "AP05", "AP06", "AP08"):
            self.assertIn(want, got)
        ap08 = by(F, "AP08")[0].detail
        self.assertIn("dockerbox", ap08)
        self.assertNotIn("shared-in", ap08)
        self.assertEqual(len(by(F, "AP06")), 1)                    # one-shot key not flagged
        self.assertIn("new-thing", by(F, "AP02")[0].detail)


class ProbeOverrideTest(unittest.TestCase):
    def _run(self, probe):
        d = Path(tempfile.mkdtemp())
        try:
            txt = (FIX / "fleet" / "staged-02.txt").read_text().replace("Environment=TS_SSH_DISABLE_FORWARDING=1", "Environment=")
            (d / "z.txt").write_text(txt)
            (d / "z.probe").write_text(probe)
            h = ta.load_host(d / "z.txt")
            ta.analyze_host(h)
            return {f.id: f.sev for f in h.findings if f.id.startswith("TW03")}
        finally:
            shutil.rmtree(d)

    def test_blocked_downgrades_config_high(self):
        got = self._run("probe=forwarding_blocked tailscaled.sock: disabled; docker.sock: disabled; /tmp: disabled; /root: disabled; -R /tmp: refused; tcp: disabled;")
        self.assertEqual(got, {"TW03": "INFO", "TW03P": "OK"})

    def test_allowlisted_stays_high(self):
        got = self._run("probe=UNIX_FORWARDING_ALLOWLISTED tailscaled.sock: allowlist; /tmp: reached;")
        self.assertEqual(got, {"TW03": "HIGH", "TW03P": "HIGH"})

    def test_direct_root_socket_is_crit(self):
        got = self._run("probe=UNIX_DIRECT_ROOT_SOCKET docker.sock: reached (http=200);")
        self.assertEqual(got, {"TW03": "HIGH", "TW03P": "CRIT"})

    def test_inconclusive_never_downgrades(self):
        got = self._run("probe=inconclusive tailscaled.sock: inconclusive;")
        self.assertEqual(got, {"TW03": "HIGH", "TW03P": "WARN"})


if __name__ == "__main__":
    unittest.main()
