"""Exercise the installed CLI against both SNMP agents."""

import os
import re
import selectors
import signal
import socket
import subprocess
import time
import unittest

EXPECTED_SECTIONS = [
    "System information", "User accounts", "Network information",
    "Network interfaces", "Network IP", "Routing information",
    "TCP connections and listening ports", "Listening UDP ports",
    "Network services", "Processes", "Storage information",
    "File system information", "Device information", "Software components",
    "IIS server information", "Share", "HP LaserJet printer enumeration",
]


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.addresses = {
            name: socket.gethostbyname(name) for name in ("net-snmp", "fixture")
        }
        for name, community in (("net-snmp", "lab-ro"), ("fixture", "lab-full")):
            deadline = time.monotonic() + 20
            while True:
                result = cls.cli(name, "2c", community, "-d")
                if result.returncode == 0:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"{name} never became ready: {result.stderr}")

    @classmethod
    def cli(cls, agent, version, community, *flags, retries=0):
        return subprocess.run(
            ["snmpcheck", "-p", "1161", "-t", "0.3", "-r", str(retries),
             "-v", version, "-c", community, *flags, cls.addresses[agent]],
            capture_output=True, text=True, timeout=20,
        )

    def assert_report(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[*] System information:", result.stdout)

    def section(self, report, title):
        match = re.search(rf"(?ms)^\[\*\] {re.escape(title)}:\n(.*?)(?=^\[\*\] |\Z)", report)
        self.assertIsNotNone(match, f"Missing {title} in report")
        return match[1]

    def test_all_sections_and_value_types(self):
        for version in ("1", "2c"):
            with self.subTest(version=version):
                result = self.cli("fixture", version, "lab-full")
                self.assert_report(result)
                self.assertEqual(result.stderr, "")
                self.assertEqual(
                    re.findall(r"^\[\*\] (.*):$", result.stdout, re.M), EXPECTED_SECTIONS
                )
                expected = {
                    "Hostname": "fixture-host",
                    "System date": "2026-1-2 03:04:05.06",
                    "Uptime system": "12345",
                    "Uptime snmp": "6789",
                    "Domain": "FIXTURE",
                    "IP forwarding enabled": "yes",
                    "Default TTL": "64",
                    "TCP segments retrans": "0",
                    "Mac Address": "02:00:00:00:00:01",
                    "Speed": "1000 Mbps",
                    "Filesystem type": "Fixed Disk",
                    "Memory size": "2.00 MB",
                    "Memory used": "1.00 MB",
                    "Remote mount point": "-",
                    "Type": "NFS",
                    "TotalBytesSentLowWord": "2",
                    "NotFoundErrors": "22",
                    "Filename": "fixture-job.pdf15",
                    "Client": "fixture-client",
                    "Application command": "fixture-command",
                }
                for field, value in expected.items():
                    self.assertRegex(result.stdout, rf"(?m)^  {re.escape(field)} *: {re.escape(value)}$")
                self.assertRegex(result.stdout, r"(?m)^  MTU *: -$")
                for cell in ("fixture-user", "fixture-sparse", "192.0.2.1", "255.255.255.0",
                             "listen", "161", "Fixture Spooler", "fixture-process",
                             "fixture-cpu", "fixture-package", "fixture-share"):
                    self.assertIn(cell, result.stdout)

    def test_real_agent_write_allowed_and_denied(self):
        for version in ("1", "2c"):
            before = self.cli("net-snmp", version, "lab-ro", "-d")
            self.assert_report(before)
            hostname = re.search(r"(?m)^  Hostname *: .+$", before.stdout)[0]
            for community, permission in (("lab-ro", "not permitted"), ("lab-rw", "permitted")):
                with self.subTest(version=version, community=community):
                    result = self.cli("net-snmp", version, community, "-w", "-d")
                    self.assert_report(result)
                    self.assertIn("snmpcheck Net-SNMP Linux lab", result.stdout)
                    self.assertIn("[*] Network interfaces:", result.stdout)
                    self.assertIn(f"[*] Write access {permission}!", result.stdout)
                    self.assertNotIn("[*] TCP connections and listening ports:", result.stdout)
                    self.assertIn(hostname, result.stdout)
                    self.assertNotIn(community, result.stdout + result.stderr)
            after = self.cli("net-snmp", version, "lab-ro", "-d")
            self.assert_report(after)
            self.assertIn(hostname, after.stdout)

    def test_real_linux_inventory(self):
        for version in ("1", "2c"):
            with self.subTest(version=version):
                result = self.cli("net-snmp", version, "lab-ro")
                self.assert_report(result)
                report = result.stdout
                self.assertRegex(report, r"(?m)^  Location *: Docker$")
                self.assertRegex(report, r"(?m)^  Contact *: Lab$")
                self.assertIn(self.addresses["net-snmp"], self.section(report, "Network IP"))
                self.assertIn("softwareLoopback", self.section(report, "Network interfaces"))
                tcp = self.section(report, "TCP connections and listening ports")
                self.assertRegex(tcp, r"(?m)^ +0\.0\.0\.0 +8443 +0\.0\.0\.0 +0 +listen *$")
                udp = self.section(report, "Listening UDP ports")
                self.assertRegex(udp, r"(?m)^ +0\.0\.0\.0 +8162 *$")
                self.assertIn("linux_agent.py", self.section(report, "Processes"))
                storage = self.section(report, "Storage information")
                self.assertRegex(storage, r"(?m)^  Description *: /lab-storage$")
                volume = re.search(r"(?ms)^  Description *: /lab-storage\n(.*?)(?:\n\n|\Z)", storage)
                self.assertIsNotNone(volume)
                self.assertRegex(volume[1], r"(?m)^  Memory size *: 16\.00 MB$")

    def test_cli_defaults_and_long_options(self):
        address = self.addresses["net-snmp"]
        default = subprocess.run(
            ["snmpcheck", address], capture_output=True, text=True, timeout=10,
        )
        self.assert_report(default)
        self.assertIn(f"{address}:161 using SNMPv1", default.stdout)
        result = subprocess.run(
            ["snmpcheck", "--port", "1161", "--timeout", "0.3", "--retries", "0",
             "--version", "2c", "--community", "lab-rw", "--write", "--disable_tcp", address],
            capture_output=True, text=True, timeout=10,
        )
        self.assert_report(result)
        self.assertIn(f"{address}:1161 using SNMPv2c", result.stdout)
        self.assertIn("[*] Write access permitted!", result.stdout)
        self.assertNotIn("[*] TCP connections and listening ports:", result.stdout)

    def test_tcp_option_on_fixture_with_known_tcp_row(self):
        result = self.cli("fixture", "2c", "lab-full", "--disable_tcp")
        self.assert_report(result)
        self.assertNotIn("[*] TCP connections and listening ports:", result.stdout)
        self.assertIn("[*] Listening UDP ports:", result.stdout)
        self.assertNotIn("Write access", result.stdout)

    def test_partial_report_on_protocol_errors(self):
        for version in ("1", "2c"):
            with self.subTest(version=version):
                result = self.cli("fixture", version, "lab-partial")
                self.assert_report(result)
                self.assertIn("Skipping Default TTL", result.stderr)
                self.assertIn("non-increasing OID", result.stderr)
                self.assertNotIn("Default TTL", result.stdout)
                self.assertRegex(result.stdout, r"(?m)^  Contact *: -$")
                self.assertIn("fixture-eth", result.stdout)
                self.assertNotIn("fixture-sparse", result.stdout)
                self.assertIn("fixture-package", result.stdout)

    def test_timeout_and_retry(self):
        for version in ("1", "2c"):
            with self.subTest(version=version):
                for community in ("unknown", "lab-retry"):
                    result = self.cli("fixture", version, community)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("SNMP request timeout", result.stderr)
                self.assert_report(self.cli("fixture", version, "lab-retry", retries=1))

    def test_unrecoverable_agent_errors(self):
        cases = (
            ("lab-get-error", "SNMP GET failed (status 5"),
            ("lab-walk-error", "SNMP GETNEXT failed (status 5"),
            ("lab-wrong-oid", "Unexpected SNMP GET response OIDs"),
            ("lab-short-walk", "Unexpected number of SNMP GETNEXT bindings"),
        )
        for version in ("1", "2c"):
            for community, error in cases:
                with self.subTest(version=version, community=community):
                    result = self.cli("fixture", version, community)
                    self.assertEqual(result.returncode, 1)
                    self.assertIn(error, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertNotIn("[*] System information:", result.stdout)

    def test_write_without_hostname(self):
        for version in ("1", "2c"):
            with self.subTest(version=version):
                result = self.cli("fixture", version, "lab-no-name", "-w")
                self.assert_report(result)
                self.assertRegex(result.stdout, r"(?m)^  Hostname *: -$")
                self.assertIn("[*] Write access not permitted!", result.stdout)

    def test_interrupt_waiting_for_reply(self):
        with subprocess.Popen(
            ["snmpcheck", "-p", "1161", "-t", "20", "-r", "0",
             "-c", "unknown", self.addresses["fixture"]],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        ) as process:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(timeout=5), "CLI did not start")
                time.sleep(0.1)
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 130, (stdout, stderr))
                self.assertNotIn(b"Traceback", stderr)
            finally:
                if process.poll() is None:
                    process.kill()

    def test_cli_validation_and_metadata(self):
        target = self.addresses["fixture"]
        invalid = [
            [], ["::1"], ["localhost"], ["999.0.0.1"], [target, target],
            ["--community"], ["--unknown-option", target],
        ]
        invalid += [
            [option, value, target]
            for option, values in (
                ("--port", ("0", "65536", "text")),
                ("--retries", ("-1", "11")),
                ("--timeout", ("0", "-1", "nan", "inf")),
                ("--version", ("3",)),
            )
            for value in values
        ]
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    ["snmpcheck", *arguments], capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("error:", result.stderr)
        for option, expected in (("-h", "--disable_tcp"), ("--help", "--disable_tcp"),
                                 ("-i", "v1.9.1"), ("--info", "v1.9.1")):
            result = subprocess.run(["snmpcheck", option], capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertIn(expected, result.stdout)
