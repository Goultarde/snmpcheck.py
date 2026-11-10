import io
import unittest
from contextlib import redirect_stderr
from types import SimpleNamespace
from unittest.mock import AsyncMock

from pyasn1.type import univ
from pysnmp.proto import rfc1155, rfc1902, rfc1905

from snmpcheck import IIS, LASERJET, WINDOWS, SnmpClient, collect, decode, oid_parts, system_date


class SnmpClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_v1_oid_does_not_hide_other_fields(self):
        client = SnmpClient(None, None, "test", "1")
        hostname = "1.3.6.1.2.1.1.5.0"
        missing = "1.3.6.1.2.1.25.1.2.0"
        client.request = AsyncMock(side_effect=[
            (2, 2, ()),
            (0, 0, [(oid_parts(hostname), univ.OctetString("router"))]),
        ])
        self.assertEqual(
            await client.read({"Hostname": hostname, "System date": missing}),
            {"Hostname": b"router"},
        )

    async def test_walk_aligns_sparse_columns_and_stops_at_subtree_boundary(self):
        client = SnmpClient(None, None, "test", "2c")
        prefix = "1.3.6.1.2.1.2.2.1"
        first, second = (oid_parts(f"{prefix}.{i}") for i in (1, 2))
        client.request = AsyncMock(side_effect=[
            (0, 0, [(first + (1,), rfc1902.Integer(1)),
                    (second + (2,), rfc1902.OctetString("eth0"))]),
            (0, 0, [(first + (2,), rfc1902.Integer(2)),
                    (second + (2,), rfc1902.OctetString("eth0"))]),
            (0, 0, [(second + (2,), rfc1902.OctetString("eth0")),
                    (second + (2,), rfc1905.endOfMibView)]),
        ])
        self.assertEqual(
            [row async for row in client.rows(prefix, 1, 2)],
            [[1, None], [2, b"eth0"]],
        )

    async def test_indexed_gen_err_only_skips_the_failed_field(self):
        client = SnmpClient(None, None, "test", "2c")
        forwarding = "1.3.6.1.2.1.4.1.0"
        ttl = "1.3.6.1.2.1.4.2.0"
        client.request = AsyncMock(side_effect=[
            (5, 2, ()),
            (0, 0, [(oid_parts(forwarding), rfc1902.Integer(1))]),
        ])
        with redirect_stderr(io.StringIO()) as warnings:
            values = await client.read({"IP forwarding": forwarding, "Default TTL": ttl})
        self.assertEqual(values, {"IP forwarding": 1})
        self.assertIn("Skipping Default TTL", warnings.getvalue())

    async def test_walk_keeps_rows_before_non_increasing_oid(self):
        client = SnmpClient(None, None, "test", "2c")
        prefix = "1.3.6.1.2.1.2.2.1"
        row = (0, 0, [(oid_parts(f"{prefix}.1.1"), rfc1902.Integer(1))])
        client.request = AsyncMock(side_effect=[row, row])
        with redirect_stderr(io.StringIO()) as warnings:
            rows = [item async for item in client.rows(prefix, 1)]
        self.assertEqual(rows, [[1]])
        self.assertIn(f"Stopping table {prefix}: non-increasing OID", warnings.getvalue())

    def test_decodes_v1_types(self):
        self.assertEqual(decode(univ.Integer(6)), 6)
        self.assertEqual(decode(rfc1155.Gauge(1000)), 1000)
        self.assertEqual(decode(rfc1155.IpAddress("192.0.2.1")), "192.0.2.1")
        self.assertEqual(system_date(decode(univ.OctetString(bytes(
            (7, 234, 11, 11, 12, 13, 14, 5)
        )))), "2026-11-11 12:13:14.05")
        self.assertIsNone(decode(rfc1905.noSuchInstance))


class ReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_windows_iis_and_laserjet_sections(self):
        async def read(fields):
            values = {
                "Description": b"Windows",
                "Domain": b"EXAMPLE",
                "TotalBytesSentLowWord": 0,
            }
            if "TotalBytesSentLowWord" in fields:
                self.assertEqual(fields["TotalBytesSentLowWord"], f"{IIS}.2.0")
                self.assertEqual(fields["NotFoundErrors"], f"{IIS}.22.0")
            return {label: values[label] for label in fields if label in values}

        async def rows(prefix, *columns):
            for row in {
                f"{WINDOWS}.1.2.25.1": [[b"admin"]],
                f"{WINDOWS}.1.2.3.1": [[b"Print Spooler"]],
                f"{WINDOWS}.1.2.27.1": [[b"print", b"C:\\print", b"Printer queue"]],
                LASERJET: [
                    [b"report", b".pdf", b"JobAcct1=admin", b"JobAcct2=host",
                     None, b"JobAcct4=now", b"JobAcct6=app", None],
                    [b"incomplete", None, None, None, None, None, None, None],
                ],
            }.get(prefix, []):
                self.assertEqual(len(columns), len(row))
                yield row

        report = await collect(
            SimpleNamespace(read=read, rows=rows),
            SimpleNamespace(target="192.0.2.1", disable_tcp=True, write=False),
        )
        self.assertEqual(report["User accounts"], [[b"admin"]])
        self.assertEqual(report["Network services"][1], (0, b"Print Spooler"))
        self.assertEqual(report["Share"][0][" Name"], b"print")
        self.assertEqual(report["IIS server information"], {"TotalBytesSentLowWord": 0})
        jobs = report["HP LaserJet printer enumeration"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["Filename"], "report.pdf10")
        self.assertEqual(jobs[0]["Username"], "admin")


if __name__ == "__main__":
    unittest.main()
