#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Based on snmpcheck by Matteo Cantoni (copyright 2005-2015).

import argparse
import asyncio
import ipaddress
import math
import re
import sys

from pyasn1.type import univ
from pysnmp.hlapi.v1arch.asyncio import (
    CommunityData,
    SnmpDispatcher,
    UdpTransportTarget,
    get_cmd,
    next_cmd,
    set_cmd,
)
from pysnmp.proto import errind, rfc1155, rfc1902
from pysnmp.smi.error import SmiError

BANNER = (
    "snmpcheck v1.9.1 - SNMP enumerator\n"
    "Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)"
)
MIB = "1.3.6.1.2.1"
WINDOWS = "1.3.6.1.4.1.77.1"
IIS = "1.3.6.1.4.1.311.1.7.3.1"
LASERJET = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6"
HOSTNAME = f"{MIB}.1.5.0"

FIELDS = (
    "Host IP address", "Hostname", "Description", "Contact", "Location",
    "Uptime snmp", "Uptime system", "System date", "Domain", "User accounts",
    "Network information", "Network interfaces", "Network IP",
    "Routing information", "TCP connections and listening ports",
    "Listening UDP ports", "Network services", "Processes",
    "Storage information", "File system information", "Device information",
    "Software components", "IIS server information", "Share",
    "HP LaserJet printer enumeration",
)
INTERFACE_TYPES = (
    "other", "regular1822", "hdh1822", "ddn-x25", "rfc877-x25",
    "ethernet-csmacd", "iso88023-csmacd", "iso88024-tokenBus",
    "iso88025-tokenRing", "iso88026-man", "starLan", "proteon-10Mbit",
    "proteon-80Mbit", "hyperchannel", "fddi", "lapb", "sdlc", "ds1", "e1",
    "basicISDN", "primaryISDN", "propPointToPointSerial", "ppp",
    "softwareLoopback", "eon", "ethernet-3Mbit", "nsip", "slip", "ultra",
    "ds3", "sip", "frame-relay",
)
TCP_STATES = (
    "closed", "listen", "synSent", "synReceived", "established", "finWait1",
    "finWait2", "closeWait", "lastAck", "closing", "timeWait", "deleteTCB",
)
STORAGE_TYPES = (
    "Other", "Ram", "Virtual Memory", "Fixed Disk", "Removable Disk",
    "Floppy Disk", "Compact Disc", "RamDisk", "Flash Memory", "Network Disk",
)
FS_TYPES = (
    "Other", "Unknown", "BerkeleyFFS", "Sys5FS", "Fat", "HPFS", "HFS",
    "MFS", "NTFS", "VNode", "Journaled", "iso9660", "RockRidge", "NFS",
    "Netware", "AFS", "DFS", "Appleshare", "RFS", "DGCFS", "BFS", "FAT32",
    "LinuxExt2",
)
DEVICE_TYPES = (
    "Other", "Unknown", "Processor", "Network", "Printer", "Disk Storage",
    "unknown", "unknown", "unknown", "Video", "Audio", "Coprocessor",
    "Keyboard", "Modem", "Parallel Port", "Pointing", "Serial Port", "Tape",
    "Clock", "Volatile Memory", "Non Volatile Memory",
)
IIS_FIELDS = (
    "TotalBytesSentLowWord", "TotalBytesReceivedLowWord", "TotalFilesSent",
    "CurrentAnonymousUsers", "CurrentNonAnonymousUsers", "TotalAnonymousUsers",
    "TotalNonAnonymousUsers", "MaxAnonymousUsers", "MaxNonAnonymousUsers",
    "CurrentConnections", "MaxConnections", "ConnectionAttempts",
    "LogonAttempts", "Gets", "Posts", "Heads", "Others", "CGIRequests",
    "BGIRequests", "NotFoundErrors",
)


class SnmpError(Exception):
    pass


def oid_parts(oid):
    return tuple(map(int, oid.split(".")))


def decode(value):
    if isinstance(value, univ.Null):
        return None
    if isinstance(value, (rfc1155.IpAddress, rfc1902.IpAddress)):
        return value.prettyPrint()
    if isinstance(value, univ.OctetString):
        return value.asOctets()
    if isinstance(value, univ.Integer):
        return int(value)
    return value.prettyPrint()


class SnmpClient:
    def __init__(self, dispatcher, target, community, version):
        self.dispatcher = dispatcher
        self.target = target
        self.auth = CommunityData(community, mpModel=0 if version == "1" else 1)

    async def request(self, command, *bindings):
        error, status, index, response = await command(
            self.dispatcher, self.auth, self.target, *bindings, lookupMib=False
        )
        if isinstance(error, errind.RequestTimedOut):
            raise TimeoutError("SNMP request timeout")
        if error:
            raise SnmpError(str(error))
        return int(status), int(index), response

    async def read(self, fields):
        pending = [(label, oid_parts(oid)) for label, oid in fields.items()]
        values = {}
        while pending:
            status, index, response = await self.request(
                get_cmd, *((oid, rfc1902.Null("")) for _, oid in pending)
            )
            if status in (2, 5) and 1 <= index <= len(pending):
                # An error on one binding invalidates the whole response.
                label, _ = pending.pop(index - 1)
                if status == 5:
                    print(f"[!] Skipping {label}: SNMP agent returned genErr", file=sys.stderr)
                continue
            if status == 1 and len(pending) > 1:
                middle = len(pending) // 2
                for group in (pending[:middle], pending[middle:]):
                    values.update(await self.read({
                        label: ".".join(map(str, oid)) for label, oid in group
                    }))
                break
            if status:
                raise SnmpError(f"SNMP GET failed (status {status}, index {index})")
            if [tuple(oid) for oid, _ in response] != [oid for _, oid in pending]:
                raise SnmpError("Unexpected SNMP GET response OIDs")
            values.update(
                (label, decode(value))
                for (label, _), (_, value) in zip(pending, response)
            )
            break
        return {label: values[label] for label in fields if values.get(label) is not None}

    async def rows(self, prefix, *columns):
        roots = [oid_parts(f"{prefix}.{column}") for column in columns]
        active = list(range(len(roots)))
        suffix = ()
        while active:
            cursors = [roots[i] + suffix for i in active]
            status, index, response = await self.request(
                next_cmd, *((oid, rfc1902.Null("")) for oid in cursors)
            )
            if status == 2 and 1 <= index <= len(active):
                if active.pop(index - 1) == 0:
                    return
                continue
            if status:
                raise SnmpError(f"SNMP GETNEXT failed (status {status}, index {index})")
            if len(response) != len(active):
                raise SnmpError("Unexpected number of SNMP GETNEXT bindings")

            first_oid, first_value = response[0]
            first_oid = tuple(first_oid)
            root = roots[0]
            if first_oid[:len(root)] != root or decode(first_value) is None:
                return
            if first_oid <= cursors[0]:
                print(f"[!] Stopping table {prefix}: non-increasing OID", file=sys.stderr)
                return
            suffix = first_oid[len(root):]
            row = [None] * len(roots)
            for i, (oid, value) in zip(active, response):
                # Sparse columns can return the value for a later row.
                if tuple(oid) == roots[i] + suffix:
                    row[i] = decode(value)
            yield row

    async def check_write(self, hostname):
        if not isinstance(hostname, bytes):
            return False
        status, _, _ = await self.request(
            set_cmd, (oid_parts(HOSTNAME), rfc1902.OctetString(hostname))
        )
        return status == 0


def text(value, missing="-"):
    if value is None:
        return missing
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", str(value)).strip()
    return value or missing


def enum(values, number, default="unknown"):
    if isinstance(number, int) and 1 <= number <= len(values):
        return values[number - 1]
    return default


def oid_enum(values, value, prefix, default="unknown"):
    value = str(value)
    head, _, tail = value.rpartition(".")
    return enum(values, int(tail), default) if head == prefix and tail.isdecimal() else default


def system_date(value):
    if isinstance(value, bytes) and len(value) >= 8:
        year = int.from_bytes(value[:2], "big")
        month, day, hour, minute, second, tenth = value[2:8]
        return f"{year}-{month}-{day} {hour:02}:{minute:02}:{second:02}.{tenth:02}"
    return "-"


def human_size(count, unit):
    if not isinstance(count, int) or not isinstance(unit, int):
        return "unknown"
    size = count * unit
    if size < 1024:
        return f"{size} bytes"
    for exponent, label in ((3, "GB"), (2, "MB"), (1, "KB")):
        if size >= 1024 ** exponent:
            return f"{size / 1024 ** exponent:.2f} {label}"


def job_attribute(value):
    match = re.match(r"JobAcct[0-9]+=(.*)", text(value, ""))
    return (match[1] or "-") if match else "-"


async def collect(client, args):
    report = {"Host IP address": args.target}
    system = await client.read({
        "Hostname": HOSTNAME,
        "Description": f"{MIB}.1.1.0",
        "Contact": f"{MIB}.1.4.0",
        "Location": f"{MIB}.1.6.0",
        "Uptime system": f"{MIB}.1.3.0",
        "Uptime snmp": f"{MIB}.25.1.1.0",
        "System date": f"{MIB}.25.1.2.0",
    })
    if args.write:
        permitted = await client.check_write(system.get("Hostname"))
        print("[*] Write access " + ("permitted!" if permitted else "not permitted!"))
    report.update({label: system.get(label) for label in FIELDS[1:8]})
    report["System date"] = system_date(system.get("System date"))
    windows = "Windows" in text(system.get("Description"))
    if windows:
        report["Domain"] = (await client.read({"Domain": f"{WINDOWS}.1.4.1.0"})).get("Domain")
        report["User accounts"] = [
            row async for row in client.rows(f"{WINDOWS}.1.2.25.1", 1)
        ]

    network = await client.read({
        "IP forwarding enabled": f"{MIB}.4.1.0",
        "Default TTL": f"{MIB}.4.2.0",
        "TCP segments received": f"{MIB}.6.10.0",
        "TCP segments sent": f"{MIB}.6.11.0",
        "TCP segments retrans": f"{MIB}.6.12.0",
        "Input datagrams": f"{MIB}.4.3.0",
        "Delivered datagrams": f"{MIB}.4.9.0",
        "Output datagrams": f"{MIB}.4.10.0",
    })
    forwarding = network.get("IP forwarding enabled")
    if forwarding in (0, 1, 2):
        network["IP forwarding enabled"] = "yes" if forwarding == 1 else "no"
    else:
        network.pop("IP forwarding enabled", None)
    report["Network information"] = network
    report["Network interfaces"] = [
        {
            "Interface": f"[ {enum(('up', 'down', 'testing'), status)} ] {text(desc)}",
            "Id": index,
            "Mac Address": mac.hex(":") if isinstance(mac, bytes) else None,
            "Type": enum(INTERFACE_TYPES, kind),
            "Speed": f"{speed // 1_000_000} Mbps" if isinstance(speed, int) else None,
            "MTU": mtu,
            "In octets": incoming,
            "Out octets": outgoing,
        }
        async for index, desc, mac, kind, mtu, speed, incoming, outgoing, status
        in client.rows(f"{MIB}.2.2.1", 1, 2, 6, 3, 4, 5, 10, 16, 7)
    ]

    async def table(label, headers, prefix, *columns):
        rows = [row async for row in client.rows(prefix, *columns)]
        if rows:
            report[label] = [headers, *rows]

    await table("Network IP", ("Id", "IP Address", "Netmask", "Broadcast"),
                f"{MIB}.4.20.1", 2, 1, 3, 4)
    await table("Routing information", ("Destination", "Next hop", "Mask", "Metric"),
                f"{MIB}.4.21.1", 1, 7, 11, 3)
    if not args.disable_tcp:
        tcp = [
            [local, local_port, remote, remote_port, enum(TCP_STATES, state)]
            async for local, local_port, remote, remote_port, state
            in client.rows(f"{MIB}.6.13.1", 2, 3, 4, 5, 1)
        ]
        if tcp:
            report["TCP connections and listening ports"] = [
                ("Local address", "Local port", "Remote address", "Remote port", "State"),
                *tcp,
            ]
    await table("Listening UDP ports", ("Local address", "Local port"),
                f"{MIB}.7.5.1", 1, 2)

    if windows:
        services = [name async for (name,) in client.rows(f"{WINDOWS}.1.2.3.1", 1)]
        if services:
            report["Network services"] = [("Index", "Name"), *enumerate(services)]
        report["Share"] = [
            {" Name": name, "  Path": path, "  Comment": comment}
            async for name, path, comment in client.rows(f"{WINDOWS}.1.2.27.1", 1, 2, 3)
        ]
        # IIS uses OIDs 2, then 4 through 22.
        report["IIS server information"] = await client.read({
            label: f"{IIS}.{column}.0"
            for label, column in zip(IIS_FIELDS, (2, *range(4, 23)))
        })

    report["Storage information"] = [
        {
            "Description": desc,
            "Device id": index,
            "Filesystem type": oid_enum(STORAGE_TYPES, kind, f"{MIB}.25.2.1"),
            "Device unit": unit if unit is not None else "unknown",
            "Memory size": human_size(size, unit),
            "Memory used": human_size(used, unit),
        }
        async for index, kind, desc, unit, size, used
        in client.rows(f"{MIB}.25.2.3.1", 1, 2, 3, 4, 5, 6)
    ]
    filesystem = await client.read({
        label: f"{MIB}.25.3.8.1.{column}.1"
        for column, label in enumerate(
            ("Index", "Mount point", "Remote mount point", "Type", "Access", "Bootable"), 1
        )
    })
    if "Type" in filesystem:
        kind = oid_enum(FS_TYPES, filesystem["Type"], f"{MIB}.25.3.9", None)
        if kind is None:
            del filesystem["Type"]
        else:
            filesystem["Type"] = kind
    report["File system information"] = filesystem
    devices = [
        [index, oid_enum(DEVICE_TYPES, kind, f"{MIB}.25.3.1"),
         enum(("unknown", "running", "warning", "testing", "down"), status),
         text(desc, "unknown")]
        async for index, kind, status, desc in client.rows(f"{MIB}.25.3.2.1", 1, 2, 5, 3)
    ]
    if devices:
        report["Device information"] = [("Id", "Type", "Status", "Descr"), *devices]
    await table("Software components", ("Index", "Name"), f"{MIB}.25.6.3.1", 1, 2)
    processes = [
        [index, enum(("running", "runnable"), status), name, path, parameters]
        async for index, name, path, parameters, status
        in client.rows(f"{MIB}.25.4.2.1", 1, 2, 4, 5, 7)
    ]
    if processes:
        report["Processes"] = [("Id", "Status", "Name", "Path", "Parameters"), *processes]

    printers = []
    async for first, second, user, host, domain, timestamp, app, command in client.rows(
        LASERJET, "5.1", "5.2", "23.1", "23.2", "23.3", "23.4", "23.6", "23.7"
    ):
        if timestamp is None:
            continue
        filename = text(first, "") + text(second, "")
        printers.append({
            "Filename": f"{filename}{len(filename)}",
            "Username": job_attribute(user),
            "Client": job_attribute(host),
            "Timestamp": job_attribute(timestamp),
            "Domain": job_attribute(domain),
            "Application name": job_attribute(app),
            "Application command": job_attribute(command),
        })
    report["HP LaserJet printer enumeration"] = printers
    return report


def print_report(report):
    def field(label, value):
        print(f"  {label[:31]:30}: {text(value)}")

    print("[*] System information:\n")
    for label in FIELDS:
        if label not in report:
            continue
        value = report[label]
        if isinstance(value, (list, dict)):
            if not value:
                continue
            print(f"\n[*] {label}:\n")
            if isinstance(value, dict):
                value = [value]
            for row in value:
                if isinstance(row, dict):
                    for name, item in row.items():
                        field(name, item)
                    if len(value) > 1:
                        print()
                else:
                    print("".join(f"  {text(item):20}" for item in row))
        else:
            field(label, value)


async def run(args):
    target = await UdpTransportTarget.create(
        (args.target, args.port), timeout=args.timeout, retries=args.retries
    )
    with SnmpDispatcher() as dispatcher:
        report = await collect(SnmpClient(dispatcher, target, args.community, args.version), args)
    print_report(report)


def main():
    parser = argparse.ArgumentParser(
        prog="snmpcheck", description="SNMP enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", type=ipaddress.IPv4Address, help="target IPv4 address")
    parser.add_argument("-p", "--port", type=int, default=161, help="SNMP port (default: 161)")
    parser.add_argument("-c", "--community", default="public", help="SNMP community (default: public)")
    parser.add_argument("-v", "--version", choices=("1", "2c"), default="1",
                        help="SNMP version (default: 1)")
    parser.add_argument("-w", "--write", action="store_true",
                        help="check write access by sending the existing sysName")
    parser.add_argument("-d", "--disable_tcp", action="store_true",
                        help="skip the TCP connections table")
    parser.add_argument("-t", "--timeout", type=float, default=5,
                        help="per-request timeout in seconds (default: 5)")
    parser.add_argument("-r", "--retries", type=int, default=1,
                        help="request retries (default: 1)")
    parser.add_argument("-i", "--info", action="version", version=BANNER)
    args = parser.parse_args()
    args.target = str(args.target)
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be a finite positive number")
    if not 0 <= args.retries <= 10:
        parser.error("retries must be between 0 and 10")

    print(f"{BANNER}\n\n[+] Try to connect to {args.target}:{args.port} using SNMPv{args.version}")
    if args.write:
        print("[+] Write access check enabled")
    if args.disable_tcp:
        print("[+] TCP connections enumeration disabled")
    print()

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        return 130
    except (OSError, SnmpError, SmiError) as error:
        print(f"[!] {args.target}:{args.port} {text(error)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
