"""Serve deterministic SNMPv1 and v2c inventory data over UDP."""

from bisect import bisect_right
from socketserver import BaseRequestHandler, UDPServer

from pyasn1.codec.ber import decoder, encoder
from pysnmp.proto import rfc1905
from pysnmp.proto.api import v1, v2c, verdec

MIB = "1.3.6.1.2.1"
WINDOWS = "1.3.6.1.4.1.77.1"
IIS = "1.3.6.1.4.1.311.1.7.3.1"
LASERJET = "1.3.6.1.4.1.11.2.3.9.4.2.1.1.6"


def oid(value):
    return tuple(map(int, value.split(".")))


def inventory(protocol):
    result = {}
    counter = v1.Counter if protocol is v1 else v2c.Counter32
    gauge = v1.Gauge if protocol is v1 else v2c.Gauge32

    def row(root, index, values):
        for column, value in values.items():
            if isinstance(value, int):
                value = protocol.Integer(value)
            elif isinstance(value, (str, bytes)):
                value = protocol.OctetString(value)
            result[oid(f"{root}.{column}.{index}")] = value

    row(f"{MIB}.1", 0, {
        1: "Windows SNMP lab fixture", 3: protocol.TimeTicks(12345),
        4: "Fixture contact", 5: "fixture-host", 6: "Fixture location",
    })
    row(f"{MIB}.25.1", 0, {1: protocol.TimeTicks(6789), 2: bytes((7, 234, 1, 2, 3, 4, 5, 6))})
    row(f"{MIB}.4", 0, {1: 1, 2: 64, 3: counter(3), 9: counter(9), 10: counter(10)})
    row(f"{MIB}.6", 0, {10: counter(101), 11: counter(102), 12: counter(0)})
    row(f"{MIB}.2.2.1", 1, {
        1: 1, 2: "fixture-eth", 3: 6, 4: 1500, 5: gauge(1_000_000_000),
        6: bytes.fromhex("020000000001"), 7: 1, 10: counter(42), 16: counter(43),
    })
    # The MTU and MAC are intentionally absent in the second row.
    row(f"{MIB}.2.2.1", 2, {1: 2, 2: "fixture-sparse", 3: 24, 7: 2})
    row(f"{MIB}.4.20.1", "192.0.2.10", {
        1: protocol.IpAddress("192.0.2.10"), 2: 1,
        3: protocol.IpAddress("255.255.255.0"), 4: 1,
    })
    row(f"{MIB}.4.21.1", "0.0.0.0", {
        1: protocol.IpAddress("0.0.0.0"), 3: 7,
        7: protocol.IpAddress("192.0.2.1"), 11: protocol.IpAddress("0.0.0.0"),
    })
    row(f"{MIB}.6.13.1", "192.0.2.10.443.0.0.0.0.0", {
        1: 2, 2: protocol.IpAddress("192.0.2.10"), 3: 443,
        4: protocol.IpAddress("0.0.0.0"), 5: 0,
    })
    row(f"{MIB}.7.5.1", "192.0.2.10.161", {1: protocol.IpAddress("192.0.2.10"), 2: 161})
    row(f"{MIB}.25.2.3.1", 1, {
        1: 1, 2: protocol.ObjectIdentifier(f"{MIB}.25.2.1.4"),
        3: "fixture-disk", 4: 4096, 5: 512, 6: 256,
    })
    row(f"{MIB}.25.3.8.1", 1, {
        1: 1, 2: "/fixture", 3: "", 4: protocol.ObjectIdentifier(f"{MIB}.25.3.9.14"),
        5: 1, 6: 2,
    })
    row(f"{MIB}.25.3.2.1", 1, {
        1: 1, 2: protocol.ObjectIdentifier(f"{MIB}.25.3.1.3"),
        3: "fixture-cpu", 5: 2,
    })
    row(f"{MIB}.25.4.2.1", 100, {1: 100, 2: "fixture-process", 4: "/fixture/bin", 5: "--fixture", 7: 1})
    row(f"{MIB}.25.6.3.1", 1, {1: 1, 2: "fixture-package"})
    row(f"{WINDOWS}.1.4", 0, {1: "FIXTURE"})
    row(f"{WINDOWS}.1.2.25.1", 1, {1: "fixture-user"})
    row(f"{WINDOWS}.1.2.3.1", 1, {1: "Fixture Spooler", 2: 1})
    row(f"{WINDOWS}.1.2.27.1", 1, {1: "fixture-share", 2: "C:\\fixture", 3: "Share comment"})
    row(IIS, 0, {column: counter(column) for column in (2, *range(4, 23))})
    row(LASERJET, 1, {
        "5.1": "fixture-job", "5.2": ".pdf", "23.1": "JobAcct1=fixture-user",
        "23.2": "JobAcct2=fixture-client", "23.3": "JobAcct3=FIXTURE",
        "23.4": "JobAcct4=fixture-time", "23.6": "JobAcct6=fixture-app",
        "23.7": "JobAcct7=fixture-command",
    })
    return result


INVENTORIES = {protocol: inventory(protocol) for protocol in (v1, v2c)}
SORTED_OIDS = {protocol: sorted(data) for protocol, data in INVENTORIES.items()}
TTL = oid(f"{MIB}.4.2.0")
CONTACT = oid(f"{MIB}.1.4.0")
HOSTNAME = oid(f"{MIB}.1.5.0")
INTERFACE_INDEX = oid(f"{MIB}.2.2.1.1.1")


class Fixture(BaseRequestHandler):
    def handle(self):
        packet, socket = self.request
        protocol = {0: v1, 1: v2c}[int(verdec.decode_message_version(packet))]
        message, _ = decoder.decode(packet, asn1Spec=protocol.Message())
        community = protocol.apiMessage.get_community(message).asOctets()
        if community not in (
            b"lab-full", b"lab-partial", b"lab-retry",
            b"lab-get-error", b"lab-walk-error", b"lab-wrong-oid",
            b"lab-short-walk", b"lab-no-name",
        ):
            return

        request = protocol.apiMessage.get_pdu(message)
        if community == b"lab-retry" and self.client_address not in self.server.dropped:
            self.server.dropped.add(self.client_address)
            return

        reply = protocol.apiMessage.get_response(message)
        response = protocol.apiMessage.get_pdu(reply)
        data, keys = INVENTORIES[protocol], SORTED_OIDS[protocol]
        bindings = protocol.apiPDU.get_varbinds(request)
        status, index, values = 0, 0, []
        if isinstance(request, protocol.GetRequestPDU) and community == b"lab-get-error":
            status = 5  # genErr without an error index
        elif isinstance(request, protocol.GetNextRequestPDU) and community == b"lab-walk-error":
            status, index = 5, 1
        elif isinstance(request, protocol.GetRequestPDU) and len(bindings) > 8:
            status = 1  # tooBig
        else:
            for position, (name, value) in enumerate(bindings, 1):
                name = tuple(name)
                if isinstance(request, protocol.GetNextRequestPDU):
                    if community == b"lab-partial" and name == INTERFACE_INDEX:
                        values.append((name, data[name]))
                        continue
                    successor = bisect_right(keys, name)
                    if successor < len(keys):
                        name = keys[successor]
                    elif protocol is v1:
                        status, index = 2, position
                        break
                    else:
                        values.append((name, rfc1905.endOfMibView))
                        continue
                elif isinstance(request, protocol.SetRequestPDU):
                    if community == b"lab-no-name":
                        # A SET would succeed here, so the test detects an attempted write.
                        values.append((name, value))
                        continue
                    status, index = (4 if protocol is v1 else 17), position
                    break
                elif community == b"lab-partial" and name == TTL:
                    status, index = 5, position  # genErr
                    break

                missing = (
                    (community == b"lab-partial" and name == CONTACT)
                    or (community == b"lab-no-name" and name == HOSTNAME)
                )
                if name in data and not missing:
                    values.append((name, data[name]))
                elif protocol is v1:
                    status, index = 2, position  # noSuchName
                    break
                else:
                    values.append((name, rfc1905.noSuchObject))

        if status:
            values = [] if status == 1 and protocol is v2c else bindings
        elif community == b"lab-wrong-oid" and isinstance(request, protocol.GetRequestPDU):
            values[0] = (CONTACT, data[CONTACT])
        elif community == b"lab-short-walk" and isinstance(request, protocol.GetNextRequestPDU):
            values.pop()
        protocol.apiPDU.set_error_status(response, status)
        protocol.apiPDU.set_error_index(response, index)
        protocol.apiPDU.set_varbinds(response, values)
        socket.sendto(encoder.encode(reply), self.client_address)


if __name__ == "__main__":
    with UDPServer(("0.0.0.0", 1161), Fixture) as server:
        server.dropped = set()
        server.serve_forever()
