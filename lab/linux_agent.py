"""Keep known Linux resources alive while Net-SNMP serves the lab."""

import signal
import socket
import subprocess


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(("0.0.0.0", 8443))
        tcp.listen()
        udp.bind(("0.0.0.0", 8162))

        with subprocess.Popen([
            "snmpd", "-f", "-Lo", "-C", "-c", "/app/lab/snmpd.conf"
        ]) as agent:
            signal.signal(signal.SIGTERM, lambda *_: agent.terminate())
            raise SystemExit(agent.wait())
