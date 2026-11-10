# snmpcheck.py

Python port of Matteo Cantoni's **snmpcheck**, a command-line tool that reads
SNMP data from one IPv4 device and displays an inventory report.

## Install

Requires Python 3.11 or later. Install the command with pipx and Git:

```sh
pipx install git+https://github.com/Goultarde/snmpcheck.py.git
snmpcheck --info
```

From a local checkout, run `pipx install .`. See [INSTALL](INSTALL) to run
the script from a virtual environment.

## Usage

```sh
snmpcheck 192.0.2.10
snmpcheck -v 2c -c my-community -d 192.0.2.10
```

| Option | Description |
| --- | --- |
| `-p, --port` | SNMP port (default: 161). |
| `-c, --community` | SNMP community (default: `public`). |
| `-v, --version` | SNMP version, `1` or `2c` (default: `1`). |
| `-w, --write` | Test write access by sending a SET request with the existing `sysName`. The default mode only reads data. |
| `-d, --disable_tcp` | Skip the TCP connections table. |
| `-t, --timeout` | Per-request timeout in seconds (default: 5). |
| `-r, --retries` | Request retries, from 0 to 10 (default: 1). |
| `-i, --info` | Show the program version. |
| `-h, --help` | Show usage. |

## Report

The report covers system details, interfaces, IP addresses, routes, TCP and
UDP endpoints, processes, storage, file systems, devices, and installed
software. Windows accounts, services, shares, IIS counters, and HP LaserJet
job details depend on the OIDs exposed by the agent.

If the agent reports a generic error for a specific OID in a grouped read,
snmpcheck warns on stderr, skips that field, and retries the remaining OIDs.
If a table stops advancing, snmpcheck warns, keeps the rows already read, and
continues the report. A request timeout exits with status 1. Invalid CLI
arguments exit with status 2.

## License

Original snmpcheck copyright © 2005–2015 Matteo Cantoni.
Distributed under [GPL-3.0-or-later](LICENSE).
