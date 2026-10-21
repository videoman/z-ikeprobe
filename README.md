# ikednmi

A standalone client for the **z/OS Communications Server IPsec Network Management Interface (NMI)**, the local AF_UNIX management socket served by the IKE daemon (IKED).

`ikednmi.py` speaks the NMIv2 wire protocol directly. It handles the INIT handshake, sends any `GET_*` request, and decodes every response record into named fields: IP filters, manual and dynamic tunnels, IKE phase 1 and phase 2 SAs, stack settings, statistics, interfaces and NSS configuration. It can also send the state-changing control requests (activate, deactivate, refresh, policy reload), gated behind an explicit authorization flag.

It's a single file, uses only the standard library, and needs no IBM headers or C compiler. It runs on z/OS UNIX with IBM's Python.

## Why

On a lot of z/OS systems the IPsec NMI is reachable by any local user who can open the socket. Whether a request is actually answered depends on SAF (SERVAUTH) controls that are often missing or too broad. When they are, a low-privileged user can:

- enumerate IPsec policy, filter rules, VPN peers, SPIs and live SA state
- identify weak IKE configurations, such as IKEv1 aggressive mode with pre-shared keys, DES/3DES, MD5/SHA-1 or weak DH groups
- with control access, tear down, refresh or re-establish IPsec tunnels, or reload policy

This tool makes that surface easy to assess during authorized testing.

## Requirements

- Python 3.8 or later, standard library only
- On z/OS: IBM Open Enterprise SDK for Python. It is often installed under `/usr/lpp/IBM/cyp/v3rNN/pyz/bin` even when it isn't on `PATH`.
- Read access to the NMI socket, plus whatever SERVAUTH access IKED enforces for each request

## Installation on z/OS

Transfer `ikednmi.py` in **binary** mode, then tag it as ASCII so Python reads it correctly:

```bash
chtag -tc ISO8859-1 ikednmi.py
```

To find a Python interpreter and set up a shortcut:

```bash
ls -d /usr/lpp/IBM/cyp/*/pyz/bin
alias nmi='/usr/lpp/IBM/cyp/v3r14/pyz/bin/python3 ~/ikednmi.py'
```

## Quick start

```bash
nmi info            # handshake only: NMI version, server time
nmi all             # every read-only query
```

`info` succeeding only shows that the socket is reachable. The SAF check is applied per request, so the read-only queries are what tell you whether data is actually exposed.

## Commands

| Command | Message type(s) | Returns |
|---|---|---|
| `info` | INIT (0) | NMI version, server clock, greeting header |
| `stack` | GET_STACKINFO (2) | IPSECURITY settings, filter set, FIPS, defensive filtering, exclusion addresses |
| `summary` | GET_SUMMARY (3) | P1/P2 counts, activation successes and failures, retransmits, replays, filter hit counters |
| `filters [--set current\|default\|policy]` | 4 / 5 / 6 | IP filter rules: addresses, ports, protocol, action, logging, match counters |
| `porttran` | GET_PORTTRAN (7) | NAT-T port translations |
| `tunnels manual` | 8 | Manual tunnels, SPIs, packet and byte counters |
| `tunnels dynstack` | 9 | Dynamic tunnels as the stack sees them |
| `tunnels dynike` | 10 | Phase 2 SAs: traffic selectors, PFS, client IDs |
| `tunnels ike` *(default)* | 11 | Phase 1 SAs: peers, IKE version, exchange mode, crypto, cookies, identities, certificates |
| `tunnels cascade` | 12 | Phase 1 SAs with their phase 2 SAs nested underneath |
| `interfaces` | 13 | IP interfaces, security class, DVIPA |
| `nss` | 14 | Network Security Services client configuration and status |
| `all` | 2, 3, 13, 14, 4, 7, 8, 9, 11, 10 | Runs all of the above and reconnects if IKED drops the connection |
| `get <type>` | any 2–999 | Any read-only type by number |
| `control <action>` | 1001–1008 | State-changing requests, gated (see below) |

## Global options

Global options go **before** the subcommand:

```bash
nmi --debug --raw tunnels ike
```

| Option | Purpose |
|---|---|
| `-s, --socket PATH` | NMI socket path (default `/var/sock/ipsecmgmt`) |
| `-t, --target NAME` | Value for the header's target field, such as a TCP/IP stack name. Defaults to blanks. |
| `--timeout SECS` | Socket timeout (default 10) |
| `--raw` | Also hexdump every section, with an EBCDIC text column |
| `--debug` | Hexdump every message sent and received, and report section length mismatches |
| `--blank-pad` | Pad names in requests with EBCDIC blanks instead of nulls |
| `--sec-offset-base record\|message` | Base for section offsets in requests (default `record`) |

## Input filters

`filters`, `tunnels`, `porttran` and `get` accept filters. IKED evaluates them on its side.

```bash
nmi tunnels ike --remote 192.0.2.77
nmi tunnels dynike --tunnel-id Y5 --state active
nmi filters --set policy --dport 23 --proto 6
```

| Filter | Field |
|---|---|
| `--src`, `--dst` | Traffic source and destination address |
| `--proto`, `--sport`, `--dport` | Protocol number and ports |
| `--local`, `--remote` | Local and remote security endpoints |
| `--tunnel-id` | Tunnel ID |
| `--name`, `--group`, `--assoc` | Object, group and associated object names |
| `--state` | SA state: `INACTIVE`, `PENDING`, `INCOMPLETE`, `ACTIVE`, `EXPIRED`, `HALF_CLOSED` |

## Control actions

Control requests change live IPsec state on the target. The tool refuses to send one unless you pass `--i-have-authorization`. It then shows exactly what it is about to send and waits for you to type `YES` (`--yes` skips the prompt).

```bash
nmi control deactivate-ike --tunnel-id K12 --i-have-authorization
nmi control refresh-dyn --name DynRule1 --i-have-authorization
nmi control load-policy --i-have-authorization
```

| Action | Type |
|---|---|
| `activate-manual` / `deactivate-manual` | 1001 / 1003 |
| `activate-dyn` / `deactivate-dyn` | 1002 / 1004 |
| `deactivate-ike` | 1005 |
| `refresh-dyn` / `refresh-ike` | 1006 / 1007 |
| `load-policy [--source N]` | 1008 |

`--tunnel-id` and `--name` can be repeated to act on several tunnels in one request. The response reports a status for each tunnel, such as `STATE_UPDATED`, `NOT_FOUND` or `STATE_ALREADY_SET`.

Get written approval before you use these on a production system. Tearing down a tunnel can break production traffic.

## Example output

Captured against the test harness, so the addresses are documentation ranges:

```
[+] /var/sock/ipsecmgmt: IPsec NMI v2, INIT rc=0, server time 2026-10-21 22:36:57 UTC

[*] GET_IKETUNCASCADE: rc=0  records: 2 returned / 2 matched
  === IKE tunnel (P1) 1/2: K12  10.10.1.5 -> 192.0.2.77  IKEv1.0  ACTIVE ===
    TunnelID                 K12
    KeyExchangeRule          KeyExRule_PartnerA
    LocalEndpoint            10.10.1.5
    RemoteEndpoint           192.0.2.77
    ExchangeMode             AGGRESSIVE (4)  [!] aggressive mode + PSK: hash exposed to offline PSK cracking
    AuthAlg                  HMAC_SHA1 (39)  [!] SHA-1
    EncryptAlg               3DES (3)  [!] weak cipher
    DHGroup                  group 2  [!] weak DH group
    PeerAuthMethod           PRESHARED_KEY (3)
    MajorVer                 IKEv1.0  (IKEv1)
    ...
    Local identity           IPV4 10.10.1.5
    Remote identity          FQDN vpn.partnera.test
    -- 1 associated phase 2 tunnel(s) --
      === P2 1/1: Y5  10.10.1.5 -> 192.0.2.77  ACTIVE ===
        AuthProto                ESP (50)
        EncryptAlg               DES (18)  [!] weak cipher
        InboundEncryptSPI        0xDEADBEEF
        SrcAddr                  10.10.0.0/16
        DstAddr                  192.0.2.200
        DstPort                  23
        PFSDHGroup               none  (no PFS)
```

## Annotations

As it decodes, the tool marks configuration worth a closer look:

| Marker | Condition |
|---|---|
| `[!] aggressive mode + PSK` | IKEv1 aggressive mode with pre-shared key authentication. The PSK hash can be captured and cracked offline. |
| `[!] weak cipher` / `NULL encryption` | DES, 3DES or NULL; ESP with no encryption |
| `[!] MD5` / `[!] SHA-1` | Weak integrity algorithms |
| `[!] no integrity` | NULL authentication without AES-GCM |
| `[!] weak DH group` | Groups 1, 2, 5, 22, 23 and 24 |
| `(no PFS)` | Phase 2 negotiated without PFS |
| `(IKEv1)` | Tunnel negotiated with IKEv1 |

## Troubleshooting

### Return and reason codes

| rc / rsn | Meaning | Next step |
|---|---|---|
| `111 / 4` (EACCES / NoAuthForService) | Denied by SAF | Your ID lacks the SERVAUTH profile IKED checks, typically `EZB.NETMGMT.<sysname>.<tcpname>.IPSEC.DISPLAY` for reads and `.IPSEC.CONTROL` for control requests. A denial is still worth recording. |
| `121 / 2` (BadVersion) | NMI version rejected | Unexpected: NMI v2 is the only defined version. |
| `121 / 3` (BadType) | Message type not supported | That type isn't available on this release. |
| `121 / 10` or `12` | Input section or filter rejected | Retry with `--sec-offset-base message`. |
| Filter matches nothing | Name padding mismatch | Retry with `--blank-pad`. |
| `IKED closed the connection` | Silent drop | Usually the wrong socket, or a malformed request. Run with `--debug`. |

### Wrong socket

`/var/ike/` holds a **different** socket, `iked.sock`, which carries the private channel between the `ipsec` command and IKED. It doesn't speak NMI and closes the connection without replying. The NMI socket is in `/var/sock/`:

```bash
ls -la /var/sock/      # look for ipsecmgmt
```

## How it works

- **Message header:** every message starts with a 140-byte header identified by `0xD5D4A2D4` (EBCDIC `NMsM`). The header carries the NMI version (2), the message type, a correlator, rc and rsn, the total length, the server's timestamp, input and output record descriptors, and a 24-byte target field.
- **Handshake:** IKED speaks first. When a client connects, the server sends an INIT message (type 0); the client then sends requests.
- **Records and sections:** responses contain records identified by `0xD5D4A2D9` (`NMsR`). Each record lists descriptors (offset, element length, count) for its sections, plus cascading descriptors that point to nested records. `GET_IKETUNCASCADE` uses those to attach phase 2 SAs to their phase 1.
- **Encoding:** all structures are packed and big-endian. Bitfields are allocated from the most significant bit first, and a run of bitfields takes `ceil(bits/8)` bytes. Text fields are EBCDIC (IBM-1047); the tool includes its own 1047 table because most Python builds lack that codec.
- **Offset detection:** section offsets in responses are recognized as either record-relative or message-relative.
- **Version tolerance:** layouts decode up to whatever section length the server sends. Records from releases before z/OS 2.5, such as IKE tunnel records without the certificate fields, still decode.

## Limitations

- The response layouts match the z/OS 2.5 definitions. Testing so far has been against a protocol-accurate mock server and a live INIT handshake. Two request-side details haven't been confirmed against a live IKED: the section offset base and the padding of name fields. Both have overrides (see Global options).
- `GET_CLIENTINFO` (101) is served by the NSS daemon on its own socket, `/var/sock/nss`, not by IKED.
- Output is text only.

## Legal

Use this tool only on systems you own or are explicitly authorized to test. The control actions disrupt production IPsec traffic.

This project reimplements a documented wire format for interoperability. It contains no IBM source or header files. z/OS, IBM and Communications Server are trademarks of IBM Corp.

## License

MIT. See [LICENSE](LICENSE).
