#!/usr/bin/env python3
# -*- coding: ascii -*-
"""
ikednmi.py - client for the z/OS Communications Server IPsec Network
Management Interface (NMI) served by the IKE daemon (IKED).

IKED listens on an AF_UNIX stream socket (default /var/sock/ipsecmgmt).
On connect the server sends an NMsec_INIT message; the client then sends
NMIv2 requests and receives responses made of NMsR records and sections.

This tool reimplements the documented wire format for interoperability.
It contains no IBM header text and needs no IBM headers or compiler.

Requirements: Python 3.8+, standard library only. Runs on z/OS UNIX
(IBM Open Enterprise SDK for Python) and anywhere else for offline use.

Usage examples:
  ikednmi.py info                          # handshake: NMI version, server time
  ikednmi.py stack                         # stack IPsec settings
  ikednmi.py summary                       # P1/P2/filter statistics
  ikednmi.py filters --set policy          # policy IP filters
  ikednmi.py tunnels ike                   # IKE (phase 1) tunnels
  ikednmi.py tunnels dynike --remote 10.1.1.1
  ikednmi.py tunnels cascade               # P1s with their P2s
  ikednmi.py all                           # everything read-only
  ikednmi.py get 11 --raw                  # any read-only type + hexdump
  ikednmi.py control deactivate-ike --tunnel-id K12 --i-have-authorization

Control actions change live IPsec state and are refused unless
--i-have-authorization is given; they also prompt for confirmation.

License: MIT
Copyright (c) 2026 David

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions: The above copyright notice and this permission
notice shall be included in all copies or substantial portions of the
Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED.
"""

import argparse
import codecs
import ipaddress
import socket
import struct
import sys
import time

__version__ = "0.1.0"

DEFAULT_SOCKET = "/var/sock/ipsecmgmt"

# --------------------------------------------------------------------------
# Wire constants (NMIv2)
# --------------------------------------------------------------------------
MSG_IDENT = 0xD5D4A2D4          # EBCDIC "NMsM"
REC_IDENT = 0xD5D4A2D9          # EBCDIC "NMsR"
NMI_VERSION = 2

# Message header: 140 bytes, packed, big-endian
HDR_FMT = ">IIHH16sIIIII20sIHH8s4I4I24s"
HDR_LEN = struct.calcsize(HDR_FMT)
assert HDR_LEN == 140
REC_HDR_FMT = ">IIHH"           # ident, length, #cascade descs, #section descs
REC_HDR_LEN = 12
DESC_FMT = ">III"               # offset, length, number
DESC_LEN = 12
MAX_MSG = 64 * 1024 * 1024

MSG_TYPES = {
    0: "INIT", 1: "TERM", 2: "GET_STACKINFO", 3: "GET_SUMMARY",
    4: "GET_IPFLTCURR", 5: "GET_IPFLTDEFAULT", 6: "GET_IPFLTPOLICY",
    7: "GET_PORTTRAN", 8: "GET_IPTUNMANUAL", 9: "GET_IPTUNDYNSTACK",
    10: "GET_IPTUNDYNIKE", 11: "GET_IKETUN", 12: "GET_IKETUNCASCADE",
    13: "GET_IPINTERFACES", 14: "GET_IKENSINFO", 101: "GET_CLIENTINFO",
    1001: "ACTIVATE_IPTUNMANUAL", 1002: "ACTIVATE_IPTUNDYN",
    1003: "DEACTIVATE_IPTUNMANUAL", 1004: "DEACTIVATE_IPTUNDYN",
    1005: "DEACTIVATE_IKETUN", 1006: "REFRESH_IPTUNDYN",
    1007: "REFRESH_IKETUN", 1008: "LOAD_POLICY",
}

RC_NAMES = {
    111: "EACCES", 121: "EINVAL", 131: "ENOLCK", 132: "ENOMEM",
    138: "ENXIO", 1112: "EOPNOTSUPP", 10004: "EGSKCMS", 10005: "ECSFBEXT",
}
RSN_NAMES = {
    121: {1: "BadIdent", 2: "BadVersion", 3: "BadType", 4: "ExcessiveSize",
          5: "HdrSize", 6: "MsgSize", 7: "ReservedNonzero",
          8: "RecordLength", 9: "RecordCount", 10: "SectionLength",
          11: "SectionCount", 12: "FilterSpec", 13: "FilterValue",
          14: "ManTypeConflict", 15: "PolicySource"},
    132: {1: "TooManyConns", 2: "NSClient"},
    111: {1: "DisconnectPending", 2: "UpdatePending",
          3: "NoAuthForClientname", 4: "NoAuthForService"},
}
RC_HINTS = {
    (111, 4): "caller lacks SERVAUTH access to the IPsec NMI resource "
              "(typically EZB.NETMGMT.<sysname>.<tcpname>.IPSEC.DISPLAY for "
              "reads, .IPSEC.CONTROL for control requests)",
    (121, 3): "message type not supported by this IKED",
    (121, 7): "a reserved field was non-zero; try --target '' or check input",
    (121, 10): "input section length rejected; try --sec-offset-base message",
    (121, 12): "input filter rejected; try --sec-offset-base message or --blank-pad",
    (121, 15): "policy source value not valid",
}

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------
SASTATE = {1: "INACTIVE", 2: "PENDING", 3: "INCOMPLETE", 4: "ACTIVE",
           5: "EXPIRED", 6: "HALF_CLOSED"}
AUTH = {0: "NULL", 4: "AES_GMAC_128", 6: "AES_GMAC_256",
        7: "HMAC_SHA2_256_128", 9: "AES128_XCBC_96", 13: "HMAC_SHA2_384_192",
        14: "HMAC_SHA2_512_256", 15: "HMAC_SHA2_256", 16: "HMAC_SHA2_384",
        17: "HMAC_SHA2_512", 18: "AES128_XCBC", 38: "HMAC_MD5",
        39: "HMAC_SHA1", 40: "HMAC_MD5_96", 41: "HMAC_SHA1_96"}
ENCR = {0: "NONE", 3: "3DES", 11: "NULL", 12: "AES_CBC", 18: "DES",
        20: "AES_GCM_16"}
IDTYPE = {0: "NONE", 1: "IPV4", 2: "FQDN", 3: "EMAIL", 4: "IPV4_SUBNET",
          5: "IPV6", 6: "IPV6_SUBNET", 7: "IPV4_RANGE", 8: "IPV6_RANGE",
          9: "X500DN", 11: "KEY_ID"}
FLT_TYPE = {1: "GENERIC", 2: "MANUAL", 3: "DYNANCHOR", 4: "DYNAMIC",
            5: "NATTANCHOR", 6: "NATTDYN", 7: "NRF", 8: "DEFENSIVE"}
FLT_STATE = {0: "INACTIVE", 1: "ACTIVE"}
FLT_ACTION = {1: "PERMIT", 2: "DENY", 3: "IPSEC", 4: "DEFENSIVE_SIMULATE"}
FLT_SCOPE = {1: "LOCAL", 2: "ROUTED", 3: "ALL"}
FLT_CONNECT = {0: "NONE", 1: "INBOUND", 2: "OUTBOUND"}
FLT_DIR = {1: "INBOUND", 2: "OUTBOUND"}
NATT_ID = {0: "NONE", 1: "IP", 2: "RANGE", 3: "PREFIX", 4: "OTHER(MD5)"}
TUN_TYPE = {1: "MANUAL", 2: "DYNAMIC(stack)", 3: "DYNAMIC(IKE)"}
ENCAP = {1: "TUNNEL", 2: "TRANSPORT"}
PROTO = {0: "ANY", 1: "ICMP", 4: "IPIP", 6: "TCP", 17: "UDP", 41: "IPv6",
         47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
         135: "MIPv6"}
ACT_METHOD = {1: "USER", 2: "REMOTE", 3: "ONDEMAND", 5: "SWSA_TAKEOVER",
              6: "AUTOACTIVATE"}
P2STATE = {0: "INIT", 1: "IN_KEP", 2: "DONE", 3: "PENDING_NOTIFY",
           4: "PENDING_START", 5: "HALF_CLOSED"}
EXCH = {2: "MAIN", 4: "AGGRESSIVE"}
AUTHMETH = {2: "RSA_SIGNATURE", 3: "PRESHARED_KEY", 4: "ECDSA_256",
            5: "ECDSA_384", 6: "ECDSA_521", 7: "DIGITAL_SIGNATURE"}
ROLE = {1: "INITIATOR", 2: "RESPONDER"}
P1STATE = {0: "INIT", 1: "WAIT_SA", 2: "IN_KE", 3: "WAIT_KE", 4: "DONE",
           5: "EXPIRED", 6: "WAIT_AUTH", 7: "HALF_CLOSED"}
NATTLVL = {0: "NONE", 1: "RFC_DRAFT2", 3: "RFC_DRAFT3", 4: "RFC",
           5: "RFC_ZOS_PEER", 6: "IKEV2", 7: "IKEV2_ZOS_PEER"}
FLTSET = {0: "DEFAULT", 1: "POLICY"}
DEFFLT = {0: "INACTIVE", 1: "ACTIVE", 2: "SIMULATE"}
SRVSTATUS = {0: "DISCONNECTED", 1: "CONNECT_PENDING", 2: "CONNECTED",
             3: "DISCONNECT_PENDING", 4: "UPDATE_PENDING"}
TUNSTATUS = {0: "-", 1: "NOT_FOUND", 2: "STATE_UPDATED",
             3: "STATE_ALREADY_SET", 5: "NO_KEYEXCHANGERULE",
             6: "NO_IPFILTERRULE", 7: "NO_IPDATAOFFER"}

# --------------------------------------------------------------------------
# EBCDIC (IBM-1047) helpers. Python lacks cp1047 on most platforms, so
# derive it from cp037: the two differ in six printable code points.
# --------------------------------------------------------------------------
def _build_1047():
    try:
        codecs.lookup("cp1047")
        dec = [bytes([i]).decode("cp1047") for i in range(256)]
    except LookupError:
        dec = [bytes([i]).decode("cp037") for i in range(256)]
        dec[0x5F] = "^"
        dec[0xAD] = "["
        dec[0xB0] = "\xac"
        dec[0xBA] = "\xdd"
        dec[0xBB] = "\xa8"
        dec[0xBD] = "]"
    enc = {}
    for i, ch in enumerate(dec):
        enc.setdefault(ch, i)
    return dec, enc


_E2A, _A2E = _build_1047()


def ebcdic_decode(b):
    return "".join(_E2A[x] for x in b)


def ebcdic_encode(s, size, pad=0x40):
    out = bytearray()
    for ch in s:
        if ch not in _A2E:
            raise ValueError("character %r has no IBM-1047 mapping" % ch)
        out.append(_A2E[ch])
    if len(out) > size:
        raise ValueError("%r longer than %d bytes" % (s, size))
    return bytes(out) + bytes([pad]) * (size - len(out))


def ebcdic_str(b):
    """Fixed-width EBCDIC char field -> str (null-terminated, blank padded)."""
    b = b.split(b"\x00", 1)[0].rstrip(b"\x40")
    return ebcdic_decode(b)


def _printable(s):
    return all(c.isprintable() for c in s)


def smart_text(b):
    """Decode a byte field that may be ASCII, EBCDIC or binary."""
    b = b.split(b"\x00", 1)[0] if b.endswith(b"\x00") else b
    b = b.rstrip(b"\x00")
    if not b:
        return ""
    if all(0x20 <= x < 0x7F for x in b):
        return b.decode("ascii")
    e = ebcdic_decode(b).rstrip()
    if e and _printable(e):
        return e
    return "hex:" + b.hex()


# --------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------
def fmt_time(v):
    if not v:
        return "-"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(v))
    except (OverflowError, OSError, ValueError):
        return str(v)


def fmt_enum(v, enum):
    name = enum.get(v)
    return "%s (%d)" % (name, v) if name else "UNKNOWN (%d)" % v


def fmt_proto(v):
    name = PROTO.get(v)
    return "%s (%d)" % (name, v) if name else str(v)


def fmt_ip(raw, v6):
    if raw is None:
        return "-"
    try:
        if v6:
            return str(ipaddress.IPv6Address(bytes(raw[:16])))
        return str(ipaddress.IPv4Address(bytes(raw[:4])))
    except ValueError:
        return "hex:" + bytes(raw).hex()


def hexdump(b, indent="    "):
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hx = " ".join(chunk[j:j + 4].hex() for j in range(0, len(chunk), 4))
        eb = "".join(c if (c.isprintable() and ord(c) < 0x7F) else "."
                     for c in ebcdic_decode(chunk))
        lines.append("%s%06X  %-35s |%s|" % (indent, i, hx, eb))
    return lines


# --------------------------------------------------------------------------
# Declarative struct layouts (packed, big-endian, MSB-first bitfields;
# a run of bitfields occupies ceil(bits/8) bytes under #pragma pack(1)).
# --------------------------------------------------------------------------
def U8(n, e=None, f=None):
    return ("u8", n, e, f)


def U16(n, e=None, f=None):
    return ("u16", n, e, f)


def U32(n, e=None, f=None):
    return ("u32", n, e, f)


def U64(n, e=None, f=None):
    return ("u64", n, e, f)


def STR(n, size):
    return ("str", n, size)


def RAW(n, size, f="hex"):
    return ("raw", n, size, f)


def IP(n):
    return ("ip", n)


def IP4(n):
    return ("ip4", n)


def BITS(nbytes, *items):
    return ("bits", nbytes, items)


def PAD(size):
    return ("pad", size)


SIZES = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "ip": 16, "ip4": 4}


def field_size(f):
    k = f[0]
    if k in ("bits", "pad", "str", "raw"):
        return f[1] if k in ("bits", "pad") else f[2]
    return SIZES[k]


class Layout(object):
    def __init__(self, title, fields, v6=None, hide=(), custom=None):
        self.title = title
        self.fields = fields
        self.v6 = v6
        self.hide = set(hide)
        self.custom = custom or {}
        self.size = sum(field_size(f) for f in fields)


class IdSection(object):
    """Variable-length identity section; type comes from another field."""
    def __init__(self, title, typekey, v6_from=None):
        self.title = title
        self.typekey = typekey


def decode(layout, buf):
    out = {}
    pos, n = 0, len(buf)
    for f in layout.fields:
        k = f[0]
        if k == "bits":
            nb = f[1]
            if pos + nb > n:
                break
            v = int.from_bytes(buf[pos:pos + nb], "big")
            shift = nb * 8
            for item in f[2]:
                shift -= item[1]
                out[item[0]] = (v >> shift) & ((1 << item[1]) - 1)
            pos += nb
        elif k == "pad":
            pos += f[1]
        else:
            size = field_size(f)
            if pos + size > n:
                break
            b = bytes(buf[pos:pos + size])
            out[f[1]] = int.from_bytes(b, "big") if k[0] == "u" else b
            pos += size
    return out


# ---- custom formatters ----------------------------------------------------
def _ip(c, key):
    return fmt_ip(c.get(key), c.get("IPv6"))


def _addr(c, side):
    single, prefix, rng = (c.get(side + "IsSingle"), c.get(side + "IsPrefix"),
                           c.get(side + "IsRange"))
    a = _ip(c, side + "Addr")
    if prefix:
        return "%s/%d" % (a, c.get(side + "AddrPrefix", 0))
    if rng:
        return "%s - %s" % (a, _ip(c, side + "AddrRange"))
    if not single and not any(c.get(side + "Addr", b"")):
        return "any"
    return a


def _port(c, side):
    p, r = c.get(side + "Port", 0), c.get(side + "PortRange", 0)
    if r and r != p:
        return "%d-%d" % (p, r)
    return str(p) if p else "any"


def _ikev(c):
    return "IKEv%d.%d" % (c.get("MajorVer", 0) & 0xF, c.get("MinorVer", 0) & 0xF)


def _range_val(c, key, rkey, guard):
    if not c.get(guard):
        return None
    v, r = c.get(key, 0), c.get(rkey, 0)
    return "%d-%d" % (v, r) if r and r != v else str(v)


def _nattid(c):
    t = c.get("NATTClientIDType", 0)
    if not t:
        return None
    a, b = c.get("NATTClientID", b""), c.get("NATTClientID2", b"")
    label = NATT_ID.get(t, str(t))
    if t == 1:
        return "%s %s" % (label, fmt_ip(a, False))
    if t == 2:
        return "%s %s - %s" % (label, fmt_ip(a, False), fmt_ip(b, False))
    if t == 3:
        return "%s %s/%d" % (label, fmt_ip(a, False), int.from_bytes(b[:4], "big"))
    return "%s %s" % (label, a.hex())


def _nonzero(key, fn=str):
    return lambda c: fn(c[key]) if c.get(key) else None


def _icmp_guard(c):
    return c.get("Protocol") in (1, 58, 135)


def _cert_time(side):
    def f(c):
        if not c.get(side + "CertSerialLen") and not c.get(side + "CertNotAfterType"):
            return None
        return smart_text(c.get(side + "CertNotAfter", b"")) or "-"
    return f


def _cert_serial(side):
    def f(c):
        n = c.get(side + "CertSerialLen", 0)
        if not n:
            return None
        return c.get(side + "CertSerial", b"")[:n].hex(":")
    return f


# ---- layouts --------------------------------------------------------------
L_STACK = Layout("Stack", [
    BITS(4, ("IPSecurity", 1), ("IPv6Security", 1), ("DVIPSec", 1),
         ("FilterLogging", 1), ("PreDecapFiltering", 1),
         ("FilterSet", 1, FLTSET), ("FIPS140", 1), ("DVLocalFltr", 1),
         ("Rsvd1", 24)),
    STR("StackName", 24), U32("NATKeepAlive", f="secs"),
    U32("FilterCount"), U32("DefensiveFilterCount"),
    U8("DefensiveFilterMode", DEFFLT), PAD(3)])

L_EXCL = Layout("Defensive filter exclusion address", [
    BITS(1, ("IsSingle", 1), ("IsPrefix", 1), ("IPv6", 1), ("Rsvd1", 5)),
    PAD(2), U8("Prefix"), IP("Address")],
    v6="IPv6", hide=("IsSingle", "IsPrefix", "Prefix", "IPv6"),
    custom={"Address": lambda c: _ip(c, "Address") + (
        "/%d" % c.get("Prefix", 0) if c.get("IsPrefix") else "")})

L_STATS = Layout("Summary statistics", [
    U32("P1Active"), U32("P1InProgress"), U32("P1Expired"),
    U64("P1LocalActSuccess"), U64("P1RemoteActSuccess"),
    U64("P1LocalActFailure"), U64("P1RemoteActFailure"),
    U64("P1Retransmits"), U64("P1Replays"), U64("P1InvalidMsgs"),
    U64("P1AuthFailures"),
    U32("P2Active"), U32("P2ActiveShadow"), U32("P2InProgress"),
    U32("P2Expired"), U64("P2ActSuccess"), U64("P2ActFailure"),
    U64("P2Retransmits"), U64("P2Replays"), U64("P2InvalidMsgs"),
    U64("P1BytesOut"), U64("P1BytesIn"), U64("P2BytesOut"), U64("P2BytesIn"),
    U64("FilterDenied"), U64("FilterMismatch"), U64("FilterMatched")])

_FLT_HIDE = ("SrcIsSingle", "SrcIsPrefix", "SrcIsRange", "DstIsSingle",
             "DstIsPrefix", "DstIsRange", "ProtoDef", "SrcPortDef",
             "DstPortDef", "ICMPTypeDef", "ICMPCodeDef", "OSPFTypeDef",
             "MIPv6TypeDef", "SrcAddrRange", "DstAddrRange", "SrcAddrPrefix",
             "DstAddrPrefix", "SrcPortRange", "DstPortRange", "NATTClientID2",
             "TypeRange", "CodeRange", "NATTClientIDType", "IPv6")

L_IPFILTER = Layout("IP filter", [
    STR("Name", 48), STR("Group", 48), STR("LocalStartAction", 48),
    STR("VPNAction", 48), STR("TunnelID", 48),
    BITS(4, ("IPv6", 1), ("OnDemand", 1), ("Shadow", 1),
         ("SrcIsSingle", 1), ("SrcIsPrefix", 1), ("SrcIsRange", 1),
         ("DstIsSingle", 1), ("DstIsPrefix", 1), ("DstIsRange", 1),
         ("ProtoDef", 1), ("SrcPortDef", 1), ("DstPortDef", 1),
         ("ICMPTypeDef", 1), ("ICMPCodeDef", 1), ("OSPFTypeDef", 1),
         ("SrcAddrPktGran", 1), ("DstAddrPktGran", 1), ("ProtoPktGran", 1),
         ("SrcPortPktGran", 1), ("DstPortPktGran", 1), ("NATDetected", 1),
         ("NAPTDetected", 1), ("NATGWDetected", 1), ("LogPermit", 1),
         ("LogDeny", 1), ("MIPv6TypeDef", 1), ("ProtoOpaque", 1),
         ("DiscardICMP", 1), ("FragmentsOnly", 1), ("DefensiveGlobal", 1),
         ("TransportOpaque", 1), ("MIPv6TypePktGran", 1)),
    U8("Type", FLT_TYPE), U8("State", FLT_STATE), U8("Action", FLT_ACTION),
    U8("Scope", FLT_SCOPE), U8("Direction", FLT_DIR), U8("SecurityClass"),
    U8("TCPConnect", FLT_CONNECT),
    BITS(1, ("ICMPTypePktGran", 1), ("ICMPCodePktGran", 1),
         ("ICMPv6TypePktGran", 1), ("ICMPv6CodePktGran", 1), ("Rsvd2", 4)),
    U8("Protocol", f="proto"), U8("ICMPType"), U8("ICMPCode"), U8("OSPFType"),
    U16("SrcPort"), U16("SrcPortRange"), U16("DstPort"), U16("DstPortRange"),
    IP("SrcAddr"), IP("SrcAddrRange"), IP("DstAddr"), IP("DstAddrRange"),
    U8("SrcAddrPrefix"), U8("DstAddrPrefix"), PAD(1),
    U8("NATTClientIDType", NATT_ID),
    RAW("NATTClientID", 16), RAW("NATTClientID2", 16),
    U16("NATTPeerPort"), U16("NATTNRFOrigPort"),
    U64("Mismatches"), U64("Matches"),
    U32("CreateTime", f="time"), U32("UpdateTime", f="time"),
    U8("MIPv6Type"), U8("TypeRange"), U8("CodeRange"),
    U8("RemoteIdType", IDTYPE),
    U64("DefensiveExpire", f="time64"), U16("LogLimit")],
    v6="IPv6", hide=_FLT_HIDE,
    custom={
        "SrcAddr": lambda c: _addr(c, "Src"),
        "DstAddr": lambda c: _addr(c, "Dst"),
        "SrcPort": lambda c: _port(c, "Src") if c.get("SrcPortDef") else "any",
        "DstPort": lambda c: _port(c, "Dst") if c.get("DstPortDef") else "any",
        "Protocol": lambda c: fmt_proto(c["Protocol"]) if c.get("ProtoDef") else "any",
        "ICMPType": lambda c: _range_val(c, "ICMPType", "TypeRange", "ICMPTypeDef"),
        "ICMPCode": lambda c: _range_val(c, "ICMPCode", "CodeRange", "ICMPCodeDef"),
        "OSPFType": lambda c: str(c["OSPFType"]) if c.get("OSPFTypeDef") else None,
        "MIPv6Type": lambda c: _range_val(c, "MIPv6Type", "TypeRange", "MIPv6TypeDef"),
        "NATTClientID": _nattid,
        "NATTPeerPort": _nonzero("NATTPeerPort"),
        "NATTNRFOrigPort": _nonzero("NATTNRFOrigPort"),
        "RemoteIdType": lambda c: fmt_enum(c["RemoteIdType"], IDTYPE) if c.get("RemoteIdType") else None,
        "DefensiveExpire": lambda c: (fmt_time(c["DefensiveExpire"]) if 0 < c["DefensiveExpire"] < 2 ** 32
                                      else str(c["DefensiveExpire"])) if c.get("Type") == 8 else None,
        "LogLimit": lambda c: str(c["LogLimit"]) if c.get("Type") == 8 else None,
    })

L_IPTUN = Layout("IP tunnel", [
    STR("TunnelID", 48), STR("VPNAction", 48),
    BITS(4, ("IPv6", 1), ("FIPS140", 1), ("Rsvd1", 30)),
    U8("TunnelType", TUN_TYPE), U8("State", SASTATE), PAD(2),
    IP("LocalEndpoint"), IP("RemoteEndpoint"),
    U8("EncapMode", ENCAP), U8("AuthProto", f="proto"), U8("AuthAlg", AUTH),
    U8("EncryptAlg", ENCR),
    U32("InboundAuthSPI", f="hex"), U32("OutboundAuthSPI", f="hex"),
    U32("InboundEncryptSPI", f="hex"), U32("OutboundEncryptSPI", f="hex"),
    U32("StartTime", f="time"), U32("EncryptKeyLength")],
    v6="IPv6")

L_IPMAN = Layout("Manual tunnel", [
    U64("OutPackets"), U64("InPackets"), U64("OutBytes"), U64("InBytes"),
    BITS(4, ("ClearDF", 1), ("SetDF", 1), ("ClearDSCP", 1), ("Rsvd1", 29))])

_DYN_HIDE = ("SrcIsSingle", "SrcIsPrefix", "SrcIsRange", "DstIsSingle",
             "DstIsPrefix", "DstIsRange", "SrcAddrRange", "DstAddrRange",
             "SrcAddrPrefix", "DstAddrPrefix", "SrcPortRange", "DstPortRange",
             "MinorVer", "IcmpTypeRange", "IcmpCodeRange")

L_IPDYN = Layout("Dynamic tunnel", [
    BITS(4, ("UDPEncap", 1), ("LocalNAT", 1), ("RemoteNAT", 1),
         ("RemoteNAPT", 1), ("RemoteNATGW", 1), ("RemoteIsZOS", 1),
         ("CanInitP2", 1), ("SrcIsSingle", 1), ("SrcIsPrefix", 1),
         ("SrcIsRange", 1), ("DstIsSingle", 1), ("DstIsPrefix", 1),
         ("DstIsRange", 1), ("TransportOpaque", 1), ("Rsvd1", 18)),
    STR("VPNRule", 48), STR("P1TunnelID", 48),
    U64("Lifesize"), U64("LifesizeRefresh"),
    U32("LifetimeExpire", f="time"), U32("LifetimeRefresh", f="time"),
    U32("VPNLifeExpire", f="time"),
    U8("ActivationMethod", ACT_METHOD), PAD(3),
    U16("RemoteUDPPort"), PAD(2), IP4("SrcNATOA"), IP4("DstNATOA"),
    U8("Protocol", f="proto"), PAD(3), U16("SrcPort"), U16("DstPort"),
    IP("SrcAddr"), IP("SrcAddrRange"), IP("DstAddr"), IP("DstAddrRange"),
    U8("SrcAddrPrefix"), U8("DstAddrPrefix"),
    U8("MajorVer", f="ver"), U8("MinorVer", f="ver"),
    U8("IcmpType"), U8("IcmpTypeRange"), U8("IcmpCode"), U8("IcmpCodeRange"),
    U16("SrcPortRange"), U16("DstPortRange"), U32("Generation")],
    v6="IPv6", hide=_DYN_HIDE,
    custom={
        "SrcAddr": lambda c: _addr(c, "Src"),
        "DstAddr": lambda c: _addr(c, "Dst"),
        "SrcPort": lambda c: _port(c, "Src"),
        "DstPort": lambda c: _port(c, "Dst"),
        "MajorVer": _ikev,
        "IcmpType": lambda c: _range_val(c, "IcmpType", "IcmpTypeRange", "Protocol") if _icmp_guard(c) else None,
        "IcmpCode": lambda c: _range_val(c, "IcmpCode", "IcmpCodeRange", "Protocol") if _icmp_guard(c) else None,
        "SrcNATOA": lambda c: fmt_ip(c["SrcNATOA"], False) if any(c["SrcNATOA"]) else None,
        "DstNATOA": lambda c: fmt_ip(c["DstNATOA"], False) if any(c["DstNATOA"]) else None,
        "RemoteUDPPort": _nonzero("RemoteUDPPort"),
    })

L_IPDYNSTACK = Layout("Stack counters", [
    BITS(4, ("Shadow", 1), ("ClearDF", 1), ("SetDF", 1), ("ClearDSCP", 1),
         ("Rsvd1", 28)),
    U64("LifesizeCurrent"), U64("OutPackets"), U64("InPackets"),
    U64("OutBytes"), U64("InBytes")])

L_IPDYNIKE = Layout("IKE phase 2", [
    BITS(4, ("PendingNewP2", 1), ("Rsvd1", 31)),
    STR("FilterRule", 48), U32("PFSDHGroup", f="dh"),
    U8("LocalClientIDType", IDTYPE), U8("RemoteClientIDType", IDTYPE),
    U16("ExtState", P2STATE)])

L_IKETUN = Layout("IKE tunnel (phase 1)", [
    BITS(4, ("IPv6", 1), ("NATAllowed", 1), ("LocalNAT", 1),
         ("RemoteNAT", 1), ("RemoteNAPT", 1), ("CanInitP1", 1),
         ("FIPS140", 1), ("Rsvd1", 25)),
    STR("TunnelID", 48), STR("KeyExchangeRule", 48),
    STR("KeyExchangeAction", 48),
    IP("LocalEndpoint"), IP("RemoteEndpoint"),
    RAW("InitiatorCookie", 8), RAW("ResponderCookie", 8),
    U8("ExchangeMode", EXCH), U8("State", SASTATE), U8("AuthAlg", AUTH),
    U8("EncryptAlg", ENCR), U32("DHGroup", f="dh"),
    U8("PeerAuthMethod", AUTHMETH), U8("Role", ROLE),
    U8("NATTLevel", NATTLVL), U8("ExtState", P1STATE),
    U64("Lifesize"), U32("Lifetime", f="secs"),
    U32("LifetimeRefresh", f="time"), U32("LifetimeExpire", f="time"),
    U16("RemoteUDPPort"), U8("LocalIDType", IDTYPE),
    U8("RemoteIDType", IDTYPE), U32("StartTime", f="time"),
    U8("MajorVer", f="ver"), U8("MinorVer", f="ver"), U8("PRF"),
    U8("LocalAuthMethod", AUTHMETH),
    U32("ReauthInterval", f="secs"), U32("ReauthTime", f="time"),
    U32("Generation"), U32("EncryptKeyLength"),
    U8("LocalCertNotAfterType"), RAW("LocalCertNotAfter", 15, "text"),
    RAW("LocalCertSerial", 20), U16("LocalCertSerialLen"),
    U8("RemoteCertNotAfterType"), RAW("RemoteCertNotAfter", 15, "text"),
    RAW("RemoteCertSerial", 20), U16("RemoteCertSerialLen")],
    v6="IPv6",
    hide=("MinorVer", "LocalCertNotAfterType", "LocalCertSerialLen",
          "RemoteCertNotAfterType", "RemoteCertSerialLen"),
    custom={
        "MajorVer": _ikev,
        "LocalCertNotAfter": _cert_time("Local"),
        "LocalCertSerial": _cert_serial("Local"),
        "RemoteCertNotAfter": _cert_time("Remote"),
        "RemoteCertSerial": _cert_serial("Remote"),
        "ExchangeMode": lambda c: fmt_enum(c["ExchangeMode"], EXCH) if c.get("ExchangeMode") else None,
        "LocalAuthMethod": lambda c: fmt_enum(c["LocalAuthMethod"], AUTHMETH) if c.get("LocalAuthMethod") else None,
        "PRF": _nonzero("PRF"),
        "RemoteUDPPort": _nonzero("RemoteUDPPort"),
        "ReauthInterval": _nonzero("ReauthInterval", lambda v: "%ds" % v),
        "ReauthTime": _nonzero("ReauthTime", fmt_time),
    })

L_IKESTATS = Layout("IKE tunnel statistics", [
    U32("P2Current"), U32("P2InProgress"), U32("P2LocalActSuccess"),
    U32("P2RemoteActSuccess"), U32("P2LocalActFailure"),
    U32("P2RemoteActFailure"), U64("P1Bytes"), U64("P1Retransmits"),
    U64("P1Replays"), U64("P2Retransmits"), U64("P2Replays")])

L_PORTTRAN = Layout("Port translation", [
    IP4("RemoteAddr"), IP4("RemoteInnerAddr"), U8("Protocol", f="proto"),
    PAD(3), U16("OriginalPort"), U16("TranslatedPort")])

L_NSS = Layout("IKE NSS configuration", [
    STR("ClientName", 24), STR("StackName", 8), STR("Userid", 8),
    STR("ServerSysName", 8),
    BITS(4, ("Configured", 1), ("CertSvcSelected", 1), ("CertSvcEnabled", 1),
         ("MgmtSvcSelected", 1), ("MgmtSvcEnabled", 1), ("IPv6", 1),
         ("Rsvd1", 10), ("ServerConnectState", 16, SRVSTATUS)),
    IP("ClientAddr"), IP("ServerAddr"), U16("ClientPort"), U16("ServerPort"),
    U32("ConnectTime", f="time"), U32("LastMsgTime", f="time"),
    U64("FailedRequests"), U8("ClientAPIVersion"), U8("ServerAPIVersion"),
    PAD(2)],
    v6="IPv6", hide=("IPv6",))

L_INTERFACE = Layout("IP interface", [
    STR("Name", 16), IP("Address"), U8("SecurityClass"),
    BITS(3, ("IPv6", 1), ("Active", 1), ("DVIPA", 1), ("Rsvd1", 21))],
    v6="IPv6")

L_TUNCNTL = Layout("Control response", [U32("TunnelsProcessed")])

L_TUNNEL = Layout("Tunnel", [
    STR("Name", 48), STR("TunnelID", 48), U8("Status", TUNSTATUS), PAD(3)])

L_POLSRC = Layout("Policy source", [U8("Source"), PAD(3)])

# Input filter element (request side). Built by build_infilter().
INFILTER_SIZE = 4 + 16 + 16 + 1 + 1 + 2 + 2 + 2 + 16 + 16 + 48 * 4 + 2 + 1 + 1
assert INFILTER_SIZE == 272
TUNNEL_SIZE = L_TUNNEL.size
assert TUNNEL_SIZE == 100

ID_LOCAL = IdSection("Local identity", "LocalIDType")
ID_REMOTE = IdSection("Remote identity", "RemoteIDType")
ID_P2_LOCAL = IdSection("Local client identity", "LocalClientIDType")
ID_P2_REMOTE = IdSection("Remote client identity", "RemoteClientIDType")
ID_FLT_REMOTE = IdSection("Remote identity", "RemoteIdType")

# Section order per response record, by message type
SECTIONS = {
    2: [L_STACK, L_EXCL],
    3: [L_STATS],
    4: [L_IPFILTER, ID_FLT_REMOTE],
    5: [L_IPFILTER, ID_FLT_REMOTE],
    6: [L_IPFILTER, ID_FLT_REMOTE],
    7: [L_PORTTRAN],
    8: [L_IPTUN, L_IPMAN],
    9: [L_IPTUN, L_IPDYN, L_IPDYNSTACK],
    10: [L_IPTUN, L_IPDYN, L_IPDYNIKE, ID_P2_LOCAL, ID_P2_REMOTE],
    11: [L_IKETUN, L_IKESTATS, ID_LOCAL, ID_REMOTE],
    12: [L_IKETUN, L_IKESTATS, ID_LOCAL, ID_REMOTE],
    13: [L_INTERFACE],
    14: [L_NSS],
}
CASCADE_SECTIONS = SECTIONS[10]
for _t in range(1001, 1009):
    SECTIONS[_t] = [L_TUNCNTL, L_TUNNEL]

REC_TITLES = {
    2: "Stack", 3: "Summary", 4: "Current IP filter", 5: "Default IP filter",
    6: "Policy IP filter", 7: "Port translation", 8: "Manual tunnel",
    9: "Dynamic tunnel (stack view)", 10: "Dynamic tunnel (IKE/P2)",
    11: "IKE tunnel (P1)", 12: "IKE tunnel (P1)", 13: "IP interface",
    14: "IKE NSS", 101: "NSS client",
}


def record_title(mtype, c):
    es = lambda k: ebcdic_str(c.get(k, b"")) or "-"
    if mtype in (11, 12):
        return "%s  %s -> %s  %s  %s" % (
            es("TunnelID"), _ip(c, "LocalEndpoint"), _ip(c, "RemoteEndpoint"),
            _ikev(c), SASTATE.get(c.get("State"), "?"))
    if mtype in (8, 9, 10):
        return "%s  %s -> %s  %s" % (
            es("TunnelID"), _ip(c, "LocalEndpoint"), _ip(c, "RemoteEndpoint"),
            SASTATE.get(c.get("State"), "?"))
    if mtype in (4, 5, 6):
        return "%s  %s %s" % (es("Name"), FLT_ACTION.get(c.get("Action"), "?"),
                              FLT_DIR.get(c.get("Direction"), "?"))
    if mtype == 13:
        return "%s  %s" % (es("Name"), _ip(c, "Address"))
    if mtype == 2:
        return es("StackName")
    if mtype == 14:
        return es("ClientName")
    return ""


# --------------------------------------------------------------------------
# Weak-crypto / config annotations
# --------------------------------------------------------------------------
def weak_note(name, c):
    v = c.get(name)
    if name == "EncryptAlg":
        if v in (3, 18):
            return "[!] weak cipher"
        if v == 11:
            return "[!] NULL encryption"
        if v == 0 and c.get("AuthProto") == 50:
            return "[!] ESP without encryption"
    elif name == "AuthAlg":
        if v in (38, 40):
            return "[!] MD5"
        if v in (39, 41):
            return "[!] SHA-1"
        if v == 0 and c.get("EncryptAlg") != 20:
            return "[!] no integrity"
    elif name in ("DHGroup", "PFSDHGroup"):
        if v in (1, 2, 5, 22, 23, 24):
            return "[!] weak DH group"
        if name == "PFSDHGroup" and v == 0:
            return "(no PFS)"
    elif name == "ExchangeMode" and v == 4:
        if c.get("PeerAuthMethod") == 3:
            return "[!] aggressive mode + PSK: hash exposed to offline PSK cracking"
        return "[!] aggressive mode"
    elif name == "MajorVer" and (v or 0) & 0xF == 1:
        return "(IKEv1)"
    return None


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------
def fmt_field(f, v, c, layout):
    k = f[0]
    if k == "str":
        return ebcdic_str(v) or "-"
    if k == "raw":
        if f[3] == "text":
            return smart_text(v) or "-"
        return v.hex() if any(v) else "-"
    if k == "ip":
        return fmt_ip(v, c.get(layout.v6) if layout.v6 else 0)
    if k == "ip4":
        return fmt_ip(v, False)
    enum, fmt = f[2], f[3]
    if fmt == "time":
        return fmt_time(v)
    if fmt == "time64":
        return fmt_time(v) if 0 < v < 2 ** 32 else str(v)
    if fmt == "secs":
        return "%ds" % v if v else "-"
    if fmt == "hex":
        return "0x%08X" % v
    if fmt == "dh":
        return "group %d" % v if v else "none"
    if fmt == "proto":
        return fmt_proto(v)
    if fmt == "ver":
        return str(v & 0xF)
    if enum:
        return fmt_enum(v, enum)
    return str(v)


def render_fields(layout, vals, c):
    lines, flags = [], []
    for f in layout.fields:
        k = f[0]
        if k == "pad":
            continue
        if k == "bits":
            for item in f[2]:
                name, w = item[0], item[1]
                enum = item[2] if len(item) > 2 else None
                if name.startswith("Rsvd") or name in layout.hide or name not in vals:
                    continue
                v = vals[name]
                if w == 1 and enum is None:
                    if v:
                        flags.append(name)
                else:
                    lines.append((name, fmt_enum(v, enum) if enum else str(v)))
            continue
        name = f[1]
        if name.startswith("Rsvd") or name in layout.hide or name not in vals:
            continue
        if name in layout.custom:
            s = layout.custom[name](c)
            if s is None:
                continue
        else:
            s = fmt_field(f, vals[name], c, layout)
        note = weak_note(name, c)
        if note:
            s = "%s  %s" % (s, note)
        lines.append((name, s))
    if flags:
        lines.append(("Flags", ", ".join(flags)))
    return lines


def render_identity(raw, idtype):
    t = IDTYPE.get(idtype, str(idtype))
    try:
        if idtype == 1 and len(raw) >= 4:
            v = fmt_ip(raw, False)
        elif idtype == 5 and len(raw) >= 16:
            v = fmt_ip(raw, True)
        elif idtype in (4, 7) and len(raw) >= 8:
            sep = "/" if idtype == 4 else " - "
            v = fmt_ip(raw[:4], False) + sep + fmt_ip(raw[4:8], False)
        elif idtype in (6, 8) and len(raw) >= 32:
            sep = "/" if idtype == 6 else " - "
            v = fmt_ip(raw[:16], True) + sep + fmt_ip(raw[16:32], True)
        elif idtype == 11:
            v = raw.hex()
        else:
            v = smart_text(raw) or "-"
    except ValueError:
        v = "hex:" + raw.hex()
    return "%s %s" % (t, v)


def emit(lines, indent):
    for name, val in lines:
        print("%s%-24s %s" % (indent, name, val))


# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------
class Message(object):
    def __init__(self, data):
        self.data = data
        f = struct.unpack(HDR_FMT, data[:HDR_LEN])
        (self.ident, self.hdrlen, self.version, self.type, self.corr, _r1,
         self.rc, self.rsn, self.msglen, self.time, _r2, self.in_off, _r3,
         self.in_num, _r4, self.o1_off, self.o1_total, self.o1_num, _r5,
         self.o2_off, self.o2_total, self.o2_num, _r6, self.target) = f

    def status(self):
        return fmt_rc(self.rc, self.rsn)


def fmt_rc(rc, rsn):
    if not rc:
        return "rc=0"
    s = "rc=%d (%s) rsn=%d" % (rc, RC_NAMES.get(rc, "?"), rsn)
    name = RSN_NAMES.get(rc, {}).get(rsn)
    if name:
        s += " (%s)" % name
    hint = RC_HINTS.get((rc, rsn))
    if hint:
        s += "\n    hint: " + hint
    return s


def _resolve(data, rpos, rlen, off, size):
    """Map a descriptor offset to an absolute offset in the message.
    Offsets are normally record-relative; fall back to message-relative."""
    if size == 0:
        return None
    cand = rpos + off
    if off >= REC_HDR_LEN and off + size <= rlen and cand + size <= len(data):
        return cand
    if rpos <= off and off + size <= len(data):
        return off
    return -1


def parse_record(data, rpos):
    ident, rlen, ncasc, nsec = struct.unpack(REC_HDR_FMT, data[rpos:rpos + REC_HDR_LEN])
    if ident != REC_IDENT:
        raise ValueError("bad record ident %08X at offset %d" % (ident, rpos))
    descs = []
    p = rpos + REC_HDR_LEN
    for _ in range(ncasc + nsec):
        descs.append(struct.unpack(DESC_FMT, data[p:p + DESC_LEN]))
        p += DESC_LEN

    def build(order_secs_first):
        s_d = descs[:nsec] if order_secs_first else descs[ncasc:]
        c_d = descs[nsec:] if order_secs_first else descs[:ncasc]
        secs = [(_resolve(data, rpos, rlen, o, l * n), l, n) for o, l, n in s_d]
        casc = [(_resolve(data, rpos, rlen, o, l), l, n) for o, l, n in c_d]
        bad = sum(1 for a, _, _ in secs + casc if a == -1)
        return bad, secs, casc

    best = build(True)
    if ncasc and best[0]:
        alt = build(False)
        if alt[0] < best[0]:
            best = alt
    return {"pos": rpos, "len": rlen, "secs": best[1], "casc": best[2]}


def parse_records(data, off, num):
    recs, pos = [], off
    for _ in range(num):
        if pos + REC_HDR_LEN > len(data):
            break
        try:
            rec = parse_record(data, pos)
        except ValueError as e:
            print("    [!] %s" % e)
            break
        recs.append(rec)
        if rec["len"] <= 0:
            break
        pos += rec["len"]
    return recs


def render_record(data, rec, layouts, mtype, label, args, indent="  "):
    decoded = []
    ctx = {}
    for i, (abs_off, slen, snum) in enumerate(rec["secs"]):
        lay = layouts[i] if i < len(layouts) else None
        elems = []
        if abs_off not in (None, -1):
            for j in range(snum):
                elems.append(data[abs_off + j * slen: abs_off + (j + 1) * slen])
        decoded.append((lay, elems, slen, abs_off))
        if isinstance(lay, Layout) and elems:
            ctx.update(decode(lay, elems[0]))

    title = record_title(mtype, ctx)
    print("%s=== %s%s ===" % (indent, label, (": " + title) if title else ""))
    sub = indent + "  "
    for idx, (lay, elems, slen, abs_off) in enumerate(decoded):
        if abs_off == -1:
            print("%s[!] section %d descriptor out of bounds" % (sub, idx))
            continue
        if not elems:
            continue
        if isinstance(lay, IdSection):
            idtype = ctx.get(lay.typekey, 0)
            for e in elems:
                emit([(lay.title, render_identity(bytes(e), idtype))], sub)
        elif isinstance(lay, Layout):
            for j, e in enumerate(elems):
                if idx > 0 or len(elems) > 1:
                    print("%s-- %s%s --" % (sub, lay.title,
                                            " %d" % (j + 1) if len(elems) > 1 else ""))
                vals = decode(lay, e)
                c = dict(ctx)
                c.update(vals)
                emit(render_fields(lay, vals, c), sub)
                if args.debug and len(e) != lay.size:
                    print("%s(section length %d, layout expects %d)" % (sub, len(e), lay.size))
        else:
            print("%s-- unknown section %d (%d x %d bytes) --" % (sub, idx, len(elems), slen))
            for e in elems:
                for ln in hexdump(e, sub):
                    print(ln)
        if args.raw:
            for e in elems:
                for ln in hexdump(e, sub + "  "):
                    print(ln)

    for abs_off, clen, cnum in rec["casc"]:
        if abs_off in (None, -1) or not cnum:
            continue
        print("%s-- %d associated phase 2 tunnel(s) --" % (sub, cnum))
        for k, crec in enumerate(parse_records(data, abs_off, cnum)):
            render_record(data, crec, CASCADE_SECTIONS, 10,
                          "P2 %d/%d" % (k + 1, cnum), args, sub + "  ")


def render_message(msg, args):
    data = msg.data
    layouts = SECTIONS.get(msg.type, [])
    base = REC_TITLES.get(msg.type, MSG_TYPES.get(msg.type, "Record"))
    recs = parse_records(data, msg.o1_off, msg.o1_num)
    if not recs:
        print("  (no records)")
    for i, rec in enumerate(recs):
        render_record(data, rec, layouts, msg.type,
                      "%s %d/%d" % (base, i + 1, len(recs)), args)
    if msg.o2_num:
        sec_layouts = CASCADE_SECTIONS if msg.type == 12 else layouts
        print("  --- %d secondary record(s) ---" % msg.o2_num)
        for i, rec in enumerate(parse_records(data, msg.o2_off, msg.o2_num)):
            render_record(data, rec, sec_layouts, 10 if msg.type == 12 else msg.type,
                          "Secondary %d/%d" % (i + 1, msg.o2_num), args)


# --------------------------------------------------------------------------
# Request building
# --------------------------------------------------------------------------
def build_header(mtype, corr, msglen, target, in_off=0, in_num=0):
    return struct.pack(HDR_FMT, MSG_IDENT, HDR_LEN, NMI_VERSION, mtype, corr,
                       0, 0, 0, msglen, 0, b"", in_off, 0, in_num, b"",
                       0, 0, 0, 0, 0, 0, 0, 0, target)


def build_inrec(elements, elem_size, offset_base):
    payload = b"".join(elements)
    sec_off = REC_HDR_LEN + DESC_LEN
    if offset_base == "message":
        sec_off += HDR_LEN
    rec = struct.pack(REC_HDR_FMT, REC_IDENT, REC_HDR_LEN + DESC_LEN + len(payload), 0, 1)
    rec += struct.pack(DESC_FMT, sec_off, elem_size, len(elements))
    return rec + payload


def _ipbytes(s):
    a = ipaddress.ip_address(s)
    b = a.packed
    return b + b"\x00" * (16 - len(b)), a.version == 6


def _name(s, size, blank):
    if s is None:
        return b"\x00" * size
    return ebcdic_encode(s, size, 0x40 if blank else 0x00)


def build_infilter(args):
    """Return an NMsecInFilter element, or None if no filter options given."""
    keys = ("src", "dst", "proto", "sport", "dport", "local", "remote",
            "tunnel_id", "name", "group", "assoc", "state")
    if not any(getattr(args, k, None) is not None for k in keys):
        return None
    flags = 0
    v6 = False
    addrs = {}
    bit = {"ipv6": 31, "src": 30, "dst": 29, "proto": 28, "sport": 27,
           "dport": 26, "local": 25, "remote": 24, "tunnel_id": 23,
           "name": 22, "group": 21, "assoc": 20, "state": 19}
    for k in ("src", "dst", "local", "remote"):
        val = getattr(args, k, None)
        if val is not None:
            b, is6 = _ipbytes(val)
            if addrs and is6 != v6:
                raise SystemExit("[-] cannot mix IPv4 and IPv6 filter addresses")
            v6 = is6
            addrs[k] = b
            flags |= 1 << bit[k]
    for k in ("proto", "sport", "dport", "tunnel_id", "name", "group",
              "assoc", "state"):
        if getattr(args, k, None) is not None:
            flags |= 1 << bit[k]
    if v6:
        flags |= 1 << bit["ipv6"]
    state = 0
    if args.state is not None:
        st = args.state.upper()
        rev = dict((v, k) for k, v in SASTATE.items())
        state = int(st) if st.isdigit() else rev.get(st)
        if state is None:
            raise SystemExit("[-] unknown --state %s (use %s)" % (args.state, ",".join(SASTATE.values())))
    z16 = b"\x00" * 16
    blank = args.blank_pad
    elem = struct.pack(">I", flags)
    elem += addrs.get("src", z16) + addrs.get("dst", z16)
    elem += struct.pack(">BBHHH", args.proto or 0, 0, args.sport or 0, args.dport or 0, 0)
    elem += addrs.get("local", z16) + addrs.get("remote", z16)
    elem += _name(args.tunnel_id, 48, blank) + _name(args.name, 48, blank)
    elem += _name(args.group, 48, blank) + _name(args.assoc, 48, blank)
    elem += struct.pack(">HBB", 0, state, 0)
    assert len(elem) == INFILTER_SIZE
    return elem


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------
class NMIError(Exception):
    pass


class NMIClient(object):
    def __init__(self, path, timeout, target, debug=False):
        self.path, self.timeout, self.target, self.debug = path, timeout, target, debug
        self.sock = None
        self.init = None
        self.seq = 0

    def connect(self):
        self.close()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.path)
        except OSError as e:
            s.close()
            raise NMIError("connect(%s): %s" % (self.path, e))
        self.sock = s
        self.init = self._read()
        if self.init.ident != MSG_IDENT:
            raise NMIError("unexpected ident %08X in server greeting" % self.init.ident)
        return self.init

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _recvn(self, n):
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except socket.timeout:
                raise NMIError("timed out waiting for IKED (%d/%d bytes)" % (len(buf), n))
            except OSError as e:
                raise NMIError("recv: %s" % e)
            if not chunk:
                raise NMIError("IKED closed the connection (%d/%d bytes)" % (len(buf), n))
            buf += chunk
        return bytes(buf)

    def _read(self):
        hdr = self._recvn(HDR_LEN)
        msglen = struct.unpack(">I", hdr[40:44])[0]
        if msglen < HDR_LEN or msglen > MAX_MSG:
            raise NMIError("implausible message length %d" % msglen)
        data = hdr + self._recvn(msglen - HDR_LEN)
        if self.debug:
            print("[debug] <<< received %d bytes" % len(data))
            for ln in hexdump(data):
                print(ln)
        return Message(data)

    def request(self, mtype, inrec=b""):
        self.seq += 1
        corr = b"ikednmi\x00" + struct.pack(">Q", self.seq)
        in_off = HDR_LEN if inrec else 0
        msg = build_header(mtype, corr, HDR_LEN + len(inrec), self.target,
                           in_off, 1 if inrec else 0) + inrec
        if self.debug:
            print("[debug] >>> sending %s (%d bytes)" % (MSG_TYPES.get(mtype, mtype), len(msg)))
            for ln in hexdump(msg):
                print(ln)
        try:
            self.sock.sendall(msg)
        except OSError as e:
            raise NMIError("send: %s" % e)
        reply = self._read()
        if reply.type == 1:
            raise NMIError("IKED sent TERM: " + reply.status())
        if reply.corr != corr and any(reply.corr):
            print("[!] correlator mismatch on reply")
        return reply


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def print_banner(cli, init):
    print("[+] %s: IPsec NMI v%d, INIT %s, server time %s" % (
        cli.path, init.version, init.status(), fmt_time(init.time)))


def run_get(cli, mtype, args, inrec=b""):
    name = MSG_TYPES.get(mtype, str(mtype))
    reply = cli.request(mtype, inrec)
    extra = ""
    if not reply.rc:
        extra = "  records: %d returned / %d matched" % (reply.o1_num, reply.o1_total)
    print("\n[*] %s: %s%s" % (name, reply.status(), extra))
    if not reply.rc:
        render_message(reply, args)
    return reply


def filter_inrec(args):
    elem = build_infilter(args)
    if elem is None:
        return b""
    return build_inrec([elem], INFILTER_SIZE, args.sec_offset_base)


TUNNEL_KINDS = {"manual": 8, "dynstack": 9, "dynike": 10, "ike": 11, "cascade": 12}
FILTER_SETS = {"current": 4, "default": 5, "policy": 6}
CONTROL_ACTIONS = {
    "activate-manual": 1001, "activate-dyn": 1002,
    "deactivate-manual": 1003, "deactivate-dyn": 1004,
    "deactivate-ike": 1005, "refresh-dyn": 1006, "refresh-ike": 1007,
    "load-policy": 1008,
}


def cmd_info(cli, args):
    i = cli.init
    print("    ident        %08X (%s)" % (i.ident, ebcdic_decode(struct.pack(">I", i.ident))))
    print("    nmi version  %d" % i.version)
    print("    server time  %s (raw 0x%08X)" % (fmt_time(i.time), i.time))
    print("    target       %r" % ebcdic_str(i.target))


def cmd_simple(mtype):
    def f(cli, args):
        run_get(cli, mtype, args, filter_inrec(args) if mtype not in (2, 3, 13, 14) else b"")
    return f


def cmd_filters(cli, args):
    run_get(cli, FILTER_SETS[args.set], args, filter_inrec(args))


def cmd_tunnels(cli, args):
    run_get(cli, TUNNEL_KINDS[args.kind], args, filter_inrec(args))


def cmd_get(cli, args):
    if args.type >= 1000 or args.type in (0, 1):
        raise SystemExit("[-] 'get' only sends read-only types (2-999); use 'control'")
    run_get(cli, args.type, args, filter_inrec(args))


def cmd_all(cli, args):
    for mtype in (2, 3, 13, 14, 4, 7, 8, 9, 11, 10):
        try:
            run_get(cli, mtype, args)
        except NMIError as e:
            print("\n[-] %s: %s" % (MSG_TYPES[mtype], e))
            try:
                cli.connect()
            except NMIError as e2:
                print("[-] reconnect failed: %s" % e2)
                return


def cmd_control(cli, args):
    mtype = CONTROL_ACTIONS[args.action]
    name = MSG_TYPES[mtype]
    if mtype == 1008:
        if args.source is not None:
            inrec = build_inrec([struct.pack(">B3x", args.source)], 4, args.sec_offset_base)
            what = "policy source %d" % args.source
        else:
            inrec, what = b"", "no input record"
    else:
        tunnels = [(None, t) for t in (args.tunnel_id or [])]
        tunnels += [(n, None) for n in (args.name or [])]
        if not tunnels:
            raise SystemExit("[-] %s needs at least one --tunnel-id or --name" % args.action)
        elems = []
        for n, t in tunnels:
            elems.append(_name(n, 48, args.blank_pad) + _name(t, 48, args.blank_pad) + b"\x00" * 4)
        inrec = build_inrec(elems, TUNNEL_SIZE, args.sec_offset_base)
        what = ", ".join(("name=%s" % n) if n else ("tunnel-id=%s" % t) for n, t in tunnels)

    if not args.i_have_authorization:
        raise SystemExit("[-] %s changes live IPsec state on the target. Re-run with "
                         "--i-have-authorization once it is in scope and approved." % name)
    print("[!] About to send %s (%d) to %s: %s" % (name, mtype, cli.path, what))
    if not args.yes:
        try:
            ans = input("[?] Type YES to send: ")
        except EOFError:
            ans = ""
        if ans.strip() != "YES":
            raise SystemExit("[-] aborted, nothing sent")
    run_get(cli, mtype, args, inrec)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def add_filter_opts(p):
    g = p.add_argument_group("input filters (optional, AND-ed by IKED)")
    g.add_argument("--src", help="traffic source address")
    g.add_argument("--dst", help="traffic destination address")
    g.add_argument("--proto", type=int, help="IP protocol number")
    g.add_argument("--sport", type=int, help="source port")
    g.add_argument("--dport", type=int, help="destination port")
    g.add_argument("--local", help="local security endpoint")
    g.add_argument("--remote", help="remote security endpoint")
    g.add_argument("--tunnel-id", help="tunnel ID")
    g.add_argument("--name", help="object (rule/filter) name")
    g.add_argument("--group", help="object group name")
    g.add_argument("--assoc", help="associated object name")
    g.add_argument("--state", help="SA state: " + ",".join(SASTATE.values()))


def build_parser():
    p = argparse.ArgumentParser(
        prog="ikednmi.py",
        description="Query the z/OS IKED IPsec Network Management Interface.")
    p.add_argument("-V", "--version", action="version", version="%(prog)s " + __version__)
    p.add_argument("-s", "--socket", default=DEFAULT_SOCKET,
                   help="NMI socket path (default %(default)s)")
    p.add_argument("-t", "--target", default=None,
                   help="NMsMTarget value, e.g. a TCP/IP stack name (default: blanks)")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds (default 10)")
    p.add_argument("--raw", action="store_true", help="hexdump every section too")
    p.add_argument("--debug", action="store_true", help="hexdump full messages sent/received")
    p.add_argument("--blank-pad", action="store_true",
                   help="pad input names with EBCDIC blanks instead of nulls")
    p.add_argument("--sec-offset-base", choices=("record", "message"), default="record",
                   help="base for input section offsets (default record)")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    sub.add_parser("info", help="handshake only: NMI version and server time")
    sub.add_parser("stack", help="stack IPsec configuration")
    sub.add_parser("summary", help="P1/P2/filter statistics")
    sub.add_parser("interfaces", help="IP interfaces and security classes")
    sub.add_parser("nss", help="IKE Network Security Services configuration")
    sp = sub.add_parser("porttran", help="NAT-T port translations")
    add_filter_opts(sp)
    sp = sub.add_parser("filters", help="IP filters")
    sp.add_argument("--set", choices=sorted(FILTER_SETS), default="current")
    add_filter_opts(sp)
    sp = sub.add_parser("tunnels", help="IPsec / IKE tunnels")
    sp.add_argument("kind", nargs="?", choices=sorted(TUNNEL_KINDS), default="ike")
    add_filter_opts(sp)
    sub.add_parser("all", help="every read-only query")
    sp = sub.add_parser("get", help="send any read-only message type by number")
    sp.add_argument("type", type=int)
    add_filter_opts(sp)
    sp = sub.add_parser("control", help="state-changing requests (gated)")
    sp.add_argument("action", choices=sorted(CONTROL_ACTIONS))
    sp.add_argument("--tunnel-id", action="append", help="tunnel ID (repeatable)")
    sp.add_argument("--name", action="append", help="tunnel/rule name (repeatable)")
    sp.add_argument("--source", type=int, help="load-policy: policy source value")
    sp.add_argument("--i-have-authorization", action="store_true",
                    help="confirm this action is in scope and approved")
    sp.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    return p


COMMANDS = {
    "info": cmd_info, "stack": cmd_simple(2), "summary": cmd_simple(3),
    "interfaces": cmd_simple(13), "nss": cmd_simple(14),
    "porttran": cmd_simple(7), "filters": cmd_filters, "tunnels": cmd_tunnels,
    "all": cmd_all, "get": cmd_get, "control": cmd_control,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    for k in ("src", "dst", "proto", "sport", "dport", "local", "remote",
              "group", "assoc", "state"):
        if not hasattr(args, k):
            setattr(args, k, None)
    if args.cmd != "control":
        for k in ("tunnel_id", "name"):
            if not hasattr(args, k):
                setattr(args, k, None)
    target = b"\x40" * 24 if args.target is None else ebcdic_encode(args.target.upper(), 24)

    cli = NMIClient(args.socket, args.timeout, target, args.debug)
    try:
        init = cli.connect()
        print_banner(cli, init)
        if init.rc:
            return 1
        COMMANDS[args.cmd](cli, args)
    except NMIError as e:
        print("[-] %s" % e)
        return 1
    except KeyboardInterrupt:
        print("\n[-] interrupted")
        return 130
    finally:
        cli.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
