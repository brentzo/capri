"""Minimal, non-recursive DNS responder for pinned in-range Android targets."""

import ipaddress
import struct
import socket
import sys


def _question(packet):
    if len(packet) < 17:
        raise ValueError("short DNS packet")
    offset, labels = 12, []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        size = packet[offset]
        offset += 1
        if size == 0:
            break
        if size & 0xC0 or size > 63 or offset + size > len(packet):
            raise ValueError("unsupported DNS name encoding")
        labels.append(packet[offset:offset + size].decode("ascii"))
        offset += size
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    return ".".join(labels).lower(), packet[12:offset + 4], offset + 4


def answer(packet, records):
    """Answer A questions for pinned names; return NXDOMAIN for every other name."""
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    ident, flags, questions = struct.unpack_from("!HHH", packet)
    if flags & 0x8000 or flags & 0x7800 or questions != 1:
        raise ValueError("unsupported DNS message")
    name, question, end = _question(packet)
    qtype, qclass = struct.unpack_from("!HH", question, len(question) - 4)
    known = name in records and qclass == 1
    ip = records.get(name) if known and qtype == 1 else None
    rcode = 0 if known else 3
    header = struct.pack("!HHHHHH", ident, 0x8180 | rcode, 1,
                         int(ip is not None), 0, 0)
    if ip is None:
        return header + packet[12:end]
    address = ipaddress.IPv4Address(ip).packed
    resource = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, len(address)) + address
    return header + packet[12:end] + resource


def serve(records, allowed_source="0.0.0.0"):
    """Serve one UDP DNS query at a time and ignore all non-emulator clients."""
    allowed = ipaddress.IPv4Address(allowed_source)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", 53))
        while True:
            packet, (source, port) = server.recvfrom(2048)
            if ipaddress.IPv4Address(source) != allowed:
                continue
            try:
                reply = answer(packet, records)
            except (ValueError, UnicodeDecodeError):
                continue
            server.sendto(reply, (source, port))


if __name__ == "__main__":
    import json

    serve(json.loads(sys.argv[1]), sys.argv[2])
