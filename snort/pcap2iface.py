#!/usr/bin/env python3
"""Read a classic PCAP stream from stdin and transmit every frame on the given
Linux interface (AF_PACKET). Snort listens on the same interface with -i.

Usage: dumpcap.exe -i Ethernet -F pcap -q -w - | sudo pcap2iface.py snort0
"""
import socket
import struct
import sys


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: pcap2iface.py <interface>  (PCAP on stdin)")
    iface = sys.argv[1]
    inp = sys.stdin.buffer
    hdr = inp.read(24)
    if len(hdr) < 24:
        sys.exit("no PCAP header on stdin (did you pass -F pcap to dumpcap?)")
    magic = hdr[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        sys.exit("unknown magic %s - pcapng is not supported, use dumpcap -F pcap" % magic.hex())
    linktype = struct.unpack(endian + "I", hdr[20:24])[0] & 0x0FFFFFFF
    if linktype != 1:
        sys.exit("linktype %d is not Ethernet (1) - pick an Ethernet/Wi-Fi adapter" % linktype)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    rec = struct.Struct(endian + "IIII")
    sent = skipped = 0
    while True:
        h = inp.read(16)
        if len(h) < 16:
            break
        _, _, incl, _ = rec.unpack(h)
        frame = inp.read(incl)
        if len(frame) < incl:
            break
        try:
            s.send(frame)
            sent += 1
        except OSError as e:
            skipped += 1
            if skipped <= 5 or skipped % 1000 == 0:
                print("skipped frame (%d bytes): %s" % (incl, e), file=sys.stderr)
    print("end of stream: sent %d, skipped %d" % (sent, skipped), file=sys.stderr)


if __name__ == "__main__":
    main()
