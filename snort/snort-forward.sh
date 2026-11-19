#!/bin/sh
# Forward the Windows capture (Npcap + dumpcap.exe via WSL interop) into the
# WSL dummy interface that Snort listens on. Runs forever and restarts the
# pipe if it breaks. Must run as root (raw AF_PACKET socket).
#
# Override with environment variables, e.g.:
#   WIN_IFACE="Wi-Fi" CAPTURE_FILTER="not port 3389" snort-forward.sh

WIN_IFACE="${WIN_IFACE:-Ethernet}"
LINUX_IFACE="${LINUX_IFACE:-snort0}"
DUMPCAP="${DUMPCAP:-/mnt/c/Program Files/Wireshark/dumpcap.exe}"
CAPTURE_FILTER="${CAPTURE_FILTER:-}"
PCAP2IFACE="${PCAP2IFACE:-/usr/local/bin/pcap2iface.py}"

while true; do
    if ! ip link show "$LINUX_IFACE" >/dev/null 2>&1; then
        echo "snort-forward: interface $LINUX_IFACE missing, waiting..." >&2
        sleep 5
        continue
    fi
    echo "snort-forward: $WIN_IFACE (Windows) -> $LINUX_IFACE (WSL)" >&2
    if [ -n "$CAPTURE_FILTER" ]; then
        "$DUMPCAP" -i "$WIN_IFACE" -F pcap -q -f "$CAPTURE_FILTER" -w - | "$PCAP2IFACE" "$LINUX_IFACE"
    else
        "$DUMPCAP" -i "$WIN_IFACE" -F pcap -q -w - | "$PCAP2IFACE" "$LINUX_IFACE"
    fi
    echo "snort-forward: pipe ended, restarting in 5 s" >&2
    sleep 5
done
