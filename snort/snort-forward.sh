#!/bin/sh
# Forward the Windows capture (Npcap + dumpcap.exe via WSL interop) into the
# WSL dummy interface that Snort listens on. Runs forever and restarts the
# pipe if it breaks. Must run as root (raw AF_PACKET socket).
#
# Started by snort-forward.service (systemd, at WSL boot) and optionally by the
# Windows logon task. Only one instance forwards at a time: a second instance
# waits on the lock (two forwarders would inject every packet twice). A waiting
# instance started from Windows keeps its wsl.exe, and so the WSL VM, running,
# and it takes over if the forwarding instance stops.
#
# Override with environment variables, e.g.:
#   WIN_IFACE="Wi-Fi" CAPTURE_FILTER="not port 3389" snort-forward.sh

WIN_IFACE="${WIN_IFACE:-Ethernet}"
LINUX_IFACE="${LINUX_IFACE:-snort0}"
DUMPCAP="${DUMPCAP:-/mnt/c/Program Files/Wireshark/dumpcap.exe}"
CAPTURE_FILTER="${CAPTURE_FILTER:-}"
PCAP2IFACE="${PCAP2IFACE:-/usr/local/bin/pcap2iface.py}"
LOCK_FILE="${LOCK_FILE:-/run/snort-forward.lock}"

# Windows programs started from a Linux directory print a "UNC paths are not
# supported" warning; a plain root directory avoids it.
cd / || exit 1

exec 9>"$LOCK_FILE" || exit 1
if ! flock -n 9; then
    echo "snort-forward: another forwarder is running, waiting for it to stop..." >&2
    flock 9 || exit 1
fi

while true; do
    if ! ip link show "$LINUX_IFACE" >/dev/null 2>&1; then
        echo "snort-forward: interface $LINUX_IFACE missing, waiting..." >&2
        sleep 5
        continue
    fi
    echo "snort-forward: $WIN_IFACE (Windows) -> $LINUX_IFACE (WSL)" >&2
    if [ -n "$CAPTURE_FILTER" ]; then
        "$DUMPCAP" -i "$WIN_IFACE" -F pcap -q -f "$CAPTURE_FILTER" -w - 9>&- | "$PCAP2IFACE" "$LINUX_IFACE" 9>&-
    else
        "$DUMPCAP" -i "$WIN_IFACE" -F pcap -q -w - 9>&- | "$PCAP2IFACE" "$LINUX_IFACE" 9>&-
    fi
    echo "snort-forward: pipe ended, restarting in 5 s" >&2
    sleep 5
done
