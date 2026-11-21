# Network view: setup and tools

The **Network** tab shows who your computer is talking to right now. Your machine sits in the
centre of a connection map. Around it is every remote address with an open connection, grouped
by the process that owns it (or by service or network). The map also shows addresses that Snort
or AppID saw during the last hour.

Select a host to see:

- its connections
- the Snort alerts that involve it, grouped by signature
- what AppID recognised
- its names (from TLS SNI and HTTP Host lines in `appid.json`, reverse DNS, and DNS answers captured by tshark)

From the same panel you can run a **traceroute** or, for devices in your own network, an
**nmap port scan**.

The **1 h / 6 h / 24 h** switch sets how much of the Snort and AppID logs is used. Hosts that
match a simple rule (P1/P2 alerts, rising alerts, inbound connections from the internet, …)
get a badge on the map and are listed under **Needs attention**. See
[Signals: why a host is flagged](#signals-why-a-host-is-flagged).

The view works on Linux and on Windows. It runs the operating system's own tools, so nothing has
to be configured for the basic map. The optional tools below add more detail.

- [What each part needs](#what-each-part-needs)
- [Linux (and WSL)](#linux-and-wsl)
- [Windows host monitored from WSL](#windows-host-monitored-from-wsl)
- [Running the server natively on Windows](#running-the-server-natively-on-windows)
- [Hostnames from the wire (tshark)](#hostnames-from-the-wire-tshark)
- [Port scans and LAN discovery (nmap)](#port-scans-and-lan-discovery-nmap)
- [One device, several addresses](#one-device-several-addresses)
- [Signals: why a host is flagged](#signals-why-a-host-is-flagged)
- [Settings](#settings)
- [API](#api)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

---

## What each part needs

| Feature | Linux / WSL side | Windows side | Required? |
|---|---|---|---|
| Connections and processes | `ss` (iproute2), or `netstat` (net-tools) | `netstat -ano` + `tasklist` (built in) | yes, at least one |
| LAN neighbours (MAC addresses) | `ip neigh`, or `arp` (net-tools) | `arp -a` (IPv4) + `netsh interface ipv6 show neighbors` (IPv6), built in | no |
| Default gateway | `ip route` | (taken from the Linux side) | no |
| Traceroute | `traceroute` | `tracert` (built in) | no |
| Port scan, LAN discovery | `nmap` | `nmap.exe` (Nmap for Windows) | no |
| Hostnames from DNS answers / TLS SNI | `tshark` | – | no |
| Reverse DNS | Node.js built-in | Node.js built-in | – |
| Snort alerts and AppID per host | the existing Snort logs | – | no |

Tools are looked up on every request, so a tool you install shows up without restarting the
server. A missing tool only disables its button; the tooltip on the button says what is missing.

---

## Linux (and WSL)

Install the tools (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install nmap traceroute net-tools tshark
```

- `iproute2` (`ss`, `ip`) is already installed on practically every distribution. `net-tools`
  (`netstat`, `arp`) is only a fallback.
- During the `tshark` install, Debian asks whether non-superusers may capture packets. Either
  answer works, because the server runs as root (see the README).

On Fedora: `sudo dnf install nmap traceroute net-tools wireshark-cli`.
On Arch: `sudo pacman -S nmap traceroute net-tools wireshark-cli`.

Then restart the server:

```bash
cd server
sudo env "PATH=$PATH" npm start
```

The server needs root for two reasons:

- With root, `ss -p` shows the process of *every* socket, not only your own.
- tshark needs root to capture.

---

## Windows host monitored from WSL

This is the setup from [ENVIRONMENT.md](ENVIRONMENT.md): Windows traffic is forwarded into WSL
and Snort runs there. The server detects WSL and offers two sources at the top of the tab:

| Source | What it lists | How |
|---|---|---|
| **Windows host** (default) | connections of Windows programs such as browsers and Windows services | `C:\Windows\System32\netstat.exe -ano`, `tasklist.exe`, `arp.exe`, run through WSL interop |
| **WSL** | connections of Linux processes inside WSL | `ss`, `ip neigh` |

Snort sees the Windows traffic, so the **Windows host** source is the one whose connections
match the alerts.

Requirements:

1. **WSL interop is enabled.** It is by default. Check with:
   ```bash
   ls /proc/sys/fs/binfmt_misc/WSLInterop && /mnt/c/Windows/System32/netstat.exe -ano | head -3
   ```
   If `/etc/wsl.conf` has `[interop] enabled = false`, remove that line and run `wsl --shutdown`
   in Windows.
2. **`C:` is mounted at `/mnt/c`**, which is the default. If you changed `automount.root`, the
   Windows tools are not found.
3. **Optional: Nmap for Windows.** Install it from <https://nmap.org/download.html>. The server
   uses `C:\Program Files (x86)\Nmap\nmap.exe` when Linux `nmap` is missing. Linux `nmap` in WSL
   is the simpler choice. With mirrored networking (below) it reaches your LAN directly.
4. **Optional: mirrored networking.** With `networkingMode=mirrored` in `%UserProfile%\.wslconfig`,
   WSL shares the Windows IP address and gateway, so traceroute and nmap from WSL see the same
   network as Windows. See [ENVIRONMENT.md § 3](ENVIRONMENT.md#3-prerequisites).

IPv6 neighbours (your router's IPv6 address, phones, …) come from
`netsh interface ipv6 show neighbors`, because `arp -a` lists only IPv4.

Process names come from `tasklist`. Sockets owned by PID 0 are connections that are closing
(`TIME_WAIT`), so they are shown as `(closing)`.

**Packet data from Wireshark.** No extra capture is needed on the Windows side. The forwarder
from [ENVIRONMENT.md § 7](ENVIRONMENT.md#7-run-manually-first-test) already copies the Windows capture (Npcap/`dumpcap`) into the WSL
interface `snort0`. Snort reads that interface, and tshark can read the same interface (see
[below](#hostnames-from-the-wire-tshark)).

---

## Running the server natively on Windows

The server also runs on plain Windows without WSL, but without Snort the Snort and AppID parts
stay empty.

1. Install Node.js 18 or newer for Windows.
2. Optional: install Nmap for Windows (<https://nmap.org/download.html>).
3. In an **elevated** PowerShell (needed for the process names of services):
   ```powershell
   cd server
   npm install
   npm start
   ```
4. Start the client as described in the README and open the **Network** tab.

`netstat`, `tasklist`, `arp` and `tracert` are built into Windows. The tshark name capture runs
only on Linux.

---

## Hostnames from the wire (tshark)

AppID names only TLS and HTTP servers. To get a name for (almost) every address, the server can
run tshark in the background. tshark reads the same interface that Snort reads and remembers
which name each address had:

- **DNS answers:** `example.com → 93.184.216.34`
- **TLS ClientHello SNI:** the server name a browser asked for

```text
tshark -i snort0 -n -l -Q -T fields \
  -Y "dns.flags.response == 1 || tls.handshake.extensions_server_name" \
  -e ip.dst -e ipv6.dst -e dns.qry.name -e dns.a -e dns.aaaa -e tls.handshake.extensions_server_name
```

- It starts automatically the first time the Network tab is opened, if `tshark` is installed and
  the interface exists.
- The interface is `NET_CAPTURE_IFACE` if set, otherwise `snort0` if it exists (the WSL setup),
  otherwise the interface of the default route (for example `eth0` on a plain Linux machine).
- Only names and addresses are kept, in memory. They are lost when the server restarts, and no
  packets are stored.
- If tshark stops, the reason is shown under the map and the server tries again a minute later.

These names are what the DNS answer or the browser said. For content delivery networks they are
often generic, such as `*.cloudfront.net`.

---

## Port scans and LAN discovery (nmap)

- **Port scan** (in the host panel) runs `nmap -Pn -sV --version-light -F <ip>`. That is a service
  and version check of the 100 most common ports, and it takes from a few seconds to two minutes.
- **Discover LAN** (in the toolbar) runs `nmap -sn` on your private IPv4 networks (/22 to /30),
  which finds devices that are on but not yet in the ARP table.

**Scans are limited to your own network.** The server refuses addresses outside private,
link-local and loopback ranges (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7,
fe80::/10, 127/8). Scanning hosts you do not own or administer may be illegal and is often
against your ISP's terms. Only scan your own devices. On a network you do not manage, such as
work or a dormitory, ask the administrator first.

At most two traceroutes or scans run at a time.

---

## One device, several addresses

A device usually has an IPv4 address, a global IPv6 address and a link-local `fe80::` address.
The map shows them as **one host** when they belong together:

- they have the same MAC address in the neighbour tables (`arp`, `ip neigh`, `netsh`), or
- an IPv6 address has the MAC address built into it (EUI-64: `…:xxff:fexx:…`, as in
  `fe80::6c14:8aff:feb2:d281` → MAC `6e:14:8a:b2:d2:81`).

The host is named by its IPv4 address. The panel lists all addresses and all names (for
example `dna.wlan`, `dna6.wlan`), and the alert and AppID counts are summed over the addresses.
A router is marked as the gateway even when only its IPv6 address is talking. Phones often use
a random ("private") MAC address per network. That still works, because the IPv4 and IPv6
addresses share the same random MAC.

---

## Signals: why a host is flagged

The server counts, per address, the Snort alerts (by priority and signature) and the AppID
sessions of the selected window, also per time slice (`GET /network/history`). It reads the
logs backwards from the end only as far as the window reaches, including rotated
`alert_json.txt.<time>` files. The browser then applies these rules:

| Signal | Level | Rule |
|---|---|---|
| P1 alerts | high (red badge) | Snort raised priority 1 alerts involving the address |
| P2 alerts | warning | priority 2 alerts |
| Alerts rising | warning | ≥ 5 alerts in the last 10 min and ≥ 3 × the rate of the rest of the window (needs ≥ 20 min of earlier log) |
| Inbound from the internet | warning | an open **TCP** connection that a public address made to a listening port. UDP is left out: every bound UDP socket looks like a listener, so its direction cannot be told |
| Service on unexpected port | warning | AppID named a service (HTTP, SSH, DNS, SMTP, RDP, …) on a port that service does not normally use |
| New | info (dashed ring) | first appeared in the logs in the last 10 min, after ≥ 30 min of log without it |
| Uncommon remote port | info | an open outbound connection to a public address on a port that is not a well-known service port |

There is deliberately **no combined risk score**. The weights of such a score would be made up,
and a single number hides the reason. Each signal is shown with its reason and the numbers
behind it. Needs attention lists hosts by their most serious signal, then by how many signals
they have, then by alert volume.

Notes:

- The signals are counted from the logs and do not judge whether traffic is malicious. A noisy
  rule (for example UPnP advertisements from the router) flags its source every time. Tune or
  suppress such rules in Snort if they are not useful.
- *Service on unexpected port* needs AppID to name applications. If AppID reports every
  session as `unknown`, the OpenAppID detector package (ODP) is not loaded; see the Snort
  documentation for `appid.app_detector_dir`. This view does not change the Snort configuration.
- *New* only means new **within the window and the logs**. After a Snort restart the logs start
  empty, so nothing is called new until 30 minutes of log exist.
- If the logs do not reach back to the start of the window (Snort restart, rotation), a note
  under the toolbar says where they start.
- The connection list has no history: it is the current `netstat`/`ss` snapshot.

---

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `NET_CAPTURE_IFACE` | `snort0`, else the default-route interface | interface tshark reads for hostnames |

Tool paths are found automatically:

- On the Linux side, from `PATH`, `/usr/sbin` and `/sbin`.
- On the Windows side, `System32` for the built-in tools, and `Program Files` for `Nmap\nmap.exe`
  and `Wireshark\tshark.exe`.

---

## API

| Endpoint | Returns |
|---|---|
| `GET /network` | platform, available sources, which tools were found, tshark status |
| `GET /network/snapshot?source=windows\|linux` | connections (with process and direction), listening sockets, neighbours, gateway, captured names |
| `GET /network/trace/:ip?source=` | traceroute hops `[{hop, ip, rtt[], lost}]` |
| `GET /network/scan/:ip` | nmap ports `[{port, proto, state, service, version}]`; 403 for non-local addresses |
| `GET /network/discover` | hosts that answered the ping sweep |
| `GET /network/rdns/:ip` | reverse DNS names |
| `GET /network/history?window=3600\|21600\|86400` | per address: alert counts by priority, top signatures, AppID sessions, apps, service ports, TLS/HTTP names, first/last seen, 30 time slices; plus where the logs start (`coverage`) |

`:ip` must be a literal IPv4 or IPv6 address. The tools run without a shell and with fixed
arguments.

The API has no authentication, and the server runs as root. Keep ports 9000 and 3009 reachable
only from your own machine or a trusted network.

---

## Limitations

- **Snapshot.** The connection list is what `netstat`/`ss` shows at that moment, refreshed every
  10 seconds. Connections shorter than that can be missed. The hollow nodes ("seen by
  Snort/AppID") fill that gap for traffic Snort saw.
- **Direction** is inferred: a connection whose local port is a listening port is *inbound*.
- **Network labels** are based on the address. IPv6 addresses in your home network are public
  addresses, so an IPv6 address counts as *Local network* when its first 64 bits (the /64
  prefix) are the same as one of this machine's addresses. Hosts in another /64 are *Internet*.
- **UDP** shows only sockets that are connected to a peer. Most UDP traffic, such as DNS and QUIC,
  appears through Snort and AppID instead.
- **No threat intelligence** yet. Alerts come from your Snort rules only.
- **History is read from the logs on request** (cached 30–120 s). A 24 h window over large logs
  can take a second or two the first time.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Only the **WSL** source is offered | Windows tools are not reachable: check WSL interop (above). |
| Many processes show as `?` | The server is not running as root (Linux) or elevated (Windows). |
| **Traceroute** is disabled | Install `traceroute` (Linux). On Windows and WSL, `tracert.exe` is used. |
| **Port scan** / **Discover LAN** disabled | Install `nmap`. |
| Port scan says the host did not answer | A firewall on the device drops probes; that is common for phones and Windows PCs. |
| "tshark: interface snort0 not found" | Start the forwarder (ENVIRONMENT.md § 7) or set `NET_CAPTURE_IFACE`. |
| Map, alerts and AppID stop updating after WSL restarted | The forwarder did not come back: enable `snort-forward.service` (ENVIRONMENT.md § 9.1, "After a WSL restart" in § 10). |
| "tshark exited" | Run the tshark command above by hand as root to see the error. |
| Network tab shows "Could not load data … 404" | Restart the server; it predates the Network tab. |
