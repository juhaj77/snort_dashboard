# Environment: Snort 3 in WSL2, analysing Windows traffic

This guide sets up a Windows 11 + WSL2 machine so that **Snort 3 running in WSL analyses the
Windows host's network traffic** from a **live interface (`-i`)**, and `snort_dashboard` shows
the results. Snort is started once and keeps running. It does not re-read capture files
chunk by chunk.

Each command is marked with where it runs:

| Marker | Where |
|---|---|
| **[WSL]** | Ubuntu shell inside WSL |
| **[WSL → Windows program]** | WSL shell, but the command starts a Windows `.exe` through WSL interop |
| **[Windows, PowerShell (admin)]** | PowerShell started with "Run as administrator" |
| **[Windows, cmd]** | Windows Command Prompt (`cmd.exe`) |

---

## 1. Why the traffic has to be forwarded

* This guide uses WSL2 with `networkingMode=mirrored` (`%USERPROFILE%\.wslconfig`). WSL's `eth0`
  mirrors the Windows IP address, but **only WSL's own traffic** passes through the Linux
  kernel. Browser and other Windows traffic never shows up there, so `snort -i eth0` cannot
  see it.
* Snort 3 reads packets through a DAQ module. A standard build offers (`snort --daq-list`):
  * `pcap`: *readback live multi*, reads a live interface (`-i`) or a file (`-r`)
  * `afpacket`: *live inline*, Linux live interface
  * `savefile`: files only

  None of them reads a continuous PCAP stream from stdin, so `dumpcap | snort` or a FIFO is
  not a documented way to feed Snort.
* **Solution:** create a virtual Linux interface `snort0` (type `dummy`) in WSL. A small
  forwarder writes every frame from the Windows Npcap capture onto it, and Snort listens on it
  like any live interface.

```
 Windows                                   WSL2 (Ubuntu)
┌───────────────────────────┐            ┌──────────────────────────────────────────┐
│ "Ethernet" adapter        │            │                                          │
│   │ (Npcap)               │            │                                          │
│   ▼                       │   stdout   │                                          │
│ dumpcap.exe -F pcap -w - ─┼── pipe ───▶│ pcap2iface.py ──AF_PACKET──▶ snort0      │
└───────────────────────────┘ (interop)  │                         (dummy iface)    │
                                          │                            │             │
                                          │          snort (daq.inputs = snort0)     │
                                          │                            ▼             │
                                          │        /var/log/snort/*.txt|json|csv     │
                                          │                            ▼             │
                                          │            snort_dashboard (node)        │
                                          └──────────────────────────────────────────┘
```

A `dummy` interface does not deliver packets anywhere, and the kernel does not process them
as received traffic. Packet sockets listening on the interface still see the transmitted
frames, and Snort's pcap DAQ is one of them. Nothing leaks back onto the network, so no loop
can form.

> **Verified:** Windows `Ethernet` → `dumpcap.exe` → `pcap2iface.py` → virtual
> interface → Snort with `daq.inputs` from `snort.lua`. Snort received 272 packets and raised
> 53 alerts from real traffic, with nothing on the command line except `-c`, `-l` and
> `--plugin-path`. The test ran without sudo inside a user namespace, so it used a `veth`
> interface named `snort0` instead of `dummy`, because loading the `dummy` module needs root.
> The mechanism is the same. Use section 8 to check the `dummy` setup on your own machine.

---

## 2. Files in this repository

| File | Purpose | Installed to |
|---|---|---|
| `snort/snort.lua` | Snort configuration used by this project | symlinked from `/usr/local/etc/snort/snort.lua` |
| `snort/pcap2iface.py` | PCAP stream (stdin) → Linux interface | `/usr/local/bin/pcap2iface.py` |
| `snort/snort-forward.sh` | runs `dumpcap.exe \| pcap2iface.py`, restarts the pipe if it breaks, only one instance at a time | `/usr/local/bin/snort-forward.sh` |
| `snort/systemd/snort0-iface.service` | creates `snort0` at WSL boot | `/etc/systemd/system/` |
| `snort/systemd/snort.service` | runs Snort at WSL boot | `/etc/systemd/system/` |
| `snort/systemd/snort-forward.service` | runs `snort-forward.sh` at WSL boot | `/etc/systemd/system/` |

---

## 3. Prerequisites

| Component | Tested version / required state |
|---|---|
| Snort | 3.13.2.0, DAQ 3.0.29, libpcap 1.10.6, `/usr/local/bin/snort` |
| snort3_extra | `appid_listener` at `/usr/local/lib/snort/plugins/extra/inspectors/appid_listener.so` |
| Windows: Npcap | installed, `AdminOnly = 0` (capturing works without admin rights) |
| Windows: Wireshark | 4.6.0, `C:\Program Files\Wireshark\dumpcap.exe` |
| WSL | Ubuntu 26.04, WSL2 kernel 6.6, `dummy` module available, Python 3, `systemd=true` in `/etc/wsl.conf` |
| `.wslconfig` | `[wsl2] networkingMode=mirrored` |

Check the Npcap admin-only setting:

**[WSL → Windows program]**
```bash
reg.exe query 'HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters' /v AdminOnly
```
If it shows `0x1`, `dumpcap.exe` has to run elevated. In that case use the `cmd` variant in
section 7 from an elevated prompt, or reinstall Npcap without "Restrict Npcap driver's access
to Administrators only".

---

## 4. Pick the Windows adapter to capture

**[WSL → Windows program]**
```bash
"/mnt/c/Program Files/Wireshark/dumpcap.exe" -D
```
Example output:
```
4. \Device\NPF_{63E6...} (Ethernet 2)
5. \Device\NPF_{9A67...} (Ethernet)
6. \Device\NPF_{5B2C...} (vEthernet (WSL (Hyper-V firewall)))
7. \Device\NPF_Loopback (Adapter for loopback traffic capture)
```
Use the adapter that connects the machine to the network, usually **`Ethernet`** or **`Wi-Fi`**.
Pass it by name (`-i Ethernet`) rather than by number, because the numbers can change. The
examples in this guide use `Ethernet`; replace it with your adapter's name.

Do not use:
* `NPF_Loopback`: its link type is not Ethernet, and the forwarder rejects it.
* `vEthernet (WSL …)`.

---

## 5. Configure `snort.lua`

### 5.1 Keep the config in the repository (symlink)

The active Snort config lives in this repository as `snort/snort.lua`, and
`/usr/local/etc/snort/snort.lua` is a symlink to it. You can edit and version it with the
project. Snort resolves `include 'snort_defaults.lua'` relative to the path given with `-c`,
which is the symlink's directory, so the other files stay in `/usr/local/etc/snort/`.

**[WSL]**, in the root of your clone of this repository:
```bash
sudo cp -p /usr/local/etc/snort/snort.lua /usr/local/etc/snort/snort.lua.orig   # backup
sudo ln -sf "$PWD/snort/snort.lua" /usr/local/etc/snort/snort.lua
ls -l /usr/local/etc/snort/snort.lua
```
Undo: `sudo mv /usr/local/etc/snort/snort.lua.orig /usr/local/etc/snort/snort.lua`

If `/usr/local/etc/snort` is owned by your own user, `sudo` is not needed. The clone must stay
where it is, because the symlink points into it.
The rules files referenced by the config (`/usr/local/etc/snort/rules/snort3-community.rules`,
`local.rules`) are not part of this repository.

### 5.2 Settings this project needs

**Packet source.** This block, right after `include 'snort_defaults.lua'`, makes `-i`, `-s`
and `-k` unnecessary on the command line:
```lua
daq =
{
    inputs = { 'snort0' },  -- same as -i snort0 (pcap DAQ, passive)
    snaplen = 65535,        -- same as -s 65535
}

network =
{
    checksum_eval = 'none', -- same as -k none
}
```
* `inputs = { 'snort0' }`: the virtual interface from section 7.
* `snaplen = 65535`: the default is 1518, but outgoing TCP segments in a Windows capture can be
  larger because of Large Send Offload.
* `checksum_eval = 'none'`: Npcap captures outgoing packets before the NIC computes their
  checksums, so without this Snort would treat them as corrupt and ignore them.

**Log outputs read by the server.** The server reads these from `/var/log/snort/`:
```lua
perf_monitor = { }

alert_json =
{
    file = true,
    limit = 100,
    fields = 'timestamp iface src_addr src_port dst_addr dst_port proto action msg priority class sid dir dst_ap eth_dst eth_len eth_src eth_type gid icmp_code ip_id ip_len mpls pkt_gen pkt_len pkt_num rev rule seconds service src_ap target tcp_ack tcp_flags tcp_len tcp_seq tcp_win tos ttl udp_len vlan'
}
-- only timestamp, priority, rule, proto, src_ap, dst_ap, msg, class and seconds are mandatory

appid = { }

appid_listener =
{
    json_logging = true,
    file = '/var/log/snort/appid.json',
}
```

**Not settable from Lua.** These must stay on the command line. The systemd unit passes them.
* `-l /var/log/snort`: `alert_json.txt` and `perf_monitor_base.csv` go to the log directory,
  which defaults to the current directory. The `snort = { ['-l'] = ... }` table is accepted
  but has no effect. This was tested.
* `--plugin-path /usr/local/lib/snort/plugins/extra`: plugins load before the Lua config, so
  without it `appid_listener` is silently missing.

**Home network.** `snort/snort.lua` sets `HOME_NET` to the private networks
(`10/8`, `172.16/12`, `192.168/16`, IPv6 ULA and link-local) and `EXTERNAL_NET = '!$HOME_NET'`,
so rules using `$HOME_NET` / `$EXTERNAL_NET` match the direction correctly. With Snort's default
`'any'`, "outside → inside" rules also fire on your own devices: for example, the router's
normal UPnP/SSDP announcements trigger `1:1384 "UPnP malformed advertisement"` thousands of
times a day.

Your internet provider's IPv6 prefix belongs in `HOME_NET` too. It is specific to your
connection and can change, so it is kept out of the repository in
`/usr/local/etc/snort/local_net.lua`, which `snort.lua` loads if it exists **[WSL]**:
```bash
sudo tee /usr/local/etc/snort/local_net.lua >/dev/null <<'EOF'
HOME_NET = '[192.168.1.0/24,2001:db8:1234:5600::/56,fc00::/7,fe80::/10]'
EOF
```
Replace the LAN and the prefix with your own. The dashboard's Network tab shows your current
provider prefix and warns when it is no longer inside `HOME_NET`; see
[NETWORK.md](NETWORK.md#provider-ipv6-prefix-and-snorts-home_net).

### 5.3 Validate

**[WSL]**
```bash
snort -T -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/lib/snort/plugins/extra
# expected last line: Snort successfully validated the configuration (with 0 warnings).
```
As a normal user you'll see `appid_listener: can't open file /var/log/snort/appid.json`. That
is only a permission message, and it disappears when Snort runs as root.

---

## 6. Install the helpers

**[WSL]**, in the repository root:
```bash
sudo install -m 755 snort/pcap2iface.py   /usr/local/bin/pcap2iface.py
sudo install -m 755 snort/snort-forward.sh /usr/local/bin/snort-forward.sh
sudo install -m 644 snort/systemd/snort0-iface.service /etc/systemd/system/
sudo install -m 644 snort/systemd/snort.service        /etc/systemd/system/
sudo install -m 644 snort/systemd/snort-forward.service /etc/systemd/system/
sudo systemctl daemon-reload
```
The scripts are copied rather than symlinked because they run as root. Re-run `install` after
editing them in the repository.

---

## 7. Run manually (first test)

Use this to try everything by hand before making it permanent (section 9).

**1. Create the interface.** [WSL]
```bash
sudo modprobe dummy
sudo ip link add snort0 type dummy
sudo ip link set snort0 mtu 65535                  # LSO frames can be large
sudo sysctl -w net.ipv6.conf.snort0.disable_ipv6=1 # stop the kernel sending its own IPv6 packets
sudo ip link set snort0 up
```
You can also run `sudo systemctl start snort0-iface`, which does the same.

**2. Start Snort (terminal 1).** [WSL]
```bash
sudo snort -c /usr/local/etc/snort/snort.lua \
     --plugin-path /usr/local/lib/snort/plugins/extra \
     -l /var/log/snort
```

**3. Forward the Windows traffic (terminal 2).** [WSL → Windows program]
```bash
sudo -v    # ask for the password first so it doesn't mix with the pipe
"/mnt/c/Program Files/Wireshark/dumpcap.exe" -i Ethernet -F pcap -q -w - \
  | sudo /usr/local/bin/pcap2iface.py snort0
```
Instead of the pipe, you can run `sudo /usr/local/bin/snort-forward.sh`, which does the same
and restarts automatically. If `snort-forward.service` (section 9.1) is already running, the
script only prints `another forwarder is running, waiting...` and waits; the plain pipe above
does **not** check this, so stop the service first (`sudo systemctl stop snort-forward`) or
every packet reaches Snort twice. Its settings can be overridden: `sudo WIN_IFACE="Wi-Fi"
CAPTURE_FILTER="not port 3389" /usr/local/bin/snort-forward.sh`.

* `-F pcap`: classic PCAP. The forwarder does not read pcapng. Old `-P` still works but is
  deprecated in Wireshark 4.6.
* `-w -`: write the capture to stdout.
* `-q`: no packet counter on stderr.
* `-f "<bpf>"`: optional capture filter.

**Alternative: start the forwarder from Windows.** Use `cmd.exe`, because its pipe passes
binary data unchanged. Windows PowerShell 5.1 corrupts binary pipes. PowerShell 7.4+ works.

**[Windows, cmd]**
```bat
"C:\Program Files\Wireshark\dumpcap.exe" -i Ethernet -F pcap -q -w - | wsl.exe -u root -e /usr/local/bin/pcap2iface.py snort0
```

This calls `pcap2iface.py` directly, without the single-instance lock of `snort-forward.sh`:
stop `snort-forward.service` first if it is installed.

Stop the forwarder with `Ctrl+C`. Snort keeps running and continues when forwarding restarts.

---

## 8. Verify

**Traffic arrives on the interface.** [WSL]
```bash
sudo tcpdump -i snort0 -n -c 10
```

**Alerts are written.** [WSL]
```bash
sudo tail -f /var/log/snort/alert_json.txt
```

With `enable_builtin_rules = true` (set in `snort.lua`), ordinary LAN traffic quickly
produces decoder alerts such as `116:414 "(ipv4) IPv4 packet to broadcast dest address"`.
`/usr/local/etc/snort/rules/local.rules` also contains a test rule (`sid:1000001`, any ICMP).
Running `ping 8.8.8.8` on Windows should trigger it.

---

## 9. Make it permanent

The pieces and what keeps each one alive:

| Piece | Survives reboot via |
|---|---|
| WSL mirrored networking | `%USERPROFILE%\.wslconfig` (section 3) |
| systemd in WSL | `/etc/wsl.conf` → `[boot] systemd=true` (section 3) |
| `snort0` interface | `snort0-iface.service` (systemd) |
| Snort | `snort.service` (systemd) |
| Forwarder | `snort-forward.service` (systemd), also after a WSL restart |
| Keeping WSL running | Windows Task Scheduler task at logon |
| Snort config | `snort/snort.lua` in this repo, symlinked (section 5.1) |

### 9.1 WSL side (systemd)

**[WSL]** (after section 6)
```bash
sudo systemctl enable --now snort0-iface.service snort.service snort-forward.service
systemctl status snort0-iface snort snort-forward --no-pager
journalctl -u snort -f            # Snort output
journalctl -u snort-forward -f    # forwarder / dumpcap output
```

**Why the forwarder is a systemd service.** The WSL VM can stop and start again in the
middle of a session (`wsl --shutdown`, Windows sleep or update, a WSL crash). systemd then
brings back `snort0` and Snort, but a forwarder started only by the Windows logon task (9.2)
does not come back: Snort runs on an interface that receives no packets, and the dashboard
looks broken (see "After a WSL restart" in section 10). The service starts the forwarder at
every WSL boot.

It works because systemd services can start Windows programs through WSL interop. Services do
not get the `WSL_INTEROP` variable, but WSL falls back to `/run/WSL/1_interop`. Verified with
`dumpcap.exe -D` and a short capture, both started from a systemd unit. `dumpcap.exe` has to be allowed to capture without elevation (section 3); a
service cannot answer a UAC prompt.

**Settings.** Put overrides in `/etc/default/snort-forward`, one `VAR=value` per line, then
`sudo systemctl restart snort-forward`:
```bash
WIN_IFACE=Wi-Fi
CAPTURE_FILTER=not port 3389
```
After editing `snort/snort.lua`:
```bash
snort -T -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/lib/snort/plugins/extra && sudo systemctl restart snort
```
Restarting Snort clears `appid.json` (see section 10).

### 9.2 Windows side (Task Scheduler)

WSL shuts the distribution down when no Windows process is attached to it, and that would
stop the systemd services too. A systemd service does not count as an attached process, so
the forwarder service (9.1) alone does not keep WSL running. The logon task solves that: its
`wsl.exe` process keeps the distribution running.

The task runs the same `snort-forward.sh`. The script lets only one instance forward
(a lock in `/run/snort-forward.lock`), so when the service is already forwarding, the task's
copy just waits. That is intended: the waiting `wsl.exe` keeps WSL alive, and it takes over
if the service stops. Two forwarders at once would inject every packet twice.

**[Windows, PowerShell (admin)]**
```powershell
$action   = New-ScheduledTaskAction -Execute "C:\Windows\System32\conhost.exe" `
            -Argument "--headless C:\Windows\System32\wsl.exe -d Ubuntu -u root --exec /usr/local/bin/snort-forward.sh"
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "snort-forward" -Action $action -Trigger $trigger -Settings $settings
Start-ScheduledTask -TaskName "snort-forward"
```
* `conhost.exe --headless` runs `wsl.exe` without a visible console window.
* `-d Ubuntu` is the distribution name from `wsl.exe -l -v`.
* To change the adapter, pass the variable through: `--exec /usr/bin/env WIN_IFACE=Wi-Fi /usr/local/bin/snort-forward.sh`.
* Remove the task: `Unregister-ScheduledTask -TaskName "snort-forward" -Confirm:$false`.

> The Task Scheduler setup itself has **not** been tested end to end yet. The forwarding
> command it runs has been tested.
>
> The task only runs at logon. If WSL stops later in the session, the task's `wsl.exe` ends
> with it; `-RestartCount 3` restarts the task only if Task Scheduler sees it as failed. The
> systemd service brings back the forwarding itself as soon as WSL starts again (for example
> when you open a WSL terminal), but to keep WSL running for good, start the task again:
> `Start-ScheduledTask -TaskName "snort-forward"`.

### 9.3 Check after a reboot

**[WSL]**
```bash
ip -br link show snort0                # UP / UNKNOWN
systemctl is-active snort              # active
systemctl is-active snort-forward      # active
pgrep -af pcap2iface                   # forwarder running
ip -s link show snort0                 # TX packets keep growing (the forwarder sends onto snort0)
sudo tcpdump -i snort0 -n -c 5         # packets arriving
```

---

## 10. Notes

**Log files across Snort restarts.** Tested with Snort 3.13.2 by running Snort three times in a row into the same log directory:

| File | Written by | On Snort start |
|---|---|---|
| `alert_json.txt` | `alert_json` | appended (`limit` = rollover size in MB) |
| `perf_monitor_base.csv` | `perf_monitor` | appended |
| `appid.json` | `appid_listener` (snort3_extra) | **truncated**, rewritten from the start |

This is why Snort runs once on `snort0` instead of being restarted for every capture chunk.
To keep AppID history across restarts, copy the file first, e.g. **[WSL]**
`sudo cp /var/log/snort/appid.json /var/log/snort/appid.$(date +%s).json`

**After a WSL restart.** If the WSL VM was stopped and started again (`uptime` is short;
`journalctl --list-boots` shows a new boot, and the previous boot ends without a shutdown),
the dashboard shows this until packets flow again:

| View | What you see | Why |
|---|---|---|
| Performance | empty | `perf_monitor_base.csv` gets only a new header row; data rows are written only while packets arrive |
| AppID | empty | Snort truncates `appid.json` on start; the AppID history before the restart is gone |
| Alerts / Overview, 15 min | missing alerts | no packets → no alerts since the restart; older alerts are still in `alert_json.txt` and its rotated files |

Check where the chain broke, in this order **[WSL]**:
```bash
uptime; journalctl --list-boots --no-pager | tail -2    # did WSL restart?
systemctl is-active snort0-iface snort snort-forward     # all "active"
ip -s link show snort0                                   # TX packets not growing → forwarder not delivering
journalctl -u snort-forward -n 20 --no-pager             # dumpcap errors (adapter name, permissions)
```
With `snort-forward.service` enabled (9.1) the forwarder comes back by itself. Without it,
start it by hand: `sudo /usr/local/bin/snort-forward.sh` (or `Start-ScheduledTask -TaskName
"snort-forward"` on Windows). The snort_dashboard server and client also stop with WSL;
start them again (section 11.3).

**Other notes:**
* **Alerts `116:3 "IPv4 datagram length < header field"`** come from Windows Large Send
  Offload: Npcap sees outgoing packets before the NIC segments them. To get rid of them,
  disable LSO on the captured adapter. **[Windows, PowerShell (admin)]**
  `Disable-NetAdapterLso -Name "Ethernet"` (revert with `Enable-NetAdapterLso -Name "Ethernet"`).
* **WSL's own traffic** is included, because in mirrored mode it goes through the same
  Windows adapter.
* **Wi-Fi:** Npcap delivers Ethernet-framed packets from Wi-Fi adapters (not monitor mode),
  so the same chain works.
* **Performance:** the Python forwarder is fine for home/office traffic. If `dumpcap` reports
  drops, narrow the capture with a BPF filter (`CAPTURE_FILTER` / `-f`).

---

## 11. Node.js environment for snort_dashboard

### 11.1 Node.js in WSL (nvm)

WSL must use its own Node. If Node.js is installed on Windows, WSL's PATH can contain Windows'
`npm` (`/mnt/c/Program Files/nodejs/npm`) without a Linux `node`, which breaks installs.

**[WSL]**
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
exec bash
nvm install 22          # tested: v22.23.5, npm 10.9.9
which node npm          # must point to ~/.nvm/..., not /mnt/c/...
```
nvm adds its loader lines to `~/.bashrc`, so new shells find `node` and the right `npm`.

To keep the Windows PATH out of WSL entirely, add the following to `/etc/wsl.conf` and run
`wsl --shutdown`. The scripts call `dumpcap.exe` with its full path, so they keep working.
```ini
[interop]
appendWindowsPath = false
```

### 11.2 Install dependencies

**[WSL]**, in the repository root:
```bash
cd server && npm install
cd ../client && npm install
```

`npm audit` still reports advisories that need breaking upgrades:
* **server:** `jade` (deprecated, successor `pug`) with `constantinople` and `transformers`,
  and `morgan` / `on-headers`.
* **client:** `react-scripts` 5 (Create React App, unmaintained) and its toolchain. These
  affect the build and the dev server, not the code shipped to the browser.

### 11.3 Start

`/var/log/snort/alert_json.txt` is `-rw------- root`, which is why the server is started with
`sudo`. With nvm, `sudo` does not find `node`, so pass the PATH through:

**Server (terminal 3).** [WSL], in the repository root:
```bash
cd server
sudo env "PATH=$PATH" npm start
```

**Client (terminal 4).** [WSL], in the repository root:
```bash
cd client
npm start
```
Thanks to mirrored networking, open `http://localhost:3000` in a Windows browser.
