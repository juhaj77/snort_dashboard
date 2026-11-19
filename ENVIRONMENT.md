# Environment: Snort 3 in WSL2, analysing Windows traffic

This guide sets up a Windows 11 + WSL2 machine so that **Snort 3 running in WSL analyses the
Windows host's network traffic** from a **live interface (`-i`)**, and `snort_log_view` shows
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

* WSL2 runs here with `networkingMode=mirrored` (`%USERPROFILE%\.wslconfig`). WSL's `eth0`
  mirrors the Windows IP address, but **only WSL's own traffic** passes through the Linux
  kernel. Browser and other Windows traffic never shows up there, so `snort -i eth0` cannot
  see it.
* Snort 3 reads packets through a DAQ module. In this install (`snort --daq-list`):
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
                                          │            snort_log_view (node)         │
                                          └──────────────────────────────────────────┘
```

A `dummy` interface does not deliver packets anywhere, and the kernel does not process them
as received traffic. Packet sockets listening on the interface still see the transmitted
frames, and Snort's pcap DAQ is one of them. Nothing leaks back onto the network, so no loop
can form.

> **Tested on 2026-11-19:** Windows `Ethernet` → `dumpcap.exe` → `pcap2iface.py` → virtual
> interface → Snort with `daq.inputs` from `snort.lua`. Snort received 272 packets and raised
> 53 alerts from real traffic, with nothing on the command line except `-c`, `-l` and
> `--plugin-path`. The test ran without sudo inside a user namespace, so it used a `veth`
> interface named `snort0` instead of `dummy`, because loading the `dummy` module needs root.
> The mechanism is the same. Use section 8 to check the `dummy` version on your machine.

---

## 2. Files in this repository

| File | Purpose | Installed to |
|---|---|---|
| `snort/snort.lua` | Snort configuration used by this project | symlinked from `/usr/local/etc/snort/snort.lua` |
| `snort/pcap2iface.py` | PCAP stream (stdin) → Linux interface | `/usr/local/bin/pcap2iface.py` |
| `snort/snort-forward.sh` | runs `dumpcap.exe \| pcap2iface.py` and restarts the pipe if it breaks | `/usr/local/bin/snort-forward.sh` |
| `snort/systemd/snort0-iface.service` | creates `snort0` at WSL boot | `/etc/systemd/system/` |
| `snort/systemd/snort.service` | runs Snort at WSL boot | `/etc/systemd/system/` |

---

## 3. Prerequisites

| Component | Checked version / state |
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
Example output on this machine:
```
4. \Device\NPF_{63E6...} (Ethernet 2)
5. \Device\NPF_{9A67...} (Ethernet)
6. \Device\NPF_{5B2C...} (vEthernet (WSL (Hyper-V firewall)))
7. \Device\NPF_Loopback (Adapter for loopback traffic capture)
```
Use the adapter that connects the machine to the network. On this machine that is
**`Ethernet`**. Pass it by name (`-i Ethernet`) rather than by number, because the numbers can
change.

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

**[WSL]** (already done on this machine; `/usr/local/etc/snort` is owned by the user, so no sudo needed)
```bash
cd ~/projects/snort_log_view
cp -p /usr/local/etc/snort/snort.lua /usr/local/etc/snort/snort.lua.orig   # backup
ln -sf "$PWD/snort/snort.lua" /usr/local/etc/snort/snort.lua
ls -l /usr/local/etc/snort/snort.lua
```
Undo: `mv /usr/local/etc/snort/snort.lua.orig /usr/local/etc/snort/snort.lua`

If `/usr/local/etc/snort` is owned by root on your machine, prefix the commands with `sudo`.
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

**Optional.** Set `HOME_NET` to your LAN (e.g. `HOME_NET = '192.168.1.0/24'`) so that rules
using `$HOME_NET` / `$EXTERNAL_NET` match direction correctly. It is `'any'` by default.

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

**[WSL]**
```bash
cd ~/projects/snort_log_view
sudo install -m 755 snort/pcap2iface.py   /usr/local/bin/pcap2iface.py
sudo install -m 755 snort/snort-forward.sh /usr/local/bin/snort-forward.sh
sudo install -m 644 snort/systemd/snort0-iface.service /etc/systemd/system/
sudo install -m 644 snort/systemd/snort.service        /etc/systemd/system/
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
and restarts automatically. Its settings can be overridden: `sudo WIN_IFACE="Wi-Fi"
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
| WSL mirrored networking | `%USERPROFILE%\.wslconfig` (already set) |
| systemd in WSL | `/etc/wsl.conf` → `[boot] systemd=true` (already set) |
| `snort0` interface | `snort0-iface.service` (systemd) |
| Snort | `snort.service` (systemd) |
| Forwarder + keeping WSL running | Windows Task Scheduler task at logon |
| Snort config | `snort/snort.lua` in this repo, symlinked (section 5.1) |

### 9.1 WSL side (systemd)

**[WSL]** (after section 6)
```bash
sudo systemctl enable --now snort0-iface.service snort.service
systemctl status snort0-iface snort --no-pager
journalctl -u snort -f            # Snort output
```
After editing `snort/snort.lua`:
```bash
snort -T -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/lib/snort/plugins/extra && sudo systemctl restart snort
```
Restarting Snort clears `appid.json` (see section 10).

### 9.2 Windows side (Task Scheduler)

WSL shuts the distribution down when no Windows process is attached to it, and that would
stop the systemd services too. Starting the forwarder from Windows at logon solves both
problems. It runs the capture, and its `wsl.exe` process keeps the distribution running.

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

> The Task Scheduler setup has **not** been tested on this machine yet. The forwarding
> command it runs has been tested.

### 9.3 Check after a reboot

**[WSL]**
```bash
ip -br link show snort0                # UP / UNKNOWN
systemctl is-active snort              # active
pgrep -af pcap2iface                   # forwarder running
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

## 11. Node.js environment for snort_log_view

### 11.1 Node.js in WSL (nvm)

WSL must use its own Node. On this machine the `npm` on the PATH was originally Windows' npm
(`/mnt/c/Program Files/nodejs/npm`), and there was no `node` at all, which breaks installs.

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

**[WSL]**
```bash
cd ~/projects/snort_log_view/server && npm install
cd ../client && npm install
```

Dependency changes made for Node 22:

| Where | Change | Why |
|---|---|---|
| `server/package.json` | removed `pcap` and `pcap-parser` | `pcap` (node_pcap 3.1.0) is a native addon whose `nan` build fails against Node 22's V8 API (`SetAccessor`). Neither package is required anywhere in the code |
| `server/package-lock.json` | `npm audit fix` | 23 → 7 advisories, semver-compatible updates only |
| `client/package-lock.json` | `npm audit fix` | 76 → 32 advisories, semver-compatible updates only. Build and dev server were re-tested afterwards |

Remaining advisories need breaking upgrades and were left as they are:
* **server:** `jade` (deprecated, successor `pug`) with `constantinople` and `transformers`,
  and `morgan` / `on-headers`.
* **client:** `react-scripts` 5 (Create React App, unmaintained) and its toolchain. These
  affect the build and the dev server, not the code shipped to the browser.

### 11.3 Start

`/var/log/snort/alert_json.txt` is `-rw------- root`, which is why the server is started with
`sudo`. With nvm, `sudo` does not find `node`, so pass the PATH through:

**Server (terminal 3).** [WSL]
```bash
cd ~/projects/snort_log_view/server
sudo env "PATH=$PATH" npm start
```

**Client (terminal 4).** [WSL]
```bash
cd ~/projects/snort_log_view/client
npm start
```
Thanks to mirrored networking, open `http://localhost:3000` in a Windows browser.
