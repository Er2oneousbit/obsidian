# Wifi Cyber Deck Ideas

#hardware #wifi #cyberdeck #wardriving #fieldkit #rpi

A running build/loadout list for a portable Wi-Fi pentest deck — a self-contained, battery-powered rig for wireless recon, capture, and attacks on the move (wardriving, red-team drops, site surveys). Notes are ideas and options, not a fixed BOM — mix and match to the mission and budget.

---

## Compute (SBC / brain)

- **Raspberry Pi 4** — 4/8GB, runs Kali/Raspberry Pi OS, plenty for Wi-Fi tooling
  - Add **active cooling** (PWM fan + heatsink) — sustained wireless captures and cracking peg the CPU and it will thermal-throttle bare
- Alternatives to consider:
  - **Raspberry Pi 5** — noticeably faster, NVMe via PCIe HAT, but higher power draw
  - **Pi Zero 2 W** — tiny/low-power for a throwable drop box, at the cost of horsepower
  - **Radxa / Orange Pi / Libre** boards — more RAM or faster I/O per dollar, less polished software support
  - **Steamdeck / mini-PC (x86)** — if you want a real x86 environment (hashcat GPU cracking, full VMs) and can tolerate the bulk/power

---

## Wireless (adapters + antennas)

The single most important part — the adapter chipset determines whether **monitor mode** and **packet injection** work at all.

- **Alfa AWUS036NEH ×2** — one for the **client** link, one for **evil twin / attack** so you can be associated and attacking simultaneously
- Chipset options worth stocking (all have solid monitor-mode/injection support):
  - **Atheros AR9271** (Alfa AWUS036NHA, Panda PAU09) — the gold standard for reliable injection
- **High-gain / directional antennas** — swap the stock rubber-duck for range:
  - Panel/**Yagi** directional for targeting a specific distant AP
  - High-gain omni for general wardriving coverage
- Keep RP-SMA pigtails/adapters so antennas are interchangeable across radios
- Optional: dedicated **GPS dongle** (USB, u-blox) for geo-tagged wardriving maps in Kismet

---

## Power

- **UPS / power bank** — USB-C PD bank sized to the Pi's draw + adapters under load (budget generously; two radios + fan pull more than idle specs suggest)
  - A **UPS HAT** (with 18650 cells) gives clean shutdown on power loss and hot-swap runtime
- Watch total draw: two Alfa cards + PWM fan + SSD can exceed a weak bank's sustained output → brownouts/USB resets mid-capture
- Powered USB hub if the board can't feed all radios/SSD reliably

---

## I/O (display + input)

- **Portable LCD** — small HDMI/USB-C touchscreen for a true handheld deck
  - Alternatives: headless + phone via SSH/VNC over the GL.iNet AP, or an e-ink/OLED status panel for a drop box
- **Bluetooth keyboard + mouse** (or a folding/thumb keyboard) — keep a wired USB fallback since BT pairing in the field can be flaky
- Cyberdeck aesthetic: mechanical thumb keyboard + status LEDs if going for the full build

---

## Storage

- **SD card + reader** — boot/OS; keep a spare flashed card as a known-good recovery image
- **USB SSD / NVMe** — capture files (`.pcap`/`.pcapng`) and wordlists get large fast; SSD is far faster and more write-durable than SD for long captures
  - Pi 5 can boot NVMe directly via a PCIe HAT
- Store loot **encrypted** (LUKS) — a field-lost deck shouldn't leak client data

---

## Networking / exfil / C2

- **GL.iNet travel router** — WireGuard server/client for a persistent encrypted tunnel back home; also handy as a second radio, an out-of-band AP to reach the deck headless, or upstream via a tethered LTE/phone
- **LTE/5G USB modem or phone tether** — remote drop-box connectivity when there's no wired uplink
- Consider a reverse tunnel (WireGuard/SSH/Tailscale) so a deployed drop box dials home rather than needing an inbound port

---

## Cooling / enclosure

- **PWM fan(s) + heatsinks** — required for sustained load; PWM lets you throttle noise when idle
- 3D-printed or off-the-shelf cyberdeck **enclosure** — mount the screen, keyboard, radios, and antenna connectors; leave airflow paths
- Ruggedize if it rides in a bag: standoffs, strain relief on pigtails, protected antenna connectors

---

## Software / tooling to load

- **OS:** Kali Linux ARM (or Raspberry Pi OS + tools); [[Tools/Cloud/Evilginx2|Evilginx2]] etc. as needed
- **Wi-Fi stack:**
  - `aircrack-ng` suite (airodump-ng, aireplay-ng, airbase-ng) — capture, deauth, fake AP
  - `hcxdumptool` + `hcxtools` — PMKID / WPA capture → hashcat format
  - `wifite2` — automated capture/attack wrapper
  - `kismet` — passive detection, logging, GPS wardriving maps
  - `bettercap` — Wi-Fi + BLE + MITM framework
  - `hostapd` / `dnsmasq` — evil twin / rogue AP + captive portal
- **Cracking:** [[Tools/Auth/hashcat|hashcat]] mode **22000** (WPA-PMKID-PMKID+EAPOL) / **22001** — heavy cracking is better offloaded to a real GPU box; the deck captures, a workstation cracks
- **Handoff:** captured hashes → crack elsewhere; see [[Tools/Auth/hashcat|hashcat]] / [[Tools/Auth/john the ripper|John the Ripper]]

---

## Open ideas / to-try

- GPS + Kismet wardriving map pipeline
- Captive-portal evil-twin credential-harvest lab build
- BLE/Zigbee radios to extend beyond Wi-Fi (broaden into a general RF deck)
- Solar/larger battery for extended unattended drop-box runtime

---

*Created: 2026-07-28*
*Updated: 2026-07-28*
*Model: claude-opus-4-8*
