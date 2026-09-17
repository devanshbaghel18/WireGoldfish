# 🐟 WireGoldfish

A lightweight network security monitor for Linux that captures and analyzes 
live network traffic in real time — like a goldfish watching everything from 
inside the bowl, silently and constantly.

Built from scratch in C using raw sockets. No high-level packet libraries 
used for parsing — every protocol header is decoded manually, byte by byte.

## What It Does

WireGoldfish captures raw packets directly from your network interface and 
parses each layer of the network stack:

- **Ethernet** — MAC addresses, protocol type
- **IPv4** — source/destination IPs, TTL, protocol
- **TCP** — ports, SYN/ACK/FIN flags
- **UDP** — ports, payload
- **ARP** — sender IP and MAC mappings

On top of packet capture, WireGoldfish actively detects three real network attacks:

### ⚠️ Port Scan Detection
Tracks how many unique ports a single IP connects to within a 10-second window.
If an IP hits more than 15 different ports — alert.

### ⚠️ SYN Flood Detection
Monitors the ratio of SYN packets to ACK packets per IP.
A SYN flood attack sends thousands of SYNs without completing the handshake,
exhausting server resources. WireGoldfish flags IPs where SYNs heavily 
outnumber ACKs.

### ⚠️ ARP Spoofing Detection
Maintains an IP → MAC address mapping table. If a known IP suddenly 
claims a different MAC address, someone may be intercepting your traffic.


## How It Works
Network Interface (promiscuous mode)
↓
Raw Socket (AF_PACKET, SOCK_RAW)
↓
Ethernet Header Parser
↓
IPv4 Header Parser
↓
TCP / UDP / ARP Parser
↓
Threat Detection Engine
├── Port Scan Detector
├── SYN Flood Detector
└── ARP Spoofing Detector
↓
Real-time Alerts


## Requirements

- Linux (raw sockets require Linux)
- GCC
- Root privileges (required for raw socket access)

## Build

```bash
git clone https://github.com/yourusername/wiregoldfish.git
cd wiregoldfish
gcc main.c -o wiregoldfish
```

## Run

```bash
sudo ./wiregoldfish
```

To see only security alerts (recommended):

```bash
sudo ./wiregoldfish 2>/dev/null | grep -A 4 "⚠️"
```

## Testing

**Test port scan detection:**
```bash
# In another terminal
sudo nmap -p 1-50 <target-ip>
```

**Test SYN flood detection:**
```bash
# In another terminal
sudo hping3 -S -p 80 --flood <target-ip>
```

## What I Learned Building This

- Raw socket programming on Linux
- Binary protocol parsing using C structs
- Ethernet, IPv4, TCP, UDP, ARP header layouts
- How Wireshark works under the hood
- Real network attack patterns and detection logic
- False positive tuning (DHCP uses 0.0.0.0, not spoofing)

## Why WireGoldfish?

A goldfish watches everything from inside its bowl — silently, constantly, 
missing nothing. That's exactly what this tool does to your network.

## Similar Tools

WireGoldfish implements a simplified version of what these tools do at scale:

| Tool | What it does |
|------|-------------|
| Wireshark | Packet capture and analysis |
| Snort | Network intrusion detection |
| Suricata | High-performance IDS/IPS |
| Zeek | Network analysis framework |

## Future Plans

- TCP stream reconstruction
- HTTP/DNS protocol parsing
- Live terminal dashboard
- PCAP file export

