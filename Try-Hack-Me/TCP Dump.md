
# TcpDump — CLI Packet Sniffer

```yaml
---
date: 2025-09-15
author: Sameer Saini
title: TcpDump Notes
tags: [tcpdump, networking, cli, ctf, packet-capture]
---
```

## 📌 What is TcpDump?

- TcpDump is like **Wireshark for CLI**.
    
- Useful when **GUI isn’t available** (remote servers, headless systems).
    
- Very powerful for network debugging, packet analysis, and CTF challenges.
    

---

## 🎯 Use Cases & Basic Options

|Option|Description|Example|
|---|---|---|
|`-i <iface>`|Select interface (or `any` for all)|`tcpdump -i eth0`|
|`-r <file>`|Read packets from capture file|`tcpdump -r traffic.pcap`|
|`-c <count>`|Capture limited packets|`tcpdump -c 50`|
|`-n`|Don’t resolve hostnames (faster)|`tcpdump -n`|
|`-nn`|Don’t resolve hostnames & ports|`tcpdump -nn`|
|`-v / -vv / -vvv`|Increase verbosity|`tcpdump -vvv`|
|`-w <file>`|Write output to a file|`tcpdump -w capture.pcap`|

> 💡 Use `-nnvvXSs 0` for **maximum detail** (no resolution + full packet content).

---

## 🔍 Filtering Packets

Since real traffic can be huge, **filters** are essential.

### 1️⃣ Host Filters

```bash
tcpdump host example.com -w capture.pcap
tcpdump src host 192.168.1.10
tcpdump dst host 10.0.0.5
```

### 2️⃣ Port Filters

```bash
tcpdump port 80
tcpdump src port 22
tcpdump dst port 443
```

### 3️⃣ Protocol Filters

```bash
tcpdump arp
tcpdump icmp
tcpdump tcp
```

### 4️⃣ Size & Logical Operators

- By length:
    
    ```bash
    tcpdump greater 100
    tcpdump less 200
    ```
    
- Combine filters:
    
    ```bash
    tcpdump tcp and port 80
    tcpdump udp or icmp
    tcpdump not port 22
    ```
    

---

## 🧩 Filtering Header Bytes

Format:

```
proto[expr:size]
```

- **proto**: tcp, ip, ipv6, ether
    
- **expr**: byte offset
    
- **size**: number of bytes
    

### Examples

- Find multicast addresses:
    
    ```bash
    tcpdump 'ether[0] & 1 != 0'
    ```
    
- Filter TCP flags:
    
    - SYN only:
        
        ```bash
        tcpdump 'tcp[tcpflags] == tcp-syn'
        ```
        
    - At least SYN:
        
        ```bash
        tcpdump 'tcp[tcpflags] & tcp-syn != 0'
        ```
        
    - SYN or ACK:
        
        ```bash
        tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-ack) != 0'
        ```
        

📌 **Common TCP flags**:

- `tcp-syn`
    
- `tcp-ack`
    
- `tcp-rst`
    
- `tcp-fin`
    
- `tcp-push` (flush buffer)
    

---

## 👀 Displaying Packets

|Flag|Description|Example|
|---|---|---|
|`-q`|Brief output|`tcpdump -q`|
|`-e`|Link-layer header (MAC addresses)|`tcpdump -e`|
|`-a`|Show data in ASCII|`tcpdump -a`|
|`-xx`|Headers + data (hex + ASCII)|`tcpdump -xx`|
|`-X`|Hex + ASCII (layer 2+)|`tcpdump -X`|
|`-XX`|More detailed hex + ASCII|`tcpdump -XX`|

---

## 📝 Memory Hooks

> 💡 Quick mental shortcuts:

- `-i` → interface
    
- `-r` → read file
    
- `-w` → write file
    
- `-n / -nn` → no name/port resolution
    
- `host / src / dst` → filter by IP/FQDN
    
- `port` → filter by port
    
- `tcp[tcpflags]` → filter by flags
    
---
