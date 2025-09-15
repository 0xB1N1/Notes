```yaml
---
date:  2025-08-29 
author: Sameer Sani
reason: 
title: Windows Command Line & PowerShell  
tags: [windows, powershell, cmd, notes]
---
```

# 🖥️ Windows Command Line & PowerShell

---

## ⚡ Windows Command Prompt (CMD)

### ℹ️ System & Information Commands

| Command     | Description                                           | Example              |
|-------------|-------------------------------------------------------|----------------------|
| `set`       | Displays all environment variables and their paths.   | `set`                |
| `ver`       | Shows the Windows version.                           | `ver`                |
| `systeminfo`| Displays detailed system configuration information.  | `systeminfo`         |
| `more`      | Pages output one screen at a time (use with piping). | `dir \| more`        |
| `cls`       | Clears the terminal screen.                          | `cls`                |
| `help`      | Lists available commands.                            | `help`               |
| `command /?`| Shows help for a specific command.                   | `ipconfig /?`        |

---

### 🌐 Network Diagnostics Commands

| Command     | Description                                    | Example               |
|-------------|------------------------------------------------|-----------------------|
| `tracert`   | Traces route (hops) to a destination.          | `tracert google.com`  |
| `nslookup`  | Queries DNS to find IP for a domain.           | `nslookup example.com`|

> [!example] **`netstat` — Displays network connections & listening ports**  
> Common flags: `netstat -abon`

| Flag | Description                                     |
|------|-------------------------------------------------|
| `-a` | Show all connections and listening ports.       |
| `-b` | Show the executable that created the connection.|
| `-o` | Show the PID for each connection.               |
| `-n` | Show addresses/ports in numeric form.           |

📌 *Use `netstat -ano | findstr :PORT` to quickly find processes bound to a specific port.*

---

### 📁 File System Commands

| Command   | Linux Equivalent | Description                        | Example                          |
|-----------|-----------------|------------------------------------|----------------------------------|
| `dir`     | `ls`            | List directory contents.           | `dir /a` (show hidden files)     |
| `mkdir`   | `mkdir`         | Create a new directory.            | `mkdir NewFolder`                |
| `rmdir`   | `rmdir`         | Remove an **empty** directory.     | `rmdir OldFolder`                |
| `type`    | `cat`           | Display text file content.         | `type myfile.txt`                |
| `copy`    | `cp`            | Copy files.                        | `copy file.txt C:\backup\`       |
| `move`    | `mv`            | Move/rename files.                 | `move old.txt new.txt`           |
| `del`     | `rm`            | Delete one or more files.          | `del tempfile.tmp`               |

---

### ⚙️ Process Management Commands

| Command     | Linux Equivalent | Description                 | Example                                   |
|-------------|-----------------|-----------------------------|-------------------------------------------|
| `tasklist`  | `ps`, `top`     | Show running processes.     | `tasklist` / `tasklist /FI "imagename eq chrome.exe"` |
| `taskkill`  | `kill`          | Kill task by PID or name.   | `taskkill /pid 1234` <br> `taskkill /im notepad.exe`  |

---

## 🌀 Windows PowerShell

### 🧠 Fundamentals

> [!note] **Cmdlets**  
> PowerShell commands are called **CmdLets**.  
> Naming convention: **`Verb-Noun`** → `Get-Content`, `Set-Location`.

---

### 🔍 Discovery & Help Cmdlets

| Cmdlet        | Description                          | Example                                   |
|---------------|--------------------------------------|-------------------------------------------|
| `Get-Command` | Lists all cmdlets, functions, aliases, and scripts. | `Get-Command` <br> `Get-Command -CommandType Cmdlet` |
| `Get-Help`    | Displays help for cmdlets.           | `Get-Help Get-Date` <br> `Get-Help Get-Process -Examples` |
| `Get-Alias`   | Shows aliases (e.g., `dir` → `Get-ChildItem`). | `Get-Alias` |

---

### 📦 Module Management

> [!info] **Modules**  
> Modules are packages that extend PowerShell functionality.

| Cmdlet         | Description                     | Example                               |
|----------------|---------------------------------|---------------------------------------|
| `Find-Module`  | Search PS Gallery for modules.  | `Find-Module -Name "PowerShellGet"`   |
| `Install-Module` | Download & install a module.  | `Install-Module -Name "PowerShellGet"`|

---

### 📂 File System Cmdlets

| Cmdlet          | Equivalent | Description               | Example                                                 |
|-----------------|------------|---------------------------|---------------------------------------------------------|
| `Get-ChildItem` | `ls`       | List files/folders.       | `Get-ChildItem`                                         |
| `Set-Location`  | `cd`       | Change directory.         | `Set-Location C:\Users`                                |
| `New-Item`      | `mkdir` / `touch` | Create new item.  | `New-Item -Path ".\file.txt" -ItemType "File"`          |
| `Remove-Item`   | `rm`       | Delete item.              | `Remove-Item -Path ".\MyFolder"`                        |
| `Copy-Item`     | `cp`       | Copy item.                | `Copy-Item -Path ".\file.txt" -Destination ".\Backup\"` |
| `Get-Content`   | `cat`      | Read file content.        | `Get-Content .\document.txt`                           |

---

### 🎛️ Data Filtering & Processing

> [!tip] **Piping in PowerShell**  
> Cmdlets can send objects through the pipeline (`|`) to the next cmdlet.

| Cmdlet         | Linux Equivalent | Description           | Example                                           |
|----------------|------------------|-----------------------|---------------------------------------------------|
| `Sort-Object`  | `sort`           | Sort objects.         | `Get-ChildItem \| Sort-Object Length`            |
| `Where-Object` | `grep`           | Filter objects.       | `Get-ChildItem \| Where-Object Extension -eq ".txt"` |
| `Select-Object`| `awk` (basic)    | Select properties.    | `Get-ChildItem \| Select-Object Name, Length`    |
| `Select-String`| `grep`           | Search text in files. | `Select-String -Path ".\*.log" -Pattern "error"` |

📌 **Common `Where-Object` Operators**

| Operator | Description                  |
|----------|------------------------------|
| `-eq`    | Equal to                     |
| `-ne`    | Not equal to                 |
| `-gt`    | Greater than                 |
| `-lt`    | Less than                    |
| `-ge`    | Greater or equal             |
| `-le`    | Less or equal                |
| `-like`  | Wildcard match (`"*.log"`)   |

---

### ℹ️ System & Network Information Cmdlets

| Cmdlet               | CMD Equivalent   | Description                                        |
|----------------------|------------------|----------------------------------------------------|
| `Get-ComputerInfo`   | `systeminfo`     | System & OS details.                               |
| `Get-LocalUser`      | `net user`       | List all local users.                              |
| `Get-NetIPConfiguration` | `ipconfig`   | Network config (IP, gateway, DNS).                 |
| `Get-NetIPAddress`   | `ipconfig /all`  | Detailed IP address configuration.                 |
| `Get-Process`        | `tasklist`       | List running processes.                            |
| `Get-Service`        | `sc query`       | List services and status.                          |
| `Get-NetTCPConnection` | `netstat`      | TCP connections (**useful for hidden backdoors**). |
| `Get-FileHash`       | `certutil`       | Compute file hash (MD5, SHA256, etc.).             |

---

## 🖼️ Visual Aids

- **PowerShell Pipeline Concept**  
```mermaid
graph LR
  A[Get-ChildItem] --> B[Where-Object]
  B --> C[Sort-Object]
  C --> D[Select-Object]
  D --> E[Output / Export]
