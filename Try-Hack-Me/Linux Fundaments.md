```yaml
---
date: 2025-08-20
author: Sameer Saini
reason: 0x45
title: Common Linux Directories & APT Notes
tags: [linux, directories, apt, sysadmin, notes]
---
```

## 📂 Common Linux Directories

> ℹ️ These are standard directories in a **Linux filesystem hierarchy (FHS)**.

|Directory|Description|
|---|---|
|**/etc**|⚙️ Stores system-wide configuration files (user passwords, service settings).|
|**/var**|📊 Stores variable data (logs, databases, spool files).|
|**/root**|👑 Home directory of the **root (superuser)** account.|
|**/tmp**|⚡ Temporary files (often cleared on reboot).|
|**/bin**|🔧 Essential user binaries (e.g., `ls`, `cp`, `cat`).|
|**/sbin**|🛠️ Essential system administration binaries (`fdisk`, `ifconfig`).|
|**/home**|🏠 Personal directories for regular users.|
|**/usr**|📦 User-installed software, applications, shared libraries.|
|**/lib**|📚 Shared libraries needed by binaries in `/bin` & `/sbin`.|
|**/dev**|💽 Device files representing hardware (`/dev/sda`).|
|**/sys**|🔍 Virtual FS for **kernel & hardware parameters**.|
|**/proc**|🧩 Virtual FS for **process & system info** (`ps`, `/proc/cpuinfo`).|

---

## 📦 Package Management (APT)

> 🚀 **APT (Advanced Package Tool)** is used in Debian/Ubuntu systems for package management.

### ⚙️ Configuration Files

- `/etc/apt/` → main APT configuration directory
    
- `/etc/apt/sources.list` → repository list (main, universe, restricted, multiverse)
    

### 🔑 Repository Management

- Add new repo:
    
    ```bash
    sudo add-apt-repository ppa:Name/ppa
    ```
    
- Remove repo:
    
    ```bash
    sudo add-apt-repository --remove ppa:Name/ppa
    ```
    
- Repositories are **verified with GPG keys**:
    
    ```bash
    sudo apt-key add keyfile.gpg
    ```
    

### 🔍 Common APT Commands

|Command|Description|
|---|---|
|`apt update`|Refresh package list from repos.|
|`apt upgrade`|Upgrade all installed packages.|
|`apt install pkg`|Install a package.|
|`apt remove pkg`|Remove a package (keep config).|
|`apt purge pkg`|Remove a package **with config**.|
|`apt autoremove`|Clean unused dependencies.|

---

## 📝 Memory Hook

- `/etc` = **config**
    
- `/var` = **variable data**
    
- `/bin` & `/sbin` = **essential binaries**
    
- `/usr` = **user apps & libs**
    
- `/dev` = **devices**
    
- `/proc` & `/sys` = **virtual system views**
    

---
