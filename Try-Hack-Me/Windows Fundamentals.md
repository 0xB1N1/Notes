```yaml
---
date: 2025-08-21
author: Sameer Saini
reason: 
title: Windows Administration & Active Directory
tags: [windows, ntfs, active-directory, kerberos, ntlm, sysadmin, filesystem]
---
```

# 🖥️ New Technology File System (NTFS)

> [!note]  
> Default filesystem in Windows. Replaced FAT16/32 and brought in journaling, permissions, encryption, and scalability.

## 🔑 Key Features

- **Journaling**: Logs metadata operations. If a crash happens, NTFS replays the journal to fix corruption.  
    _Example_: During a power outage, your Word file won’t vanish—NTFS uses the journal to restore the metadata.
    
- **Large File Support**: Handles files larger than 4GB (unlike FAT32).
    
- **Security Features**:
    
    - **ACLs (Access Control Lists)** → fine-grained permissions.
        
    - **EFS (Encrypting File System)** → per-file encryption.
        
- **Efficiency Features**:
    
    - **Compression** (saves space).
        
    - **Disk quotas** (limit user usage).
        
    - **Reparse points** (symlinks/junctions).
        
- **Alternate Data Streams (ADS)**:
    
    - Hidden additional data attached to a file.
        
    - Legitimate use: thumbnails, metadata.
        
    - Malicious use: malware hiding payloads.
        

```powershell
# Example: writing to ADS
echo "secret" > file.txt:hidden
# Reading ADS
more < file.txt:hidden
```

---

# 📂 File & Folder Permissions (NTFS ACLs)

|Permission|Meaning|
|---|---|
|**Full Control**|Complete control (read, write, modify, delete, change perms, ownership).|
|**Modify**|Read/write + delete.|
|**Read & Execute**|Open files/folders and run executables.|
|**List Folder**|See folder structure, not contents.|
|**Read**|View contents only.|
|**Write**|Create files/folders, append data.|

> [!example]  
> If you give _Read & Execute_ to `C:\Apps`, users can run `.exe` but cannot delete them.  
> For shared drives, combine **Modify** + **List** to allow updates but no permission tampering.

---

# ⚡ Alternate Data Streams (ADS)

- Every NTFS file has a default stream (`$DATA`).
    
- You can attach multiple streams → hidden info.
    
- Common in malware (hiding payloads inside `calc.exe:evil.dll`).
    

```powershell
# Check for ADS
Get-Item -Path "C:\test.txt" -Stream *
```

> [!warning]  
> ADS isn’t visible in Explorer or `dir`. Always scan for hidden streams.

---

# ⚙️ Windows Administrative Tools

## Environment Variable

- `%windir%` → path to Windows directory.  
    _Example_: `C:\Windows`
    

## User Manager

- Access via `lusrmgr.msc`.
    
- Manage local users & groups.
    

---

# 🔐 User Account Control (UAC)

- Stops silent privilege escalation.
    
- Modes:
    
    - _Notify only_
        
    - _Prompt for password_
        
    - _Silent elevation (disabled)_
        

> [!example]  
> If malware tries to install software in `C:\Program Files`, UAC will prompt admin approval.

---

# 🛠️ System Configuration (`msconfig`)

Sections:

1. **General** — normal, diagnostic, or selective startup.
    
2. **Boot** — safe mode, boot logging, timeout.
    
3. **Services** — enable/disable services.
    
4. **Startup** — startup apps (moved to Task Manager in modern Windows).
    
5. **Tools** — shortcuts to utilities (`compmgmt`, `msinfo32`, etc.).
    

---

# 🖥️ Computer Management (`compmgmt.msc`)

### 📌 System Tools

- **Task Scheduler** → schedule jobs (e.g., backups at 2AM).
    
- **Event Viewer** → monitor logs:
    
    - Error, Warning, Information, Success Audit, Failure Audit.  
        _Example_: Event ID `4625` = failed login.
        
- **Shared Folders** → view sessions (`ADMIN$`, `C$`).
    
- **Local Users & Groups** → manage accounts.
    
- **Performance** → live performance counters.
    
- **Device Manager** → drivers, USB, hardware management.
    

### 📌 Storage

- **Disk Management** → partitions, volumes.
    
- **Windows Backup** → configure backups.
    

### 📌 Services & Applications

- **WMI Control** → allow PowerShell/remote scripts.
    

---

# 🖨️ System Information & Monitoring

- `msinfo32` → hardware/software details.
    
- `resmon` → real-time CPU, RAM, disk, network per process.
    

---

# 🗝️ Registry Editor (`regedit`)

- Hierarchical DB for OS & app settings.
    
- Example paths:
    
    - `HKLM\Software\Microsoft`
        
    - `HKCU\Software\Microsoft`
        

> [!danger]  
> Editing registry incorrectly can brick Windows. Always export keys before changing:

```cmd
reg export HKLM\SOFTWARE backup.reg
```

---

# 🔒 Trusted Platform Module (TPM)

- Hardware chip for cryptographic keys.
    
- Works with **BitLocker** (stores startup key).
    
- Access: `tpm.msc`.
    

> [!tip]  
> Use TPM+PIN mode in BitLocker for stronger protection.

---

# 🌐 Active Directory (AD)

> [!note]  
> Centralized directory service for managing users, machines, and resources in a **domain**.

## 🔑 Core Concepts

- **Domain** → boundary for policies/accounts.
    
- **Domain Controller (DC)** → server running AD DS.
    
- **Object** → user, group, machine, printer, etc.
    
- **Security Principals** → users/groups/machines that can be assigned permissions.
    

### Users

- **People** → humans.
    
- **Service Accounts** → for apps/services.
    

### Machines

- Each machine has an AD account (e.g., `DC0$`).
    
- Passwords auto-rotated (~120 chars).
    

### Security Groups

- **Domain Admins** → full domain control.
    
- **Server Operators** → manage DC servers.
    
- **Backup Operators** → backup/restore data.
    
- **Account Operators** → manage users/groups.
    
- **Domain Users** → all accounts.
    
- **Domain Computers** → all machines.
    

---

# 🧑‍💻 Active Directory Users & Computers (ADUC)

- Manage users, groups, computers.
    
- Objects organized into **Organizational Units (OUs)**.
    
- Can apply **Group Policy Objects (GPOs)** to OUs.
    
- **Delegation** → give limited admin rights (e.g., reset passwords).
    

### Default OUs

- Builtin
    
- Computers
    
- Domain Controllers
    
- Users
    
- Managed Service Accounts
    

---

# 📜 Group Policy

- Managed via **Group Policy Management**.
    
- GPOs stored in `C:\Windows\SYSVOL\sysvol`.
    
- Linked to OUs.
    
- Example: enforce password complexity policy for all users.
    

---

# 🔑 Authentication Methods

## Kerberos


Kerberos is a **ticket-based authentication protocol**. Instead of sending passwords over the network, it uses **encrypted tickets** and **session keys** to prove identity.

The three main actors are:

- **Client (User/Machine)** → Wants to authenticate and access a service.
    
- **KDC (Key Distribution Center)** → Runs on a **Domain Controller**. Has 2 parts:
    
    - **AS (Authentication Service)** → Issues Ticket Granting Ticket (TGT).
        
    - **TGS (Ticket Granting Service)** → Issues Service Tickets.
        
- **Service/Server** → The actual resource you want to access (file server, SQL, etc).
    

#### 🔹 Step 1 – Authentication (AS Exchange)

👉 Goal: Get a **Ticket Granting Ticket (TGT)** to prove who you are.

1. **User → AS (Authentication Service)**
    
    - User sends:
        
        - Username
            
        - Timestamp (to prevent replay attacks)
            
        - All encrypted using a key derived from the user’s password hash.
            
2. **AS → User**
    
    - AS checks if it can decrypt the request using stored hash in AD. If success → user is real.
        
    - AS creates 2 things:
        
        - **TGT (Ticket Granting Ticket):**
            
            - Contains username, group, validity time, and a **session key**.
                
            - Encrypted with **krbtgt account’s password hash** (only KDC can open this).
                
        - **Session Key (User ↔ TGS):**
            
            - Encrypted with **user’s password hash**.
                

💡 **Important:**

- User can decrypt the **session key**, but not the TGT.
    
- KDC does **not store the session key** → it is kept inside the TGT itself.


#### 🔹 Step 2 – Ticket Request (TGS Exchange)

👉 Goal: Use the TGT to request access to a service.

1. **User → TGS (Ticket Granting Service)**
    
    - User sends:
        
        - TGT (still encrypted with krbtgt hash, so user can’t read/change it).
            
        - Authenticator → username + timestamp, encrypted with the **session key** from Step 1.
            
        - The **Service Principal Name (SPN)** → tells which service user wants.
            
2. **TGS → User**
    
    - TGS decrypts the TGT with the krbtgt key → gets the session key.
        
    - Uses session key to decrypt the Authenticator → proves user has the right key.
        
    - TGS now issues 2 things:
        
        - **Service Ticket (ST):**
            
            - Contains user info, validity time, and a **service session key**.
                
            - Encrypted with the **service account’s password hash**.
                
        - **Service Session Key (User ↔ Service):**
            
            - Encrypted with the **User↔TGS session key** from Step 1.
                

💡 **Important:**

- User cannot read the Service Ticket (only the service can).
    
- User can read the Service Session Key (since it’s encrypted with the session key from Step 1).
    

#### 🔹 Step 3 – Service Access (AP Exchange)

👉 Goal: Use the **Service Ticket** to actually log in to the service.

1. **User → Service**
    
    - Sends:
        
        - **Service Ticket (ST)** (still encrypted with service’s account password hash).
            
        - **Authenticator** (new timestamp, encrypted with the Service Session Key).
            
2. **Service → User** (Optional Mutual Auth)
    
    - Service decrypts the Service Ticket using its own password hash.
        
    - Gets the Service Session Key.
        
    - Uses it to decrypt the Authenticator → verifies user identity.
        
    - Optionally, service sends back a response (timestamp + 1) encrypted with Service Session Key → proving it is the real service.
        

💡 **Result:**  
User is now authenticated and can use the service without ever sending their password.

---

#### ⚡ Example Walkthrough

Suppose **Alice** wants to access `fileserver01` in a domain:

1. Alice enters password → system derives NT hash.
    
2. AS gives her a **TGT** + Session Key.
    
3. Alice presents TGT to TGS with request for `cifs/fileserver01`.
    
4. TGS gives her:
    
    - Service Ticket (encrypted for `fileserver01$`)
        
    - Service Session Key (encrypted with Alice’s session key).
        
5. Alice sends Service Ticket + Authenticator to `fileserver01`.
    
6. `fileserver01` decrypts ticket → validates Alice.
    
7. Alice gains access to shared files.
    

---

## NTLM


#### 🔒 NTLM Authentication (Detailed Flow)

NTLM = **NT LAN Manager**, an older Microsoft authentication protocol.  
It’s **challenge-response based** (no tickets, unlike Kerberos).

---

#### 🔹 Step 0 – Password Hash Stored in AD

- Each user’s password is hashed (NT Hash, sometimes LM Hash for legacy).
    
- Domain Controller (DC) stores this hash in the Security Accounts Manager (SAM) or Active Directory.
    

💡 **Note:** The actual password is never stored, only the hash.

---

#### 🔹 Step 1 – Negotiate (Client → Server)

👉 Goal: Client tells server it wants to use NTLM.

1. **Client → Server**
    
    - Sends a **Negotiate Message** with supported NTLM options.
        
2. **Server → Client**
    
    - Responds with a **Challenge Message** containing:
        
        - A **random nonce** (challenge number).
            
        - Flags for supported features.
            

---

#### 🔹 Step 2 – Challenge Response (Client → Server)

👉 Goal: Prove knowledge of password **without sending it**.

1. **Client → Server**
    
    - Client takes:
        
        - User’s NT Hash (derived from password).
            
        - The challenge nonce from server.
            
    - Runs a special function (HMAC-MD5 in NTLMv2) to combine:
        
        ```
        Response = HMAC-MD5( NT-Hash, Challenge + Timestamp + Client Nonce + Target Info )
        ```
        
    - Sends back:
        
        - Username + Domain
            
        - Response (encrypted blob).
            

💡 **Key Point:**  
The **NT Hash is never sent**. Only the response is sent.

---

#### 🔹 Step 3 – Server → Domain Controller Validation

👉 Goal: Verify client’s response against real stored hash.

1. **Server → Domain Controller (DC)**
    
    - Forwards: Username, Challenge, Response.
        
2. **Domain Controller**
    
    - Looks up the user’s NT Hash from AD.
        
    - Performs the **same calculation** (HMAC-MD5 using challenge and NT Hash).
        
    - Compares result with client’s response.
        
3. **DC → Server**
    
    - If results match → Authentication Success.
        
    - If not → Authentication Failure.
        

---

## ##  Step 4 – Access Granted / Denied

- If successful, server gives the client access to requested resource.
    

---

# ⚡ Example Walkthrough

Let’s say **Bob** wants to log into `fileserver01` using NTLM:

1. Bob enters password. His workstation computes NT Hash.
    
2. `fileserver01` sends Bob a random **Challenge = 0xA1B2C3D4**.
    
3. Bob’s machine computes:

    ```
    Response = HMAC-MD5( NT-Hash, Challenge + Timestamp +     ClientNonce + TargetInfo )
    ```
    
4. Bob sends username + domain + Response.
    
5. `fileserver01` sends this to DC.
    
6. DC computes the same Response using stored NT Hash.
    
7. If matches → Bob is authenticated, gets access.
    

---

# 🌲 Tree, Forest, and Trusts

- **Tree** → one or more domains with a common DNS root.  
    _Example_:
    
    - `corp.com`
        
    - `sales.corp.com`
        
    - `it.corp.com`
        
- **Forest** → multiple trees, even if DNS roots differ.  
    _Example_: `corp.com` + `school.edu`.
    
- **Trusts**:
    
    - **One-Way**: Domain A trusts B. A users can access B resources, but not vice versa.
        
    - **Two-Way**: Both can access each other’s resources.
        

---
