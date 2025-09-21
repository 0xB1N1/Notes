```yaml
---
date: 2025-08-29
author: Sameer Sani
reason: 0x45
title: Imp of Cryptography (Notes)
tags: [cryptography, ctf, notes]
---
```

# Imp of Cryptography

> These are quick notes — kept close to the original wording but cleaned for Obsidian readability.

> [!quote]- Why it's important  
> --> You know why it is imp  
> --> Payment Card Industry Data Security Standard (PCI DSS), as the same say

---

## Plane → Ciphertext (Terminology)

- **Plaintext** — Readable message
    
- **Ciphertext** — Scrambled message
    
- **Cipher** — Algorithm used to convert plaintext → ciphertext
    
- **Key** — Bit/string used to encrypt or decrypt text
    

---

## Historical Ciphers

> [!info] Common CTF cipher: Caesar cipher

- Shift each character by `x` positions to encrypt, shift back by `x` to decrypt.
    
- Very weak: only 25 possible shifts in English (26 letters — shift by 26 = identity).
    

---

## Types of Encryption

### Symmetric Encryption

- Same key used to encrypt and decrypt. Must be shared securely.
    
- Good for large-volume encryption (whole disks, files).
    
- Examples:
    
    - `DES` (not secure — broken quickly)
        
    - `3DES` (discontinued 2019)
        
    - `AES` — key sizes: **128**, **192**, **256** bits
        

### Asymmetric Encryption

- Uses a **public key** (encrypt) + **private key** (decrypt).
    
- Share public key; keep private key secure.
    
- Slower / larger keys than symmetric — not ideal for encrypting huge files directly; used to exchange symmetric keys or sign data.
    
- Examples:
    
    - `RSA` (2048, 3072, 4096-bit keys typical)
        
    - `Diffie-Hellman` (key exchange)
        
    - `ECC` (Elliptic Curve) — shorter keys for same security (e.g., 256-bit ECC ≈ 3072-bit RSA)
        

---

## Basic Math — XOR

- **XOR** (exclusive OR) compares bits: returns `1` if bits differ, `0` if same.
    
    ```
    0 xor 0 = 0
    0 xor 1 = 1
    1 xor 0 = 1
    1 xor 1 = 0
    ```
    
- Properties:
    
    - `A xor A = 0`
        
    - `A xor 0 = A`
        
    - Commutative: `A xor B = B xor A`
        
    - Associative: `(A xor B) xor C = A xor (B xor C)`
        
- Symmetric example:
    
    ```
    C = P xor K
    (P xor K) xor K = P xor (K xor K) = P xor 0 = P
    ```
    

---

## RSA (brief)

> Public-key algorithm based on difficulty of factoring large semiprimes.

**High-level flow**

1. Alice encrypts with Bob's **public key** → Bob decrypts with his **private key**.
    
2. Key generation (Bob):
    
    - Choose two primes `p`, `q`.
        
    - `n = p * q` (public).
        
    - `phi(n) = (p-1)*(q-1)`.
        
    - Choose `e` such that `1 < e < phi(n)` and `gcd(e, phi(n)) = 1`. (`e` is public exponent)
        
    - Compute `d` such that `e * d ≡ 1 (mod phi(n))` (private exponent).
        
    - Public key: `(n, e)` — Private key: `(n, d)`.
        

**Toy example from notes**

- `p = 157`, `q = 199` → `n = 31243`
    
- `phi(n) = 156 * 198 = 30888` (note: original had 3088 — phi should be (p-1)*(q-1) — keep the described steps)
    
- `e = 163` (coprime with phi)
    
- `d = 379` (satisfies `e * d ≡ 1 (mod phi)`)
    
- Encrypt `x = 13`: `y = x^e mod n` → `13^163 % 31243 = 16341`
    
- Decrypt `y = 16341`: `x = y^d mod n` → `16341^379 % 31243 = 13`
    

> [!note] The example illustrates the algorithm flow; real RSA uses much larger primes.

---

## Diffie–Hellman Key Exchange

- Used when two parties want a shared symmetric key without sending it directly.
    
- Both agree on public values `p` (prime) and `g` (generator). Each picks private secret (`a`, `b`) and exchanges `g^a mod p`, `g^b mod p`. Each computes shared secret:
    
    ```
    shared = (g^b)^a mod p = (g^a)^b mod p
    ```
    
- Example in notes:
    
    - `p = 29`, `g = 3`
        
    - Abhay private `a = 13` → `A = 3^13 mod 29 = 19`
        
    - Sameer private `b = 15` → `B = 3^15 mod 29 = 26`
        
    - Shared: `19^15 mod 29 = 10` and `26^13 mod 29 = 10`
        

![Diffie-Hellman image](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1728439878360.svg)

---

## SSH

- On first connect, SSH shows a host key fingerprint (e.g., ED25519). If unknown, SSH prompts to continue — this protects against MITM (man-in-the-middle).
    
- **ED25519** — public-key signature algorithm (EdDSA on Curve25519).
    
- `ssh-keygen -t <algo>` to generate keys. Common algos:
    
    - `dsa` (DSA)
        
    - `ecdsa` (ECDSA)
        
    - `ecdsa-sk` (ECDSA with security key)
        
    - `ed25519` (Ed25519)
        
    - `ed25519-sk` (Ed25519 with security key)
        

---

## Digital Signature

- Sign a file by encrypting its hash with a private key; recipient verifies by decrypting with public key and comparing hashes.
    
- Certificates (CA-signed) prove identity — e.g., HTTPS certificates. Let's Encrypt is a free CA option.
    

---

## PGP & GPG

- `PGP` — Pretty Good Privacy (encryption/signing tool).
    
- `GPG` — GNU Privacy Guard (open-source OpenPGP implementation).
    
- Use `gpg` for encrypting and signing; choose algorithms and expiry when generating keys.
    
- Example commands:
    
    ```bash
    gpg --import backup.key
    gpg --decrypt message.gpg
    ```
    
- For CTFs: might use `gpg2john` + John the Ripper to crack passphrase-protected private keys.
    

---

## Hash Basics

- Hashing: one-way, same input → same digest. Collisions possible (different inputs → same digest).
    
- Many hash formats include: `$prefix$options$salt$hash` — prefix indicates algorithm (e.g., `$6$` → SHA512). See `man 5 crypt`.
    
- Cracking: rainbow tables, `hashcat`, `john`.
    
    - `hashcat` example:
        
        ```
        hashcat -m <hashcode> -a <attack-mode> <hashFile> <wordlist>
        ```
        
- Hashes used for integrity. HMAC = keyed-hash for authentication + integrity.
    

---

## John (John the Ripper)

- Basic automatic cracking:
    
    ```bash
    john --wordlist=/path/to/wordlist <hashfile>
    ```
    
- John may not auto-detect hash format reliably — use `hash-id.py` or online hash identification, or pass `--format=<format>`.
    

---

## Cracking Windows Auth Hashes

- `NTHash` / `NTLM` formats used by Windows. Hashes stored in SAM or `NTDS.dit`. Tools: `mimikatz`, AD database extraction.
    

---

## Cracking `/etc/shadow` (Linux)

- Use `unshadow` to combine `/etc/passwd` + `/etc/shadow` into John format:
    
    ```bash
    unshadow /etc/passwd /etc/shadow > johnfile.txt
    ```
    
- Often converts to `sha512crypt` or other recognizable formats for John.
    

---

## Single Crack Mode (John)

- `--single` mode guesses passwords from username/GECOS fields using mangling (e.g., `Sameer1`, `Sameer!`).
    
- GECOS contains user info (full name, office, phone) — John can use this to generate candidate passwords.
    
- Example transform of hash file to single-mode-compatible format:
    
    ```
    mike:1efee03cdcb96d90ad48ccc7b8666033
    ```
    

---

## Custom Rules (John)

- Define rules in `john.conf` or `/opt/john/john.conf`, e.g.:
    
    ```
    [List.Rules:THMRules]
    Az   # append chars
    A0   # prepend chars
    c    # capitalize positionally
    ```
    
- Rule syntax can include character sets: `[0-9]`, `[A-Z]`, `[a-z]`, `[A-z]`, `[a]` (only 'a').
    
- Example rule to generate `Polopassword1!` variants:
    
    ```
    [List.Rules:Polopassword1!]
    cAz"[0-9] [!$@%&]"
    ```
    
- Use rules with `--rules=<ruleName>` or `--rule=<ruleName>` (depends on John version).
    

---

## Zip / RAR / SSH Key Cracking

- Zip:
    
    ```bash
    zip2john file.zip > zip.hash
    john zip.hash --wordlist=...
    ```
    
- RAR:
    
    ```bash
    rar2john file.rar > rar.hash
    ```
    
- SSH private keys:
    
    ```bash
    ssh2john id_rsa > ssh.hash
    john ssh.hash --wordlist=...
    ```
    

---


