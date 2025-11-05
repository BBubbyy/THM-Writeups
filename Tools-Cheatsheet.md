# 🛠️ Toolkit

This is a summary list of essential tools and wordlists required for my Pentesting/CTF workflow. This file serves as a setup guide when moving to a new machine.

---

## 1. 📖 Wordlists

It's not necessary to fork the entire repositories. Instead, install or clone them locally for use.

### SecLists
The largest and most comprehensive collection of wordlists (usernames, passwords, fuzzing, etc.).
* **Install (Kali):**
    ```bash
    sudo apt update
    sudo apt install seclists
    ```
* **Path (Location):** `/usr/share/seclists/`
* **Install (General):**
    ```bash
    # Clone into your /opt or ~/Tools folder
    git clone [https://github.com/danielmiessler/SecLists.git](https://github.com/danielmiessler/SecLists.git)
    ```

### RockYou
The most famous breached password list (14 million passwords). A must-have for all cracking tasks.
* **Path (Location):** `/usr/share/wordlists/rockyou.txt.gz` (Already included in Kali)
* **Unzip Command:**
    ```bash
    sudo gunzip /usr/share/wordlists/rockyou.txt.gz
    ```

---

## 2. 🧰 Core Tools

These tools usually come pre-installed on Kali Linux, but this list ensures they are accounted for.

* **`nmap`**: The number one network and port scanner.
* **`john` (John the Ripper)**: Hash cracking tool (often used with `*2john` utilities like `ssh2john`, `zip2john`).
* **`hashcat`**: GPU-based hash cracker (faster than JtR).
* **`metasploit-framework` (msfconsole)**: The primary framework for exploitation.
* **`hydra`**: Popular brute-forcing tool (for SSH, FTP, etc.).
* **`responder`**: A tool for capturing network hashes (like NTLMv2).
* **`impacket-scripts`**: A suite of Python tools for attacking Windows networks (e.g., `secretsdump.py`, `psexec.py`).
* **`burpsuite`**: The standard proxy for intercepting and modifying HTTP requests (Web Hacking).
* **`nikto`**: Web server vulnerability scanner.
* **`dirbuster` / `gobuster` / `feroxbuster`**: Tools for brute-forcing web server directories and files.

---

## 3. 🌐 Web Hacking (Web-Specific Tools)

* **`sqlmap`**: Automated SQL Injection (SQLi) exploitation tool.
* **`wpscan`**: A dedicated scanner for WordPress vulnerabilities.

---

## 4. 🚀 Post-Exploitation & Privilege Escalation

These tools are not typically included by default and must be downloaded from GitHub. They are used on the attacker machine or uploaded to the victim machine to scan for internal misconfigurations.

### Privilege Escalation Scripts
(Uploaded to the victim machine)

* **PEASNG (LinPEAS & WinPEAS)**
    * **What it does:** The best all-in-one scripts for finding privilege escalation vectors on Linux and Windows. They check file permissions, services, cron jobs, saved credentials, kernel vulnerabilities, and more.
    * **GitHub:** `https://github.com/carlospolop/PEASNG`
    * **How to use:** Download the `.sh` (for Linux) or `.exe` (for Windows) file from the "Releases" tab.

* **PowerSploit (Specifically PowerUp.ps1)**
    * **What it does:** A collection of PowerShell scripts for Windows post-exploitation. `PowerUp.ps1` is excellent at finding misconfigured services, unquoted service paths, and other privilege escalation opportunities.
    * **GitHub:** `https://github.com/PowerShellMafia/PowerSploit`
    * **How to use:** `git clone` the repo and find `PowerUp.ps1` in the `Privesc` folder.

### Active Directory (AD) & Windows Tools
(Mostly run from the attacker machine)

* **BloodHound**
    * **What it does:** (Essential for AD) A tool that graphs relationships and "Attack Paths" in an Active Directory environment, helping you find the easiest way to Domain Admin.
    * **GitHub:** `https://github.com/BloodHoundAD/BloodHound`
    * **How to use:** You download the main GUI application and an ingestor called `SharpHound` (which you upload and run on the victim).

* **Mimikatz (Full)**
    * **What it does:** The original tool for dumping cleartext passwords and Kerberos tickets from Windows memory (LSASS). While Metasploit has `kiwi`, the full version is often more up-to-date.
    * **GitHub:** `https://github.com/gentilkiwi/mimikatz`
    * **How to use:** Download the `.exe` from the "Releases" tab.

* **Rubeus**
    * **What it does:** The number one tool for "Kerberos abuse" (like Kerberoasting).
    * **GitHub:** `https://github.com/GhostPack/Rubeus`

### Advanced Fuzzing and Web Tools

* **ffuf (Fuzz Faster U Fool)**
    * **What it does:** The fastest fuzzer available (written in Go), used for brute-forcing directories, subdomains, and web parameters. Often preferred over `gobuster`.
    * **GitHub:** `https://github.com/ffuf/ffuf`
    * **How to use:** Download the pre-compiled binary from the "Releases" tab.
