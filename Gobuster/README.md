# Gobuster: The Basics 

This is a summary of Gobuster, a critical tool for web reconnaissance. It covers the primary use cases (modes) and the practical steps learned in the TryHackMe room.

## 1. 🧠 What is Gobuster? 

**Gobuster** is an open-source, command-line tool written in Go, designed for brute-force enumeration of web servers. It's a fundamental tool in the **Reconnaissance** phase of a penetration test.

Its job is to take a **wordlist** (a list of common names) and try every single one against a target to discover hidden resources.

Gobuster operates in several "modes," but the three most important for web hacking are:

- **`dir`**: Directory and file enumeration
    
- **`dns`**: Subdomain enumeration
    
- **`vhost`**: Virtual Host enumeration
    

---

## 2. ⚙️ Setup & Critical Errors 

Before Gobuster can work on a target like `offensivetools.thm`, you must resolve two common errors:

### Error 1: DNS Not Resolving

- **The Problem:** You run Gobuster, and it immediately fails with `no such host`.
    
    Bash
    
    ```
    gobuster dns --domain offensivetools.thm ...
    ... dial tcp: lookup offensivetools.thm on 192.168.64.1:53: no such host
    ```
    
- **The Reason:** Your computer (`192.168.64.1`) doesn't know what IP address `offensivetools.thm` corresponds to. You must tell your machine to ask the lab's DNS server (`10.10.162.90`) first.
    
- **The Fix (Manual):**
    
    1. `sudo nano /etc/resolv.conf`
        
    2. Add the lab's DNS server **as the very first line**:
        
        ```
        nameserver 10.10.162.90
        nameserver 192.168.64.1
        ```
        
    3. Save the file. Your machine will now resolve the correct IP.
        

### Error 2: Wordlist Not Found

- **The Problem:** You try to use a wordlist, and Gobuster fails with `no such file or directory`.
    
    Bash
    
    ```
    ... wordlist file "/usr/share/wordlists/SecLists/..." does not exist
    ```
    
- **The Reason:** The `SecLists` collection is not installed on Kali by default.
    
- **The Fix (One-time Install):**
    
    Bash
    
    ```
    sudo apt update
    sudo apt install seclists
    ```
    

---

## 3. 📁 Use Case 1: Directory & File Enumeration (`dir` mode)

This is the most common use of Gobuster. It brute-forces directory and file names to find hidden pages like `/admin` or `config.php`.

### Key Flags

|**Flag**|**Description**|
|---|---|
|**`-u`**|The target **U**RL (e.g., `http://target.com`)|
|**`-w`**|The **W**ordlist to use|
|**`-x`**|File e**X**tensions to check for (e.g., `.php,.txt`)|
|**`-s`**|Only show results with these **S**tatus codes (e.g., `200,301`)|
|**`-b`**|**B**lacklist (hide) these status codes (e.g., `404,403`)|

### Lab Walkthrough (Task 4)

1. **Find the directory:** We scan the main site, looking for `.js` files.
    
    Bash
    
    ```
    gobuster dir -u http://www.offensivetools.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .js
    ```
    
    - **Discovery:** A directory named `/secret` is found.
        
2. **Find the file:** We run a new scan _inside_ the `/secret` directory.
    
    Bash
    
    ```
    gobuster dir -u http://www.offensivetools.thm/secret -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .js
    ```
    
    - **Discovery:** A file named `flag.js` is found.
        
3. **Get the flag:** We use `curl` to read the file's content.
    
    Bash
    
    ```
    curl http://www.offensivetools.thm/secret/flag.js
    THM{ReconWasASuccess}
    ```
    

---

## 4. 🌐 Use Case 2: Subdomain Enumeration (`dns` mode)

This mode queries the DNS server to find subdomains (e.g., `admin.target.com`, `api.target.com`).

### Key Flags

|**Flag**|**Description**|
|---|---|
|**`--domain`** or **`--do`**|The target **D**omain (e.g., `offensivetools.thm`)|
|**`-w`**|The **W**ordlist (this one should contain subdomain names)|
|**`-i`**|Show the **I**P addresses for each subdomain found|

### Lab Walkthrough (Task 5)

- **The Problem:** The lab example used `-d` for domain, but in modern Gobuster (`v3.8+`), `-d` is for `--delay`.
    
- **The Fix:** We must use the full `--domain` flag.
    

Bash

```
# We must use --domain, not -d
gobuster dns --domain offensivetools.thm -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

- **Result:** Gobuster lists all valid subdomains found (e.g., `Found: www.offensivetools.thm`, `Found: shop.offensivetools.thm`).
    

---

## 5. 🖥️ Use Case 3: Virtual Host Enumeration (`vhost` mode)

This mode is used to find other websites hosted on the **same IP address**. It works by changing the `Host` header in the HTTP request.

### Key Flags

|**Flag**|**Description**|
|---|---|
|**`-u`**|The target **U**RL (must be the IP address, e.g., `http://10.10.162.90`)|
|**`-w`**|The **W**ordlist (same as `dns` mode, a list of potential names)|
|**`--domain`**|The base domain to append (e.g., `offensivetools.thm`)|
|**`--append-domain`**|(Crucial) Appends the `--domain` to the wordlist entry (e.g., `blog` becomes `blog.offensivetools.thm`)|
|**`--exclude-length`**|Hides responses of a certain size (great for filtering out 404 pages)|

### Lab Walkthrough (Task 6)

Bash

```
gobuster vhost -u "http://10.10.162.90" --domain offensivetools.thm -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
```

- **Result:** Gobuster sends requests to the IP `10.10.162.90` but changes the `Host:` header for each word (e.g., `Host: blog.offensivetools.thm`), revealing other sites hosted on that server.
    

---

---

# 🚀 Gobuster: The Basics Cheat Sheet 

## 1. Workflows & Methods

|**🧠 Situation**|**🚀 Recommended Technique**|**🎯 Goal**|
|---|---|---|
|I need to find hidden pages or folders (e.g., `/admin`).|**`gobuster dir`** (Directory Mode)|Find accessible paths on a web server.|
|I need to find other websites on the same IP (e.g., `dev.target.com`).|**`gobuster dns`** (DNS Mode)|Enumerate subdomains via DNS queries.|
|`gobuster dns` found nothing, but I suspect more sites are on the IP.|**`gobuster vhost`** (VHost Mode)|Enumerate virtual hosts by modifying the `Host` header.|
|My scan fails with `no such host`.|**Edit `/etc/resolv.conf`**|Add the lab's DNS server (e.g., `nameserver 10.10.162.90`) as the _first_ line.|
|My scan fails with `wordlist ... does not exist`.|**`sudo apt install seclists`**|Install the standard wordlist collection on Kali.|

## 2. Key Commands & Flags

|**Mode**|**Command Example**|**Key Flags Explained**|
|---|---|---|
|**`dir`**|`gobuster dir -u http://[IP_or_Domain] -w [list.txt] -x .php,.txt -s 200,301`|**`-u`** (URL)<br><br>  <br><br>**`-w`** (Wordlist)<br><br>  <br><br>**`-x`** (Extensions)<br><br>  <br><br>**`-s`** (Show Status)|
|**`dns`**|`gobuster dns --domain [domain.com] -w [subdomains.txt] -i`|**`--domain`** (Target Domain)<br><br>  <br><br>**`-w`** (Wordlist)<br><br>  <br><br>**`-i`** (Show IPs)|
|**`vhost`**|`gobuster vhost -u http://[IP] -w [subdomains.txt] --domain [domain.com]`|**`-u`** (Target IP)<br><br>  <br><br>**`-w`** (Wordlist)<br><br>  <br><br>**`--domain`** (Base domain to test)|
