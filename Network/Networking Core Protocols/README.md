# Networking Core Protocols

### 1. WHOIS

**Purpose:**  
WHOIS is a protocol/service to query public registration data for domain names (and sometimes IP blocks). It tells you who registered a domain, registrar, important dates, and contact/admin info.

**What you get (common fields):**

- **Domain:** example.com
    
- **Registrar:** company that registered the domain
    
- **Registrant:** owner organization/person (may be redacted/privileged)
    
- **Creation Date / Expiry Date** (important for lifecycle)
    
- **Name Servers (NS)**
    
- **Registrant/Tech/Admin contact** (email/phone) — often privacy-protected
    
- **Status** (e.g., ok, clientTransferProhibited)
    

**How to query (examples):**

- CLI whois:
    

`whois example.com`

- Web WHOIS lookup pages (registrars, ICANN WHOIS)
    

**Notes / Caveats:**

- Accuracy depends on registrant/proxy/privacy services — many entries are redacted.
    
- WHOIS data differs by TLD (gTLD vs ccTLD).
    
- There’s also RDAP (Registration Data Access Protocol) as a modern replacement with JSON and access control.
    

---

### 2. DNS (Domain Name System)

**Purpose:**  
DNS resolves human names (e.g., `example.com`) to network resources (IP addresses, mail servers, etc.). It is the Internet’s naming system.

**Common record types:**

- **A** — IPv4 address (e.g., `example.com. A 93.184.216.34`)
    
- **AAAA** — IPv6 address
    
- **CNAME** — canonical name (alias)
    
- **MX** — mail exchanger (priority + hostname)
    
- **NS** — authoritative name servers for the zone
    
- **SOA** — start of authority (zone metadata: serial, refresh, retry, expire, TTL)
    
- **TXT** — arbitrary text (used for SPF, DKIM, verification)
    
- **PTR** — reverse DNS (IP → name)
    

**How it works (brief):**

1. Resolver asks recursive DNS server (ISP or public) for `www.example.com`
    
2. Recursive server queries root → TLD → authoritative name server
    
3. Authoritative server returns record (A/AAAA), resolver caches the answer per TTL.
    

**Commands / Examples:**

- `dig example.com A +short` → returns IPv4
    
- `dig mx example.com` → returns mail exchangers
    
- `nslookup example.com` → interactive/legacy tool
    
- `host -t txt example.com` → check TXT records
    

**Security / Operations:**

- **DNSSEC** adds signatures to prevent tampering (validates authenticity).
    
- Be aware of **cache poisoning**, **spoofing**, and **misconfigured MX/TXT**.
    
- TTL controls caching duration.
    

---

### 3. HTTP and FTP

#### HTTP (Hypertext Transfer Protocol)

**Purpose:** Client-server protocol for web resources (web pages, APIs).

**Key concepts:**

- **Methods:** GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
    
- **Status codes:** 1xx (info), **2xx** (success e.g., 200), **3xx** (redirect e.g., 301), **4xx** (client e.g., 404), **5xx** (server e.g., 500)
    
- **Headers:** Host, User-Agent, Accept, Content-Type, Authorization, Cookie, Set-Cookie, Content-Length, Location (redirect)
    
- **HTTPS:** HTTP over TLS — protects confidentiality and integrity.
    

**Tools / Examples:**

- `curl -I https://example.com` → fetch headers
    
- `curl -v -X POST -d "name=alice" https://api.example.com/submit`
    
- `openssl s_client -connect example.com:443` → TLS handshake debug
    

**Security notes:** Use HTTPS (TLS), watch for insecure headers, CSRF, insecure cookies, HSTS, and certificate issues.

#### FTP (File Transfer Protocol)

**Purpose:** Transfer files between client and server (legacy but still used).

**Modes:**

- **Active mode:** server connects back to client’s port for data — may fail behind NAT/firewall.
    
- **Passive mode:** client connects to server’s data port — usually works better with NAT.
    

**Commands (FTP session):**

`ftp> open ftp.example.com Name: anonymous ftp> ls ftp> get file.txt ftp> put upload.bin ftp> quit`

**Ports / Security:**

- **Port 21** for control; data uses dynamic ports (or specified).
    
- **FTPS** = FTP over TLS (adds encryption).
    
- **SFTP** is different — runs over SSH (port 22) and is preferred over plain FTP.
    

---

## **4. SMTP, POP3, and IMAP (with Example)**

### **POP3 Practical Example via Telnet**

Below is a real-world demonstration of how a user connects to a POP3 mail server, authenticates, lists, and retrieves messages using **Telnet**:

`root@ip-10-10-101-191:~# telnet 10.10.60.35 110 Trying 10.10.60.35... Connected to 10.10.60.35. Escape character is '^]'. +OK [XCLIENT] Dovecot (Ubuntu) ready. AUTH +OK PLAIN . USER linda +OK PASS Pa$$123 +OK Logged in. STAT +OK 4 2216 LIST +OK 4 messages: 1 690 2 589 3 483 4 454 . RETR 4 +OK 454 octets Return-path: <user@client.thm> Envelope-to: linda@server.thm Delivery-date: Thu, 12 Sep 2024 20:12:42 +0000 Received: from [10.11.81.126] (helo=client.thm)  by example.thm with smtp (Exim 4.95)  id 1soqAj-0007li-39  for linda@server.thm;  Thu, 12 Sep 2024 20:12:42 +0000 From: user@client.thm To: linda@server.thm Subject: Your Flag  Hello! Here's your flag: THM{TELNET_RETR_EMAIL} Enjoy your journey!`

### **Explanation**

- `telnet 10.10.60.35 110` → connects to POP3 port (110).
    
- Server banner shows **Dovecot (Ubuntu)** — POP3 service.
    
- `USER` / `PASS` → authentication for mailbox _linda_.
    
- `STAT` → shows total message count and total size.
    
- `LIST` → lists all emails with size.
    
- `RETR 4` → retrieves message number 4, showing full headers and body.
    
- Message body contains a flag: **`THM{TELNET_RETR_EMAIL}`**
    

**Note:** Telnet over plaintext POP3 transmits credentials unencrypted — use **POP3S (995)** or **STARTTLS** in real environments.

---

---

#### POP3 (Post Office Protocol v3)

**Purpose:** Download emails from server to client (commonly downloads & optionally deletes on server).

**Ports:**

- **110** — POP3 (plaintext or STARTTLS)
    
- **995** — POP3S (POP3 over TLS)
    

**Common commands:** `USER`, `PASS`, `STAT`, `LIST`, `RETR <msg>`, `DELE <msg>`, `QUIT`

**Use case:** Simple offline mail reading (old-school). Not good for multi-device sync.

---

#### IMAP (Internet Message Access Protocol)

**Purpose:** Access and manage mail **on the server** — supports folders, flags, partial fetch; better for multi-device sync.

**Ports:**

- **143** — IMAP (plaintext / STARTTLS)
    
- **993** — IMAPS (IMAP over TLS)
    

**Common commands:** `LOGIN`, `SELECT <mailbox>`, `FETCH`, `SEARCH`, `STORE` (set flags), `LOGOUT`

**Use case:** Keeps mail on server; multiple clients can see same state (ideal for phones + laptop).

**Security notes (all email):**

- Prefer TLS (STARTTLS or implicit TLS).
    
- Use SPF, DKIM, DMARC, and rate-limiting to reduce spoofing/phishing.
    
- Protect credentials; avoid plaintext auth on port 25 without TLS.
