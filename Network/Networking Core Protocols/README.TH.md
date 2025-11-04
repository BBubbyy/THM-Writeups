# Networking Core Protocols (TH ver.)
### 1. WHOIS

**หน้าที่:**  
WHOIS คือบริการ/โปรโตคอลสำหรับค้นข้อมูลทะเบียนโดเมนสาธารณะ เช่น ใครเป็นผู้จดทะเบียน ใครเป็นผู้ให้บริการจดทะเบียน (registrar) วันที่สร้าง/หมดอายุ และข้อมูลติดต่อ (ถ้ามี)

**ฟิลด์ที่พบบ่อย:**

- ชื่อโดเมน (`Domain`)
    
- ผู้จดทะเบียน (`Registrar`)
    
- เจ้าของ/Registrant (มักถูกปิดด้วยบริการ privacy)
    
- วันที่สร้าง / หมดอายุ (creation / expiry)
    
- Name servers (NS)
    
- ข้อมูลติดต่อ (registrant/tech/admin)
    
- สถานะโดเมน (e.g., clientTransferProhibited)
    

**ตัวอย่างคำสั่ง:**

`whois example.com`

**ข้อสังเกต:**

- ข้อมูลอาจถูกปกป้องด้วยบริการความเป็นส่วนตัว (privacy/redaction)
    
- รูปแบบข้อมูลต่างกันตาม TLD (เช่น .com vs .uk)
    
- มีโปรโตคอลสมัยใหม่ชื่อ RDAP ที่ให้ผลลัพธ์เป็น JSON และมีการควบคุมการเข้าถึง
    

---

### 2. DNS (Domain Name System)

**หน้าที่:**  
แปลงชื่อที่มนุษย์อ่านได้เป็นทรัพยากรเครือข่าย (เช่น IP) และจัดการข้อมูลระดับโดเมน (MX, TXT ฯลฯ)

**ระเบียนที่สำคัญ:**

- **A** → แปลงชื่อเป็น IPv4
    
- **AAAA** → แปลงเป็น IPv6
    
- **CNAME** → alias → canonical name
    
- **MX** → ระบุเมลเซิร์ฟเวอร์และลำดับความสำคัญ
    
- **NS** → ระบุ nameserver ของโซน
    
- **SOA** → ข้อมูลเริ่มต้นของโซน (serial, refresh, retry...)
    
- **TXT** → เก็บข้อความ/นโยบาย (เช่น SPF, DKIM record)
    
- **PTR** → reverse DNS (IP → name)
    

**ลำดับการค้น (recursive resolution):**

1. Resolver → ถาม root servers
    
2. Root → ตอบ TLD servers
    
3. TLD → ตอบ authoritative nameserver
    
4. authoritative → ส่ง A/AAAA/MX กลับ
    

**คำสั่งตรวจสอบ:**

- `dig example.com A +short`
    
- `dig mx example.com`
    
- `nslookup example.com`
    
- `host -t txt example.com`
    

**ความปลอดภัย/ข้อควรระวัง:**

- ใช้ **DNSSEC** เพื่อยืนยันความถูกต้องของข้อมูล (ป้องกันการปลอมแปลง/caching poisoning)
    
- ระมัดระวังค่า TTL และการตั้งค่า MX/TXT ผิดพลาด
    

---

### 3. HTTP และ FTP

#### HTTP

**หน้าที่:** โปรโตคอลสำหรับดึง/ส่งทรัพยากรเว็บ (เว็บเพจ, API ฯลฯ)

**ประเด็นสำคัญ:**

- **Methods:** GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
    
- **Status codes:** 200, 301, 302, 404, 500 ฯลฯ
    
- **Headers:** Host, User-Agent, Content-Type, Authorization, Cookie, Set-Cookie, Location
    
- **HTTPS:** HTTP ผ่าน TLS — สำคัญด้านความลับและความถูกต้องของข้อมูล
    

**ตัวอย่างคำสั่ง:**

`curl -I https://example.com         # ดึง HTTP headers curl -v -X POST -d "a=1" https://api.example.com openssl s_client -connect example.com:443`

**ความปลอดภัย:** ควรใช้ HTTPS, ตรวจ cert, ตั้ง HSTS, ป้องกัน CSRF/Session hijacking

#### FTP

**หน้าที่:** โอนย้ายไฟล์ (client ↔ server)

**โหมดการเชื่อม:**

- **Active**: server เปิด connection กลับไปหาคลไอเอ็นต์ (ปัญหา NAT)
    
- **Passive**: client เปิด connection ไปยังพอร์ต data ของ server (ใช้กับ NAT ได้ดีขึ้น)
    

**คำสั่ง FTP ตัวอย่าง:**

`ftp> open ftp.example.com ftp> user anonymous ftp> ls ftp> get file.txt ftp> put upload.bin ftp> quit`

**พอร์ต/ความปลอดภัย:**

- ควบคุมที่พอร์ต 21 (control) และพอร์ต data แบบไดนามิก
    
- ใช้ **FTPS** (FTP+TLS) หรือ **SFTP** (SSH File Transfer Protocol — ไม่ใช่ FTP แต่ใช้ SSH บนพอร์ต 22) เพื่อความปลอดภัย
    

---

### 4. SMTP, POP3, IMAP (อีเมล)

#### SMTP (ส่งเมล)

**หน้าที่:** ส่งอีเมลจากผู้ส่งไปยัง Mail Transfer Agents (MTA) และระหว่างเซิร์ฟเวอร์

**พอร์ตสำคัญ:**

- 25 → SMTP (server-to-server)
    
- 587 → Submission (client → server; ใช้ STARTTLS)
    
- 465 → SMTPS (implicit TLS; legacy/common)
    

**ตัวอย่างการส่งแบบมือ (telnet):**

`telnet mail.example.com 25 HELO client.example.net MAIL FROM:<alice@example.net> RCPT TO:<bob@example.com> DATA Subject: Test Hello Bob . QUIT`

**ข้อควรระวัง:** เปิด relay ต้องป้องกัน; ใช้ TLS และ auth สำหรับการส่ง

---

#### POP3 (ดาวน์โหลดเมล)

**หน้าที่:** ดาวน์โหลดอีเมลจากเซิร์ฟเวอร์มายังคไลเอ็นต์ (มักลบจากเซิร์ฟเวอร์หลังดาวน์โหลด)

**พอร์ต:** 110 (POP3), 995 (POP3S/TLS)

**คำสั่งพื้นฐาน:** `USER`, `PASS`, `STAT`, `LIST`, `RETR <n>`, `DELE <n>`, `QUIT`

**ใช้งาน:** เหมาะเมื่อต้องการเก็บเมลไว้ในเครื่องเดียว (ไม่เหมาะกับหลายอุปกรณ์)

---

#### IMAP (จัดการเมลบนเซิร์ฟเวอร์)

**หน้าที่:** เข้าถึงและจัดการเมลบนเซิร์ฟเวอร์ (folder, flags, partial fetch) — ดีสำหรับหลายอุปกรณ์

**พอร์ต:** 143 (IMAP), 993 (IMAPS/TLS)

**คำสั่งตัวอย่าง:** `LOGIN`, `SELECT INBOX`, `FETCH 1:* (FLAGS BODY[HEADER])`, `SEARCH`, `STORE`, `LOGOUT`

**ใช้งาน:** เหมาะสำหรับการซิงก์สถานะเมลระหว่างอุปกรณ์หลายเครื่อง

**ความปลอดภัยอีเมลโดยรวม:**

- ใช้ **TLS** (STARTTLS/Implicit TLS) เพื่อปกป้อง credentials และเนื้อหาจดหมาย
    
- ติดตั้ง **SPF**, **DKIM**, **DMARC** เพื่อลดการปลอมแปลง/ฟิชชิง
