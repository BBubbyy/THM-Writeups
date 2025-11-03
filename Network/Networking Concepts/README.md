# Networking Concepts ENG ver.

### **1. ISO OSI Network Model**

**Full name:** Open Systems Interconnection (OSI) model  
**Purpose:** A conceptual model that describes how data travels from one computer to another over a network.
![The seven layers of the OSI ISO Model.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719848845717.svg)
**Layers (7 total):**

|#|Layer Name|Function|Example|
|---|---|---|---|
|7|Application|Interface for end users|HTTP, FTP, DNS|
|6|Presentation|Data formatting, encryption|SSL/TLS, JPEG|
|5|Session|Maintains connections|NetBIOS, RPC|
|4|Transport|Data transfer reliability|TCP, UDP|
|3|Network|Routing and addressing|IP, ICMP|
|2|Data Link|Error detection, framing|Ethernet, MAC|
|1|Physical|Transmission through cables|Cables, Hubs, Wi-Fi|

📘 **Simple analogy:**  
Sending a letter —  
You write (Application), pack (Presentation), manage delivery (Session), ensure correct delivery (Transport), find address (Network), send through post office (Data Link), and physically move the letter (Physical).

---

### **2. IP Addresses, Subnets, and Routing**
![An IP address is made up of 4 octets or bytes and each octet represents a decimal number between 0 and 255.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849005781.png)
**IP Address** – A unique identifier for a device on a network.

- IPv4 → 192.168.1.1
    
- IPv6 → 2001:0db8::1
    

**Subnet** – A subdivision of a network used to organize and improve efficiency.  
Example:

- Network: 192.168.1.0/24 → 256 possible IPs (0–255)
    
- Subnet mask: 255.255.255.0
    

**Routing** – The process of finding the best path for data to travel across networks.  
Routers forward packets based on their destination IP address.

---

### **3. TCP, UDP, and Port Numbers**
![The TCP three-way handshake requires the exchange of three packets.](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1719849036216.svg)

|Feature|TCP (Transmission Control Protocol)|UDP (User Datagram Protocol)|
|---|---|---|
|Connection|Connection-oriented (3-way handshake)|Connectionless|
|Reliability|Guaranteed delivery|No guarantee|
|Speed|Slower|Faster|
|Use cases|Web (HTTP), Email (SMTP), File transfer (FTP)|Video streaming, VoIP, Gaming|
|Example port|80 (HTTP), 443 (HTTPS)|53 (DNS), 69 (TFTP)|

**Port Numbers:**  
Identify specific applications on a device.  
Range: 0–65535

- 0–1023 → Well-known ports
    
- 1024–49151 → Registered
    
- 49152–65535 → Dynamic/Private
    

---

### **4. How to Connect to an Open TCP Port (Command Line)**

You can connect to a TCP port from the terminal using several tools:

🧩 **1. Telnet**

`telnet <IP> <port> # Example: telnet example.com 80`

🧩 **2. Netcat (nc)**

`nc <IP> <port> # Example: nc 192.168.1.10 22`

🧩 **3. PowerShell (on Windows)**

`Test-NetConnection <IP> -Port <port> # Example: Test-NetConnection google.com -Port 443`

✅ If the connection succeeds → the port is open.  
❌ If it fails → the port is closed or filtered by a firewall.
