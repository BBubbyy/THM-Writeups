# Burp Suite: The Basics

This is a comprehensive summary of the **Burp Suite** framework, covering the essential concepts and techniques for web application penetration testing.

## 1. 🧠 What is Burp Suite? 

**Burp Suite** is a Java-based framework that serves as the industry-standard tool for web application security testing.

Its primary function is to act as a **"Proxy"** or **"Man-in-the-Middle" (MITM)**, allowing it to **"Intercept"** all HTTP Requests and Responses traveling between your "web browser" and the target "web server."

This interception allows you to:

1. **Inspect:** View the raw data being sent and received.
    
2. **Manipulate:** "Edit" the data _before_ it reaches its destination.
    

### 🛠️ Core Tools (Community Edition)

|**Tool**|**Function**|
|---|---|
|**Proxy**|(The core) Intercepts, views, and modifies all HTTP/S traffic.|
|**Repeater**|"Replays" a single request multiple times, allowing for trial-and-error testing.|
|**Intruder**|"Sprays" a target with many requests (used for brute-forcing, fuzzing). (This is rate-limited in the free edition).|
|**Decoder**|"Transforms" data between formats (e.g., Base64, URL Encoding, Hex).|
|**Comparer**|"Compares" two pieces of data (like two requests or responses) to find differences.|
|**Site map (Target)**|A "map" of the target application, built from the traffic Burp has seen.|

---

## 2. ⚙️ Essential Setup & Configuration

Before you can intercept traffic, you must configure your browser and Burp Suite to work together.

### Workflow 1: FoxyProxy Setup 

This browser extension allows you to quickly turn proxying on or off.

1. **In FoxyProxy Options:** Click `Add`.
    
2. **Configure:**
    
    - **Title:** `Burp`
        
    - **Proxy IP address:** `127.0.0.1` (your local machine)
        
    - **Port:** `8080` (Burp's default port)
        
3. **Activate:** Click the FoxyProxy icon in your browser and select the `Burp` profile.
    

### Workflow 2: Handling HTTPS

When you try to intercept an `HTTPS` site, your browser will show a security error because it doesn't trust Burp's "fake" certificate. You must fix this:

1. **Enable Proxy:** (Turn on Burp and FoxyProxy).
    
2. **Go to:** `http://burp/cert` (in your browser).
    
3. **Download:** Save the `cacert.der` file.
    
4. **In Firefox:** Go to `about:preferences` -> Search for `Certificates` -> Click `View Certificates...`
    
5. **Import:** Select the `Authorities` tab -> `Import...` -> Choose the `cacert.der` file.
    
6. **Trust:** Check the box for **"Trust this CA to identify websites"** and click OK.
    

### Workflow 3: The Burp Browser 

This is the "easy shortcut" that bypasses the FoxyProxy and Certificate steps.

- Burp Suite includes its own built-in Chromium browser that is pre-configured to use the proxy and trust its certificate.
    
- **How to use:** Go to the `Proxy` tab -> `Intercept` tab -> Click the **`Open Browser`** button.
    
- **(If on Kali/AttackBox):** If it fails to start (due to running as `root`), go to `Settings` -> `Tools` -> `Burp's browser` -> Check the box **"Allow Burp's browser to run without a sandbox"**.
    

---

## 3. 🎯 Practical Usage (Scoping & Example Attack)

### Defining the Scope 

To prevent "noise" (traffic from Google, Mozilla) from cluttering your logs, you must set a "Scope."

1. **Step 1 (Target Scope):**
    
    - Go to `Target` -> `Site map`.
        
    - Right-click your target (e.g., `http://10.10.78.61`).
        
    - Select **`Add To Scope`** (and click `Yes`).
        
    - _Result:_ `Site map` and `HTTP history` will now hide out-of-scope items.
        
2. **Step 2 (Proxy Scope):**
    
    - Go to `Proxy` -> `Proxy settings`.
        
    - In the `Intercept Client Requests` section...
        
    - Check the box: **`And URL Is in target scope`**.
        
    - _Result:_ The `Intercept is on` button will now _only_ stop traffic that is in your scope.
        

### Reconnaissance 

The `Site map` (in the `Target` tab) is your map of the application.

- **Challenge:** We had to browse the target site and check the `Site map` for an "unusual endpoint."
    
- **Discovery:** We found a hidden path (`/5yP2GLCoiGejZ2K`) by reading the source code of the **`emailFilter.js`** file (located in `/assets/js/`).
    

### The Attack (Example Attack - XSS Bypass)

This is a classic example of using Burp to bypass a "Client-Side Filter."

1. **The Problem:** The `/ticket/` page has JavaScript (Internal JS) that blocks special characters (like `< >`) in the Email field.
    
2. **The Solution:** We use Burp to "intercept" the request _after_ it passes the JavaScript filter but _before_ it reaches the server.
    
3. **Steps:**
    
    - Turn **`Intercept is on`**.
        
    - In the browser, submit "clean" data (e.g., `test@test.com`) and submit the form.
        
    - In Burp (Intercept tab), "catch" the request.
        
    - "Edit" the body of the request, replacing test@test.com with our XSS payload:
        
        <script>alert("Succ3ssful XSS")</script>
        
    - **(Critical!)** Highlight the payload and press **`Ctrl + U`** (Cmd+U) to **URL Encode** it.
        
    - Press `Forward`.
        
4. **Result:** An alert box pops up on the website = **Successful XSS!**
    

---

---

# 🚀 Burp Suite: The Basics Cheat Sheet

## 1. Methods & Workflows

|**🧠 Situation**|**🚀 Recommended Technique**|**🎯 Goal**|
|---|---|---|
|I want to "start" using Burp.|**Configure FoxyProxy** (Point to `127.0.0.1:8080`).|Send browser traffic to Burp.|
|I see a "Secure Connection Failed" error (HTTPS).|**Import Burp CA Certificate** (Go to `http://burp/cert`).|Make the browser "trust" Burp to intercept HTTPS.|
|I'm "lazy" and don't want to set up FoxyProxy/Certs.|Use the **`Open Browser`** button (in the Proxy tab).|Use Burp's built-in, pre-configured browser.|
|My `HTTP History` is "messy" (Google/Mozilla traffic).|**Set Scope** (in `Target` tab and `Proxy settings`).|Filter Burp to only focus on and intercept the target.|
|I found an interesting endpoint (e.g., `/api/user`).|Right-click -> **`Send to Repeater`**.|Send the request to Repeater for trial-and-error testing.|
|I want to brute-force (e.g., a password).|Right-click -> **`Send to Intruder`**.|Send the request to Intruder to set up the attack.|
|A webpage "blocks" me from typing special chars (`< >`).|**Bypass Client-Side Filter**|1. Send clean data.<br><br>  <br><br>2. `Intercept` the request.<br><br>  <br><br>3. "Edit" the body to include the payload.<br><br>  <br><br>4. Press `Ctrl + U` (URL Encode).<br><br>  <br><br>5. `Forward`.|

## 2. Key Commands & Shortcuts

|**Command / Button**|**Function**|
|---|---|
|**`Intercept is on`**|**"Stops"** traffic for inspection/modification (Request will hang).|
|**`Intercept is off`**|**"Lets"** traffic pass through (but still "logs" it in `HTTP history`).|
|**`Forward`** (in Intercept)|"Send" the intercepted request to the server.|
|**`Drop`** (in Intercept)|"Discard" the intercepted request (The server will never receive it).|
|**`Send`** (in Repeater)|"Fire" the modified request.|
|**`Ctrl + U`** (Cmd + U)|(In Intercept/Repeater) **URL Encode** the highlighted text.|
|**`Ctrl + Shift + U`**|(In Intercept/Repeater) **URL Decode** the highlighted text.|
|**`Ctrl + Shift + P`**|Hotkey to switch to the **Proxy** tab.|
|**`Ctrl + Shift + R`**|Hotkey to switch to the **Repeater** tab.|
|**`Ctrl + Shift + I`**|Hotkey to switch to the **Intruder** tab.|
