-- ==========================================
-- SQL INJECTION LABS (20 total)
-- ==========================================

-- Level 1 Labs (Beginner)
INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection in Login Form - UNION Attack',
    'The login form is vulnerable to SQL Injection. Try to bypass authentication using UNION SELECT.',
    'sql_injection',
    1,
    50,
    'FLAG{sqli_union_login_2024}',
    'Try adding a quote and UNION to the username field',
    'UNION allows combining query results',
    'Use: '' UNION SELECT 1,2,3,4 --'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection in Search Box - String-based',
    'The search functionality is vulnerable to string-based SQL Injection.',
    'sql_injection',
    2,
    50,
    'FLAG{sqli_search_string_2024}',
    'Try searching for: test'' OR ''1''=''1',
    'String concatenation in SQL can be exploited',
    'Look for where user input is directly concatenated'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Blind SQL Injection - Boolean-based',
    'This application is vulnerable to blind SQL injection. The response changes based on TRUE/FALSE conditions.',
    'sql_injection',
    3,
    75,
    'FLAG{sqli_blind_boolean_2024}',
    'Use conditional statements in the parameter',
    'Try: id=1 AND 1=1 vs id=1 AND 1=2',
    'Observe response differences to extract data'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Time-based Blind SQL Injection',
    'Exploit time-based SQL Injection to extract database information.',
    'sql_injection',
    4,
    75,
    'FLAG{sqli_time_based_2024}',
    'Use SLEEP() or BENCHMARK() function',
    'Introduce delays to measure response time',
    'Try: id=1 AND SLEEP(5)'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection with Data Limitations',
    'Bypass authentication with input restrictions and character limitations.',
    'sql_injection',
    5,
    75,
    'FLAG{sqli_limited_input_2024}',
    'Try using SQL comments to bypass restrictions',
    'Comments: # -- /* */',
    'Combine techniques: truncation + comments'
);

-- Level 2 Labs (Intermediate)
INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Stacked Queries SQL Injection',
    'Execute multiple SQL queries using semicolon stacking.',
    'sql_injection',
    6,
    100,
    'FLAG{sqli_stacked_queries_2024}',
    'Use semicolon to execute multiple statements',
    'Try: id=1; DROP TABLE users; --',
    'Some databases support stacked queries'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection in Advanced Filter',
    'Filter parameters are vulnerable to complex SQL injection attacks.',
    'sql_injection',
    7,
    100,
    'FLAG{sqli_advanced_filter_2024}',
    'Multiple parameters might be vulnerable',
    'Test each parameter independently',
    'Combine multiple injection points'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection in ORDER BY Clause',
    'Exploit SQL Injection in the ORDER BY clause.',
    'sql_injection',
    8,
    100,
    'FLAG{sqli_order_by_2024}',
    'ORDER BY accepts column numbers',
    'Try: sort=1 UNION SELECT...',
    'Determine number of columns first'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection with Encoding/Bypass',
    'SQL Injection protected by encoding filters.',
    'sql_injection',
    9,
    100,
    'FLAG{sqli_encoding_bypass_2024}',
    'Try URL encoding: %27 = single quote',
    'Double encoding might bypass filters',
    'Hex encoding: 0x...'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Multi-stage SQL Injection',
    'Exploit SQL Injection across multiple application stages.',
    'sql_injection',
    10,
    125,
    'FLAG{sqli_multistage_2024}',
    'First stage: authenticate',
    'Second stage: data extraction',
    'Combine results from both stages'
);

-- Level 3 Labs (Advanced)
INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection with WAF Bypass',
    'Web Application Firewall blocks common SQL injection patterns.',
    'sql_injection',
    11,
    150,
    'FLAG{sqli_waf_bypass_2024}',
    'Try case modification: UnIoN, sElEcT',
    'Use inline comments: /**/SELECT',
    'Combine techniques for evasion'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SQL Injection in Stored Procedure',
    'Exploit SQL injection within stored procedures.',
    'sql_injection',
    12,
    150,
    'FLAG{sqli_stored_proc_2024}',
    'Stored procedures have different parsing',
    'Try breaking out of procedure context',
    'Use xp_cmdshell or similar functions'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Out-of-band SQL Injection (DNS Exfiltration)',
    'Extract data using DNS queries and external services.',
    'sql_injection',
    13,
    175,
    'FLAG{sqli_oob_dns_2024}',
    'Use DNS subdomains to exfiltrate data',
    'Services like dnslog.cn or burpcollaborator',
    'Craft DNS queries with concatenated data'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Second-order SQL Injection',
    'Injected payload is stored and exploited later.',
    'sql_injection',
    14,
    175,
    'FLAG{sqli_second_order_2024}',
    'Payload stored in database first',
    'Triggered when data is retrieved',
    'Look for reflection in different context'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Advanced Blind Injection with INFORMATION_SCHEMA',
    'Use INFORMATION_SCHEMA to extract database structure.',
    'sql_injection',
    15,
    200,
    'FLAG{sqli_information_schema_2024}',
    'Query TABLE_NAME from INFORMATION_SCHEMA',
    'Extract column names and data types',
    'Build complete database map'
);

-- Level 4 Labs (Master Challenge)
INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Master Challenge: Combined SQLi + Authentication',
    'Multi-stage challenge combining SQLi, authentication bypass, and data exfiltration.',
    'sql_injection',
    16,
    250,
    'FLAG{sqli_master_auth_2024}',
    'Stage 1: Bypass login with SQLi',
    'Stage 2: Escalate privileges',
    'Stage 3: Extract admin credentials'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Master Challenge: SQLi with Dynamic Query Building',
    'Complex scenario with dynamically constructed SQL queries.',
    'sql_injection',
    17,
    250,
    'FLAG{sqli_master_dynamic_2024}',
    'Queries built from user input at runtime',
    'Multiple injection points possible',
    'Trace complete execution flow'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Master Challenge: SQLi in Complex Application Logic',
    'Real-world scenario with multiple business logic layers.',
    'sql_injection',
    18,
    250,
    'FLAG{sqli_master_logic_2024}',
    'Understand application workflow first',
    'Inject at critical business logic points',
    'Track data flow through layers'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Master Challenge: SQLi + NoSQL Injection Combo',
    'Exploit both SQL and NoSQL injection vectors.',
    'sql_injection',
    19,
    300,
    'FLAG{sqli_nosql_combo_2024}',
    'Application uses both SQL and NoSQL databases',
    'Find which endpoint uses which',
    'Chain attacks together'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Master Challenge: Complete Database Compromise',
    'Ultimate challenge: gain full control of database and application.',
    'sql_injection',
    20,
    300,
    'FLAG{sqli_complete_compromise_2024}',
    'Extract all user data and credentials',
    'Modify application data and configuration',
    'Establish persistence and backdoor'
);

-- ==========================================
-- SSRF LABS (20 total)
-- ==========================================

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Basic SSRF to Localhost',
    'Exploit SSRF to read files from localhost.',
    'ssrf',
    1,
    50,
    'FLAG{ssrf_localhost_2024}',
    'Try accessing http://localhost/admin',
    'Common ports: 8000, 8080, 9000',
    'Look for file reading endpoints'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF to Internal IP Ranges',
    'Access internal network resources using SSRF.',
    'ssrf',
    2,
    50,
    'FLAG{ssrf_internal_ip_2024}',
    'Try 192.168.0.0/16 or 10.0.0.0/8',
    'Scan internal network for services',
    'Port 22, 3306, 5432 are common'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF to Cloud Metadata Endpoint',
    'Access AWS/GCP metadata endpoint.',
    'ssrf',
    3,
    75,
    'FLAG{ssrf_metadata_2024}',
    'AWS: 169.254.169.254',
    'Try: /latest/meta-data/',
    'Retrieve IAM credentials'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF with Port Hopping',
    'Bypass SSRF filter using port number manipulation.',
    'ssrf',
    4,
    75,
    'FLAG{ssrf_port_hopping_2024}',
    'Try different port representations',
    'Octal notation: 0177 = 127',
    'Hex notation: 0x7f = 127'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF to AWS Metadata Service',
    'Extract AWS credentials via SSRF.',
    'ssrf',
    5,
    75,
    'FLAG{ssrf_aws_creds_2024}',
    'Access 169.254.169.254/latest/meta-data/iam/',
    'Extract security credentials',
    'Use credentials for lateral movement'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF with Redirect Chaining',
    'Use redirects to bypass SSRF filters.',
    'ssrf',
    6,
    100,
    'FLAG{ssrf_redirect_chain_2024}',
    'First request: attacker-controlled endpoint',
    'That endpoint redirects to internal resource',
    'Application follows redirect'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF for Internal Network Scanning',
    'Port scanning via SSRF.',
    'ssrf',
    7,
    100,
    'FLAG{ssrf_port_scan_2024}',
    'Systematically test port ranges',
    'Observe response times for closed vs open',
    'Map internal network topology'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF Combined with XXE',
    'Chain SSRF and XXE attacks.',
    'ssrf',
    8,
    100,
    'FLAG{ssrf_xxe_chain_2024}',
    'XXE to read files from internal system',
    'SSRF to exfiltrate via external server',
    'Combine both techniques'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF via CSV Upload',
    'Exploit SSRF in CSV processing.',
    'ssrf',
    9,
    100,
    'FLAG{ssrf_csv_upload_2024}',
    'CSV with URL: =cmd|'' cat /etc/passwd''!A0',
    'Application processes CSV formulas',
    'URL fetching triggered during processing'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF with Protocol Confusion',
    'Use different protocols to bypass filters.',
    'ssrf',
    10,
    125,
    'FLAG{ssrf_protocol_confusion_2024}',
    'Try file://, gopher://, dict://',
    'Dict protocol: dict://server:port/stats',
    'Gopher: gopher://internal-service'
);

-- Additional SSRF labs continue similarly...
INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF with Gzip Compression Bypass',
    'Bypass SSRF filter using compression.',
    'ssrf',
    11,
    150,
    'FLAG{ssrf_gzip_bypass_2024}',
    'Compress payload to bypass length check',
    'Use gzip encoding on URL',
    'Server decompresses and processes'
);

-- Continue adding more SSRF, CSRF, XSS, XXE, IDOR, RCE, Command Injection labs...
-- (Truncated for brevity - full labs continue in similar pattern)

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'SSRF Master Challenge: Multi-stage Exploitation',
    'Complex SSRF with multiple stages and authentication.',
    'ssrf',
    20,
    300,
    'FLAG{ssrf_master_multistage_2024}',
    'Stage 1: Identify internal services',
    'Stage 2: Exploit internal application',
    'Stage 3: Extract credentials and pivot'
);

-- ==========================================
-- CSRF LABS (Sample 5)
-- ==========================================

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Simple CSRF - State Changing Request',
    'Exploit CSRF to change user settings.',
    'csrf',
    1,
    50,
    'FLAG{csrf_state_change_2024}',
    'Create a form that posts to victim application',
    'Victim must be authenticated',
    'Use hidden form fields'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'CSRF to Change Password',
    'CSRF attack to change user password.',
    'csrf',
    2,
    50,
    'FLAG{csrf_password_change_2024}',
    'Password change form likely lacks CSRF protection',
    'Submit form without token',
    'New password becomes attacker-controlled'
);

-- ==========================================
-- XSS LABS (Sample 3)
-- ==========================================

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Reflected XSS - Alert Box',
    'Simple reflected XSS vulnerability.',
    'xss',
    1,
    50,
    'FLAG{xss_alert_2024}',
    'Try injecting: <script>alert(1)</script>',
    'Look for user input in response',
    'Check source code comments'
);

INSERT INTO labs (title, description, category, difficulty, points, flag, hint_1, hint_2, hint_3) VALUES
(
    'Stored XSS in Comments',
    'Stored XSS in application comments.',
    'xss',
    2,
    50,
    'FLAG{xss_stored_comments_2024}',
    'Inject script in comment field',
    'Script executes for all viewers',
    'Check for input validation'
);

-- Continue with XXE, IDOR, RCE, Command Injection labs...
