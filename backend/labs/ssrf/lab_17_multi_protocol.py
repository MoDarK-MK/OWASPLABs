"""
SSRF Lab 17: Multi-Protocol SSRF
Difficulty: 4 (Expert)
Points: 150

Description:
SSRF using multiple protocols for exploitation.
"""

from flask import Flask, request
import requests
import socket

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Multi-protocol SSRF
    
    Attack Vector:
    HTTP:
    /?url=http://localhost:8080/admin
    
    HTTPS (ignore cert):
    /?url=https://internal.local/api/key
    
    FTP:
    /?url=ftp://ftp.internal.local/secrets.txt
    
    SFTP:
    /?url=sftp://internal.local/etc/passwd
    
    LDAP:
    /?url=ldap://ldap.internal.local/cn=admin
    
    Dict (Redis):
    /?url=dict://redis.internal:6379/info
    
    Gopher (SMTP, misc):
    /?url=gopher://smtp.internal:25/MAIL
    
    Flag: FLAG{ssrf_multi_protocol_017}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            response = requests.get(url, timeout=5, verify=False)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Multi-Protocol SSRF</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Protocol URL" size="70" value="{url}">
            <button>Request</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
        <hr>
        <p>Supported: http, https, ftp, sftp, file, dict, gopher, ldap</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5017, debug=False)
