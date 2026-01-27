"""
SSRF Lab 8: Protocol Confusion
Difficulty: 2 (Intermediate)
Points: 75

Description:
SSRF using unexpected protocols.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Protocol confusion SSRF
    
    Attack Vector:
    /?url=dict://localhost:6379/info
    /?url=gopher://localhost:25/MAIL%20FROM%3A%20attacker@example.com
    /?url=tftp://192.168.1.1/etc/passwd
    /?url=ldap://localhost:389/cn=*
    
    Note: Requires requests library with protocol support
    
    Flag: FLAG{ssrf_protocol_confusion_008}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: Allows unusual protocols
            response = requests.get(url, timeout=5)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Protocol Confusion SSRF</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Protocol URL" size="60" value="{url}">
            <button>Request</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
        <hr>
        <p>Supported protocols: http, ftp, file, dict, gopher</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008, debug=False)
