"""
SSRF Lab 7: DNS Rebinding
Difficulty: 3 (Advanced)
Points: 100

Description:
SSRF via DNS rebinding attack.
"""

from flask import Flask, request
import requests
import socket

app = Flask(__name__)

DNS_RECORDS = {
    'attacker.local': ['1.1.1.1', '127.0.0.1'],  # First public, then localhost
}

@app.route('/')
def index():
    """
    VULNERABLE: DNS rebinding attack
    
    Attack Vector:
    1. Attacker registers domain that returns different IPs on repeated lookups
    2. First lookup returns attacker's IP (passes whitelist check)
    3. Second lookup returns 127.0.0.1 (SSRF to localhost)
    4. /?url=http://attacker.local
    
    Exploit pattern:
    - attacker.com first returns public IP
    - Check DNS (passes validation)
    - Make request (DNS returns localhost)
    
    Flag: FLAG{ssrf_dns_rebinding_007}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: DNS lookup doesn't prevent rebinding
            response = requests.get(url, timeout=5)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>DNS Rebinding SSRF Lab</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="URL" size="50" value="{url}">
            <button>Fetch</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/admin')
def admin():
    return "Admin panel via DNS rebinding!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=False)
