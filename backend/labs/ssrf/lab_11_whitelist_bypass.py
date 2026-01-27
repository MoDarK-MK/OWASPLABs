"""
SSRF Lab 11: Whitelist Bypass
Difficulty: 3 (Advanced)
Points: 100

Description:
SSRF bypassing whitelist filters.
"""

from flask import Flask, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = ['example.com', 'trusted.com']

@app.route('/')
def index():
    """
    VULNERABLE: Whitelist bypass techniques
    
    Attack Vector:
    Whitelist contains 'example.com':
    /?url=http://example.com.attacker.com (subdomain bypass)
    /?url=http://example.com@attacker.com (credential bypass)
    /?url=http://attacker.com#example.com (fragment bypass)
    /?url=http://attacker.com:80@example.com:8080 (port confusion)
    /?url=http://example.com/../../../localhost (path traversal in URL)
    
    Flag: FLAG{ssrf_whitelist_bypass_011}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: Simple whitelist check
            parsed = urlparse(url)
            hostname = parsed.hostname or parsed.netloc
            
            is_allowed = any(allowed in hostname for allowed in ALLOWED_DOMAINS)
            
            if not is_allowed:
                error = f"Domain {hostname} not in whitelist"
            else:
                response = requests.get(url, timeout=5)
                content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Whitelist-Protected Fetcher</h1>
        <p>Whitelist: {', '.join(ALLOWED_DOMAINS)}</p>
        <form method="GET">
            <input type="text" name="url" placeholder="URL" size="60" value="{url}">
            <button>Fetch</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/secret')
def secret():
    return "Secret content - whitelist bypassed!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)
