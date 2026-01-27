"""
SSRF Lab 9: Blacklist Filter Bypass
Difficulty: 3 (Advanced)
Points: 100

Description:
SSRF bypassing blacklist filters.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

BLACKLIST = ['localhost', '127.0.0.1', '0.0.0.0']

@app.route('/')
def index():
    """
    VULNERABLE: Blacklist bypass techniques
    
    Attack Vector:
    Bypass 'localhost' blacklist:
    /?url=http://127.1 (localhost shorthand)
    /?url=http://127.0.0.1/ encoded as %31%32%37%2e%30%2e%30%2e%31
    /?url=http://LOCALHOST (case bypass)
    /?url=http://127.0.0.256 (integer overflow)
    /?url=http://0 (null address)
    /?url=http://[::]/ (IPv6 localhost)
    
    Flag: FLAG{ssrf_blacklist_bypass_009}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        # VULNERABLE: Simple blacklist check
        is_blocked = any(blocked in url.lower() for blocked in BLACKLIST)
        
        if is_blocked:
            error = "URL contains blocked content"
        else:
            try:
                response = requests.get(url, timeout=5)
                content = response.text[:1000]
            except Exception as e:
                error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Filtered URL Fetcher</h1>
        <p>Blacklist: {', '.join(BLACKLIST)}</p>
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
    return "BYPASS SUCCESSFUL!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009, debug=False)
