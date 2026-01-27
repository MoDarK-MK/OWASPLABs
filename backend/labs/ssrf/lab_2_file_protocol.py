"""
SSRF Lab 2: File Protocol Access
Difficulty: 1 (Beginner)
Points: 50

Description:
SSRF using file:// protocol to read local files.
"""

from flask import Flask, request
import requests
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Allows file:// protocol for local file access
    
    Attack Vector:
    /?url=file:///etc/passwd
    /?url=file:///etc/hostname
    /?url=file://C:/Windows/System32/drivers/etc/hosts
    /?url=file:///proc/self/environ
    
    Flag: FLAG{ssrf_file_protocol_002}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: Allows file protocol
            response = requests.get(url, timeout=5)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>File Fetcher</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Enter URL/File path" value="{url}">
            <button>Fetch</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
        <hr>
        <p>Try: file:///etc/passwd</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
