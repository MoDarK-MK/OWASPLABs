"""
SSRF Lab 3: Localhost Access
Difficulty: 1 (Beginner)
Points: 50

Description:
SSRF to access localhost services.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Access to localhost services
    
    Attack Vector:
    /?url=http://localhost:5000/admin
    /?url=http://127.0.0.1:8080/internal
    /?url=http://localhost/admin/panel
    /?url=http://127.0.0.1:9000/debug
    
    Flag: FLAG{ssrf_localhost_003}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: No localhost restriction
            response = requests.get(url, timeout=5, allow_redirects=True)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Localhost Service Access</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="URL" size="50" value="{url}">
            <button>Access</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/admin')
def admin():
    """Hidden admin endpoint"""
    return "Admin Panel - Secret Content Here"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
