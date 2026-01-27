"""
SSRF Lab 6: Redirect-Based SSRF
Difficulty: 2 (Intermediate)
Points: 75

Description:
SSRF using HTTP redirects to bypass restrictions.
"""

from flask import Flask, request, redirect
import requests

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Redirect bypass for SSRF
    
    Attack Vector:
    1. Set up attacker server that redirects to internal URL
    2. /?url=http://attacker.com/redirect
    3. Attacker's redirect points to http://localhost/admin
    4. Application follows redirect to internal service
    
    Flag: FLAG{ssrf_redirect_006}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            # VULNERABLE: Follows redirects to internal URLs
            response = requests.get(url, timeout=5, allow_redirects=True)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Content Fetcher (with redirects)</h1>
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
    """Hidden admin endpoint"""
    return "SECRET: Admin panel accessed via redirect!"

@app.route('/redirect')
def redir():
    """Redirect endpoint"""
    return redirect('http://localhost:5006/admin')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=False)
