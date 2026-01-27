"""
SSRF Lab 16: Combined SSRF + RCE
Difficulty: 4 (Expert)
Points: 150

Description:
SSRF leading to Remote Code Execution.
"""

from flask import Flask, request
import requests
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: SSRF to internal service with RCE endpoint
    
    Attack Vector:
    1. SSRF to internal service running on localhost:5000
    2. /?url=http://localhost:5000/execute?cmd=id
    3. Internal service executes arbitrary commands
    4. Result returned through SSRF response
    
    Flag: FLAG{ssrf_combined_rce_016}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            response = requests.get(url, timeout=5)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>SSRF to RCE</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="Internal service URL" size="70" value="{url}">
            <button>Execute</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/execute')
def execute():
    """Vulnerable internal service"""
    cmd = request.args.get('cmd', 'whoami')
    try:
        result = subprocess.check_output(cmd, shell=True, text=True)
        return result
    except:
        return "Error executing command"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5016, debug=False)
