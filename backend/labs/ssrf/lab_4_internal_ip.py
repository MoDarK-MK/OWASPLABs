"""
SSRF Lab 4: Internal IP Access
Difficulty: 2 (Intermediate)
Points: 75

Description:
SSRF to access internal network services.
"""

from flask import Flask, request
import requests
import socket

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Access to internal IP ranges
    
    Attack Vector:
    /?ip=192.168.1.1
    /?ip=10.0.0.1
    /?ip=172.16.0.1
    /?ip=10.0.0.50:8080/api
    
    Flag: FLAG{ssrf_internal_ip_004}
    """
    ip = request.args.get('ip', '')
    port = request.args.get('port', '80')
    content = None
    error = None
    
    if ip:
        try:
            # VULNERABLE: No IP range validation
            url = f"http://{ip}:{port}/"
            response = requests.get(url, timeout=5)
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>Internal Network Scanner</h1>
        <form method="GET">
            <input type="text" name="ip" placeholder="Internal IP" value="{ip}">
            <input type="number" name="port" placeholder="Port" value="{port}">
            <button>Scan</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
