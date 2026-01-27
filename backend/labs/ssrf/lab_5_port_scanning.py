"""
SSRF Lab 5: Port Scanning via SSRF
Difficulty: 2 (Intermediate)
Points: 75

Description:
SSRF to discover open ports.
"""

from flask import Flask, request
import requests
import socket
from threading import Thread

app = Flask(__name__)

OPEN_PORTS = {
    80: "HTTP",
    8080: "HTTP Alt",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB"
}

@app.route('/')
def index():
    """
    VULNERABLE: Port enumeration via SSRF
    
    Attack Vector:
    /?host=127.0.0.1&port=80 (check if open)
    /?host=192.168.1.1&start=1&end=1000 (scan range)
    
    Flag: FLAG{ssrf_port_scan_005}
    """
    host = request.args.get('host', 'localhost')
    port = request.args.get('port', '80')
    result = None
    
    if host and port:
        try:
            port = int(port)
            # VULNERABLE: Port scanning via response time
            url = f"http://{host}:{port}/"
            response = requests.get(url, timeout=2)
            result = f"Port {port} appears OPEN (HTTP {response.status_code})"
        except requests.exceptions.Timeout:
            result = f"Port {port} might be open (timeout)"
        except Exception as e:
            result = f"Port {port} likely CLOSED"
    
    return f"""
    <html>
    <body>
        <h1>Port Scanner</h1>
        <form method="GET">
            <input type="text" name="host" placeholder="Host" value="{host}">
            <input type="number" name="port" placeholder="Port" value="{port}">
            <button>Scan</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
