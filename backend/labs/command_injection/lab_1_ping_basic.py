"""
Command Injection Lab 1: Ping Injection - Basic
Difficulty: 1 (Beginner)
Type: Command Injection
Points: 50

Description:
This lab demonstrates basic command injection through a ping utility.
User input is directly concatenated into a system command without validation.
"""

from flask import Flask, request, render_template_string
import subprocess
import os

app = Flask(__name__)

VULNERABLE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Ping Tool</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; }
    </style>
</head>
<body>
    <h1>Network Ping Tool</h1>
    <form method="GET">
        <input type="text" name="host" placeholder="Enter IP or hostname" value="{{ host }}">
        <button type="submit">Ping</button>
    </form>
    {% if output %}
    <h3>Results:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
    <p><small>Flag: FLAG{cmd_injection_ping_basic_001}</small></p>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable ping endpoint that executes user input
    
    Attack Vector:
    /?host=127.0.0.1; id
    /?host=127.0.0.1 && whoami
    /?host=127.0.0.1 | cat /etc/passwd
    
    Flag: FLAG{cmd_injection_ping_basic_001}
    """
    host = request.args.get('host', '')
    output = ''
    
    if host:
        try:
            # VULNERABLE: Direct command concatenation
            cmd = f"ping -c 1 {host}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(VULNERABLE_TEMPLATE, host=host, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
