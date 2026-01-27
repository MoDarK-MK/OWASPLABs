"""
Command Injection Lab 2: Semicolon Separator
Difficulty: 1 (Beginner)
Type: Command Injection
Points: 50

Description:
This lab demonstrates command injection using semicolon separator.
Multiple commands can be executed sequentially using semicolon.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>System Info Tool</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>System Information</h1>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command" value="{{ cmd }}">
        <button type="submit">Execute</button>
    </form>
    {% if output %}
    <h3>Output:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable command execution endpoint
    
    Attack Vector:
    /?cmd=help; id
    /?cmd=help; whoami
    /?cmd=help; cat /etc/passwd
    
    Flag: FLAG{cmd_injection_semicolon_002}
    """
    cmd = request.args.get('cmd', '')
    output = ''
    
    if cmd:
        try:
            # VULNERABLE: Direct concatenation with semicolon
            full_cmd = f"echo 'Help: {cmd}'; id"
            result = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, cmd=cmd, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
