"""
Command Injection Lab 16: Privilege Escalation
Difficulty: 4 (Expert)
Type: Command Injection
Points: 150

Description:
Using command injection to escalate privileges.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Process Manager</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Process Manager</h1>
    <form method="GET">
        <input type="text" name="pid" placeholder="Enter PID" value="{{ pid }}">
        <button type="submit">Manage</button>
    </form>
    {% if output %}
    <h3>Result:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable privilege escalation
    
    Attack Vector:
    /?pid=1234; sudo whoami
    /?pid=1234; sudo -u root cat /root/.ssh/id_rsa
    
    Flag: FLAG{cmd_injection_privesc_016}
    """
    pid = request.args.get('pid', '')
    output = ''
    
    if pid:
        try:
            # VULNERABLE: Allows privilege escalation attempts
            cmd = f"ps -p {pid}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, pid=pid, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5016, debug=False)
