"""
RCE Lab 8: Subprocess with shell=True RCE
Difficulty: 1 (Beginner)
Points: 50

Description:
Remote Code Execution through subprocess with shell=True.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>RCE Lab 8</title></head>
<body>
    <h1>Command Executor</h1>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command">
        <button>Execute</button>
    </form>
    {% if output %}
        <pre>{{ output }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: subprocess.call() with shell=True
    
    Attack Vector:
    /?cmd=id
    /?cmd=whoami
    /?cmd=cat /etc/passwd
    /?cmd=ls -la /
    
    Flag: FLAG{rce_subprocess_shell_008}
    """
    cmd = request.args.get('cmd', '')
    output = None
    
    if cmd:
        try:
            # VULNERABLE: shell=True allows command injection
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008, debug=False)
