"""
Command Injection Lab 17: Wildcard Injection
Difficulty: 3 (Advanced)
Type: Command Injection
Points: 100

Description:
Using wildcards to inject options into commands.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Backup Scheduler</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Backup Scheduler</h1>
    <form method="GET">
        <input type="text" name="dir" placeholder="Enter directory" value="{{ dir }}">
        <button type="submit">Backup</button>
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
    Vulnerable wildcard injection
    
    Attack Vector:
    /?dir=/tmp -e sh
    
    Flag: FLAG{cmd_injection_wildcard_inject_017}
    """
    directory = request.args.get('dir', '')
    output = ''
    
    if directory:
        try:
            # VULNERABLE: Wildcard can inject tar options
            cmd = f"tar -cf backup.tar {directory}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, dir=directory, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5017, debug=False)
