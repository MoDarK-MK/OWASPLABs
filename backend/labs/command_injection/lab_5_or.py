"""
Command Injection Lab 5: OR Operator
Difficulty: 1 (Beginner)
Type: Command Injection
Points: 50

Description:
Commands can be chained using || operator (execute if previous fails).
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Backup Tool</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Backup Tool</h1>
    <form method="GET">
        <input type="text" name="backup" placeholder="Enter backup name" value="{{ backup }}">
        <button type="submit">Create Backup</button>
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
    Vulnerable OR operator injection
    
    Attack Vector:
    /?backup=db || id
    /?backup=db || whoami
    /?backup=db || cat /etc/shadow
    
    Flag: FLAG{cmd_injection_or_005}
    """
    backup_name = request.args.get('backup', '')
    output = ''
    
    if backup_name:
        try:
            # VULNERABLE: OR operator executes second command on failure
            cmd = f"tar -cf /backup/{backup_name}.tar /data || echo 'Backup alternative'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, backup=backup_name, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
