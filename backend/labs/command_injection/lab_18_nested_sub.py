"""
Command Injection Lab 18: Command Substitution Nesting
Difficulty: 3 (Advanced)
Type: Command Injection
Points: 100

Description:
Nested command substitution for complex attacks.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>System Analyzer</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>System Analyzer</h1>
    <form method="GET">
        <input type="text" name="cmd" placeholder="Enter command name" value="{{ cmd }}">
        <button type="submit">Analyze</button>
    </form>
    {% if output %}
    <h3>Analysis:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable nested substitution
    
    Attack Vector:
    /?cmd=$(whoami)
    /?cmd=`whoami`
    /?cmd=$(cat $(find / -name passwd))
    
    Flag: FLAG{cmd_injection_nested_sub_018}
    """
    cmd_name = request.args.get('cmd', '')
    output = ''
    
    if cmd_name:
        try:
            # VULNERABLE: Nested command substitution
            cmd = f"which {cmd_name}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, cmd=cmd_name, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5018, debug=False)
