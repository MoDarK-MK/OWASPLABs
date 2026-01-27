"""
Command Injection Lab 10: Environment Variable Expansion
Difficulty: 2 (Intermediate)
Type: Command Injection
Points: 75

Description:
Environment variables can be expanded in commands.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>System Monitor</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>System Monitor</h1>
    <form method="GET">
        <input type="text" name="var" placeholder="Enter variable name" value="{{ var }}">
        <button type="submit">Get Value</button>
    </form>
    {% if output %}
    <h3>Value:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable environment variable expansion
    
    Attack Vector:
    /?var=$PATH
    /?var=$(whoami)
    /?var=`id`
    
    Flag: FLAG{cmd_injection_env_var_010}
    """
    var = request.args.get('var', '')
    output = ''
    
    if var:
        try:
            # VULNERABLE: Variable expansion
            cmd = f"echo Variable: {var}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, var=var, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
