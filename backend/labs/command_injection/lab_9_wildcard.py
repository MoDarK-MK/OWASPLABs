"""
Command Injection Lab 9: Wildcard Expansion
Difficulty: 2 (Intermediate)
Type: Command Injection
Points: 75

Description:
Wildcards can be used for filename expansion in commands.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>File Manager</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>File Manager</h1>
    <form method="GET">
        <input type="text" name="path" placeholder="Enter path pattern" value="{{ path }}">
        <button type="submit">List</button>
    </form>
    {% if output %}
    <h3>Files:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable wildcard expansion
    
    Attack Vector:
    /?path=/tmp/*
    /?path=/home/*/.*
    
    Flag: FLAG{cmd_injection_wildcard_009}
    """
    path = request.args.get('path', '')
    output = ''
    
    if path:
        try:
            # VULNERABLE: Wildcard expansion allows file access
            cmd = f"ls -la {path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, path=path, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009, debug=False)
