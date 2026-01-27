"""
Command Injection Lab 4: AND Operator
Difficulty: 1 (Beginner)
Type: Command Injection
Points: 50

Description:
Commands can be chained using && operator (execute if previous succeeds).
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>File Validator</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>File Validator</h1>
    <form method="GET">
        <input type="text" name="file" placeholder="Enter filename" value="{{ file }}">
        <button type="submit">Validate</button>
    </form>
    {% if output %}
    <h3>Validation Result:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable AND operator injection
    
    Attack Vector:
    /?file=test.txt && id
    /?file=test.txt && whoami
    /?file=test.txt && cat /etc/passwd
    
    Flag: FLAG{cmd_injection_and_004}
    """
    filename = request.args.get('file', '')
    output = ''
    
    if filename:
        try:
            # VULNERABLE: AND operator allows second command execution
            cmd = f"ls -la {filename} && echo 'File validated'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, file=filename, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=False)
