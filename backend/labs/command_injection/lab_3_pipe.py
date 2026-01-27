"""
Command Injection Lab 3: Pipe Operator
Difficulty: 1 (Beginner)
Type: Command Injection
Points: 50

Description:
Command output can be piped to another command using pipe operator.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Log Filter</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Log Filter Tool</h1>
    <form method="GET">
        <input type="text" name="filter" placeholder="Enter filter keyword" value="{{ filter }}">
        <button type="submit">Search</button>
    </form>
    {% if output %}
    <h3>Results:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable pipe injection
    
    Attack Vector:
    /?filter=error | whoami
    /?filter=error | id
    /?filter=error | cat /etc/passwd
    
    Flag: FLAG{cmd_injection_pipe_003}
    """
    filter_str = request.args.get('filter', '')
    output = ''
    
    if filter_str:
        try:
            # VULNERABLE: Input used in pipe command
            cmd = f"echo 'Searching logs...' | grep {filter_str}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, filter=filter_str, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
