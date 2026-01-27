"""
Command Injection Lab 8: Newline Character Injection
Difficulty: 2 (Intermediate)
Type: Command Injection
Points: 75

Description:
Newline characters can be used to inject commands on new lines.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Log Viewer</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Log Viewer</h1>
    <form method="GET">
        <input type="text" name="logfile" placeholder="Enter log file" value="{{ logfile }}">
        <button type="submit">View</button>
    </form>
    {% if output %}
    <h3>Log Content:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable newline injection
    
    Attack Vector (URL encoded):
    /?logfile=app.log%0Awhois
    /?logfile=app.log%0Aid
    
    Flag: FLAG{cmd_injection_newline_008}
    """
    logfile = request.args.get('logfile', '')
    output = ''
    
    if logfile:
        try:
            # VULNERABLE: Newline characters allow command injection
            cmd = f"tail -f /var/log/{logfile}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, logfile=logfile, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008, debug=False)
