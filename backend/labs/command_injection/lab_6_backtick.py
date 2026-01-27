"""
Command Injection Lab 6: Backtick Command Substitution
Difficulty: 2 (Intermediate)
Type: Command Injection
Points: 75

Description:
Backticks allow command substitution within a command.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>DNS Lookup</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>DNS Lookup Tool</h1>
    <form method="GET">
        <input type="text" name="domain" placeholder="Enter domain" value="{{ domain }}">
        <button type="submit">Lookup</button>
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
    Vulnerable backtick substitution
    
    Attack Vector:
    /?domain=google.com`whoami`
    /?domain=google.com`id`
    /?domain=google.com`cat /etc/passwd`
    
    Flag: FLAG{cmd_injection_backtick_006}
    """
    domain = request.args.get('domain', '')
    output = ''
    
    if domain:
        try:
            # VULNERABLE: Backticks allow command substitution
            cmd = f"nslookup {domain}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, domain=domain, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=False)
