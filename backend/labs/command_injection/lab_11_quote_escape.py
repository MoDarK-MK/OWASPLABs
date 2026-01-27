"""
Command Injection Lab 11: Quote Escaping
Difficulty: 3 (Advanced)
Type: Command Injection
Points: 100

Description:
Breaking out of quotes to inject commands.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Validator</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Email Validator</h1>
    <form method="GET">
        <input type="text" name="email" placeholder="Enter email" value="{{ email }}">
        <button type="submit">Validate</button>
    </form>
    {% if output %}
    <h3>Result:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable quote escaping
    
    Attack Vector:
    /?email=test@test.com"; whoami; echo "
    /?email=test@test.com' OR '1'='1' #
    
    Flag: FLAG{cmd_injection_quote_escape_011}
    """
    email = request.args.get('email', '')
    output = ''
    
    if email:
        try:
            # VULNERABLE: Double quotes can be escaped
            cmd = f'grep "{email}" /tmp/emails.txt'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, email=email, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)
