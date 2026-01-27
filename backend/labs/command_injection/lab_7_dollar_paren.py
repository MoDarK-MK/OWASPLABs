"""
Command Injection Lab 7: Dollar Parenthesis Substitution
Difficulty: 2 (Intermediate)
Type: Command Injection
Points: 75

Description:
$(command) syntax also allows command substitution.
"""

from flask import Flask, request, render_template_string
import subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Weather Report</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        input { padding: 8px; width: 300px; }
        button { padding: 8px 15px; }
        #output { margin-top: 20px; background: #f0f0f0; padding: 10px; white-space: pre; max-height: 400px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Weather Report</h1>
    <form method="GET">
        <input type="text" name="city" placeholder="Enter city" value="{{ city }}">
        <button type="submit">Get Weather</button>
    </form>
    {% if output %}
    <h3>Report:</h3>
    <div id="output">{{ output }}</div>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    """
    Vulnerable $() substitution
    
    Attack Vector:
    /?city=London$(whoami)
    /?city=London$(id)
    /?city=London$(cat /etc/passwd)
    
    Flag: FLAG{cmd_injection_dollar_paren_007}
    """
    city = request.args.get('city', '')
    output = ''
    
    if city:
        try:
            # VULNERABLE: $() allows command substitution
            cmd = f"echo 'Weather for {city}:' && date"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
        except Exception as e:
            output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, city=city, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=False)
