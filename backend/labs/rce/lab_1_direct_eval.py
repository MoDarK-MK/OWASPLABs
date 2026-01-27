"""
RCE Lab 1: Direct eval() Execution
Difficulty: 1 (Beginner)
Points: 50

Description:
Remote Code Execution through direct eval() function.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>RCE Lab 1</title>
</head>
<body>
    <h1>Math Calculator</h1>
    <form method="GET">
        <input type="text" name="expr" placeholder="Enter math expression">
        <button type="submit">Calculate</button>
    </form>
    {% if result %}
        <p>Result: {{ result }}</p>
    {% endif %}
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Direct eval() on user input
    
    Attack Vector:
    /?expr=__import__('os').system('id')
    /?expr=__import__('os').popen('cat /etc/passwd').read()
    
    Flag: FLAG{rce_direct_eval_001}
    """
    expr = request.args.get('expr', '')
    result = None
    error = None
    
    if expr:
        try:
            # VULNERABLE: Direct eval without sanitization
            result = eval(expr)
        except Exception as e:
            error = str(e)
    
    return render_template_string(TEMPLATE, result=result, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
