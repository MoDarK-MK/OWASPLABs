"""
RCE Lab 2: exec() Code Execution
Difficulty: 1 (Beginner)
Points: 50

Description:
Remote Code Execution through exec() function.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>RCE Lab 2</title></head>
<body>
    <h1>Code Executor</h1>
    <form method="POST">
        <textarea name="code" placeholder="Enter Python code"></textarea>
        <button>Execute</button>
    </form>
    {% if output %}
        <pre>{{ output }}</pre>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Direct exec() on user code
    
    Attack Vector:
    POST code=import os;os.system('whoami')
    POST code=__import__('subprocess').call(['bash','-c','id'])
    
    Flag: FLAG{rce_exec_002}
    """
    output = None
    
    if request.method == 'POST':
        code = request.form.get('code', '')
        
        if code:
            try:
                # VULNERABLE: Direct exec() without restrictions
                exec(code)
                output = "Code executed successfully"
            except Exception as e:
                output = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, output=output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
