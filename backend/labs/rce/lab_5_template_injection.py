"""
RCE Lab 5: Template Injection RCE
Difficulty: 2 (Intermediate)
Points: 75

Description:
Remote Code Execution through Jinja2 template injection.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>RCE Lab 5</title></head>
<body>
    <h1>Template Renderer</h1>
    <form method="GET">
        <input type="text" name="name" placeholder="Your name">
        <button>Render</button>
    </form>
    {% if msg %}{{ msg }}{% endif %}
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: User input in template without escaping
    
    Attack Vector:
    /?name={{7*7}}
    /?name={{__import__('os').popen('id').read()}}
    /?name={{config.items()}}
    
    Flag: FLAG{rce_template_injection_005}
    """
    name = request.args.get('name', 'Guest')
    
    try:
        # VULNERABLE: Direct template rendering of user input
        msg = render_template_string(f"Hello {name}!")
    except Exception as e:
        msg = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, msg=msg)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
