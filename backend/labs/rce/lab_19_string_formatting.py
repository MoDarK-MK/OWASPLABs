"""
RCE Lab 19: Safe String Formatting Bypass RCE
Difficulty: 3 (Advanced)
Points: 100

Description:
Remote Code Execution through string formatting vulnerabilities.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: String .format() with user input
    
    Attack Vector:
    /?fmt={.__class__.__bases__[0].__subclasses__()[104].__init__.__globals__[sys].modules[os].system('id')}
    
    Or simpler Python f-string evaluation:
    ?name={__import__('os').system('id')}
    
    Payloads:
    - {request.__class__}
    - {config.__dict__}
    - {''.__class__.__mro__[1].__subclasses__()}
    
    Flag: FLAG{rce_string_formatting_019}
    """
    fmt_str = request.args.get('fmt', 'Hello {name}')
    name = request.args.get('name', 'World')
    result = None
    
    try:
        # VULNERABLE: User input in format string
        result = fmt_str.format(name=name)
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>String Formatter</h1>
        <form method="GET">
            <input type="text" name="fmt" placeholder="Format string" value="{fmt_str}">
            <input type="text" name="name" placeholder="Name" value="{name}">
            <button>Format</button>
        </form>
        <p>Result: {result}</p>
        <p>Hint: Try using {{{{name.__class__}}}} or similar class access</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5019, debug=False)
