"""
RCE Lab 11: Code Injection Through Format Strings
Difficulty: 2 (Intermediate)
Points: 75

Description:
Remote Code Execution through format string vulnerabilities.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Format string evaluation
    
    Attack Vector:
    /?fmt=%s%s%s&val=test
    /?fmt=%x.%x.%x (leak stack memory)
    Advanced: Craft format string to write to memory/execute
    
    Flag: FLAG{rce_format_string_011}
    """
    fmt = request.args.get('fmt', 'Hello %s')
    val = request.args.get('val', 'World')
    
    try:
        # VULNERABLE: Using user input in format strings
        result = fmt % val
    except Exception as e:
        result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Format String Processor</h1>
        <form method="GET">
            <input type="text" name="fmt" placeholder="Format string" value="{fmt}">
            <input type="text" name="val" placeholder="Value" value="{val}">
            <button>Process</button>
        </form>
        <p>Result: {result}</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)
