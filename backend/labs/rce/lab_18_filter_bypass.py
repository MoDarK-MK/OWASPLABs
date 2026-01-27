"""
RCE Lab 18: Input Filter Bypass RCE
Difficulty: 4 (Expert)
Points: 150

Description:
Remote Code Execution bypassing input filters.
"""

from flask import Flask, request

app = Flask(__name__)

BLACKLIST = ['import', 'exec', 'eval', 'os', 'system', '__', 'popen']

@app.route('/')
def index():
    """
    VULNERABLE: Filter bypass techniques
    
    Attack Vector:
    Use encoding/obfuscation to bypass blacklist:
    - Hex encoding: \\x69\\x6d\\x70\\x6f\\x72\\x74
    - Unicode: \\u0069\\u006d\\u0070\\u006f\\u0072\\u0074
    - Case variation: ImPoRt
    - Concatenation: 'im'+'port'
    - Spaces: im\\nport
    
    Payloads:
    ?code='__\\x69mport\\_\\_'
    ?code=eval(chr(95)*2+'import'+chr(95)*2)
    
    Flag: FLAG{rce_filter_bypass_018}
    """
    code = request.args.get('code', '')
    result = None
    
    # VULNERABLE: Filter can be bypassed
    is_blocked = any(word in code.lower() for word in BLACKLIST)
    
    if code and not is_blocked:
        try:
            result = eval(code)
        except Exception as e:
            result = f"Error: {str(e)}"
    elif is_blocked:
        result = "Blocked by filter (try bypassing)"
    
    return f"""
    <html>
    <body>
        <h1>Code Filter (Bypassable)</h1>
        <form method="GET">
            <textarea name="code" placeholder="Enter code"></textarea>
            <button>Execute</button>
        </form>
        <p>Blacklist: {', '.join(BLACKLIST)}</p>
        {f"<p>Result: {result}</p>" if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5018, debug=False)
