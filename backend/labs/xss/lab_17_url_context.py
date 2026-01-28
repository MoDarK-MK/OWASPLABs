"""
XSS Lab 17: Context-Aware XSS - URL Context
Difficulty: 3 (Advanced)
Type: Context-specific XSS
Points: 100

Description:
XSS in URL context. User input inside href attribute.
Must break out of URL context properly.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 17: URL Context</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 17: Context-Aware XSS - URL</h1>
            
            <form action="/link-gen" method="GET">
                <input type="text" name="redirect" placeholder="Redirect URL" value="http://example.com">
                <button type="submit">Generate Link</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_url_context_017}</p>
        </body>
    </html>
    """

@app.route('/link-gen', methods=['GET'])
def link_gen():
    redirect_url = request.args.get('redirect', 'http://example.com')
    
    # Basic check that's insufficient
    if redirect_url.startswith('javascript:'):
        redirect_url = 'http://example.com'
    
    # VULNERABLE: User input in URL context without proper escaping
    html_response = f"""
    <html>
        <head><title>Link Generator</title></head>
        <body>
            <h1>Generated Link:</h1>
            <!-- VULNERABLE: No proper URL escaping -->
            <a href="{redirect_url}">Click here</a>
            
            <h3>Bypass methods:</h3>
            <ul>
                <li>Mixed case: <code>JaVaScript:alert('XSS')</code></li>
                <li>URL encoded: <code>%6a%61%76%61%73%63%72%69%70%74%3aalert('XSS')</code></li>
                <li>With space: <code>java script:alert('XSS')</code></li>
                <li>Data URI: <code>data:text/html,&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html_response

if __name__ == '__main__':
    app.run(debug=True, port=5017)
