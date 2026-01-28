"""
XSS Lab 16: Context-Aware XSS - JavaScript Context
Difficulty: 3 (Advanced)
Type: Context-specific XSS
Points: 100

Description:
XSS in JavaScript context. User input inside JavaScript code.
Must break out of JavaScript context first.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 16: JavaScript Context</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 16: Context-Aware XSS - JavaScript</h1>
            <p>User input is embedded inside JavaScript code.</p>
            
            <form action="/js-context" method="GET">
                <input type="text" name="username" placeholder="Enter username" value="Guest">
                <button type="submit">Login</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_js_context_016}</p>
        </body>
    </html>
    """

@app.route('/js-context', methods=['GET'])
def js_context():
    username = request.args.get('username', 'Guest')
    
    # VULNERABLE: User input inside JavaScript string without proper escaping
    html_response = f"""
    <html>
        <head><title>Dashboard</title></head>
        <body>
            <h1>Dashboard</h1>
            <p id="greeting"></p>
            
            <script>
                // VULNERABLE: User input directly in JavaScript string
                var username = "{username}";
                document.getElementById('greeting').textContent = 'Welcome, ' + username;
                
                // Alternative vulnerable patterns
                var user_data = "{username}";
                eval('console.log("' + username + '")');
            </script>
            
            <h3>Break out payloads:</h3>
            <ul>
                <li><code>"; alert('XSS'); //"</code></li>
                <li><code>\\"; alert('XSS'); //</code></li>
                <li><code>'; alert('XSS'); //</code></li>
                <li><code>\" + alert('XSS') + \"</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html_response

if __name__ == '__main__':
    app.run(debug=True, port=5016)
