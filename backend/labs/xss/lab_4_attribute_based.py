"""
XSS Lab 4: Attribute-based XSS
Difficulty: 1 (Beginner)
Type: Reflected XSS via HTML Attributes
Points: 50

Description:
XSS vulnerability in HTML attributes.
User input is inserted into HTML tag attributes without proper escaping.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    """Home page"""
    return """
    <html>
        <head>
            <title>XSS Lab 4: Attribute-based XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 4: Attribute-based XSS</h1>
            <p>This lab has an XSS vulnerability in HTML attributes.</p>
            
            <form action="/search" method="GET">
                <input type="text" name="redirect" placeholder="Enter redirect URL">
                <button type="submit">Search</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_attribute_004}</p>
        </body>
    </html>
    """

@app.route('/search', methods=['GET'])
def search():
    """
    Vulnerable search endpoint with attribute injection
    """
    redirect_url = request.args.get('redirect', '/')
    
    # VULNERABLE: User input directly in HTML attribute
    html = f"""
    <html>
        <head>
            <title>Search Results</title>
            <style>
                body {{ font-family: Arial; margin: 40px; }}
                .button {{ padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <h1>Search Results</h1>
            <p>Searching for your query...</p>
            
            <!-- VULNERABLE: User input directly in img src -->
            <img src="{redirect_url}" onerror="alert('XSS')">
            
            <!-- Alternative vulnerable points -->
            <a href="{redirect_url}" class="button">Continue to results</a>
            
            <p><a href="/">Back to home</a></p>
            
            <h3>Attack Vectors:</h3>
            <ul>
                <li><code>" onmouseover="alert('XSS')</code></li>
                <li><code>x" onerror="alert('XSS')</code></li>
                <li><code>javascript:alert('XSS')</code></li>
                <li><code>data:text/html,&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            </ul>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5004)
