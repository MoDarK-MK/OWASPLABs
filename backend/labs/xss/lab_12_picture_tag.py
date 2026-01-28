"""
XSS Lab 12: Picture/Source Tag XSS
Difficulty: 2 (Intermediate)
Type: Reflected XSS via Picture/Source Tags
Points: 75

Description:
XSS through HTML5 picture and source tags.
These tags can execute JavaScript through various attributes.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 12: Picture Tag XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 12: Picture Tag XSS</h1>
            <p>This lab is vulnerable to XSS via picture/source tags.</p>
            
            <form action="/photo" method="GET">
                <input type="text" name="src" placeholder="Image source URL">
                <button type="submit">Load Image</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_picture_tag_012}</p>
        </body>
    </html>
    """

@app.route('/photo', methods=['GET'])
def photo():
    src = request.args.get('src', '/default.png')
    media = request.args.get('media', '(min-width: 600px)')
    
    # VULNERABLE: User input directly in picture/source tags
    html = f"""
    <html>
        <head><title>Photo Viewer</title></head>
        <body>
            <h1>Photo Viewer</h1>
            
            <!-- VULNERABLE: User input in picture tag attributes -->
            <picture>
                <source media="{media}" srcset="{src}">
                <img src="{src}" alt="Photo">
            </picture>
            
            <!-- Alternative vulnerable point -->
            <source src="{src}" onerror="alert('XSS')">
            
            <h3>Payloads:</h3>
            <ul>
                <li><code>" onerror="alert('XSS')</code></li>
                <li><code>" onload="alert('XSS')</code></li>
                <li><code>x" onerror="fetch('/hack')</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5012)
