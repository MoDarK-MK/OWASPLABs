"""
XSS Lab 15: Filter Bypass - Mutation
Difficulty: 3 (Advanced)
Type: Reflected XSS with Mutation Bypass
Points: 100

Description:
Browser mutation can change the meaning of encoded content.
Use HTML5 parsing quirks to bypass filters.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 15: Filter Bypass - Mutation</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Lab 15: Filter Bypass - Mutation</h1>
            <p>This lab is vulnerable to HTML5 mutation attacks.</p>
            
            <form action="/mutate" method="GET">
                <input type="text" name="tag" placeholder="HTML tag">
                <input type="text" name="attr" placeholder="Attribute value">
                <button type="submit">Generate</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_mutation_bypass_015}</p>
        </body>
    </html>
    """

@app.route('/mutate', methods=['GET'])
def mutate():
    tag = request.args.get('tag', 'div')
    attr = request.args.get('attr', 'test')
    
    # Simple filter that doesn't account for HTML parsing quirks
    if 'script' in tag.lower() or 'onclick' in attr.lower():
        tag = 'div'
        attr = 'safe'
    
    # VULNERABLE: Browser mutation can bypass filter
    html_response = f"""
    <html>
        <head><title>Mutation Test</title></head>
        <body>
            <h1>Generated Element</h1>
            
            <!-- VULNERABLE: HTML5 parser mutation -->
            <svg>
                <{tag} {attr}></{tag}>
            </svg>
            
            <!-- More mutation examples -->
            <noembed>
                <{tag} onclick="alert('XSS')" /></{tag}>
            </noembed>
            
            <h3>Payloads using mutation:</h3>
            <ul>
                <li>Tag: <code>iframe</code> | Attr: <code>onload=alert('XSS')</code></li>
                <li>Tag: <code>img</code> | Attr: <code>src=x onerror=alert('XSS')</code></li>
                <li>Tag: <code>body</code> | Attr: <code>onload=alert('XSS')</code></li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html_response

if __name__ == '__main__':
    app.run(debug=True, port=5015)
