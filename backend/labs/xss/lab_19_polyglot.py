"""
XSS Lab 19: Polyglot XSS - Multi-Context
Difficulty: 4 (Master)
Type: Advanced Polyglot XSS
Points: 150

Description:
A single payload that works in multiple contexts (HTML, JavaScript, URL, etc.)
Requires understanding of multiple encoding/execution contexts.
"""

from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 19: Polyglot XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
                textarea { width: 100%; }
            </style>
        </head>
        <body>
            <h1>Lab 19: Polyglot XSS</h1>
            <p>This lab processes data in multiple contexts. Find a payload that works everywhere!</p>
            
            <form action="/process" method="POST">
                <textarea name="data" placeholder="Enter data" rows="4"></textarea>
                <button type="submit">Process</button>
            </form>
            
            <p><strong>Flag:</strong> FLAG{xss_polyglot_019}</p>
        </body>
    </html>
    """

@app.route('/process', methods=['POST'])
def process():
    data = request.form.get('data', '')
    
    # Data is used in multiple contexts without proper escaping
    html_response = f"""
    <html>
        <head><title>Result</title></head>
        <body>
            <h1>Processing Results:</h1>
            
            <!-- Context 1: HTML Content -->
            <div id="html-context">
                {data}
            </div>
            
            <script>
                // Context 2: JavaScript String
                var js_string = "{data}";
                console.log(js_string);
                
                // Context 3: JavaScript Object Key
                var obj = {{{data}: 'value'}};
                
                // Context 4: URL Context
                var url = "http://example.com/?param={data}";
            </script>
            
            <!-- Context 5: HTML Attribute -->
            <img alt="{data}" />
            
            <h3>Polyglot Challenge:</h3>
            <p>Find a payload that triggers XSS in multiple contexts above!</p>
            <ul>
                <li>HTML Context: Direct HTML tags</li>
                <li>JS String Context: Break out of string quotes</li>
                <li>Object Key Context: Valid JavaScript identifier</li>
                <li>URL Context: Valid URL parameter</li>
                <li>Attribute Context: Break out of attribute quotes</li>
            </ul>
            
            <p><a href="/">Back</a></p>
        </body>
    </html>
    """
    
    return html_response

if __name__ == '__main__':
    app.run(debug=True, port=5019)
