"""
XSS Lab 3: DOM-based XSS - innerHTML
Difficulty: 2 (Intermediate)
Type: DOM-based XSS
Points: 75

Description:
Client-side JavaScript vulnerability where user input is used with innerHTML.
The vulnerability is purely on the client side, not server-side.
"""

from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    """Home page with vulnerable DOM manipulation"""
    return """
    <html>
        <head>
            <title>XSS Lab 3: DOM-based XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                .container { background: #f5f5f5; padding: 20px; border-radius: 5px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #28a745; color: white; border: none; border-radius: 3px; cursor: pointer; }
                #output { background: white; border: 1px solid #ddd; padding: 15px; margin: 20px 0; border-radius: 3px; min-height: 100px; }
            </style>
        </head>
        <body>
            <h1>Lab 3: DOM-based XSS - innerHTML</h1>
            <p>This lab has a DOM-based XSS vulnerability in client-side JavaScript.</p>
            
            <div class="container">
                <h3>Welcome Message Generator:</h3>
                <input type="text" id="nameInput" placeholder="Enter your name">
                <button onclick="generateWelcome()">Generate Welcome</button>
            </div>
            
            <div id="output"></div>
            
            <script>
                // Parse URL parameters
                function getUrlParam(param) {
                    const url = new URL(window.location);
                    return url.searchParams.get(param);
                }
                
                function generateWelcome() {
                    const name = document.getElementById('nameInput').value;
                    
                    // VULNERABLE: User input directly used with innerHTML
                    document.getElementById('output').innerHTML = `
                        <h2>Welcome, ${name}!</h2>
                        <p>Thank you for visiting our site.</p>
                    `;
                }
                
                // Also process URL parameters
                const urlName = getUrlParam('name');
                if (urlName) {
                    document.getElementById('nameInput').value = urlName;
                    // VULNERABLE: Also vulnerable to URL parameter XSS
                    document.getElementById('output').innerHTML = `
                        <h2>Welcome, ${urlName}!</h2>
                        <p>We detected you in our system.</p>
                    `;
                }
            </script>
            
            <h3>Attack Vectors:</h3>
            <ul>
                <li><strong>Via Input:</strong> <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                <li><strong>Via URL:</strong> <code>?name=&lt;svg onload=alert('XSS')&gt;</code></li>
                <li><strong>Via URL:</strong> <code>?name=&lt;iframe src="javascript:alert('XSS')"&gt;</code></li>
                <li><strong>Via Input:</strong> <code>&lt;body onload=alert('XSS')&gt;</code></li>
            </ul>
            
            <h3>Try This:</h3>
            <ol>
                <li>Type payload in input and click button, OR</li>
                <li>Visit URL with parameter: <code>/?name=&lt;img src=x onerror=alert('XSS')&gt;</code></li>
            </ol>
            
            <p><strong>Flag:</strong> FLAG{xss_dom_innerHTML_003}</p>
        </body>
    </html>
    """

if __name__ == '__main__':
    app.run(debug=True, port=5003)
