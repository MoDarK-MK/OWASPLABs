"""
XSS Lab 10: JSON Response XSS
Difficulty: 2 (Intermediate)
Type: Reflected XSS via JSON response
Points: 75

Description:
XSS vulnerability when JSON responses are incorrectly processed.
Often occurs when JSON is used with script tags or eval().
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <html>
        <head>
            <title>XSS Lab 10: JSON Response XSS</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 600px; }
                input { padding: 8px; width: 300px; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; cursor: pointer; }
                #output { background: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 3px; }
            </style>
        </head>
        <body>
            <h1>Lab 10: JSON Response XSS</h1>
            <p>This lab processes JSON data in an unsafe manner.</p>
            
            <input type="text" id="userInput" placeholder="Enter data">
            <button onclick="sendRequest()">Send Request</button>
            
            <div id="output"></div>
            
            <script>
                function sendRequest() {
                    const input = document.getElementById('userInput').value;
                    
                    // VULNERABLE: Loading JSON via script tag
                    const script = document.createElement('script');
                    script.src = '/api/data?callback=processData&msg=' + encodeURIComponent(input);
                    document.head.appendChild(script);
                }
                
                // VULNERABLE: Global callback function
                function processData(data) {
                    // VULNERABLE: Using innerHTML with data from callback
                    document.getElementById('output').innerHTML = '<p>' + data.msg + '</p>';
                }
            </script>
            
            <h3>Or try the JSON endpoint:</h3>
            <p>Visit: <code>/api/data?msg=&lt;img src=x onerror=alert('XSS')&gt;</code></p>
            
            <p><strong>Flag:</strong> FLAG{xss_json_response_010}</p>
        </body>
    </html>
    """

@app.route('/api/data', methods=['GET'])
def api_data():
    """
    VULNERABLE: Returns JSON that can be exploited via script tag callback
    """
    msg = request.args.get('msg', 'Hello')
    callback = request.args.get('callback', 'processData')
    
    # VULNERABLE: JSONP without proper escaping
    response = f'{callback}({{"msg": "{msg}"}})'
    
    return response, 200, {'Content-Type': 'application/javascript'}

@app.route('/api/eval-data', methods=['GET'])
def api_eval_data():
    """
    VULNERABLE: Alternative endpoint that's also exploitable
    """
    data = request.args.get('data', 'test')
    
    # VULNERABLE: Using unsanitized data
    response = jsonify({
        'result': data,
        'processed': True
    })
    
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5010)
