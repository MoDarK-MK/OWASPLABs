"""
XXE Lab 14: XXE Comment Injection
Difficulty: 2 (Intermediate)
Points: 75

Description:
XXE bypassing via comment injection.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE comment injection bypass
    
    Attack Vector:
    Input validation may check for DOCTYPE declarations
    Bypass using comments:
    
    <?xml version="1.0"?>
    <!-- <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> -->
    <foo>&xxe;</foo>
    
    Or inject DTD via comments:
    <? xml version="1.0"?>
    <!-- This comment contains:
         <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    -->
    <foo>&xxe;</foo>
    
    Flag: FLAG{xxe_comment_injection_014}
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
        <h1>XXE Comment Injection</h1>
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
    app.run(host='0.0.0.0', port=5014, debug=False)
