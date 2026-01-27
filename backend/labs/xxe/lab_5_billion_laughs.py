"""
XXE Lab 5: Billion Laughs (Denial of Service)
Difficulty: 2 (Intermediate)
Points: 75

Description:
XXE Denial of Service via billion laughs attack.
"""

from flask import Flask, request
import xml.etree.ElementTree as ET

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Entity expansion DoS
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE lol [
        <!ENTITY lol "lol">
        <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    ]>
    <lol>&lol4;</lol>
    
    Exponential expansion causes memory exhaustion
    
    Flag: FLAG{xxe_billion_laughs_005}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            # VULNERABLE: No entity expansion limits
            root = ET.fromstring(xml_input)
            result = "XML parsed (potential DoS)"
        except Exception as e:
            error = f"Error (likely from huge entity): {str(e)[:100]}"
    
    return f"""
    <html>
    <body>
        <h1>Billion Laughs XXE DoS</h1>
        <form method="POST">
            <textarea name="xml" rows="10" cols="60">{xml_input}</textarea>
            <button>Parse</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
        {f"<p style='color:red;'>{error}</p>" if error else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5005, debug=False)
