"""
XXE Lab 1: Basic XXE - External Entity Injection
Difficulty: 1 (Beginner)
Points: 50

Description:
Basic XML External Entity (XXE) injection.
"""

from flask import Flask, request, render_template_string
import xml.etree.ElementTree as ET

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>XXE Lab 1</title></head>
<body>
    <h1>XML Parser</h1>
    <form method="POST">
        <textarea name="xml" placeholder="Enter XML" rows="10" cols="50">{{ xml }}</textarea>
        <button>Parse</button>
    </form>
    {% if result %}
        <p><strong>Result:</strong></p>
        <pre>{{ result }}</pre>
    {% endif %}
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Direct XML parsing without XXE protection
    
    Attack Vector:
    <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <foo>&xxe;</foo>
    
    Flag: FLAG{xxe_basic_001}
    """
    xml_input = request.form.get('xml', '')
    result = None
    error = None
    
    if xml_input:
        try:
            # VULNERABLE: No XXE prevention
            root = ET.fromstring(xml_input)
            result = ET.tostring(root, encoding='unicode')
        except Exception as e:
            error = f"Error: {str(e)}"
    
    return render_template_string(TEMPLATE, xml=xml_input, result=result, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
