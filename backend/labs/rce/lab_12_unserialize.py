"""
RCE Lab 12: PHP Unserialize RCE
Difficulty: 3 (Advanced)
Points: 100

Description:
Remote Code Execution through unsafe unserialization.
"""

from flask import Flask, request
import base64

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Unsafe unserialize of user data
    
    Attack Vector:
    PHP: O:4:"User":2:{s:4:"name";s:4:"test";s:4:"role";s:5:"admin";}
    Gadget chains to execute code during unserialization
    
    Payload construction:
    - Identify magic methods (__wakeup, __destruct, __toString)
    - Chain them together to execute code
    
    Flag: FLAG{rce_unserialize_012}
    """
    result = None
    
    if request.method == 'POST':
        data = request.form.get('serialized', '')
        
        try:
            # VULNERABLE: Direct unserialize (simulated)
            # In real PHP: unserialize($data)
            result = f"Unserialized (simulated): {data}"
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Serializer</h1>
        <form method="POST">
            <textarea name="serialized" placeholder="Serialized data"></textarea>
            <button>Unserialize</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5012, debug=False)
