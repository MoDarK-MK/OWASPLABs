"""
RCE Lab 6: Pickle Deserialization RCE
Difficulty: 2 (Intermediate)
Points: 75

Description:
Remote Code Execution through unsafe pickle deserialization.
"""

from flask import Flask, request
import pickle
import base64

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Unsafe pickle.loads() on user input
    
    Attack Vector:
    Use pickletools or craft pickle bytecode that executes code
    POST data=<base64 pickle payload>
    
    Payload example (pseudo):
    os.system('id') inside pickle reduce
    
    Flag: FLAG{rce_pickle_006}
    """
    result = None
    
    if request.method == 'POST':
        try:
            data = request.form.get('data', '')
            decoded = base64.b64decode(data)
            
            # VULNERABLE: Direct pickle.loads() without validation
            obj = pickle.loads(decoded)
            result = f"Deserialized: {obj}"
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>Pickle Deserializer</h1>
        <form method="POST">
            <textarea name="data" placeholder="Base64 pickle payload"></textarea>
            <button>Deserialize</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=False)
