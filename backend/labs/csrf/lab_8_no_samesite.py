"""
CSRF Lab 8: No SameSite Cookie
Difficulty: 2 (Intermediate)
Type: CSRF
Points: 75

Description:
Cookies don't have SameSite attribute.
"""

from flask import Flask, request, render_template_string, make_response
import secrets

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Change Theme</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        select { padding: 8px; width: 200px; }
        button { padding: 8px 15px; background: #20c997; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Change Theme</h1>
    <form method="POST" action="/theme">
        <select name="theme" required>
            <option>light</option>
            <option>dark</option>
            <option>auto</option>
        </select>
        <button type="submit">Apply</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/theme', methods=['POST'])
def change_theme():
    """
    VULNERABLE: No SameSite attribute on cookies
    
    Attack Vector:
    POST /theme from cross-site, cookie sent automatically
    
    Flag: FLAG{csrf_no_samesite_008}
    """
    theme = request.form.get('theme', 'light')
    
    response = make_response(f"""
    <html>
        <body>
            <h2>Theme Updated</h2>
            <p>Your theme is now: {theme}</p>
        </body>
    </html>
    """)
    
    # No SameSite attribute
    response.set_cookie('theme', theme)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5008, debug=False)
