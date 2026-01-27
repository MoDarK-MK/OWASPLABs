"""
CSRF Lab 9: GET Request State Change
Difficulty: 2 (Intermediate)
Type: CSRF
Points: 75

Description:
State-changing operations allowed via GET.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Invite User</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        a { color: blue; text-decoration: underline; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Invite User</h1>
    <p><a href="/invite?user=newuser">Invite newuser to team</a></p>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(TEMPLATE)

@app.route('/invite')
def invite():
    """
    VULNERABLE: GET request modifies state
    
    Attack Vector:
    GET /invite?user=admin (can be done via <img> tag)
    
    Flag: FLAG{csrf_get_state_change_009}
    """
    user = request.args.get('user', '')
    
    return f"""
    <html>
        <body>
            <h2>Invitation Sent</h2>
            <p>{user} has been invited to your team</p>
        </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5009, debug=False)
