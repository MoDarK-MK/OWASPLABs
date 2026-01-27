"""
IDOR Lab 10: Blind IDOR
Difficulty: 2 (Intermediate)
Type: IDOR
Points: 75

Description:
IDOR without direct response feedback.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

SUBSCRIPTIONS = {
    '101': {'id': '101', 'user': 'alice', 'plan': 'pro', 'status': 'active'},
    '102': {'id': '102', 'user': 'bob', 'plan': 'premium', 'status': 'active'},
    '103': {'id': '103', 'user': 'charlie', 'plan': 'basic', 'status': 'expired'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Cancel Subscription</title>
    <style>
        body { font-family: Arial; margin: 20px; }
    </style>
</head>
<body>
    <h1>Cancel Subscription</h1>
    <form method="POST">
        <input type="hidden" name="sub_id" value="{{ sub_id }}">
        <button type="submit">Cancel Subscription</button>
    </form>
    <p id="msg" style="color: green;">Processing...</p>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    VULNERABLE: Blind IDOR (no feedback on success/failure)
    
    Attack Vector:
    POST with sub_id=102 (cancel Bob's subscription)
    
    Flag: FLAG{idor_blind_idor_010}
    """
    sub_id = request.args.get('sub_id') or request.form.get('sub_id', '101')
    
    if request.method == 'POST':
        # Process cancellation without proper authorization
        subscription = SUBSCRIPTIONS.get(sub_id)
        if subscription:
            # Just return success regardless
            return "Subscription cancelled successfully"
        return "Subscription not found"
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, sub_id=sub_id)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010, debug=False)
