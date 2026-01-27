"""
IDOR Lab 2: Sequential ID Enumeration
Difficulty: 1 (Beginner)
Type: IDOR
Points: 50

Description:
Sequential IDs allow easy enumeration of all records.
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

POSTS = {
    '1': {'id': '1', 'title': 'My Day', 'content': 'Had a great day today!', 'author': 'Alice'},
    '2': {'id': '2', 'title': 'Secret Thoughts', 'content': 'Planning to leave the company...', 'author': 'Bob'},
    '3': {'id': '3', 'title': 'Weekend Plans', 'content': 'Going hiking tomorrow', 'author': 'Charlie'},
}

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Post View</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        .post { border: 1px solid #ddd; padding: 20px; background: #f9f9f9; }
        a { color: blue; margin-right: 10px; }
    </style>
</head>
<body>
    <h1>View Post</h1>
    <div class="post">
        <h2>{{ post.title }}</h2>
        <p>By: {{ post.author }}</p>
        <p>{{ post.content }}</p>
    </div>
    <p>
        <a href="/?post_id=1">Post 1</a>
        <a href="/?post_id=2">Post 2</a>
        <a href="/?post_id=3">Post 3</a>
    </p>
</body>
</html>
"""

@app.route('/')
def index():
    """
    VULNERABLE: Sequential IDs allow enumeration
    
    Attack Vector:
    /?post_id=1, /?post_id=2, /?post_id=3... (enumerate all posts)
    
    Flag: FLAG{idor_sequential_enumeration_002}
    """
    post_id = request.args.get('post_id', '1')
    post = POSTS.get(post_id, {'id': post_id, 'title': 'Not Found', 'content': '', 'author': ''})
    
    from flask import render_template_string
    return render_template_string(TEMPLATE, post=post)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False)
