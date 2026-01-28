"""
XSS Lab 2: Stored XSS - Comments
Difficulty: 1 (Beginner)
Type: Stored/Persistent XSS
Points: 50

Description:
Stored XSS vulnerability in a comment system.
Comments are stored in database without sanitization and displayed to all users.
"""

from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# In-memory database for comments
comments_db = {
    1: {
        'id': 1,
        'author': 'Admin',
        'text': 'Welcome to our blog!',
        'timestamp': datetime.now().isoformat()
    }
}
next_comment_id = 2

@app.route('/')
def index():
    """Home page with comment form"""
    return """
    <html>
        <head>
            <title>XSS Lab 2: Stored XSS - Comments</title>
            <style>
                body { font-family: Arial; margin: 40px; max-width: 800px; }
                .comment-form { background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }
                input, textarea { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
                button { padding: 8px 15px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
                .comments-section { margin: 30px 0; }
                .comment { background: #f9f9f9; border-left: 4px solid #ddd; padding: 10px; margin: 10px 0; }
                .comment-author { font-weight: bold; }
                .comment-time { color: #666; font-size: 0.9em; }
            </style>
        </head>
        <body>
            <h1>Lab 2: Stored XSS - Comments</h1>
            <p>This lab has a stored XSS vulnerability in the comment system.</p>
            
            <div class="comment-form">
                <h3>Post a Comment:</h3>
                <form id="commentForm">
                    <input type="text" id="author" placeholder="Your name" required>
                    <textarea id="text" placeholder="Your comment" required rows="4"></textarea>
                    <button type="submit">Post Comment</button>
                </form>
            </div>
            
            <div class="comments-section" id="commentsContainer">
                <h3>Comments:</h3>
                <div id="commentsList"></div>
            </div>
            
            <script>
                // Load comments on page load
                function loadComments() {
                    fetch('/api/comments')
                        .then(r => r.json())
                        .then(data => {
                            const list = document.getElementById('commentsList');
                            list.innerHTML = '';
                            data.forEach(comment => {
                                const div = document.createElement('div');
                                div.className = 'comment';
                                // VULNERABLE: innerHTML used with unsanitized content
                                div.innerHTML = `
                                    <div class="comment-author">${comment.author}</div>
                                    <div class="comment-time">${new Date(comment.timestamp).toLocaleString()}</div>
                                    <div>${comment.text}</div>
                                `;
                                list.appendChild(div);
                            });
                        });
                }
                
                document.getElementById('commentForm').addEventListener('submit', function(e) {
                    e.preventDefault();
                    fetch('/api/comments', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            author: document.getElementById('author').value,
                            text: document.getElementById('text').value
                        })
                    }).then(r => r.json()).then(data => {
                        if (data.success) {
                            document.getElementById('commentForm').reset();
                            loadComments();
                        }
                    });
                });
                
                loadComments();
                setInterval(loadComments, 3000); // Refresh every 3 seconds
            </script>
            
            <h3>Attack Vectors:</h3>
            <ul>
                <li>Author: <code>John</code> | Comment: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
                <li>Author: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code> | Comment: <code>Test</code></li>
                <li>Comment: <code>&lt;svg/onload=fetch('/hack')&gt;</code></li>
            </ul>
            
            <p><strong>Flag:</strong> FLAG{xss_stored_comments_002}</p>
        </body>
    </html>
    """

@app.route('/api/comments', methods=['GET'])
def get_comments():
    """Get all comments - returns unsanitized data"""
    return jsonify(list(comments_db.values()))

@app.route('/api/comments', methods=['POST'])
def post_comment():
    """
    Post a new comment
    
    VULNERABLE: No input sanitization or validation
    Comments are stored as-is and rendered with innerHTML
    """
    global next_comment_id
    
    data = request.get_json()
    author = data.get('author', 'Anonymous')
    text = data.get('text', '')
    
    if not text:
        return jsonify({'success': False, 'error': 'Comment cannot be empty'}), 400
    
    # VULNERABLE: Storing unsanitized user input
    comment = {
        'id': next_comment_id,
        'author': author,  # No sanitization
        'text': text,      # No sanitization
        'timestamp': datetime.now().isoformat()
    }
    
    comments_db[next_comment_id] = comment
    next_comment_id += 1
    
    return jsonify({'success': True, 'comment_id': comment['id']})

if __name__ == '__main__':
    app.run(debug=True, port=5002)
