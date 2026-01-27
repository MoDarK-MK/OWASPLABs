"""
IDOR Lab 18: GraphQL IDOR
Difficulty: 4 (Expert)
Points: 150

Description:
IDOR vulnerability in GraphQL API.
"""

from flask import Flask, request, jsonify

app = Flask(__name__)

USERS_DB = {
    '1': {'id': '1', 'username': 'alice', 'email': 'alice@example.com', 'role': 'user', 'balance': 100},
    '2': {'id': '2', 'username': 'bob', 'email': 'bob@example.com', 'role': 'admin', 'balance': 5000},
    '3': {'id': '3', 'username': 'charlie', 'email': 'charlie@example.com', 'role': 'user', 'balance': 250},
    '4': {'id': '4', 'username': 'diana', 'email': 'diana@example.com', 'role': 'moderator', 'balance': 1000},
}

def resolve_query(query):
    """Simple GraphQL-like resolver"""
    if 'user(' in query:
        import re
        match = re.search(r'user\(id:"(\w+)"\)', query)
        if match:
            user_id = match.group(1)
            return USERS_DB.get(user_id)
    return None

@app.route('/graphql', methods=['POST'])
def graphql():
    """
    VULNERABLE: GraphQL endpoint without ID validation
    
    Attack Vector:
    POST /graphql
    { "query": "query { user(id:\"2\") { id username email role balance } }" }
    
    Or simpler:
    ?query=user(id:"2")
    
    Flag: FLAG{idor_graphql_018}
    """
    data = request.get_json() or {}
    query = data.get('query', request.args.get('query', ''))
    
    result = resolve_query(query)
    
    if result:
        return jsonify({'data': {'user': result}})
    
    return jsonify({'data': {'user': None}})

@app.route('/')
def index():
    return '''
    <html>
    <body>
    <h1>GraphQL IDOR Lab</h1>
    <p>POST to /graphql with query parameter</p>
    <p>Example: { "query": "query { user(id:\\"2\\") { username email balance } }" }</p>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5018, debug=False)
