import os
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import jwt

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-in-production')
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mock_users = {
    1: {'id': 1, 'username': 'admin', 'password': 'admin123', 'email': 'admin@test.com', 'role': 'admin'}
}

mock_labs = [
    {'id': 1, 'title': 'SQL Injection - Login Bypass', 'category': 'sql_injection', 'difficulty': 1, 'description': 'Bypass login using SQL injection', 'points': 100, 'flag': 'FLAG{sqli_basic}'},
    {'id': 2, 'title': 'XSS in Search', 'category': 'xss', 'difficulty': 2, 'description': 'Execute XSS in search box', 'points': 100, 'flag': 'FLAG{xss_basic}'},
    {'id': 3, 'title': 'CSRF Attack', 'category': 'csrf', 'difficulty': 3, 'description': 'Perform CSRF attack', 'points': 150, 'flag': 'FLAG{csrf_basic}'},
]

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Missing authentication token'}), 401
        
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = payload['user_id']
            request.username = payload['username']
            request.role = payload['role']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not all([username, password, email]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    if username in [u['username'] for u in mock_users.values()]:
        return jsonify({'error': 'User already exists'}), 400
    
    user_id = max([u['id'] for u in mock_users.values()]) + 1
    mock_users[user_id] = {
        'id': user_id,
        'username': username,
        'password': password,
        'email': email,
        'role': 'user'
    }
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = next((u for u in mock_users.values() if u['username'] == username and u['password'] == password), None)
    
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    token = jwt.encode(
        {
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=24)
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    
    return jsonify({'token': token, 'user': {'id': user['id'], 'username': user['username'], 'role': user['role']}}), 200

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/labs', methods=['GET'])
@require_auth
def get_labs():
    return jsonify(mock_labs), 200

@app.route('/api/labs/<int:lab_id>', methods=['GET'])
@require_auth
def get_lab(lab_id):
    lab = next((l for l in mock_labs if l['id'] == lab_id), None)
    if lab:
        return jsonify(lab), 200
    return jsonify({'error': 'Lab not found'}), 404

@app.route('/api/labs/<int:lab_id>/start', methods=['POST'])
@require_auth
def start_lab(lab_id):
    return jsonify({'message': 'Lab session started', 'lab_id': lab_id}), 200

@app.route('/api/labs/<int:lab_id>/submit', methods=['POST'])
@require_auth
def submit_flag(lab_id):
    data = request.get_json()
    flag = data.get('flag')
    
    lab = next((l for l in mock_labs if l['id'] == lab_id), None)
    if not lab:
        return jsonify({'error': 'Lab not found'}), 404
    
    if flag == lab['flag']:
        return jsonify({
            'success': True,
            'message': 'Flag is correct!',
            'points': lab['points'],
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    else:
        return jsonify({'success': False, 'message': 'Flag is incorrect'}), 400

@app.route('/api/labs/<int:lab_id>/hint', methods=['GET'])
@require_auth
def get_hint(lab_id):
    hint_level = request.args.get('level', 1, type=int)
    lab = next((l for l in mock_labs if l['id'] == lab_id), None)
    
    if lab:
        return jsonify({'hint': f'Hint {hint_level} for {lab["title"]}', 'level': hint_level}), 200
    return jsonify({'error': 'No hint available'}), 404

@app.route('/api/user/progress', methods=['GET'])
@require_auth
def get_user_progress():
    return jsonify({
        'total_labs': len(mock_labs),
        'completed_labs': 0,
        'total_points': 0
    }), 200

@app.route('/api/user/profile', methods=['GET'])
@require_auth
def get_user_profile():
    user = mock_users.get(request.user_id)
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role'],
            'created_at': datetime.utcnow().isoformat()
        }), 200
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/leaderboard', methods=['GET'])
def get_leaderboard():
    limit = request.args.get('limit', 100, type=int)
    return jsonify([
        {
            'id': 1,
            'username': 'admin',
            'labs_completed': 5,
            'total_points': 500,
            'last_completed': datetime.utcnow().isoformat()
        }
    ]), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Internal server error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
