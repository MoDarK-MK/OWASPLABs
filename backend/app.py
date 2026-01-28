import os
import logging
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import jwt
import hashlib
from labs_database import get_all_labs, get_lab_by_id, get_labs_by_category

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:3000", "http://localhost:3001", "http://localhost:5000"]}})

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Path to labs directory
LABS_DIR = Path(__file__).parent / 'labs'

user_sessions = {}

mock_users = {
    1: {'id': 1, 'username': 'admin', 'password_hash': hashlib.sha256('admin123'.encode()).hexdigest(), 'email': 'admin@test.com', 'role': 'admin'}
}

completed_labs = {}

# Load all 160 labs from database
mock_labs = get_all_labs()

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
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        email = data.get('email', '').strip()
        
        if not all([username, password, email]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if len(username) < 3 or len(password) < 6:
            return jsonify({'error': 'Username must be 3+ chars, password 6+ chars'}), 400
        
        if any(u['username'] == username for u in mock_users.values()):
            return jsonify({'error': 'User already exists'}), 409
        
        user_id = max([u['id'] for u in mock_users.values()]) + 1
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        mock_users[user_id] = {
            'id': user_id,
            'username': username,
            'password_hash': password_hash,
            'email': email,
            'role': 'user'
        }
        
        return jsonify({'message': 'User registered successfully', 'user_id': user_id}), 201
    except Exception as e:
        logger.error(f'Registration error: {str(e)}')
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Missing credentials'}), 400
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user = next((u for u in mock_users.values() if u['username'] == username and u['password_hash'] == password_hash), None)
        
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
        
        user_sessions[user['id']] = token
        
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
    except Exception as e:
        logger.error(f'Login error: {str(e)}')
        return jsonify({'error': 'Login failed'}), 500

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
    try:
        data = request.get_json()
        flag = data.get('flag', '').strip()
        
        lab = next((l for l in mock_labs if l['id'] == lab_id), None)
        if not lab:
            return jsonify({'error': 'Lab not found'}), 404
        
        if not flag:
            return jsonify({'success': False, 'message': 'Please enter a flag'}), 400
        
        if flag == lab['flag']:
            user_id = request.user_id
            if user_id not in completed_labs:
                completed_labs[user_id] = []
            
            if lab_id not in completed_labs[user_id]:
                completed_labs[user_id].append(lab_id)
            
            return jsonify({
                'success': True,
                'message': 'Flag is correct!',
                'points': lab['points'],
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Flag is incorrect'}), 400
    except Exception as e:
        logger.error(f'Flag submission error: {str(e)}')
        return jsonify({'error': 'Submission failed'}), 500

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
    try:
        user_id = request.user_id
        user_completed = completed_labs.get(user_id, [])
        total_points = sum(lab['points'] for lab in mock_labs if lab['id'] in user_completed)
        
        return jsonify({
            'total_labs': len(mock_labs),
            'completed_labs': len(user_completed),
            'total_points': total_points,
            'completed_lab_ids': user_completed
        }), 200
    except Exception as e:
        logger.error(f'Progress fetch error: {str(e)}')
        return jsonify({'error': 'Failed to fetch progress'}), 500

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
    try:
        limit = request.args.get('limit', 100, type=int)
        
        leaderboard_data = []
        for user_id, user in mock_users.items():
            user_completed = completed_labs.get(user_id, [])
            total_points = sum(lab['points'] for lab in mock_labs if lab['id'] in user_completed)
            
            leaderboard_data.append({
                'id': user['id'],
                'username': user['username'],
                'labs_completed': len(user_completed),
                'total_points': total_points,
                'last_completed': datetime.utcnow().isoformat() if user_completed else None
            })
        
        leaderboard_data.sort(key=lambda x: (-x['total_points'], -x['labs_completed']))
        
        return jsonify(leaderboard_data[:limit]), 200
    except Exception as e:
        logger.error(f'Leaderboard fetch error: {str(e)}')
        return jsonify({'error': 'Failed to fetch leaderboard'}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f'Internal server error: {str(error)}')
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/labs/<int:lab_id>/launch', methods=['GET'])
@require_auth
def launch_lab(lab_id):
    """Launch practical lab file if it exists"""
    try:
        lab = get_lab_by_id(lab_id)
        if not lab:
            return jsonify({'error': 'Lab not found'}), 404
        
        category = lab.get('category', '')
        title = lab.get('title', 'Lab')
        
        # Define port mapping based on category and lab ID
        category_port_map = {
            'sql_injection': (1, 20, 5001),      # Labs 1-20 -> ports 5001-5020
            'xss': (21, 40, 5021),               # Labs 21-40 -> ports 5021-5040
            'csrf': (41, 60, 5041),              # Labs 41-60 -> ports 5041-5060
            'idor': (61, 80, 5061),              # Labs 61-80 -> ports 5061-5080
            'rce': (81, 100, 5081),              # Labs 81-100 -> ports 5081-5100
            'ssrf': (101, 120, 5101),            # Labs 101-120 -> ports 5101-5120
            'xxe': (121, 140, 5121),             # Labs 121-140 -> ports 5121-5140
            'command_injection': (141, 160, 5141)  # Labs 141-160 -> ports 5141-5160
        }
        
        if category not in category_port_map:
            return jsonify({
                'message': 'Lab content loaded',
                'practical_lab': None,
                'instructions': 'No practical lab available for this category yet'
            }), 200
        
        start_id, end_id, base_port = category_port_map[category]
        
        # Calculate lab file number and port
        lab_file_num = lab_id - start_id + 1
        port = base_port + lab_file_num - 1
        
        # Find the lab file
        lab_dir = LABS_DIR / category
        if not lab_dir.exists():
            return jsonify({
                'error': f'Lab directory not found: {category}'
            }), 404
        
        # Find lab file (pattern: lab_N_*.py)
        import glob
        lab_pattern = str(lab_dir / f'lab_{lab_file_num}_*.py')
        files = glob.glob(lab_pattern)
        
        if not files:
            return jsonify({
                'error': f'Lab file not found for {category} lab {lab_file_num}',
                'pattern': lab_pattern
            }), 404
        
        lab_path = files[0]
        
        # Try to start the lab
        try:
            process = subprocess.Popen(
                [sys.executable, str(lab_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(lab_dir)
            )
            
            # Store process info for later reference
            logger.info(f'Started lab: {category}/{Path(lab_path).name} on port {port}')
            
            return jsonify({
                'message': 'Lab launched successfully',
                'practical_lab': f'http://localhost:{port}',
                'category': category,
                'lab_id': lab_id,
                'lab_file': Path(lab_path).name,
                'port': port,
                'title': title
            }), 200
        except Exception as e:
            logger.error(f'Failed to launch lab: {str(e)}')
            return jsonify({
                'error': 'Failed to launch practical lab',
                'details': str(e),
                'lab_file': lab_path
            }), 500
        
    except Exception as e:
        logger.error(f'Lab launch error: {str(e)}')
        return jsonify({'error': 'Failed to launch lab'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
