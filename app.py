from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
import requests
import json
import os
from datetime import datetime, timedelta
import random
import string
import jwt
import uuid
from functools import wraps
from database import (
    get_admin_key, update_admin_key, get_all_user_keys, get_user_key,
    create_user_key, update_key_usage, delete_user_key, validate_user_key,
    log_usage, get_usage_logs, is_ip_banned, ban_ip, init_db,
    create_session, get_session, delete_session, cleanup_expired_sessions
)

app = Flask(__name__)
CORS(app, supports_credentials=True)

# ========== JWT CONFIGURATION ==========
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-super-secret-jwt-key-change-this-in-production-2024')
app.config['JWT_EXPIRATION_HOURS'] = 24

# ========== API ENDPOINTS (HIDDEN IN BACKEND) ==========
LIKE_API_URL = "https://stargvhuuvjpy.vercel.app/like"
VISIT_API_URL = "https://star-visit.vercel.app"

def call_like_api(uid, region):
    """Call like API from backend (hidden from frontend)"""
    try:
        url = f"{LIKE_API_URL}?uid={uid}&server_name={region}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            return response.json()
        return {"error": "API_ERROR"}
    except Exception as e:
        return {"error": "API_ERROR"}

def call_visit_api(region, uid):
    """Call visit API from backend (hidden from frontend)"""
    try:
        url = f"{VISIT_API_URL}/{region}/{uid}"
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            return response.json()
        return {"error": "API_ERROR"}
    except Exception as e:
        return {"error": "API_ERROR"}

# ========== JWT HELPER FUNCTIONS ==========
def generate_jwt_token(user_key, user_type, key_data=None):
    """Generate JWT token for authenticated user"""
    payload = {
        'session_id': str(uuid.uuid4()),
        'user_key': user_key,
        'user_type': user_type,
        'key_data': key_data,
        'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS']),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    
    # Store session in database
    create_session(
        session_id=payload['session_id'],
        user_key=user_key,
        user_type=user_type,
        ip_address=request.remote_addr,
        expires_at=datetime.now() + timedelta(hours=app.config['JWT_EXPIRATION_HOURS'])
    )
    
    return token

def verify_jwt_token(token):
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        # Check if session exists in database
        session_data = get_session(payload['session_id'])
        if not session_data:
            return None, "Session expired or invalid"
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, "Token expired"
    except jwt.InvalidTokenError:
        return None, "Invalid token"

def token_required(f):
    """Decorator to protect routes with JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'success': False, 'message': 'Token missing'}), 401
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload, error = verify_jwt_token(token)
        if error:
            return jsonify({'success': False, 'message': error}), 401
        
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator to protect admin routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'success': False, 'message': 'Token missing'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload, error = verify_jwt_token(token)
        if error:
            return jsonify({'success': False, 'message': error}), 401
        
        if payload.get('user_type') != 'admin':
            return jsonify({'success': False, 'message': 'Admin access required'}), 403
        
        request.jwt_payload = payload
        return f(*args, **kwargs)
    return decorated

# ========== FORMAT KEY HELPER ==========
def format_key(key):
    """Format key to XXXX-XXXX-XXXX"""
    clean = key.upper().replace('-', '').replace(' ', '')[:12]
    if len(clean) >= 12:
        parts = [clean[i:i+4] for i in range(0, 12, 4)]
        return '-'.join(parts)
    return key.upper()

def generate_random_key():
    """Generate random key in format XXXX-XXXX-XXXX"""
    chars = string.ascii_uppercase + string.digits
    chars = chars.replace('O', '').replace('I', '')
    segments = []
    for _ in range(3):
        seg = ''.join(random.choices(chars, k=4))
        segments.append(seg)
    return '-'.join(segments)

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    return request.remote_addr

# Cleanup expired sessions periodically
@app.before_request
def cleanup():
    cleanup_expired_sessions()

# ========== ROUTES ==========
@app.route('/')
def index():
    """Serve frontend UI"""
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    """Check login key (admin or user) - Returns JWT token"""
    data = request.json
    key = data.get('key', '').strip()
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    # Check if IP is banned
    if is_ip_banned(client_ip):
        return jsonify({'success': False, 'message': 'Your IP is banned'})
    
    # Check admin key
    current_admin = get_admin_key()
    if key == current_admin:
        # Generate JWT token for admin
        token = generate_jwt_token(key, 'admin', None)
        log_usage(key, 'login', '-', '-', 'admin_success', client_ip, user_agent)
        return jsonify({
            'success': True,
            'type': 'admin',
            'token': token,
            'message': 'Admin login successful'
        })
    
    # Check user keys
    key_data, error = validate_user_key(key)
    if key_data:
        # Generate JWT token for user
        token = generate_jwt_token(key, 'user', {
            'key': key_data['key'],
            'like_used': key_data['like_used'],
            'visit_used': key_data['visit_used'],
            'used_count': key_data['used_count'],
            'use_limit': key_data['use_limit']
        })
        log_usage(key, 'login', '-', '-', 'user_success', client_ip, user_agent)
        return jsonify({
            'success': True,
            'type': 'user',
            'token': token,
            'key_data': {
                'key': key_data['key'],
                'like_used': key_data['like_used'],
                'visit_used': key_data['visit_used'],
                'used_count': key_data['used_count'],
                'use_limit': key_data['use_limit']
            }
        })
    
    log_usage(key, 'login', '-', '-', f'failed: {error}', client_ip, user_agent)
    return jsonify({'success': False, 'message': error or 'Invalid key'})

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    """Logout - invalidate JWT token"""
    session_id = request.jwt_payload.get('session_id')
    if session_id:
        delete_session(session_id)
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/verify-token', methods=['POST'])
def verify_token():
    """Verify if JWT token is still valid"""
    token = request.json.get('token')
    if not token:
        return jsonify({'success': False, 'message': 'Token missing'})
    
    payload, error = verify_jwt_token(token)
    if error:
        return jsonify({'success': False, 'message': error})
    
    return jsonify({'success': True, 'type': payload.get('user_type')})

@app.route('/api/send-like', methods=['POST'])
@token_required
def send_like():
    """Send like request (backend handles API call)"""
    data = request.json
    uid = data.get('uid')
    region = data.get('region')
    user_key = request.jwt_payload.get('user_key')
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    if is_ip_banned(client_ip):
        return jsonify({'success': False, 'message': 'Your IP is banned'})
    
    # Validate key
    key_data, error = validate_user_key(user_key)
    if not key_data:
        log_usage(user_key, 'like', uid, region, f'failed: {error}', client_ip, user_agent)
        return jsonify({'success': False, 'message': error})
    
    # Check if like already used
    if key_data['like_used']:
        log_usage(user_key, 'like', uid, region, 'failed: like_already_used', client_ip, user_agent)
        return jsonify({'success': False, 'message': 'Like already used with this key'})
    
    # Call actual like API from backend
    result = call_like_api(uid, region)
    
    if 'error' in result:
        log_usage(user_key, 'like', uid, region, 'failed: api_error', client_ip, user_agent)
        return jsonify({'success': False, 'message': 'API Error', 'error': True})
    
    # Update key usage
    update_key_usage(user_key, 'like')
    log_usage(user_key, 'like', uid, region, 'success', client_ip, user_agent)
    
    return jsonify({
        'success': True,
        'data': result
    })

@app.route('/api/send-visit', methods=['POST'])
@token_required
def send_visit():
    """Send visit request (backend handles API call)"""
    data = request.json
    uid = data.get('uid')
    region = data.get('region')
    user_key = request.jwt_payload.get('user_key')
    client_ip = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    if is_ip_banned(client_ip):
        return jsonify({'success': False, 'message': 'Your IP is banned'})
    
    # Validate key
    key_data, error = validate_user_key(user_key)
    if not key_data:
        log_usage(user_key, 'visit', uid, region, f'failed: {error}', client_ip, user_agent)
        return jsonify({'success': False, 'message': error})
    
    # Check if visit already used
    if key_data['visit_used']:
        log_usage(user_key, 'visit', uid, region, 'failed: visit_already_used', client_ip, user_agent)
        return jsonify({'success': False, 'message': 'Visit already used with this key'})
    
    # Call actual visit API from backend
    result = call_visit_api(region, uid)
    
    if 'error' in result:
        log_usage(user_key, 'visit', uid, region, 'failed: api_error', client_ip, user_agent)
        return jsonify({'success': False, 'message': 'API Error', 'error': True})
    
    # Update key usage
    update_key_usage(user_key, 'visit')
    log_usage(user_key, 'visit', uid, region, 'success', client_ip, user_agent)
    
    return jsonify({
        'success': True,
        'data': result
    })

@app.route('/api/admin/keys', methods=['GET'])
@admin_required
def get_keys():
    """Get all user keys (admin only)"""
    keys = get_all_user_keys()
    return jsonify({'success': True, 'keys': keys})

@app.route('/api/admin/generate-key', methods=['POST'])
@admin_required
def generate_key():
    """Generate new user key (admin only)"""
    data = request.json
    custom_key = data.get('custom_key', '').strip()
    validity_days = int(data.get('validity_days', 30))
    use_limit = int(data.get('use_limit', 30))
    
    # Limit use limit to max 30
    if use_limit > 30:
        use_limit = 30
    
    # Generate or use custom key
    if custom_key:
        final_key = format_key(custom_key)
    else:
        final_key = generate_random_key()
    
    # Create key in database
    success = create_user_key(final_key, validity_days, use_limit)
    
    if not success:
        return jsonify({'success': False, 'message': 'Key already exists'})
    
    return jsonify({
        'success': True,
        'key': final_key,
        'validity_days': validity_days,
        'use_limit': use_limit
    })

@app.route('/api/admin/update-admin-key', methods=['POST'])
def update_admin_key_route():
    """Update admin key"""
    data = request.json
    old_key = data.get('old_key')
    new_key = data.get('new_key')
    
    if update_admin_key(old_key, new_key):
        return jsonify({'success': True, 'message': 'Admin key updated'})
    
    return jsonify({'success': False, 'message': 'Invalid current admin key'})

@app.route('/api/admin/delete-key', methods=['POST'])
@admin_required
def delete_key_route():
    """Delete a user key"""
    data = request.json
    key_to_delete = data.get('key')
    
    success = delete_user_key(key_to_delete)
    return jsonify({'success': success})

@app.route('/api/admin/logs', methods=['GET'])
@admin_required
def get_logs():
    """Get usage logs (admin only)"""
    logs = get_usage_logs(100)
    return jsonify({'success': True, 'logs': logs})

@app.route('/api/admin/ban-ip', methods=['POST'])
@admin_required
def ban_ip_route():
    """Ban an IP address (admin only)"""
    data = request.json
    ip = data.get('ip')
    reason = data.get('reason', 'Manual ban')
    
    success = ban_ip(ip, reason)
    return jsonify({'success': success})

if __name__ == '__main__':
    # Initialize database
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)