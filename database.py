import sqlite3
import json
from datetime import datetime, timedelta
import os

DATABASE_PATH = 'instance/like_system.db'

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Create admin table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_key TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create user_keys table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            expiry TIMESTAMP NOT NULL,
            use_limit INTEGER DEFAULT 2,
            used_count INTEGER DEFAULT 0,
            like_used BOOLEAN DEFAULT 0,
            visit_used BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT
        )
    ''')
    
    # Create usage_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usage_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_used TEXT,
            action TEXT,
            uid TEXT,
            region TEXT,
            status TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create banned_ips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            reason TEXT,
            banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create active_sessions table (for JWT tracking)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL UNIQUE,
            user_key TEXT,
            user_type TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    ''')
    
    # Insert default admin key if not exists
    cursor.execute('SELECT * FROM admin WHERE admin_key = ?', ('KIRITO_AX',))
    if not cursor.fetchone():
        cursor.execute('INSERT INTO admin (admin_key) VALUES (?)', ('KIRITO_AX',))
    
    conn.commit()
    conn.close()

# ========== ADMIN FUNCTIONS ==========

def get_admin_key():
    """Get current admin key"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT admin_key FROM admin ORDER BY id DESC LIMIT 1')
    row = cursor.fetchone()
    conn.close()
    return row['admin_key'] if row else 'KIRITO_AX'

def update_admin_key(old_key, new_key):
    """Update admin key"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM admin WHERE admin_key = ?', (old_key,))
    if cursor.fetchone():
        cursor.execute('INSERT INTO admin (admin_key) VALUES (?)', (new_key,))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

# ========== USER KEY FUNCTIONS ==========

def get_all_user_keys():
    """Get all user keys"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT key, expiry, use_limit, used_count, like_used, visit_used, created_at 
        FROM user_keys 
        ORDER BY created_at DESC
    ''')
    keys = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return keys

def get_user_key(key):
    """Get specific user key"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user_keys WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def create_user_key(key, validity_days, use_limit, created_by='admin'):
    """Create new user key"""
    expiry = datetime.now() + timedelta(days=validity_days)
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO user_keys (key, expiry, use_limit, created_by)
            VALUES (?, ?, ?, ?)
        ''', (key, expiry, use_limit, created_by))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def update_key_usage(key, action):
    """Update key usage (like or visit)"""
    conn = get_db()
    cursor = conn.cursor()
    
    if action == 'like':
        cursor.execute('''
            UPDATE user_keys 
            SET like_used = 1, used_count = used_count + 1 
            WHERE key = ? AND like_used = 0
        ''', (key,))
    elif action == 'visit':
        cursor.execute('''
            UPDATE user_keys 
            SET visit_used = 1, used_count = used_count + 1 
            WHERE key = ? AND visit_used = 0
        ''', (key,))
    
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0

def delete_user_key(key):
    """Delete a user key"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_keys WHERE key = ?', (key,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0

def validate_user_key(key):
    """Validate if key is usable"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT key, expiry, use_limit, used_count, like_used, visit_used 
        FROM user_keys 
        WHERE key = ?
    ''', (key,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return None, "Key not found"
    
    key_data = dict(row)
    
    # Check expiry
    expiry = datetime.fromisoformat(key_data['expiry']) if isinstance(key_data['expiry'], str) else key_data['expiry']
    if datetime.now() > expiry:
        return None, "Key expired"
    
    # Check use limit
    if key_data['used_count'] >= key_data['use_limit']:
        return None, "Key usage limit reached"
    
    return key_data, None

# ========== SESSION FUNCTIONS (JWT) ==========

def create_session(session_id, user_key, user_type, ip_address, expires_at):
    """Create a new session in database"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO active_sessions (session_id, user_key, user_type, ip_address, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, user_key, user_type, ip_address, expires_at))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def get_session(session_id):
    """Get session from database"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM active_sessions WHERE session_id = ?', (session_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_session(session_id):
    """Delete a session (logout)"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM active_sessions WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()

def cleanup_expired_sessions():
    """Remove expired sessions"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM active_sessions WHERE expires_at < ?', (datetime.now(),))
    conn.commit()
    conn.close()

# ========== LOGGING FUNCTIONS ==========

def log_usage(key, action, uid, region, status, ip, user_agent=''):
    """Log key usage for audit"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO usage_logs (key_used, action, uid, region, status, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (key, action, uid, region, status, ip, user_agent))
    conn.commit()
    conn.close()

def get_usage_logs(limit=100):
    """Get recent usage logs"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM usage_logs 
        ORDER BY created_at DESC 
        LIMIT ?
    ''', (limit,))
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return logs

def is_ip_banned(ip):
    """Check if IP is banned"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM banned_ips WHERE ip_address = ?', (ip,))
    banned = cursor.fetchone() is not None
    conn.close()
    return banned

def ban_ip(ip, reason):
    """Ban an IP address"""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO banned_ips (ip_address, reason) VALUES (?, ?)', (ip, reason))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

# Initialize database when module loads
if not os.path.exists('instance'):
    os.makedirs('instance')
init_db()