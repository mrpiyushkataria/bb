from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from database.models import db, User
from datetime import datetime
import re

auth_bp = Blueprint('auth', __name__)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    
    return True, "Password is valid"

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register new user"""
    data = request.get_json()
    
    # Validate input
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data or not data[field].strip():
            return jsonify({
                'success': False,
                'error': f'{field} is required'
            }), 400
    
    username = data['username'].strip()
    email = data['email'].strip().lower()
    password = data['password']
    
    # Validate username
    if len(username) < 3 or len(username) > 50:
        return jsonify({
            'success': False,
            'error': 'Username must be between 3 and 50 characters'
        }), 400
    
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return jsonify({
            'success': False,
            'error': 'Username can only contain letters, numbers and underscores'
        }), 400
    
    # Validate email
    if not validate_email(email):
        return jsonify({
            'success': False,
            'error': 'Invalid email format'
        }), 400
    
    # Validate password
    is_valid, password_error = validate_password(password)
    if not is_valid:
        return jsonify({
            'success': False,
            'error': password_error
        }), 400
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        return jsonify({
            'success': False,
            'error': 'Username already exists'
        }), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({
            'success': False,
            'error': 'Email already registered'
        }), 400
    
    # Create new user
    hashed_password = generate_password_hash(password)
    
    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_password,
        role='user',  # Default role
        created_at=datetime.utcnow()
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Registration failed: {str(e)}'
        }), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    # Validate input
    if 'username' not in data or 'password' not in data:
        return jsonify({
            'success': False,
            'error': 'Username and password are required'
        }), 400
    
    username = data['username'].strip()
    password = data['password']
    
    # Find user by username or email
    user = User.query.filter(
        (User.username == username) | (User.email == username)
    ).first()
    
    if not user:
        return jsonify({
            'success': False,
            'error': 'Invalid username or password'
        }), 401
    
    if not user.is_active:
        return jsonify({
            'success': False,
            'error': 'Account is disabled'
        }), 401
    
    # Check password
    if not check_password_hash(user.password_hash, password):
        return jsonify({
            'success': False,
            'error': 'Invalid username or password'
        }), 401
    
    # Login user
    login_user(user, remember=data.get('remember', False))
    
    return jsonify({
        'success': True,
        'message': 'Login successful',
        'user': user.to_dict()
    }), 200

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """User logout"""
    logout_user()
    return jsonify({
        'success': True,
        'message': 'Logout successful'
    }), 200

@auth_bp.route('/profile', methods=['GET'])
@login_required
def get_profile():
    """Get current user profile"""
    return jsonify({
        'success': True,
        'user': current_user.to_dict()
    }), 200

@auth_bp.route('/profile', methods=['PUT'])
@login_required
def update_profile():
    """Update user profile"""
    data = request.get_json()
    
    # Check if email is being updated
    if 'email' in data:
        email = data['email'].strip().lower()
        
        if not validate_email(email):
            return jsonify({
                'success': False,
                'error': 'Invalid email format'
            }), 400
        
        # Check if email already exists (excluding current user)
        existing_user = User.query.filter(
            User.email == email,
            User.id != current_user.id
        ).first()
        
        if existing_user:
            return jsonify({
                'success': False,
                'error': 'Email already registered'
            }), 400
        
        current_user.email = email
    
    # Update password if provided
    if 'password' in data and data['password']:
        password = data['password']
        
        # Validate current password
        if 'current_password' not in data:
            return jsonify({
                'success': False,
                'error': 'Current password is required to change password'
            }), 400
        
        if not check_password_hash(current_user.password_hash, data['current_password']):
            return jsonify({
                'success': False,
                'error': 'Current password is incorrect'
            }), 401
        
        # Validate new password
        is_valid, password_error = validate_password(password)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': password_error
            }), 400
        
        current_user.password_hash = generate_password_hash(password)
    
    try:
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': current_user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Update failed: {str(e)}'
        }), 500

@auth_bp.route('/check-auth', methods=['GET'])
def check_auth():
    """Check if user is authenticated"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': current_user.to_dict()
        }), 200
    
    return jsonify({
        'authenticated': False
    }), 200
