from flask import Flask, render_template, send_from_directory, jsonify
from flask_login import LoginManager, current_user
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from config import config
from database.models import db, User
from api.auth import auth_bp
from api.scans import scans_bp
import os

# Initialize extensions
login_manager = LoginManager()
socketio = SocketIO()

def create_app():
    """Create Flask application"""
    app = Flask(__name__,
                template_folder='../frontend',
                static_folder='../frontend/assets')
    
    # Load configuration
    app.config.from_object(config)
    config.init_app(app)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    CORS(app, supports_credentials=True)
    socketio.init_app(app, cors_allowed_origins="*", async_mode='eventlet')
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(scans_bp, url_prefix='/api/scans')
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @login_manager.unauthorized_handler
    def unauthorized():
        return jsonify({
            'success': False,
            'error': 'Authentication required'
        }), 401
    
    # WebSocket events
    @socketio.on('connect')
    def handle_connect():
        if current_user.is_authenticated:
            emit('connected', {'message': 'Connected to scan server'})
    
    @socketio.on('scan_progress')
    def handle_scan_progress(data):
        # Broadcast scan progress to all connected clients
        emit('scan_update', data, broadcast=True)
    
    @socketio.on('notification')
    def handle_notification(data):
        # Send notification to specific user
        emit('new_notification', data, room=data.get('user_id'))
    
    # Frontend routes
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')
    
    @app.route('/login')
    def login_page():
        return render_template('login.html')
    
    @app.route('/register')
    def register_page():
        return render_template('register.html')
    
    @app.route('/scan/<int:scan_id>')
    def scan_details(scan_id):
        return render_template('results.html')
    
    # Static files
    @app.route('/assets/<path:filename>')
    def serve_static(filename):
        return send_from_directory('../frontend/assets', filename)
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'service': 'InSecLabs Dashboard',
            'version': '1.0.0'
        }), 200
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'Resource not found'
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            from werkzeug.security import generate_password_hash
            admin = User(
                username='admin',
                email='admin@inseclabs.com',
                password_hash=generate_password_hash('admin@123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created: admin / admin@123")
    
    # Start server
    print("Starting InSecLabs Dashboard...")
    print(f"Dashboard URL: https://server.inseclabs.com")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
