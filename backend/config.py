import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'inseclabs-secret-key-2024')
    
    # Database
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', 'root@123')
    DB_NAME = os.getenv('DB_NAME', 'inseclabs_db')
    SQLALCHEMY_DATABASE_URI = f'mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Cloudflare
    CLOUDFLARE_ACCOUNT_ID = os.getenv('CLOUDFLARE_ACCOUNT_ID')
    CLOUDFLARE_TUNNEL_ID = os.getenv('CLOUDFLARE_TUNNEL_ID')
    CLOUDFLARE_TUNNEL_TOKEN = os.getenv('CLOUDFLARE_TUNNEL_TOKEN')
    
    # SMTP
    SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USER = os.getenv('SMTP_USER')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    NOTIFICATION_EMAIL = os.getenv('NOTIFICATION_EMAIL')
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
    SCANS_DIR = os.path.join(OUTPUT_DIR, 'scans')
    SCREENSHOTS_DIR = os.path.join(OUTPUT_DIR, 'screenshots')
    REPORTS_DIR = os.path.join(OUTPUT_DIR, 'reports')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    
    # Celery
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    
    # Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    
    # Tool Configurations
    TOOL_TIMEOUT = 300  # 5 minutes
    MAX_CONCURRENT_SCANS = 3
    
    @staticmethod
    def init_app(app):
        # Create directories if they don't exist
        os.makedirs(Config.SCANS_DIR, exist_ok=True)
        os.makedirs(Config.SCREENSHOTS_DIR, exist_ok=True)
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        os.makedirs(Config.LOGS_DIR, exist_ok=True)

config = Config()
