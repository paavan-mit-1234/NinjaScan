import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 'postgresql://ninjascan:ninjascan_pass@localhost:5432/ninjascan_db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 52428800))  # 50MB
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    ALLOWED_EXTENSIONS = {
        'exe', 'dll',
        'doc', 'docx', 'pdf', 'xls', 'xlsx', 'ppt', 'pptx',
        'ps1', 'vbs', 'js', 'bat', 'cmd',
        'zip', 'rar',
        'txt'
    }


class DevelopmentConfig(Config):
    DEBUG = True
    FLASK_ENV = 'development'


class ProductionConfig(Config):
    DEBUG = False
    FLASK_ENV = 'production'


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
