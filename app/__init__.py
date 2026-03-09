import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

load_dotenv()

db = SQLAlchemy()

logger = logging.getLogger(__name__)


def create_app():
    app = Flask(__name__)

    # Load configuration
    secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')
    flask_env = os.environ.get('FLASK_ENV', 'development')
    if secret_key == 'dev-secret-key' and flask_env == 'production':
        logger.warning(
            "SECRET_KEY is using an insecure default in production! "
            "Set the SECRET_KEY environment variable to a strong random value."
        )
    app.config['SECRET_KEY'] = secret_key
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', 'postgresql://ninjascan:ninjascan_pass@localhost:5432/ninjascan_db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 52428800))
    app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Initialize extensions
    db.init_app(app)

    # Register blueprints
    from app.routes import main
    app.register_blueprint(main)

    # Create database tables
    with app.app_context():
        try:
            db.create_all()
        except Exception as e:
            app.logger.warning(f"Database initialization warning: {e}")

    return app
