from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)

    # Register blueprints
    from app.routes import main, auth, monitor, alerts, logs
    app.register_blueprint(main.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(monitor.bp)
    app.register_blueprint(alerts.bp)
    app.register_blueprint(logs.bp)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app