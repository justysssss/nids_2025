# app/core/__init__.py
from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
import os

# Initialize Flask extensions
socketio = SocketIO()
db = SQLAlchemy()
login_manager = LoginManager()

# Define user loader callback
@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)

    # Load configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-this')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///nids.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    socketio.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    with app.app_context():
        # Import all models to ensure they're registered with SQLAlchemy
        from app.models import User, Packet, Log, Alert, Report
        
        # Import parts of our application
        from app.routes import main, auth, dashboard, monitor, alerts, logs, reports
        from app.core.packet_capture import PacketCapture
        from app.core.packet_analyzer import PacketAnalyzer

        # Register blueprints
        app.register_blueprint(main.bp)  # Register the main blueprint for the root route
        app.register_blueprint(auth.bp)
        app.register_blueprint(dashboard.bp)
        app.register_blueprint(monitor.bp)
        app.register_blueprint(alerts.bp)
        app.register_blueprint(logs.bp)
        app.register_blueprint(reports.bp)

        # Initialize database
        db.create_all()

        # Initialize NIDS components
        app.packet_capture = PacketCapture()
        app.packet_analyzer = PacketAnalyzer()

        # Don't automatically start packet capture for now,
        # let the user start it manually to avoid issues during initialization
        # We'll provide instructions on how to start it

        return app
