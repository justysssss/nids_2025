from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
import threading

# Initialize Flask extensions
db = SQLAlchemy()
login_manager = LoginManager()
# Initialize SocketIO with CORS enabled and engineio logging for debugging
socketio = SocketIO(cors_allowed_origins="*", logger=True, engineio_logger=True)

# Configure LoginManager
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(int(user_id))

def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('config.Config')
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    
    with app.app_context():
        # Import all models to ensure they're registered with SQLAlchemy
        from app.models import User, Packet, Log, Alert, Report
        
        # Import parts of our application
        from app.routes import main, auth, dashboard, monitor, logs, alerts, reports
        from app.core.packet_capture import PacketCapture
        from app.core.packet_analyzer import PacketAnalyzer
        
        # Register blueprints
        app.register_blueprint(main.bp)  # Register the main blueprint for the root route
        app.register_blueprint(auth.bp)
        app.register_blueprint(dashboard.bp)
        app.register_blueprint(monitor.bp)
        app.register_blueprint(logs.bp)
        app.register_blueprint(alerts.bp)
        app.register_blueprint(reports.bp)
        
        # Create database tables
        db.create_all()

        # Initialize NIDS components
        # Pass the initialized socketio instance to PacketCapture
        app.packet_capture = PacketCapture(socketio_instance=socketio)
        app.packet_analyzer = PacketAnalyzer()

        # Start packet capture in a background thread
        capture_thread = threading.Thread(target=app.packet_capture.start_capture, daemon=True)
        capture_thread.start()
        print("Packet capture thread started.")

        return app
