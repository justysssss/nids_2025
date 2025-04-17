# init_db.py - Database initialization script
from app import create_app, db

def init_db():
    """Initialize the database by creating all tables."""
    print("Initializing the database...")
    app = create_app()
    with app.app_context():
        # Import models to ensure they're registered with SQLAlchemy
        from app.models.user import User
        from app.models.packet import Packet
        from app.models.log import Log
        from app.models.alert import Alert
        from app.models.report import Report
        
        # Drop all tables first to ensure a clean slate (optional)
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        print("Database initialization complete!")

if __name__ == "__main__":
    init_db()