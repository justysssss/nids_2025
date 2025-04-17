# run.py
from app import create_app, socketio
import os

app = create_app()

if __name__ == "__main__":
    host = os.getenv('HOST', '127.0.0.1')
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV', 'development') == 'development'
    socketio.run(app, host=host, port=port, debug=debug)
