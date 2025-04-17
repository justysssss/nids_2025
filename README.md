# NIDS 2025 - Network Intrusion Detection System

A modern network intrusion detection system with real-time monitoring, machine learning-based analysis, and honeypot capabilities.

## Features

- **Real-time Network Monitoring**: Capture and analyze network packets in real-time
- **Machine Learning Detection**: Identify potential threats using trained ML models
- **Interactive Dashboard**: Visualize network traffic patterns and security incidents
- **Honeypot Integration**: Detect and analyze attack patterns with configurable honeypots
- **Alert System**: Receive notifications for suspicious activities
- **Detailed Reporting**: Generate comprehensive security reports

## Requirements

- Python 3.9+
- Flask and Flask extensions
- SQLite (default) or PostgreSQL
- Scapy for packet capture
- Machine Learning libraries (scikit-learn, numpy)
- Socket.IO for real-time communication

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/nids_2025.git
cd nids_2025
```

2. Create and activate a virtual environment:

```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Initialize the database:

```bash
python init_db.py
```

## Configuration

Create an `instance/config.py` file with your configuration:

```python
SECRET_KEY = 'your-secret-key'
SQLALCHEMY_DATABASE_URI = 'sqlite:///nids.db'
INTERFACE = 'Wi-Fi'  # Network interface to monitor
DEBUG = True
```

You can also use environment variables to configure the application.

## Running the Application

1. Start the application:

```bash
python run.py
```

2. By default, the application will run on http://127.0.0.1:5000

3. Log in with the default admin credentials:
   - Username: admin
   - Password: admin123

**Note:** Change the default admin password immediately after first login!

## Running with Different Network Interfaces

The application will capture packets from the network interface specified in your configuration or environment variables. To use a specific network interface:

```bash
# On Windows
set INTERFACE=Ethernet
python run.py

# On macOS/Linux
export INTERFACE=eth0
python run.py
```

## Development Environment

The application uses Socket.IO for real-time updates. To run in development mode with hot reloading:

```bash
set FLASK_ENV=development  # Windows
export FLASK_ENV=development  # macOS/Linux
python run.py
```

## Troubleshooting

### Socket.IO Connection Issues

If you experience disconnections or packets not appearing in the UI:
- Ensure your browser supports WebSockets
- Check that no firewall or security software is blocking connections
- Try running the application with a different port if 5000 is already in use:
  ```
  set PORT=5001  # Windows
  export PORT=5001  # macOS/Linux
  python run.py
  ```

### Packet Capture Issues

- Ensure you're running the application with administrator/root privileges for packet capture
- Verify the network interface name is correct for your system
- On Windows, check that WinPcap or Npcap is installed for Scapy to work properly

## License

[MIT License](LICENSE)

## Acknowledgments

- Flask framework
- Scapy packet manipulation library
- scikit-learn for machine learning capabilities