# config.py
import os
from dotenv import load_dotenv

# Get the base directory of the application
basedir = os.path.abspath(os.path.dirname(__file__))

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev')
    # Set SQLite as default if DATABASE_URL is not set
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app', 'nids.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ML_MODEL_PATH = os.getenv('ML_MODEL_PATH')
    PCAP_STORAGE_PATH = os.getenv('PCAP_STORAGE_PATH')
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    ITEMS_PER_PAGE = int(os.getenv('ITEMS_PER_PAGE', 20)) # Pagination setting
