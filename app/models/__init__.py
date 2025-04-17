# app/models/__init__.py
# Import models in order of dependency (tables without foreign keys first)

from app.models.user import User
from app.models.packet import Packet
from app.models.log import Log
from app.models.alert import Alert
from app.models.report import Report

# This ensures that models are registered with SQLAlchemy in the correct order
# to handle foreign key relationships properly