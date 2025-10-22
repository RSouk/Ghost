from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# Create database in the data folder
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'ghost.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

engine = create_engine(f'sqlite:///{DB_PATH}', echo=False)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class Profile(Base):
    __tablename__ = 'profiles'
    
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String)
    username = Column(String)
    phone = Column(String)
    notes = Column(Text)
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # OSINT data fields
    breach_count = Column(Integer, default=0)
    social_media_json = Column(Text)  # Store as JSON string
    exposed_passwords = Column(Text)
    data_leaks = Column(Text)

class SocialMedia(Base):
    __tablename__ = 'social_media'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String, nullable=False)
    platform = Column(String)
    username = Column(String)
    url = Column(String)
    followers = Column(Integer)
    posts_count = Column(Integer)
    discovered_at = Column(DateTime, default=datetime.utcnow)

class Breach(Base):
    __tablename__ = 'breaches'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String, nullable=False)
    breach_name = Column(String)
    breach_date = Column(String)
    data_classes = Column(Text)  # What data was leaked
    discovered_at = Column(DateTime, default=datetime.utcnow)

class Device(Base):
    __tablename__ = 'devices'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(String)
    ip_address = Column(String)
    hostname = Column(String)
    device_type = Column(String)
    ports_open = Column(Text)
    vulnerabilities = Column(Text)
    location = Column(String)
    discovered_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    """Initialize the database and create all tables"""
    Base.metadata.create_all(engine)
    print(f"Database initialized at: {DB_PATH}")

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        return db
    finally:
        pass

# Initialize database on import
init_db()