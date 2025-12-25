# -*- coding: utf-8 -*-
"""
Database models for Web-ScannerWeb Interface - SQLAlchemy
"""

import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Float

# Initialize SQLAlchemy
db = SQLAlchemy()

class Scan(db.Model):
    """Scan model for storing scan history"""
    __tablename__ = 'scans'
    
    id = Column(String(100), primary_key=True)  # scan_id
    url = Column(String(500), nullable=False)
    status = Column(String(50), nullable=False)
    progress = Column(Float, default=0.0)
    results_count = Column(Integer, default=0)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    config = Column(JSON, nullable=True)
    error = Column(Text, nullable=True)
    debug_info = Column(JSON, nullable=True)
    
    # Relationships
    results = db.relationship('ScanResult', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.id,
            'url': self.url,
            'status': self.status,
            'progress': self.progress,
            'results_count': self.results_count,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'config': self.config,
            'error': self.error,
            'debug_info': self.debug_info
        }

class ScanResult(db.Model):
    """Scan results model for storing found paths"""
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(100), db.ForeignKey('scans.id'), nullable=False)
    path = Column(String(1000), nullable=False)
    status = Column(Integer, nullable=False)
    size = Column(Integer, nullable=True)
    url = Column(String(1000), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    response_time = Column(Float, nullable=True)
    content_type = Column(String(200), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'path': self.path,
            'status': self.status,
            'size': self.size,
            'url': self.url,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'response_time': self.response_time,
            'content_type': self.content_type
        }

class Wordlist(db.Model):
    """Wordlist model for storing available wordlists"""
    __tablename__ = 'wordlists'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    path = Column(String(500), nullable=False, unique=True)
    size = Column(Integer, nullable=False)
    entries_count = Column(Integer, nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'path': self.path,
            'size': self.size,
            'entries_count': self.entries_count,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None
        }

def init_database(app):
    """Initialize database with app"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Load wordlists from db folder
        load_wordlists()

def load_wordlists():
    """Load all wordlists from the db folder"""
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'Web-Scanner', 'db')
    
    if not os.path.exists(db_path):
        print(f"Warning: db directory not found at {db_path}")
        return
    
    # Clear existing wordlists
    Wordlist.query.delete()
    
    # Find all .txt files in db folder (recursive)
    for root, _, files in os.walk(db_path):
        for filename in files:
            if not filename.lower().endswith('.txt'):
                continue

            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, db_path)
            # Store paths relative to Web-Scanner root, using forward slashes for consistency
            stored_path = os.path.join('db', rel_path).replace('\\', '/')
            
            try:
                # Get file size
                file_size = os.path.getsize(file_path)
                
                # Count entries (lines)
                entries_count = 0
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        entries_count = sum(1 for _ in f)
                except Exception:
                    entries_count = None
                
                display_name = os.path.splitext(rel_path)[0].replace('\\', '/').replace('_', ' ')

                # Create wordlist entry
                wordlist = Wordlist(
                    name=display_name,
                    path=stored_path,
                    size=file_size,
                    entries_count=entries_count,
                    description=f"Wordlist from {stored_path}"
                )
                
                db.session.add(wordlist)
                print(f"Loaded wordlist: {stored_path} ({entries_count} entries)")
                
            except Exception as e:
                print(f"Error loading wordlist {stored_path}: {e}")
    
    # Commit changes
    try:
        db.session.commit()
        print(f"Successfully loaded {Wordlist.query.count()} wordlists")
    except Exception as e:
        db.session.rollback()
        print(f"Error saving wordlists to database: {e}")

def save_scan_to_database(scanner):
    """Save scan results to database"""
    try:
        # Create scan record
        scan = Scan(
            id=scanner.scan_id,
            url=scanner.config.get('url', ''),
            status=scanner.status,
            progress=scanner.progress,
            results_count=len(scanner.results),
            start_time=scanner.start_time,
            end_time=scanner.end_time,
            config=scanner.config,
            error=scanner.error,
            debug_info=scanner.debug_info
        )
        
        db.session.add(scan)
        
        # Save results
        for result in scanner.results:
            scan_result = ScanResult(
                scan_id=scanner.scan_id,
                path=result.get('path', ''),
                status=result.get('status', 0),
                size=result.get('size', 0),
                url=result.get('url', ''),
                timestamp=datetime.fromisoformat(result.get('timestamp', datetime.utcnow().isoformat())),
                response_time=result.get('response_time'),
                content_type=result.get('content_type')
            )
            db.session.add(scan_result)
        
        db.session.commit()
        print(f"Successfully saved scan {scanner.scan_id} to database")
        
    except Exception as e:
        db.session.rollback()
        print(f"Error saving scan to database: {e}")

def get_scan_history(limit=50):
    """Get scan history from database"""
    try:
        scans = Scan.query.order_by(Scan.start_time.desc()).limit(limit).all()
        return [scan.to_dict() for scan in scans]
    except Exception as e:
        print(f"Error getting scan history: {e}")
        return []

def get_scan_results_from_db(scan_id):
    """Get scan results from database"""
    try:
        scan = Scan.query.get(scan_id)
        if not scan:
            return None
            
        results = ScanResult.query.filter_by(scan_id=scan_id).all()
        return {
            'scan': scan.to_dict(),
            'results': [result.to_dict() for result in results]
        }
    except Exception as e:
        print(f"Error getting scan results from database: {e}")
        return None

def get_wordlists():
    """Get all wordlists from database"""
    try:
        wordlists = Wordlist.query.order_by(Wordlist.name).all()
        return [wordlist.to_dict() for wordlist in wordlists]
    except Exception as e:
        print(f"Error getting wordlists: {e}")
        return []
