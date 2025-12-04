"""
Database module for OverApi
Provides SQLAlchemy models and session management for scan history.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional, List
import json

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import logging


logger = logging.getLogger(__name__)

Base = declarative_base()


class ScanHistory(Base):
    """Model for scan history."""

    __tablename__ = 'scan_history'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(100), unique=True, nullable=False, index=True)
    target_url = Column(String(500), nullable=False, index=True)
    api_type = Column(String(50))
    scan_mode = Column(String(20))
    start_time = Column(DateTime, nullable=False, index=True)
    end_time = Column(DateTime)
    duration_seconds = Column(Float)
    status = Column(String(20), default='running')  # running, completed, failed, interrupted
    threads = Column(Integer)
    timeout = Column(Integer)

    # Results summary
    total_endpoints = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)

    # Configuration
    config_json = Column(Text)  # Serialized configuration

    # Reports
    report_html_path = Column(String(500))
    report_json_path = Column(String(500))
    report_pdf_path = Column(String(500))
    report_csv_path = Column(String(500))

    # Metadata
    user = Column(String(100))
    notes = Column(Text)
    tags = Column(String(500))  # Comma-separated tags

    # Relationships
    vulnerabilities = relationship('Vulnerability', back_populates='scan', cascade='all, delete-orphan')

    def __repr__(self):
        return f"<ScanHistory(id={self.id}, target={self.target_url}, status={self.status})>"

    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'api_type': self.api_type,
            'scan_mode': self.scan_mode,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'status': self.status,
            'total_endpoints': self.total_endpoints,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'info_count': self.info_count,
            'user': self.user,
            'tags': self.tags.split(',') if self.tags else []
        }


class Vulnerability(Base):
    """Model for discovered vulnerabilities."""

    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(100), ForeignKey('scan_history.scan_id'), nullable=False, index=True)
    vuln_id = Column(String(100), unique=True, nullable=False)

    # Vulnerability details
    vuln_type = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    endpoint = Column(String(500), nullable=False)
    method = Column(String(10))
    parameter = Column(String(200))

    # Description
    description = Column(Text)
    evidence = Column(Text)
    remediation = Column(Text)

    # Classification
    cwe_id = Column(String(20))
    owasp_category = Column(String(100))
    cvss_score = Column(Float)

    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)

    # Relationship
    scan = relationship('ScanHistory', back_populates='vulnerabilities')

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type={self.vuln_type}, severity={self.severity})>"

    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'vuln_id': self.vuln_id,
            'scan_id': self.scan_id,
            'type': self.vuln_type,
            'severity': self.severity,
            'endpoint': self.endpoint,
            'method': self.method,
            'parameter': self.parameter,
            'description': self.description,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'cvss_score': self.cvss_score,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None,
            'verified': self.verified,
            'false_positive': self.false_positive
        }


class DatabaseManager:
    """
    Database manager for OverApi.

    Handles database connections, session management, and CRUD operations.
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database manager.

        Args:
            db_path: Path to SQLite database file (default: ~/.overapi/scans.db)
        """
        if db_path is None:
            # Default to user's home directory
            db_dir = Path.home() / '.overapi'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'scans.db')

        self.db_path = db_path
        self.engine = create_engine(f'sqlite:///{db_path}', echo=False)
        self.SessionLocal = sessionmaker(bind=self.engine)

        # Create tables if they don't exist
        Base.metadata.create_all(self.engine)
        logger.info(f"Database initialized at {db_path}")

    def get_session(self) -> Session:
        """Get a new database session."""
        return self.SessionLocal()

    def create_scan(self, scan_id: str, target_url: str, config: dict) -> ScanHistory:
        """
        Create a new scan record.

        Args:
            scan_id: Unique scan identifier
            target_url: Target API URL
            config: Scan configuration dictionary

        Returns:
            Created ScanHistory object
        """
        session = self.get_session()
        try:
            scan = ScanHistory(
                scan_id=scan_id,
                target_url=target_url,
                api_type=config.get('api_type'),
                scan_mode=config.get('mode'),
                start_time=datetime.utcnow(),
                status='running',
                threads=config.get('threads', 10),
                timeout=config.get('timeout', 30),
                config_json=json.dumps(config),
                user=config.get('user', 'unknown')
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            logger.info(f"Created scan record: {scan_id}")
            return scan
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating scan: {e}")
            raise
        finally:
            session.close()

    def update_scan(self, scan_id: str, **kwargs):
        """
        Update scan record.

        Args:
            scan_id: Scan identifier
            **kwargs: Fields to update
        """
        session = self.get_session()
        try:
            scan = session.query(ScanHistory).filter_by(scan_id=scan_id).first()
            if scan:
                for key, value in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, value)
                session.commit()
                logger.debug(f"Updated scan {scan_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error updating scan: {e}")
            raise
        finally:
            session.close()

    def complete_scan(self, scan_id: str, results: dict):
        """
        Mark scan as completed and update results.

        Args:
            scan_id: Scan identifier
            results: Scan results dictionary
        """
        session = self.get_session()
        try:
            scan = session.query(ScanHistory).filter_by(scan_id=scan_id).first()
            if scan:
                scan.end_time = datetime.utcnow()
                scan.status = 'completed'

                if scan.start_time:
                    scan.duration_seconds = (scan.end_time - scan.start_time).total_seconds()

                # Update vulnerability counts
                scan.total_vulnerabilities = results.get('total_vulnerabilities', 0)
                scan.critical_count = results.get('critical_count', 0)
                scan.high_count = results.get('high_count', 0)
                scan.medium_count = results.get('medium_count', 0)
                scan.low_count = results.get('low_count', 0)
                scan.info_count = results.get('info_count', 0)

                scan.total_endpoints = results.get('total_endpoints', 0)

                session.commit()
                logger.info(f"Completed scan {scan_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error completing scan: {e}")
            raise
        finally:
            session.close()

    def fail_scan(self, scan_id: str, error: str):
        """
        Mark scan as failed.

        Args:
            scan_id: Scan identifier
            error: Error message
        """
        session = self.get_session()
        try:
            scan = session.query(ScanHistory).filter_by(scan_id=scan_id).first()
            if scan:
                scan.end_time = datetime.utcnow()
                scan.status = 'failed'
                scan.notes = f"Error: {error}"

                if scan.start_time:
                    scan.duration_seconds = (scan.end_time - scan.start_time).total_seconds()

                session.commit()
                logger.warning(f"Failed scan {scan_id}: {error}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error failing scan: {e}")
        finally:
            session.close()

    def add_vulnerability(self, scan_id: str, vuln_data: dict) -> Vulnerability:
        """
        Add vulnerability to scan.

        Args:
            scan_id: Scan identifier
            vuln_data: Vulnerability data dictionary

        Returns:
            Created Vulnerability object
        """
        session = self.get_session()
        try:
            vuln = Vulnerability(
                scan_id=scan_id,
                vuln_id=vuln_data.get('vuln_id', f"{scan_id}_{datetime.utcnow().timestamp()}"),
                vuln_type=vuln_data.get('type'),
                severity=vuln_data.get('severity'),
                endpoint=vuln_data.get('endpoint'),
                method=vuln_data.get('method'),
                parameter=vuln_data.get('parameter'),
                description=vuln_data.get('description'),
                evidence=vuln_data.get('evidence'),
                remediation=vuln_data.get('remediation'),
                cwe_id=vuln_data.get('cwe_id'),
                owasp_category=vuln_data.get('owasp_category'),
                cvss_score=vuln_data.get('cvss_score')
            )
            session.add(vuln)
            session.commit()
            session.refresh(vuln)
            return vuln
        except Exception as e:
            session.rollback()
            logger.error(f"Error adding vulnerability: {e}")
            raise
        finally:
            session.close()

    def get_scan(self, scan_id: str) -> Optional[ScanHistory]:
        """
        Get scan by ID.

        Args:
            scan_id: Scan identifier

        Returns:
            ScanHistory object or None
        """
        session = self.get_session()
        try:
            return session.query(ScanHistory).filter_by(scan_id=scan_id).first()
        finally:
            session.close()

    def get_recent_scans(self, limit: int = 10) -> List[ScanHistory]:
        """
        Get recent scans.

        Args:
            limit: Maximum number of scans to return

        Returns:
            List of ScanHistory objects
        """
        session = self.get_session()
        try:
            return session.query(ScanHistory)\
                .order_by(ScanHistory.start_time.desc())\
                .limit(limit)\
                .all()
        finally:
            session.close()

    def get_scans_by_target(self, target_url: str) -> List[ScanHistory]:
        """
        Get all scans for a specific target.

        Args:
            target_url: Target URL

        Returns:
            List of ScanHistory objects
        """
        session = self.get_session()
        try:
            return session.query(ScanHistory)\
                .filter_by(target_url=target_url)\
                .order_by(ScanHistory.start_time.desc())\
                .all()
        finally:
            session.close()

    def delete_scan(self, scan_id: str):
        """
        Delete scan and all associated vulnerabilities.

        Args:
            scan_id: Scan identifier
        """
        session = self.get_session()
        try:
            scan = session.query(ScanHistory).filter_by(scan_id=scan_id).first()
            if scan:
                session.delete(scan)
                session.commit()
                logger.info(f"Deleted scan {scan_id}")
        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting scan: {e}")
            raise
        finally:
            session.close()

    def get_statistics(self) -> dict:
        """
        Get database statistics.

        Returns:
            Statistics dictionary
        """
        session = self.get_session()
        try:
            total_scans = session.query(ScanHistory).count()
            total_vulns = session.query(Vulnerability).count()

            # Count by status
            completed = session.query(ScanHistory).filter_by(status='completed').count()
            failed = session.query(ScanHistory).filter_by(status='failed').count()
            running = session.query(ScanHistory).filter_by(status='running').count()

            # Count by severity
            critical = session.query(Vulnerability).filter_by(severity='CRITICAL').count()
            high = session.query(Vulnerability).filter_by(severity='HIGH').count()
            medium = session.query(Vulnerability).filter_by(severity='MEDIUM').count()
            low = session.query(Vulnerability).filter_by(severity='LOW').count()

            return {
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulns,
                'scans_completed': completed,
                'scans_failed': failed,
                'scans_running': running,
                'vulnerabilities_critical': critical,
                'vulnerabilities_high': high,
                'vulnerabilities_medium': medium,
                'vulnerabilities_low': low
            }
        finally:
            session.close()
