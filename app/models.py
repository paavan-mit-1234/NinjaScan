from datetime import datetime, timezone
from app import db


class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    file_type = db.Column(db.String(100))
    scan_timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    verdict = db.Column(db.String(20), nullable=False)  # clean, suspicious, malicious
    risk_level = db.Column(db.String(20), nullable=False)  # low, medium, high, critical
    findings = db.Column(db.JSON, default=dict)
    yara_matches = db.Column(db.JSON, default=list)
    analysis_duration = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'scan_timestamp': self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            'verdict': self.verdict,
            'risk_level': self.risk_level,
            'findings': self.findings,
            'yara_matches': self.yara_matches,
            'analysis_duration': self.analysis_duration
        }
