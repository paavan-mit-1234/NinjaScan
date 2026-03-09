import os
import hashlib
import time
import json
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, request, jsonify,
    redirect, url_for, flash, current_app
)
from werkzeug.utils import secure_filename

from app import db
from app.models import ScanResult
from app.analyzers.yara_scanner import YaraScanner
from app.analyzers.pe_analyzer import PEAnalyzer
from app.analyzers.script_inspector import ScriptInspector
from app.analyzers.document_checker import DocumentChecker

main = Blueprint('main', __name__)

ALLOWED_EXTENSIONS = {
    'exe', 'dll',
    'doc', 'docx', 'pdf', 'xls', 'xlsx', 'ppt', 'pptx',
    'ps1', 'vbs', 'js', 'bat', 'cmd',
    'zip', 'rar',
    'txt'
}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_file_type(filepath):
    try:
        import magic
        mime = magic.from_file(filepath, mime=True)
        return mime
    except Exception:
        return 'application/octet-stream'


def compute_verdict(findings, yara_matches):
    total_findings = sum(len(v) for v in findings.values() if isinstance(v, list))
    yara_count = len(yara_matches)

    if yara_count >= 2:
        verdict = 'malicious'
        risk_level = 'critical'
    elif yara_count == 1:
        verdict = 'malicious'
        risk_level = 'high'
    elif total_findings >= 6:
        verdict = 'malicious'
        risk_level = 'high'
    elif total_findings >= 3:
        verdict = 'suspicious'
        risk_level = 'medium'
    elif total_findings >= 1:
        verdict = 'suspicious'
        risk_level = 'low'
    else:
        verdict = 'clean'
        risk_level = 'low'

    return verdict, risk_level


@main.route('/')
def index():
    recent_scans = ScanResult.query.order_by(
        ScanResult.scan_timestamp.desc()
    ).limit(5).all()
    return render_template('index.html', recent_scans=recent_scans)


@main.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else 'none'
        return jsonify({'error': f'File type .{ext} is not supported'}), 400

    filename = secure_filename(file.filename)
    upload_folder = current_app.config['UPLOAD_FOLDER']
    filepath = os.path.join(upload_folder, filename)

    try:
        file.save(filepath)
        start_time = time.time()

        file_hash = get_file_hash(filepath)
        file_size = os.path.getsize(filepath)
        file_type = get_file_type(filepath)
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

        findings = {}
        yara_matches = []

        # YARA scanning
        try:
            scanner = YaraScanner()
            yara_matches = scanner.scan(filepath)
        except Exception as e:
            current_app.logger.error(f"YARA scan error: {e}")

        # PE analysis
        if ext in ('exe', 'dll'):
            try:
                pe_analyzer = PEAnalyzer()
                pe_findings = pe_analyzer.analyze(filepath)
                if pe_findings:
                    findings['pe_analysis'] = pe_findings
            except Exception as e:
                current_app.logger.error(f"PE analysis error: {e}")

        # Script inspection
        if ext in ('ps1', 'vbs', 'js', 'bat', 'cmd'):
            try:
                inspector = ScriptInspector()
                script_findings = inspector.inspect(filepath, ext)
                if script_findings:
                    findings['script_analysis'] = script_findings
            except Exception as e:
                current_app.logger.error(f"Script inspection error: {e}")

        # Document checking
        if ext in ('pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'):
            try:
                checker = DocumentChecker()
                doc_findings = checker.check(filepath, ext)
                if doc_findings:
                    findings['document_analysis'] = doc_findings
            except Exception as e:
                current_app.logger.error(f"Document check error: {e}")

        # Archive inspection (basic)
        if ext in ('zip', 'rar'):
            try:
                archive_findings = inspect_archive(filepath, ext)
                if archive_findings:
                    findings['archive_analysis'] = archive_findings
            except Exception as e:
                current_app.logger.error(f"Archive inspection error: {e}")

        duration = time.time() - start_time
        verdict, risk_level = compute_verdict(findings, yara_matches)

        scan = ScanResult(
            filename=filename,
            file_hash=file_hash,
            file_size=file_size,
            file_type=file_type,
            scan_timestamp=datetime.now(timezone.utc),
            verdict=verdict,
            risk_level=risk_level,
            findings=findings,
            yara_matches=yara_matches,
            analysis_duration=round(duration, 3)
        )
        db.session.add(scan)
        db.session.commit()

        return jsonify({'scan_id': scan.id, 'redirect': url_for('main.results', scan_id=scan.id)})

    except Exception as e:
        current_app.logger.error(f"Upload error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        if os.path.exists(filepath):
            _secure_delete(filepath)


def _secure_delete(filepath):
    """Overwrite file contents before deletion for extra security with malicious files."""
    try:
        size = os.path.getsize(filepath)
        with open(filepath, 'r+b') as f:
            f.write(b'\x00' * size)
    except Exception:
        pass
    finally:
        try:
            os.remove(filepath)
        except Exception:
            pass
    findings = []
    try:
        if ext == 'zip':
            import zipfile
            with zipfile.ZipFile(filepath, 'r') as z:
                names = z.namelist()
                suspicious_exts = {'.exe', '.dll', '.ps1', '.vbs', '.bat', '.cmd', '.scr'}
                for name in names:
                    name_lower = name.lower()
                    for s_ext in suspicious_exts:
                        if name_lower.endswith(s_ext):
                            findings.append(f"Suspicious file in archive: {name}")
                            break
    except Exception as e:
        findings.append(f"Archive read error: {e}")
    return findings


@main.route('/results/<int:scan_id>')
def results(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return render_template('results.html', scan=scan)


@main.route('/history')
def history():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    verdict_filter = request.args.get('verdict', '')
    per_page = 20

    query = ScanResult.query

    if search:
        query = query.filter(ScanResult.filename.ilike(f'%{search}%'))
    if verdict_filter:
        query = query.filter(ScanResult.verdict == verdict_filter)

    pagination = query.order_by(ScanResult.scan_timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('history.html', pagination=pagination, search=search,
                           verdict_filter=verdict_filter)


@main.route('/api/scan/<int:scan_id>')
def api_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


@main.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 50MB.'}), 413


@main.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404
