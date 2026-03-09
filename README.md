# 🥷 NinjaScan — Static File Analysis Platform

NinjaScan is a Flask-based static analysis platform for inspecting suspicious files **without executing them**. It combines YARA rules, PE import analysis, document checks, and script inspection to produce a verdict, risk level, and historical scan record.

> **Files are never executed. Only static inspection is performed.**

## Features

- 🧬 **30+ YARA Rules** covering ransomware, trojans, backdoors, cryptominers, spyware, worms, rootkits, fileless malware, and anti-analysis behavior
- 🔍 **PE Analysis** with 85+ suspicious API import checks, section entropy, packer detection
- 📜 **Script Inspection** for PowerShell, VBScript, JavaScript, Batch, CMD
- 📄 **Document Checks** for PDFs and Office files (macros, OLE, DDE)
- 🗄️ **Scan History** persisted in PostgreSQL
- 🎨 **Responsive Bootstrap 5 UI** with drag-and-drop upload
- 🐳 **Docker Compose** deployment

## Quick Start (Docker)

```bash
git clone https://github.com/paavan-mit-1234/NinjaScan.git
cd NinjaScan
cp .env.example .env
docker compose up --build
# Open http://localhost:5000
```

## Supported File Types

| Category | Extensions |
|---|---|
| Executables | .exe, .dll |
| Documents | .doc, .docx, .pdf, .xls, .xlsx, .ppt, .pptx |
| Scripts | .ps1, .vbs, .js, .bat, .cmd |
| Archives | .zip, .rar |
| Text | .txt |

## Verdict Logic

- **Clean**: No suspicious indicators
- **Suspicious**: Minor indicators (few flagged imports, no YARA matches)
- **Malicious**: Strong indicators (YARA matches, multiple patterns)

## Tech Stack

- **Backend**: Python 3.11, Flask 3, SQLAlchemy
- **Database**: PostgreSQL 15
- **Detection**: yara-python, pefile, python-magic, oletools
- **Frontend**: Bootstrap 5.3, Bootstrap Icons, Vanilla JS
- **Deployment**: Docker Compose, Gunicorn

## Security

- Files are analyzed **statically only** — never executed
- Uploaded files are deleted immediately after analysis
- Secure filename handling (path traversal prevention)

## License

MIT License
