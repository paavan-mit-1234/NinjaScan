import re


# Suspicious PDF keywords
PDF_SUSPICIOUS_KEYWORDS = [
    '/JavaScript', '/JS', '/Launch', '/EmbeddedFile',
    '/URI', '/OpenAction', '/AA', '/AcroForm',
    '/XFA', '/RichMedia', '/ObjStm',
]

PDF_SCRIPT_PATTERNS = [
    (r'\beval\b', 'eval() in PDF JavaScript'),
    (r'\bunescape\b', 'unescape() obfuscation'),
    (r'String\.fromCharCode', 'String.fromCharCode obfuscation'),
    (r'app\.launchURL', 'launchURL action'),
    (r'this\.exportDataObject', 'exportDataObject call'),
    (r'util\.printf', 'util.printf heap spray pattern'),
    (r'app\.openDoc', 'openDoc call'),
]

# Suspicious Office/macro patterns
MACRO_AUTO_EXEC = [
    'AutoOpen', 'Document_Open', 'Workbook_Open',
    'Auto_Open', 'AutoClose', 'Document_Close',
    'Workbook_Close', 'Auto_Close', 'AutoExec',
]

MACRO_SUSPICIOUS_PATTERNS = [
    (r'Shell\b', 'Shell execution in macro'),
    (r'CreateObject\s*\(', 'CreateObject in macro'),
    (r'WScript\.Shell', 'WScript.Shell reference'),
    (r'PowerShell\b', 'PowerShell invocation in macro'),
    (r'cmd\.exe', 'cmd.exe reference'),
    (r'Environ\s*\(', 'Environment variable access'),
    (r'GetObject\s*\(\s*"winmgmts', 'WMI access in macro'),
    (r'ADODB\.Stream', 'Binary stream write'),
    (r'URLDownloadToFile', 'File download API'),
    (r'Chr\s*\(\s*\d+\s*\)', 'Character obfuscation'),
    (r'StrReverse\s*\(', 'String reversal obfuscation'),
    (r'http[s]?://', 'HTTP URL in macro'),
    (r'Base64\b', 'Base64 reference'),
    (r'Hex\b', 'Hex encoding reference'),
    (r'VirtualAlloc\b', 'Memory allocation API in macro'),
    (r'RtlMoveMemory\b', 'Memory copy API in macro'),
]


class DocumentChecker:
    def check(self, filepath, ext):
        ext = ext.lower()
        if ext == 'pdf':
            return self._check_pdf(filepath)
        elif ext in ('doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'):
            return self._check_office(filepath, ext)
        return []

    def _check_pdf(self, filepath):
        findings = []
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            text = content.decode('latin-1', errors='replace')

            # Check for suspicious PDF keywords
            for keyword in PDF_SUSPICIOUS_KEYWORDS:
                count = text.count(keyword)
                if count > 0:
                    severity = 'high' if keyword in ('/JavaScript', '/JS', '/Launch', '/OpenAction') else 'medium'
                    findings.append({
                        'category': 'pdf_feature',
                        'detail': f"Suspicious PDF feature: {keyword} (found {count} times)",
                        'severity': severity
                    })

            # Check for JavaScript patterns in PDF
            for pattern, description in PDF_SCRIPT_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append({
                        'category': 'pdf_script',
                        'detail': f"Suspicious PDF JavaScript pattern: {description}",
                        'severity': 'high'
                    })

            # Check for embedded files
            if '/EmbeddedFile' in text or '/Filespec' in text.lower():
                findings.append({
                    'category': 'pdf_embedded',
                    'detail': 'PDF contains embedded files',
                    'severity': 'medium'
                })

        except Exception as e:
            findings.append({'category': 'error', 'detail': f'PDF analysis error: {str(e)}'})
        return findings

    def _check_office(self, filepath, ext):
        findings = []

        # Try oletools for macro detection
        try:
            from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
            vba_parser = VBA_Parser(filepath)
            if vba_parser.detect_vba_macros():
                findings.append({
                    'category': 'macro_detected',
                    'detail': 'VBA macros detected in document',
                    'severity': 'high'
                })

                # Analyze macro code
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    if vba_code:
                        # Check for auto-execute macros
                        for auto_func in MACRO_AUTO_EXEC:
                            if re.search(r'\b' + auto_func + r'\b', vba_code, re.IGNORECASE):
                                findings.append({
                                    'category': 'auto_execute_macro',
                                    'detail': f'Auto-execute macro found: {auto_func}',
                                    'severity': 'critical'
                                })

                        # Check for suspicious patterns
                        for pattern, description in MACRO_SUSPICIOUS_PATTERNS:
                            if re.search(pattern, vba_code, re.IGNORECASE):
                                findings.append({
                                    'category': 'suspicious_macro_code',
                                    'detail': f'Suspicious macro pattern: {description}',
                                    'severity': 'high'
                                })
            vba_parser.close()
        except ImportError:
            findings.append({'category': 'note', 'detail': 'oletools not available for macro analysis'})
        except Exception as e:
            findings.append({'category': 'error', 'detail': f'Macro analysis error: {str(e)}'})

        # Check for OLE objects in older formats
        if ext in ('doc', 'xls', 'ppt'):
            try:
                import olefile
                if olefile.isOleFile(filepath):
                    ole = olefile.OleFileIO(filepath)
                    streams = ole.listdir()
                    for stream in streams:
                        stream_name = '/'.join(stream).lower()
                        if 'package' in stream_name or 'ole' in stream_name:
                            findings.append({
                                'category': 'embedded_ole',
                                'detail': f'Embedded OLE object detected: {"/".join(stream)}',
                                'severity': 'medium'
                            })
                    ole.close()
            except ImportError:
                pass
            except Exception as e:
                findings.append({'category': 'error', 'detail': f'OLE analysis error: {str(e)}'})

        # Check for DDE fields in docx/xlsx
        if ext in ('docx', 'xlsx', 'pptx'):
            try:
                import zipfile
                with zipfile.ZipFile(filepath, 'r') as z:
                    for name in z.namelist():
                        if name.endswith('.xml') or name.endswith('.rels'):
                            try:
                                xml_content = z.read(name).decode('utf-8', errors='replace')
                                if 'DDE' in xml_content or 'dde' in xml_content.lower():
                                    findings.append({
                                        'category': 'dde_field',
                                        'detail': f'DDE field found in {name}',
                                        'severity': 'high'
                                    })
                                if 'externalLink' in xml_content.lower():
                                    findings.append({
                                        'category': 'external_link',
                                        'detail': f'External link reference in {name}',
                                        'severity': 'medium'
                                    })
                            except Exception:
                                pass
            except Exception as e:
                findings.append({'category': 'error', 'detail': f'ZIP analysis error: {str(e)}'})

        return findings
