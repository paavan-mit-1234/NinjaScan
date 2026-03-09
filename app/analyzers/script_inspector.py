import re


# PowerShell suspicious patterns
PS1_PATTERNS = [
    (r'-EncodedCommand\b', 'Encoded command execution', 'high'),
    (r'-enc\s+', 'Short encoded command flag', 'high'),
    (r'Invoke-Expression', 'Invoke-Expression (IEX) usage', 'high'),
    (r'\bIEX\b', 'IEX shorthand for Invoke-Expression', 'high'),
    (r'Net\.WebClient', 'WebClient download cradle', 'high'),
    (r'DownloadString\b', 'DownloadString download cradle', 'high'),
    (r'DownloadFile\b', 'DownloadFile download cradle', 'high'),
    (r'Invoke-WebRequest', 'Invoke-WebRequest download', 'medium'),
    (r'amsiInitFailed', 'AMSI bypass technique', 'critical'),
    (r'AmsiScanBuffer', 'AMSI buffer scan bypass', 'critical'),
    (r'-ExecutionPolicy\s+Bypass', 'Execution policy bypass', 'medium'),
    (r'Set-ExecutionPolicy\s+Unrestricted', 'Execution policy set to unrestricted', 'medium'),
    (r'-windowstyle\s+hidden', 'Hidden window style', 'medium'),
    (r'\[System\.Reflection\.Assembly\]::Load', '.NET assembly loading', 'high'),
    (r'Assembly\.Load\b', 'Assembly Load call', 'high'),
    (r'VirtualAlloc\b', 'Memory allocation API', 'high'),
    (r'CreateThread\b', 'Thread creation', 'high'),
    (r'VirtualProtect\b', 'Memory protection modification', 'high'),
    (r'[A-Za-z0-9+/]{100,}={0,2}', 'Long base64 string (possible encoded payload)', 'medium'),
    (r'char\[\]\s*\{[\d,\s]+\}', 'Char array construction', 'medium'),
    (r'-noprofile\s+-noninteractive', 'Non-interactive hidden PS execution', 'low'),
    (r'Bypass\s+.*(IEX|Invoke-Expression)', 'Bypass + execution combo', 'high'),
]

# VBScript suspicious patterns
VBS_PATTERNS = [
    (r'CreateObject\s*\(', 'CreateObject usage', 'medium'),
    (r'WScript\.Shell', 'WScript.Shell access', 'high'),
    (r'WScript\.Network', 'WScript.Network access', 'medium'),
    (r'Shell\b.*\bExec\b', 'Shell execution', 'high'),
    (r'Scripting\.FileSystemObject', 'File system access', 'medium'),
    (r'Scripting\.Dictionary', 'Dictionary object', 'low'),
    (r'ADODB\.Stream', 'ADODB stream (binary write)', 'high'),
    (r'RegWrite\b', 'Registry write', 'medium'),
    (r'GetObject\s*\(\s*"winmgmts', 'WMI access', 'high'),
    (r'http[s]?://', 'HTTP/HTTPS URL present', 'medium'),
    (r'ftp://', 'FTP URL present', 'medium'),
    (r'Chr\s*\(\s*\d+\s*\)', 'Chr() obfuscation', 'low'),
    (r'ChrW\s*\(\s*\d+\s*\)', 'ChrW() obfuscation', 'low'),
    (r'ExecuteGlobal\b', 'ExecuteGlobal call', 'high'),
    (r'Execute\b', 'Execute call', 'high'),
    (r'Auto(?:Open|Close|Exec)\b', 'Auto-execute macro', 'high'),
]

# JavaScript suspicious patterns
JS_PATTERNS = [
    (r'\beval\s*\(', 'eval() usage', 'high'),
    (r'ActiveXObject\b', 'ActiveXObject creation', 'high'),
    (r'WScript\.Shell', 'WScript.Shell access', 'critical'),
    (r'new\s+ActiveXObject\s*\(\s*["\']Shell', 'Shell ActiveXObject', 'critical'),
    (r'unescape\s*\(', 'unescape() obfuscation', 'medium'),
    (r'String\.fromCharCode\s*\(', 'String.fromCharCode obfuscation', 'medium'),
    (r'atob\s*\(', 'Base64 decode (atob)', 'medium'),
    (r'\\x[0-9a-fA-F]{2}', 'Hex-encoded strings', 'low'),
    (r'\\u[0-9a-fA-F]{4}', 'Unicode-encoded strings', 'low'),
    (r'document\.write\s*\(', 'document.write usage', 'low'),
    (r'window\[', 'Dynamic window property access', 'medium'),
    (r'this\[', 'Dynamic this property access', 'medium'),
    (r'Function\s*\(\s*["\']', 'Dynamic function creation', 'high'),
    (r'http[s]?://', 'HTTP/HTTPS URL present', 'medium'),
    (r'(MSXML2|Microsoft\.XMLHTTP)', 'XMLHTTP request object', 'medium'),
    (r'\.run\s*\(', '.run() call', 'high'),
]

# Batch/CMD suspicious patterns
BAT_PATTERNS = [
    (r'powershell\b', 'PowerShell invocation', 'high'),
    (r'certutil\b', 'certutil usage', 'high'),
    (r'certutil.*-decode', 'certutil decode', 'critical'),
    (r'certutil.*-urlcache', 'certutil urlcache download', 'critical'),
    (r'reg\s+add\b', 'Registry add', 'medium'),
    (r'schtasks\s+/create', 'Scheduled task creation', 'high'),
    (r'netsh\b', 'netsh command', 'medium'),
    (r'sc\s+create\b', 'Service creation', 'high'),
    (r'sc\s+start\b', 'Service start', 'medium'),
    (r'wmic\b', 'WMIC usage', 'high'),
    (r'bitsadmin\b', 'bitsadmin download', 'high'),
    (r'mshta\b', 'mshta execution', 'high'),
    (r'rundll32\b', 'rundll32 execution', 'high'),
    (r'regsvr32\b', 'regsvr32 execution', 'medium'),
    (r'cmd\s+/c\b', 'cmd /c execution', 'medium'),
    (r'echo\s+.*%ComSpec%', 'ComSpec variable usage', 'medium'),
    (r'http[s]?://', 'HTTP/HTTPS URL present', 'high'),
    (r'disable.*firewall', 'Firewall disable attempt', 'critical'),
    (r'net\s+user\b', 'net user command', 'medium'),
    (r'net\s+localgroup\b', 'net localgroup command', 'medium'),
    (r'whoami\b', 'whoami command', 'low'),
    (r'taskkill\b', 'taskkill command', 'medium'),
]


class ScriptInspector:
    def inspect(self, filepath, ext):
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            return [{'category': 'error', 'detail': str(e)}]

        ext = ext.lower()
        if ext == 'ps1':
            patterns = PS1_PATTERNS
        elif ext == 'vbs':
            patterns = VBS_PATTERNS
        elif ext == 'js':
            patterns = JS_PATTERNS
        elif ext in ('bat', 'cmd'):
            patterns = BAT_PATTERNS
        else:
            return []

        for pattern, description, severity in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    'pattern': pattern,
                    'description': description,
                    'severity': severity,
                    'match_count': len(matches),
                    'sample': str(matches[0])[:100] if matches else ''
                })

        return findings
