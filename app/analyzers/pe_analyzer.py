import math
import struct
from collections import defaultdict


# Suspicious imports organized by category
SUSPICIOUS_IMPORTS = {
    'process_injection': [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'NtCreateThreadEx', 'QueueUserAPC', 'NtQueueApcThread',
        'RtlCreateUserThread', 'SetThreadContext', 'OpenProcess',
        'NtOpenProcess', 'OpenThread', 'NtOpenThread',
    ],
    'memory_manipulation': [
        'VirtualAlloc', 'VirtualProtect', 'HeapAlloc',
        'NtAllocateVirtualMemory', 'NtWriteVirtualMemory',
        'NtProtectVirtualMemory', 'MapViewOfFile', 'CreateFileMapping',
        'ZwAllocateVirtualMemory', 'ZwWriteVirtualMemory',
    ],
    'anti_debugging': [
        'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
        'NtQueryInformationProcess', 'OutputDebugStringA', 'OutputDebugStringW',
        'GetTickCount', 'QueryPerformanceCounter', 'NtSetInformationThread',
        'CloseHandle', 'UnhandledExceptionFilter', 'SetUnhandledExceptionFilter',
    ],
    'registry_changes': [
        'RegCreateKeyExA', 'RegCreateKeyExW', 'RegSetValueExA', 'RegSetValueExW',
        'RegDeleteKeyA', 'RegDeleteKeyW', 'RegOpenKeyExA', 'RegOpenKeyExW',
        'RegQueryValueExA', 'RegQueryValueExW', 'SHSetValue', 'SHRegSetUSValue',
    ],
    'networking': [
        'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW',
        'HttpSendRequestA', 'HttpSendRequestW', 'URLDownloadToFileA', 'URLDownloadToFileW',
        'WSAStartup', 'socket', 'connect', 'send', 'recv',
        'WSAConnect', 'WinHttpOpen', 'WinHttpConnect', 'WinHttpSendRequest',
        'getaddrinfo', 'gethostbyname', 'InternetConnectA', 'InternetConnectW',
    ],
    'crypto_operations': [
        'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptAcquireContextA',
        'CryptAcquireContextW', 'CryptImportKey', 'CryptExportKey',
        'CryptCreateHash', 'CryptHashData', 'NCryptEncrypt', 'NCryptDecrypt',
    ],
    'hooking': [
        'SetWindowsHookExA', 'SetWindowsHookExW', 'UnhookWindowsHookEx',
        'GetThreadContext', 'SetThreadContext', 'SuspendThread', 'ResumeThread',
        'NtSuspendThread', 'NtResumeThread',
    ],
    'execution': [
        'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
        'WinExec', 'CreateProcessA', 'CreateProcessW', 'CreateProcessInternalA',
        'CreateProcessInternalW', 'system', 'NtCreateProcess', 'ZwCreateProcess',
    ],
    'file_operations': [
        'DeleteFileA', 'DeleteFileW', 'MoveFileA', 'MoveFileW',
        'CopyFileA', 'CopyFileW', 'FindFirstFileA', 'FindFirstFileW',
        'GetTempPathA', 'GetTempPathW',
    ],
}

# Packer/obfuscation indicators
PACKER_SECTION_NAMES = {
    'UPX0', 'UPX1', 'UPX2', '.UPX0', '.UPX1',
    '.packed', '.pack', 'MPRESS1', 'MPRESS2',
    '.ndata', '.aspack', '.adata',
}

SUSPICIOUS_SECTION_NAMES = {
    '.text0', '.text1', 'CODE', 'DATA',
    'seg000', 'seg001', 'stub',
}

HIGH_ENTROPY_THRESHOLD = 7.0


def calculate_entropy(data):
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class PEAnalyzer:
    def analyze(self, filepath):
        findings = []
        try:
            import pefile
            pe = pefile.PE(filepath)
            findings.extend(self._check_imports(pe))
            findings.extend(self._check_sections(pe))
            findings.extend(self._check_timestamp(pe))
            findings.extend(self._check_packer_indicators(pe))
            pe.close()
        except ImportError:
            findings.append({'category': 'error', 'detail': 'pefile not available'})
        except Exception as e:
            findings.append({'category': 'error', 'detail': f'PE parse error: {str(e)}'})
        return findings

    def _check_imports(self, pe):
        findings = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            findings.append({'category': 'packer_indicator', 'detail': 'No import table found (possible packing)'})
            return findings

        all_imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='replace').lower() if entry.dll else ''
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8', errors='replace')
                    all_imports.append(func_name)
                    for category, funcs in SUSPICIOUS_IMPORTS.items():
                        if func_name in funcs:
                            findings.append({
                                'category': category,
                                'detail': f"Suspicious import: {func_name} from {dll_name}",
                                'function': func_name,
                                'dll': dll_name
                            })

        # Check for packer indicator: very few imports
        if len(all_imports) < 5:
            findings.append({
                'category': 'packer_indicator',
                'detail': f'Very low import count ({len(all_imports)}) — possible packing or obfuscation'
            })

        # Check for LoadLibrary + GetProcAddress combo (dynamic import resolution)
        has_loadlib = any('LoadLibrary' in f for f in all_imports)
        has_getproc = any('GetProcAddress' in f for f in all_imports)
        if has_loadlib and has_getproc:
            findings.append({
                'category': 'packer_indicator',
                'detail': 'LoadLibrary + GetProcAddress combo detected (dynamic import resolution)'
            })

        return findings

    def _check_sections(self, pe):
        findings = []
        if not hasattr(pe, 'sections'):
            return findings

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='replace').rstrip('\x00').strip()
            data = section.get_data()
            entropy = calculate_entropy(data)

            if section_name in PACKER_SECTION_NAMES:
                findings.append({
                    'category': 'packer_indicator',
                    'detail': f'Known packer section name: {section_name}'
                })
            elif section_name in SUSPICIOUS_SECTION_NAMES:
                findings.append({
                    'category': 'suspicious_section',
                    'detail': f'Suspicious section name: {section_name}'
                })

            if entropy >= HIGH_ENTROPY_THRESHOLD:
                findings.append({
                    'category': 'high_entropy',
                    'detail': f'High entropy section ({section_name}): {entropy:.2f} — possibly encrypted/packed'
                })

        return findings

    def _check_timestamp(self, pe):
        findings = []
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts == 0:
                findings.append({
                    'category': 'timestamp_anomaly',
                    'detail': 'Compilation timestamp is zero (stripped or invalid)'
                })
            elif ts < 0x20000000:  # Before ~1995
                findings.append({
                    'category': 'timestamp_anomaly',
                    'detail': f'Suspicious compilation timestamp: {ts:#010x}'
                })
        except Exception:
            pass
        return findings

    def _check_packer_indicators(self, pe):
        findings = []
        try:
            # Check for TLS callbacks
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
                if hasattr(pe.DIRECTORY_ENTRY_TLS.struct, 'AddressOfCallBacks'):
                    findings.append({
                        'category': 'packer_indicator',
                        'detail': 'TLS callbacks present — possible anti-debug or packer technique'
                    })
        except Exception:
            pass
        return findings
