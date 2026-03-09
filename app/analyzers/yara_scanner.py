import os
import yara
from pathlib import Path


class YaraScanner:
    def __init__(self):
        rules_path = Path(__file__).parent.parent / 'yara_rules' / 'malware_rules.yar'
        self._rules = None
        self._rules_path = str(rules_path)

    def _load_rules(self):
        if self._rules is None:
            try:
                self._rules = yara.compile(filepath=self._rules_path)
            except yara.SyntaxError as e:
                raise RuntimeError(f"YARA rule syntax error: {e}")
        return self._rules

    def scan(self, filepath):
        matches = []
        try:
            rules = self._load_rules()
            raw_matches = rules.match(filepath)
            for match in raw_matches:
                match_info = {
                    'rule': match.rule,
                    'description': match.meta.get('description', ''),
                    'severity': match.meta.get('severity', 'unknown'),
                    'author': match.meta.get('author', ''),
                    'date': match.meta.get('date', ''),
                    'strings': []
                }
                for string_match in match.strings:
                    match_info['strings'].append({
                        'identifier': string_match.identifier,
                        'instances': [
                            {
                                'offset': inst.offset,
                                'matched_data': inst.matched_data[:100].decode('utf-8', errors='replace')
                            }
                            for inst in string_match.instances[:3]
                        ]
                    })
                matches.append(match_info)
        except yara.Error as e:
            matches.append({'rule': 'scan_error', 'description': str(e), 'severity': 'unknown', 'strings': []})
        except Exception as e:
            matches.append({'rule': 'error', 'description': str(e), 'severity': 'unknown', 'strings': []})
        return matches
