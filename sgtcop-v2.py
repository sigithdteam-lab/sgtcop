#!/usr/bin/env python3
# sgtcop.py - Smart Security Monitor dengan Self-Learning, ML, & VirusTotal
# Enhanced Edition v2.0
# Copyright (C) 2026 sigithdteam-lab
# GNU General Public License v3.0

import os
import re
import json
import hashlib
import logging
import time
import sys
from datetime import datetime
from pathlib import Path
import ipaddress
import subprocess
import shutil
import glob

# ============================================
# IMPOR FITUR TAMBAHAN (dengan fallback)
# ============================================
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARN] requests not installed. Signature update & VirusTotal disabled.")

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    print("[WARN] joblib not installed. ML model persistence disabled.")

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    np = None
    RandomForestClassifier = None
    print("[WARN] scikit-learn not installed. ML detection disabled.")

# ============================================
# KONFIGURASI
# ============================================
CONFIG = {
    'scan_dirs': ['/home', '/var/www', '/usr/local/apache/htdocs'],
    'log_dir': '/var/log/security_monitor',
    'learning_file': '/var/lib/security_monitor/learning_data.json',
    'report_file': '/root/security_report.txt',
    'backup_dir': '/root/security_backups',
    'max_file_size': 10485760,          # 10 MB
    'max_file_size_webshell': 2097152,   # 2 MB
    'blocked_domains_file': '/etc/blocked_incoming_email_domains',
    'blocked_country_ips_file': '/etc/blocked_incoming_email_country_ips',
    'blocked_countries_file': '/etc/blocked_incoming_email_countries',
    'exim_conf': '/etc/exim.conf',
    'exim_log': '/var/log/exim_mainlog',
    'php_versions': [
        '/opt/alt/php56/etc/php.ini',
        '/opt/alt/php70/etc/php.ini',
        '/opt/alt/php71/etc/php.ini',
        '/opt/alt/php72/etc/php.ini',
        '/opt/alt/php73/etc/php.ini',
        '/opt/alt/php74/etc/php.ini',
        '/opt/alt/php80/etc/php.ini',
        '/opt/alt/php81/etc/php.ini',
        '/opt/alt/php82/etc/php.ini',
        '/opt/alt/php83/etc/php.ini',
        '/opt/alt/php84/etc/php.ini',
        '/usr/local/lib/php.ini',
        '/etc/php.ini'
    ],
    # NEW: URL untuk signature update
    'signature_url': 'https://security-updates.example.com/signatures/latest.json',
    # NEW: VirusTotal API key (bisa dari env)
    'virustotal_api_key': os.environ.get('VIRUSTOTAL_API_KEY', ''),
    # NEW: Path model ML
    'ml_model_path': '/var/lib/security_monitor/ml_model.pkl'
}

SKIP_DIRS = [
    '/proc', '/sys', '/dev', '/run', '/tmp', '/var/tmp',
    '/var/log', '/var/cache', '/usr/share/doc', '/usr/share/man'
]

SCAN_EXTS = [
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
    '.phps', '.inc', '.module', '.theme', '.engine',
    '.cgi', '.pl', '.py'
]

# ============================================
# CLASS SECURITY MONITOR (ENHANCED)
# ============================================
class SecurityMonitor:
    def __init__(self):
        """Inisialisasi dengan fitur baru"""
        self.setup_environment()
        self.learning_data = {}
        self.load_learning_data()
        self.load_blocked_lists()
        self.load_exim_config()
        self.detect_php_versions()

        # Container hasil
        self.suspicious_files = []
        self.critical_files = []
        self.spam_emails = []
        self.new_patterns = []
        self.php_issues = []
        self.script_upgrades = []
        self.upgrade_applied = False
        self.spam_sources = []
        self.blocked_domains_found = []

        # NEW: ML model
        self.ml_model = None
        if SKLEARN_AVAILABLE and JOBLIB_AVAILABLE:
            self._load_ml_model()

    # ============================================
    # SETUP & LOGGING
    # ============================================
    def setup_environment(self):
        for dir_path in [CONFIG['log_dir'], '/var/lib/security_monitor', CONFIG['backup_dir']]:
            Path(dir_path).mkdir(parents=True, exist_ok=True)

        log_file = f"{CONFIG['log_dir']}/security_{datetime.now().strftime('%Y%m%d')}.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(log_file), logging.StreamHandler()]
        )
        self.log = logging.getLogger(__name__)

    # ============================================
    # LOAD / SAVE LEARNING DATA
    # ============================================
    def load_learning_data(self):
        if os.path.exists(CONFIG['learning_file']):
            try:
                with open(CONFIG['learning_file'], 'r') as f:
                    self.learning_data = json.load(f)
                self.log.info("Learning data loaded")
            except (json.JSONDecodeError, IOError) as e:
                self.log.error(f"Error loading learning data: {e}. Using defaults.")
                self.learning_data = self.get_default_learning_data()
                self.save_learning_data()
        else:
            self.learning_data = self.get_default_learning_data()
            self.save_learning_data()

    def get_default_learning_data(self):
        return {
            'dangerous_patterns': [
                r'shell_exec\s*\(',
                r'system\s*\(',
                r'exec\s*\(',
                r'passthru\s*\(',
                r'popen\s*\(',
                r'proc_open\s*\(',
                r'pcntl_exec\s*\(',
                r'eval\s*\(',
                r'assert\s*\(',
                r'create_function\s*\(',
                r'call_user_func\s*\(',
                r'call_user_func_array\s*\(',
                r'base64_decode\s*\(.*eval',
                r'gzinflate\s*\(.*eval',
                r'gzuncompress\s*\(.*eval',
                r'str_rot13\s*\(.*eval',
                r'hex2bin\s*\(.*eval',
                r'curl_exec\s*\(',
                r'curl_multi_exec\s*\(',
                r'fsockopen\s*\(',
                r'pfsockopen\s*\(',
                r'stream_socket_client\s*\(',
                r'socket_create\s*\(',
                r'file_put_contents\s*\(.*base64',
                r'fopen\s*\(.*w.*base64',
                r'eval\s*\(\s*base64_decode',
                r'eval\s*\(\s*gzinflate',
                r'eval\s*\(\s*str_rot13',
                r'system\s*\(\s*\$_(GET|POST|REQUEST)',
                r'exec\s*\(\s*\$_(GET|POST|REQUEST)',
                r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)',
                r'passthru\s*\(\s*\$_(GET|POST|REQUEST)',
                r'popen\s*\(\s*\$_(GET|POST|REQUEST)',
                r'proc_open\s*\(\s*\$_(GET|POST|REQUEST)',
                r'\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*\(',
                r'file_get_contents\s*\(\s*\$_(GET|POST)',
                r'include\s*\(\s*\$_(GET|POST)',
                r'require\s*\(\s*\$_(GET|POST)',
                r'assert\s*\(\s*\$_(GET|POST)',
                r'base64_decode\s*\(\s*\$_(GET|POST)',
            ],
            'dangerous_functions': [
                'eval', 'system', 'exec', 'shell_exec', 'passthru',
                'popen', 'proc_open', 'curl_exec', 'phpinfo',
                'dl', 'fsockopen', 'pfsockopen', 'posix_kill',
                'gzinflate', 'gzuncompress', 'highlight_file',
                'ini_alter', 'ini_set', 'set_time_limit',
                'php_uname', 'php_version', 'readlink',
                'symlink', 'link', 'mail', 'mb_send_mail',
                'pcntl_exec', 'create_function', 'call_user_func',
                'call_user_func_array', 'curl_multi_exec',
                'stream_socket_client', 'socket_create'
            ],
            'suspicious_names': [
                'shell', 'cmd', 'c99', 'r57', 'backdoor',
                'webshell', 'eval', 'system', 'exec',
                'phpshell', 'phpcmd', 'adminer', 'hack',
                'exploit', 'inject', 'malware', 'virus',
                'c99shell', 'r57shell', 'wso', 'b374k',
                'ninja-shell', 'ecws', 'cmd.php', 'admin.php'
            ],
            'spam_patterns': [
                r'Subject:.*(Viagra|Cialis|Casino|Poker|Lottery)',
                r'Subject:.*(Pharmacy|Medication|Loan|Credit)',
                r'Content-Type:.*multipart/alternative',
                r'X-Mailer:.*(PHP|sendmail)',
                r'click here|free offer|guarantee',
                r'Content-Transfer-Encoding:.*base64',
                r'\b(weight loss|penis|vagina|porn)\b'
            ],
            'exim_spam_rules': [
                'SPAM Assassin enabled',
                'Spam scoring configured',
                'Sender verification required',
                'DNS verification configured'
            ],
            'php_secure_settings': {
                'disable_functions': 'exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,phpinfo,pcntl_exec,dl,pfsockopen,fsockopen,posix_kill,posix_mkfifo,posix_setpgid,posix_setsid,posix_setuid,posix_setgid,posix_uname,gzinflate,gzuncompress,highlight_file,ini_alter,disk_free_space,disk_total_space,get_cfg_var,get_current_user,get_extension_funcs,get_include_path,get_magic_quotes_gpc,get_required_files,getmygid,getmyinode,getmypid,getmyuid,getopt,getrusage,getlastmod,get_defined_constants,get_defined_functions,get_defined_vars,getenv,get_browser,get_headers,get_class_vars,get_class_methods,get_declared_classes,get_declared_interfaces,get_loaded_extensions,get_meta_tags,get_object_vars,get_parent_class,get_resource_type,getallheaders,php_uname,php_logo_guid,php_sapi_name,php_version,phpinfo,phpcredits,php_ini_loaded_file,php_ini_scanned_files,php_egg_logo_guid,php_real_logo_guid,zend_logo_guid,readlink,symlink,link,set_time_limit,ini_set,set_include_path,mail',
                'allow_url_fopen': 'Off',
                'allow_url_include': 'Off',
                'register_globals': 'Off',
                'display_errors': 'Off',
                'upload_max_filesize': '2M',
                'post_max_size': '8M',
                'max_execution_time': '30',
                'memory_limit': '128M'
            },
            'critical_patterns': [
                'c99shell', 'r57shell', 'wso', 'b374k',
                'ninja-shell', 'ecws filemanager', 'webshell',
                'backdoor', 'cmd.php', 'admin.php'
            ]
        }

    def save_learning_data(self):
        try:
            backup_file = CONFIG['learning_file'] + '.bak'
            if os.path.exists(CONFIG['learning_file']):
                shutil.copy2(CONFIG['learning_file'], backup_file)
            with open(CONFIG['learning_file'], 'w') as f:
                json.dump(self.learning_data, f, indent=2)
            self.log.info("Learning data saved")
        except Exception as e:
            self.log.error(f"Error saving learning data: {e}")

    # ============================================
    # LOAD BLOCKED LISTS & EXIM
    # ============================================
    def load_blocked_lists(self):
        self.log.info("Loading blocked lists...")
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.blocked_countries = set()
        self.blocked_ip_ranges = []

        if os.path.exists(CONFIG['blocked_domains_file']):
            try:
                with open(CONFIG['blocked_domains_file'], 'r') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            self.blocked_domains.add(domain)
                self.log.info(f"Loaded {len(self.blocked_domains)} domains")
            except Exception as e:
                self.log.error(f"Error loading domains: {e}")

        if os.path.exists(CONFIG['blocked_country_ips_file']):
            try:
                with open(CONFIG['blocked_country_ips_file'], 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            if '/' in ip:
                                self.blocked_ip_ranges.append(ip)
                            else:
                                self.blocked_ips.add(ip)
                self.log.info(f"Loaded {len(self.blocked_ips)} IPs, {len(self.blocked_ip_ranges)} ranges")
            except Exception as e:
                self.log.error(f"Error loading IPs: {e}")

        if os.path.exists(CONFIG['blocked_countries_file']):
            try:
                with open(CONFIG['blocked_countries_file'], 'r') as f:
                    for line in f:
                        country = line.strip().upper()
                        if country and not country.startswith('#'):
                            self.blocked_countries.add(country)
                self.log.info(f"Loaded {len(self.blocked_countries)} countries")
            except Exception as e:
                self.log.error(f"Error loading countries: {e}")

    def load_exim_config(self):
        self.log.info("Loading Exim configuration...")
        self.exim_spam_rules = []
        self.exim_blocked_senders = []

        if os.path.exists(CONFIG['exim_conf']):
            try:
                with open(CONFIG['exim_conf'], 'r') as f:
                    content = f.read()

                spam_patterns = [
                    (r'spam\s*=\s*yes', 'SPAM Assassin enabled'),
                    (r'spam_score\s*=', 'Spam scoring configured'),
                    (r'spam_action\s*=', 'Spam action configured'),
                    (r'require_verify\s*=\s*sender', 'Sender verification required'),
                    (r'check_sender\s*=', 'Sender check configured'),
                    (r'dns_verify\s*=', 'DNS verification configured'),
                ]

                for pattern, desc in spam_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.exim_spam_rules.append(desc)

                deny_senders = re.findall(r'deny\s+senders\s*=\s*([^:]+)', content, re.IGNORECASE)
                for senders in deny_senders:
                    for sender in senders.strip().split():
                        if sender and not sender.startswith('#'):
                            self.exim_blocked_senders.append(sender)

                self.log.info(f"Found {len(self.exim_spam_rules)} Exim rules")
            except Exception as e:
                self.log.error(f"Error loading exim.conf: {e}")

    def detect_php_versions(self):
        self.log.info("Detecting PHP versions...")
        self.php_versions = {}

        alt_paths = glob.glob('/opt/alt/php*/usr/bin/php')
        for php_path in alt_paths:
            try:
                result = subprocess.run([php_path, '-v'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    version_match = re.search(r'PHP (\d+\.\d+\.\d+)', result.stdout)
                    if version_match:
                        version = version_match.group(1)
                        ini_file = f"/opt/alt/php{version[:2]}/etc/php.ini"
                        self.php_versions[version] = {
                            'path': php_path,
                            'ini_file': ini_file if os.path.exists(ini_file) else None
                        }
                        self.log.info(f"Found PHP {version}")
            except:
                pass

        for version, info in self.php_versions.items():
            if info.get('ini_file'):
                self.analyze_php_ini(info['ini_file'], version)

    def analyze_php_ini(self, ini_file, version):
        try:
            with open(ini_file, 'r') as f:
                content = f.read()

            issues = []

            disable_functions = re.search(r'disable_functions\s*=\s*(.+)', content)
            if disable_functions:
                functions = disable_functions.group(1).strip()
                dangerous = ['exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open']
                missing = [f for f in dangerous if f not in functions]
                if missing:
                    issues.append(f"Missing dangerous functions: {', '.join(missing)}")
            else:
                issues.append("disable_functions not set")

            if re.search(r'allow_url_fopen\s*=\s*On', content, re.IGNORECASE):
                issues.append("allow_url_fopen is On")

            if re.search(r'allow_url_include\s*=\s*On', content, re.IGNORECASE):
                issues.append("allow_url_include is On")

            if issues:
                self.php_issues.append({
                    'version': version,
                    'file': ini_file,
                    'issues': issues
                })
                for issue in issues:
                    self.log.warning(f"PHP {version}: {issue}")

        except Exception as e:
            self.log.error(f"Error analyzing {ini_file}: {e}")

    # ============================================
    # UTILITY FUNCTIONS
    # ============================================
    def is_encoded(self, content):
        patterns = [
            r'base64_decode\s*\([^)]+\)',
            r'str_rot13\s*\([^)]+\)',
            r'gzinflate\s*\([^)]+\)',
            r'eval\s*\(\s*gzinflate',
            r'eval\s*\(\s*base64_decode',
            r'\\x[0-9a-f]{2}',
            r'chr\s*\(\d+\)\s*\.',
            r'base64_decode.*[A-Za-z0-9+/]{50,}',
            r'gzinflate.*base64_decode',
            r'echo.*base64_decode.*[A-Za-z0-9+/]{20,}',
            r'hex2bin\s*\(',
        ]
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False

    def is_ip_blocked(self, ip):
        if ip in self.blocked_ips:
            return True
        for cidr in self.blocked_ip_ranges:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False):
                    return True
            except:
                pass
        return False

    def is_domain_blocked(self, domain):
        domain = domain.lower()
        if domain in self.blocked_domains:
            return True
        for blocked in self.blocked_domains:
            if domain.endswith(blocked) or blocked.endswith(domain):
                return True
        return False

    def is_skip_dir(self, path):
        for skip in SKIP_DIRS:
            if path.startswith(skip):
                return True
        return False

    def should_scan_file(self, filepath):
        ext = os.path.splitext(filepath)[1].lower()
        return ext in SCAN_EXTS

    # ============================================
    # NEW: SIGNATURE DATABASE UPDATE
    # ============================================
    def update_signatures(self, signature_url=None):
        if not REQUESTS_AVAILABLE:
            self.log.warning("requests not installed, signature update skipped.")
            return False

        if signature_url is None:
            signature_url = CONFIG.get('signature_url', '')
            if not signature_url:
                self.log.warning("No signature URL configured.")
                return False

        self.log.info(f"Checking for signature updates from {signature_url}...")
        try:
            response = requests.get(signature_url, timeout=30)
            response.raise_for_status()
            new_data = response.json()

            # Verifikasi checksum (jika ada)
            if 'checksum' in new_data:
                calc = hashlib.sha256(json.dumps(new_data['data']).encode()).hexdigest()
                if calc != new_data['checksum']:
                    self.log.error("Signature checksum mismatch! Aborting.")
                    return False

            # Merge dengan data existing
            keys = ['dangerous_patterns', 'dangerous_functions',
                    'suspicious_names', 'critical_patterns', 'spam_patterns']
            for key in keys:
                if key in new_data:
                    existing = set(self.learning_data.get(key, []))
                    new_items = set(new_data[key])
                    self.learning_data[key] = list(existing | new_items)

            self.save_learning_data()
            self.log.info("Signature update successful.")
            return True

        except Exception as e:
            self.log.error(f"Signature update failed: {e}")
            return False

    # ============================================
    # NEW: MACHINE LEARNING FEATURES
    # ============================================
    def _shannon_entropy(self, data):
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        return entropy

    def _extract_features(self, content):
        """Ekstrak 8 fitur numerik untuk ML"""
        features = []
        features.append(len(content))  # 1. length
        features.append(self._shannon_entropy(content))  # 2. entropy
        # 3. jumlah dangerous functions
        num_funcs = sum(1 for func in self.learning_data.get('dangerous_functions', [])
                        if re.search(rf'\b{func}\s*\(', content, re.IGNORECASE))
        features.append(num_funcs)
        # 4. jumlah suspicious names
        num_names = sum(1 for name in self.learning_data.get('suspicious_names', [])
                        if name in content.lower())
        features.append(num_names)
        # 5. is encoded
        features.append(1 if self.is_encoded(content) else 0)
        # 6. jumlah eval
        features.append(len(re.findall(r'eval\s*\(', content, re.IGNORECASE)))
        # 7. jumlah base64_decode
        features.append(len(re.findall(r'base64_decode', content, re.IGNORECASE)))
        # 8. jumlah system calls
        features.append(len(re.findall(r'(system|exec|shell_exec|passthru)', content, re.IGNORECASE)))
        return features

    def _load_ml_model(self):
        model_path = CONFIG['ml_model_path']
        if os.path.exists(model_path) and JOBLIB_AVAILABLE:
            try:
                self.ml_model = joblib.load(model_path)
                self.log.info("ML model loaded from disk.")
            except Exception as e:
                self.log.warning(f"Failed to load ML model: {e}")
                self.ml_model = None
        else:
            self.ml_model = None

    def train_ml_model(self, positive_samples=None, negative_samples=None):
        if not SKLEARN_AVAILABLE or not JOBLIB_AVAILABLE:
            self.log.warning("ML libraries not available. Skipping training.")
            return

        self.log.info("Training ML model...")
        try:
            # Jika tidak ada sample, buat dari file critical/suspicious yang sudah terdeteksi
            if positive_samples is None:
                positive_samples = []
                for f in self.critical_files + self.suspicious_files:
                    try:
                        with open(f['path'], 'r', errors='ignore') as fp:
                            content = fp.read()
                            feats = self._extract_features(content)
                            positive_samples.append((feats, 1))
                    except:
                        pass

            if negative_samples is None:
                negative_samples = []
                # Ambil beberapa file dari direktori aman (untuk demo kita buat dummy)
                # Untuk produksi, sebaiknya ambil file dari /usr/share/doc atau sejenis
                # Di sini kita buat dummy jika tidak ada
                for _ in range(max(1, len(positive_samples)//2)):
                    negative_samples.append(([0]*8, 0))

            # Gabungkan
            X = [f[0] for f in positive_samples + negative_samples]
            y = [f[1] for f in positive_samples + negative_samples]

            if len(X) < 10:
                self.log.warning("Not enough samples for ML training (need at least 10).")
                return

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X_train, y_train)

            acc = accuracy_score(y_test, model.predict(X_test))
            self.log.info(f"ML model trained with accuracy: {acc:.2f}")

            # Simpan model
            model_path = CONFIG['ml_model_path']
            joblib.dump(model, model_path)
            self.ml_model = model
            self.log.info(f"Model saved to {model_path}")

        except Exception as e:
            self.log.error(f"ML training failed: {e}")

    def predict_with_ml(self, content):
        if self.ml_model is None:
            self._load_ml_model()
            if self.ml_model is None:
                return None

        try:
            features = self._extract_features(content)
            proba = self.ml_model.predict_proba([features])[0][1]
            return proba
        except Exception as e:
            self.log.error(f"ML prediction failed: {e}")
            return None

    # ============================================
    # NEW: VIRUSTOTAL INTEGRATION
    # ============================================
    def scan_with_virustotal(self, file_hash):
        if not REQUESTS_AVAILABLE:
            return None

        api_key = CONFIG.get('virustotal_api_key', '')
        if not api_key:
            self.log.debug("No VirusTotal API key set. Skipping.")
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                attributes = data['data']['attributes']
                last_analysis_stats = attributes.get('last_analysis_stats', {})
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                total = sum(last_analysis_stats.values())

                return {
                    'hash': file_hash,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'total': total,
                    'ratio': malicious / total if total > 0 else 0,
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif response.status_code == 404:
                return {'hash': file_hash, 'found': False}
            else:
                self.log.warning(f"VT API error: {response.status_code}")
                return None
        except Exception as e:
            self.log.error(f"VirusTotal request failed: {e}")
            return None

    # ============================================
    # ENHANCED SCAN PHP FILE (dengan ML & VT)
    # ============================================
    def scan_php_file(self, filepath):
        try:
            if self.is_skip_dir(filepath):
                return
            if not self.should_scan_file(filepath):
                return

            size = os.path.getsize(filepath)
            if size > CONFIG['max_file_size_webshell']:
                return

            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            reasons = []
            critical_reasons = []
            is_critical = False

            # --- Existing pattern detection ---
            critical_patterns = self.learning_data.get('critical_patterns', [])
            filename = os.path.basename(filepath)
            for pattern in critical_patterns:
                if re.search(pattern, filename, re.IGNORECASE) or re.search(pattern, content, re.IGNORECASE):
                    critical_reasons.append(f"CRITICAL: {pattern}")
                    is_critical = True

            for pattern in self.learning_data['dangerous_patterns']:
                if re.search(pattern, content, re.IGNORECASE):
                    reasons.append(f"Pattern: {pattern[:30]}...")
                    is_critical = True
                    break

            for func in self.learning_data['dangerous_functions']:
                if re.search(rf'{func}\s*\(', content, re.IGNORECASE):
                    reasons.append(f"Function: {func}()")
                    is_critical = True
                    break

            if self.is_encoded(content):
                reasons.append("Encoded/Obfuscated content")
                is_critical = True

            for name in self.learning_data['suspicious_names']:
                if name in filepath.lower():
                    reasons.append(f"Filename: {name}")
                    is_critical = True
                    break

            if re.search(r'mail\s*\(', content, re.IGNORECASE):
                for domain in self.blocked_domains:
                    if domain in content.lower():
                        reasons.append(f"Spam to blocked domain: {domain}")
                        self.blocked_domains_found.append(domain)
                        is_critical = True
                        break
                for source in self.spam_sources:
                    if source in content.lower():
                        reasons.append(f"Spam source found: {source}")
                        is_critical = True
                        break

            # --- NEW: ML Prediction ---
            if is_critical or reasons:
                ml_proba = self.predict_with_ml(content)
                if ml_proba is not None and ml_proba > 0.7:
                    reasons.append(f"ML probability: {ml_proba:.2f}")
                    is_critical = True

            # --- NEW: VirusTotal (hanya jika critical/suspicious) ---
            vt_result = None
            if is_critical or reasons:
                file_hash = hashlib.md5(content.encode()).hexdigest()
                vt_result = self.scan_with_virustotal(file_hash)
                if vt_result and vt_result.get('malicious', 0) > 0:
                    critical_reasons.append(
                        f"VirusTotal: {vt_result['malicious']}/{vt_result['total']} malicious"
                    )
                    is_critical = True

            # Simpan hasil
            if is_critical or critical_reasons:
                file_hash = hashlib.md5(content.encode()).hexdigest()
                file_info = {
                    'path': filepath,
                    'reasons': reasons + critical_reasons,
                    'hash': file_hash,
                    'size': size,
                    'critical': True,
                    'ml_proba': ml_proba,
                    'vt_result': vt_result
                }
                self.critical_files.append(file_info)
                self.log.warning(f"💀 CRITICAL: {filepath}")
                self.log.warning(f"  Reasons: {', '.join((reasons + critical_reasons)[:3])}")
            elif reasons:
                file_hash = hashlib.md5(content.encode()).hexdigest()
                file_info = {
                    'path': filepath,
                    'reasons': reasons,
                    'hash': file_hash,
                    'size': size,
                    'critical': False
                }
                self.suspicious_files.append(file_info)
                self.log.warning(f"⚠️ SUSPICIOUS: {filepath}")
                self.log.warning(f"  Reasons: {', '.join(reasons[:3])}")

        except Exception as e:
            self.log.error(f"Error scanning {filepath}: {e}")

    # ============================================
    # SPAM SCANNING (sama seperti asli)
    # ============================================
    def scan_spam(self):
        self.log.info("="*50)
        self.log.info("PHASE 1: SCANNING SPAM EMAILS & SOURCES")
        self.log.info("="*50)

        self.scan_mail_queues()
        self.scan_exim_logs()
        self.scan_mail_logs()
        self.scan_php_mail_functions()
        self.analyze_spam_sources()

        self.log.info(f"Spam scan completed: {len(self.spam_emails)} emails, {len(self.spam_sources)} sources")

    def scan_mail_queues(self):
        self.log.info("Scanning mail queues...")
        queues = ['/var/spool/mail', '/var/spool/postfix/deferred',
                  '/var/spool/postfix/incoming', '/var/spool/postfix/active']
        total_spam = 0
        for queue in queues:
            if os.path.exists(queue):
                self.log.info(f"  Checking queue: {queue}")
                spam_count = self.scan_mail_queue(queue)
                total_spam += spam_count
        self.log.info(f"Total spam found in queues: {total_spam}")

    def scan_mail_queue(self, queue_dir):
        spam_count = 0
        try:
            for root, dirs, files in os.walk(queue_dir):
                for file in files[:100]:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', errors='ignore') as f:
                            content = f.read()

                        sender = re.search(r'(?:From|Sender):\s*<?([^>\n]+)>?', content)
                        recipient = re.search(r'To:\s*<?([^>\n]+)>?', content)
                        subject = re.search(r'Subject:\s*(.+?)(?:\n|$)', content)

                        if sender and recipient:
                            sender_email = sender.group(1).strip()
                            recipient_email = recipient.group(1).strip()
                            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
                            recipient_domain = recipient_email.split('@')[-1] if '@' in recipient_email else ''

                            blocked = False
                            reason = []
                            spam_score = 0

                            if self.is_domain_blocked(sender_domain):
                                blocked = True
                                reason.append(f"Sender domain blocked: {sender_domain}")
                                self.spam_sources.append(sender_domain)

                            if self.is_domain_blocked(recipient_domain):
                                blocked = True
                                reason.append(f"Recipient domain blocked: {recipient_domain}")

                            for pattern in self.learning_data['spam_patterns']:
                                if re.search(pattern, content, re.IGNORECASE):
                                    spam_score += 0.15
                                    reason.append("Matched spam pattern")
                                    break

                            for rule in self.exim_spam_rules:
                                if rule.lower() in content.lower():
                                    spam_score += 0.1
                                    reason.append(f"Exim rule: {rule}")
                                    break

                            source_ip = re.search(r'Received:\s*from\s+[^[]*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', content)
                            if source_ip:
                                ip = source_ip.group(1)
                                if self.is_ip_blocked(ip):
                                    blocked = True
                                    reason.append(f"IP blocked: {ip}")
                                    self.spam_sources.append(ip)

                            if blocked or spam_score > 0.3:
                                spam_count += 1
                                self.spam_emails.append({
                                    'sender': sender_email,
                                    'recipient': recipient_email,
                                    'subject': subject.group(1) if subject else 'No subject',
                                    'score': spam_score,
                                    'reason': ' | '.join(reason[:3]),
                                    'source_ip': source_ip.group(1) if source_ip else None
                                })
                                self.log.warning(f"  SPAM FOUND: {sender_email} -> {recipient_email}")
                                self.log.warning(f"    Score: {spam_score:.2f}, Reason: {reason[0] if reason else 'N/A'}")
                    except Exception:
                        pass
        except Exception as e:
            self.log.error(f"Error scanning queue {queue_dir}: {e}")
        return spam_count

    def scan_exim_logs(self):
        self.log.info("Scanning Exim logs...")
        if not os.path.exists(CONFIG['exim_log']):
            self.log.warning("Exim log not found")
            return

        try:
            with open(CONFIG['exim_log'], 'r') as f:
                lines = f.readlines()[-1000:]

            spam_entries = []
            spam_patterns = [
                (r'spam', 'SPAM detected'),
                (r'rejected', 'Rejected'),
                (r'blocked', 'Blocked'),
                (r'blacklisted', 'Blacklisted'),
                (r'failed SPF', 'SPF failed'),
                (r'DKIM.*fail', 'DKIM fail'),
                (r'reject', 'Reject'),
                (r'deny', 'Deny')
            ]

            for line in lines:
                for pattern, desc in spam_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        sender = re.search(r'from <([^>]+)>', line)
                        recipient = re.search(r'to <([^>]+)>', line)
                        if sender and recipient:
                            sender_email = sender.group(1)
                            recipient_email = recipient.group(1)

                            existing = False
                            for email in self.spam_emails:
                                if email['sender'] == sender_email and email['recipient'] == recipient_email:
                                    existing = True
                                    break

                            if not existing:
                                spam_entries.append({
                                    'sender': sender_email,
                                    'recipient': recipient_email,
                                    'subject': 'From Exim log',
                                    'score': 0.5,
                                    'reason': f"Exim log: {desc}",
                                    'source_ip': None
                                })
                                if '@' in sender_email:
                                    domain = sender_email.split('@')[-1]
                                    if domain not in self.spam_sources:
                                        self.spam_sources.append(domain)

                            self.log.info(f"  Exim log spam: {sender_email} -> {recipient_email} ({desc})")
                            break

            self.spam_emails.extend(spam_entries)
            self.log.info(f"Found {len(spam_entries)} spam entries in Exim logs")

        except Exception as e:
            self.log.error(f"Error reading exim log: {e}")

    def scan_mail_logs(self):
        self.log.info("Scanning mail logs...")
        log_files = ['/var/log/maillog', '/var/log/mail.log']
        for log_file in log_files:
            if not os.path.exists(log_file):
                continue
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()[-500:]
                for line in lines:
                    if re.search(r'(spam|rejected|blocked|blacklist)', line, re.IGNORECASE):
                        sender = re.search(r'from=<([^>]+)>', line)
                        recipient = re.search(r'to=<([^>]+)>', line)
                        if sender and recipient:
                            sender_email = sender.group(1)
                            recipient_email = recipient.group(1)
                            if '@' in sender_email:
                                domain = sender_email.split('@')[-1]
                                if domain not in self.spam_sources:
                                    self.spam_sources.append(domain)
                            self.log.info(f"  Mail log spam: {sender_email} -> {recipient_email}")
            except Exception as e:
                self.log.error(f"Error reading {log_file}: {e}")

    def scan_php_mail_functions(self):
        self.log.info("Scanning PHP mail functions...")
        mail_files = []
        for directory in CONFIG['scan_dirs']:
            if not os.path.exists(directory):
                continue
            for root, dirs, files in os.walk(directory):
                skip = ['cache', 'tmp', 'session', 'backup']
                if any(s in root for s in skip):
                    continue
                for file in files:
                    if file.endswith(('.php', '.phtml', '.php5')):
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            if re.search(r'mail\s*\(', content, re.IGNORECASE):
                                spam_indicators = []
                                for pattern in self.learning_data['spam_patterns']:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        spam_indicators.append("spam pattern")
                                        break
                                blocked_domain_found = None
                                for domain in self.blocked_domains:
                                    if domain in content.lower():
                                        blocked_domain_found = domain
                                        break
                                if spam_indicators or blocked_domain_found:
                                    mail_files.append({
                                        'path': filepath,
                                        'reasons': spam_indicators + ([f"Blocked domain: {blocked_domain_found}"] if blocked_domain_found else [])
                                    })
                                    self.log.warning(f"  PHP mail spam found: {filepath}")
                                    if blocked_domain_found and blocked_domain_found not in self.spam_sources:
                                        self.spam_sources.append(blocked_domain_found)
                        except Exception:
                            pass
        self.log.info(f"Found {len(mail_files)} PHP files with potential spam mail")

    def analyze_spam_sources(self):
        self.log.info("Analyzing spam sources...")
        source_counts = {}
        for source in self.spam_sources:
            source_counts[source] = source_counts.get(source, 0) + 1

        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)

        self.log.info("Top spam sources:")
        for source, count in sorted_sources[:10]:
            self.log.info(f"  {source}: {count} times")

        for source, count in sorted_sources:
            if count > 3 and source not in self.blocked_domains and '.' in source:
                self.log.info(f"  Adding to blocked domains: {source} ({count} occurrences)")
                self.blocked_domains.add(source)
                self.blocked_domains_found.append(source)

    # ============================================
    # SCAN PHP FILES (ORCHESTRATOR)
    # ============================================
    def scan_php_files(self):
        self.log.info("="*50)
        self.log.info("PHASE 2: SCANNING PHP FILES (WebShell + ML + VT)")
        self.log.info("="*50)

        for directory in CONFIG['scan_dirs']:
            if os.path.exists(directory):
                self.log.info(f"Scanning: {directory}")
                for root, dirs, files in os.walk(directory):
                    if self.is_skip_dir(root):
                        continue
                    skip = ['cache', 'tmp', 'session', 'backup']
                    if any(s in root for s in skip):
                        continue
                    for file in files:
                        filepath = os.path.join(root, file)
                        self.scan_php_file(filepath)

        self.log.info(f"PHP scan completed: {len(self.suspicious_files)} suspicious, {len(self.critical_files)} critical")

    # ============================================
    # LEARNING (sama seperti asli)
    # ============================================
    def learn_from_findings(self):
        self.log.info("="*50)
        self.log.info("PHASE 3: LEARNING FROM FINDINGS")
        self.log.info("="*50)

        new_patterns = []

        all_files = self.suspicious_files + self.critical_files
        for file_info in all_files:
            for reason in file_info.get('reasons', []):
                if 'Pattern:' in reason:
                    pattern = reason.replace('Pattern:', '').strip()
                    if pattern not in self.learning_data['dangerous_patterns']:
                        self.learning_data['dangerous_patterns'].append(pattern)
                        new_patterns.append(pattern)
                        self.log.info(f"Learned new pattern: {pattern[:50]}...")

                if 'Function:' in reason:
                    func = reason.replace('Function:', '').replace('()', '').strip()
                    if func not in self.learning_data['dangerous_functions']:
                        self.learning_data['dangerous_functions'].append(func)
                        new_patterns.append(func)
                        self.log.info(f"Learned new function: {func}()")

                if 'Filename:' in reason:
                    name = reason.replace('Filename:', '').strip()
                    if name not in self.learning_data['suspicious_names']:
                        self.learning_data['suspicious_names'].append(name)
                        new_patterns.append(name)
                        self.log.info(f"Learned new suspicious name: {name}")

                if 'CRITICAL:' in reason:
                    crit = reason.replace('CRITICAL:', '').strip()
                    if crit not in self.learning_data.get('critical_patterns', []):
                        if 'critical_patterns' not in self.learning_data:
                            self.learning_data['critical_patterns'] = []
                        self.learning_data['critical_patterns'].append(crit)
                        new_patterns.append(f"CRITICAL: {crit}")
                        self.log.info(f"Learned new critical pattern: {crit}")

        for email in self.spam_emails:
            reason = email.get('reason', '')
            if 'domain blocked' in reason.lower():
                domain_match = re.search(r'blocked: (\S+)', reason)
                if domain_match:
                    domain = domain_match.group(1)
                    if domain not in self.blocked_domains:
                        self.blocked_domains.add(domain)
                        new_patterns.append(f"Domain: {domain}")
                        self.log.info(f"Learned new blocked domain: {domain}")

            subject = email.get('subject', '')
            if subject and len(subject) > 5:
                words = re.findall(r'\b\w+\b', subject.lower())
                for word in words:
                    if len(word) > 4 and word not in ['click', 'here', 'free', 'offer']:
                        pattern = f"r'Subject:.*{word}'"
                        if pattern not in self.learning_data['spam_patterns'] and pattern not in new_patterns:
                            self.learning_data['spam_patterns'].append(pattern)
                            new_patterns.append(f"Spam pattern: {word}")
                            self.log.info(f"Learned new spam pattern: {word}")

        for source in self.blocked_domains_found:
            if source and source not in self.blocked_domains:
                self.blocked_domains.add(source)
                new_patterns.append(f"Blocked domain: {source}")
                self.log.info(f"Added blocked domain: {source}")

        if new_patterns:
            self.new_patterns = new_patterns
            self.save_learning_data()
            self.log.info(f"Learned {len(new_patterns)} new patterns")
        else:
            self.log.info("No new patterns learned")

        return new_patterns

    # ============================================
    # AUTO-UPGRADE (sama seperti asli)
    # ============================================
    def upgrade_script(self):
        self.log.info("="*50)
        self.log.info("PHASE 4: AUTO-UPGRADE (Learning Data Only)")
        self.log.info("="*50)

        script_path = sys.argv[0]
        backup_path = f"{CONFIG['backup_dir']}/sgtcop_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.py"
        try:
            shutil.copy2(script_path, backup_path)
            self.log.info(f"✓ Backup created: {backup_path}")
        except Exception as e:
            self.log.error(f"✗ Error creating backup: {e}")
            return False

        upgrades = []
        upgrades.append("# ============================================")
        upgrades.append(f"# AUTO-UPGRADE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        upgrades.append("# ============================================")

        if self.spam_sources:
            upgrades.append("# SPAM SOURCES FOUND:")
            for source in self.spam_sources[:10]:
                upgrades.append(f"#   - {source}")
            upgrades.append("")

        if self.new_patterns:
            upgrades.append("# NEW PATTERNS LEARNED:")
            for pattern in self.new_patterns[:10]:
                upgrades.append(f"#   - {pattern}")
            upgrades.append("")

        if self.critical_files:
            upgrades.append("# CRITICAL FILES FOUND:")
            for file_info in self.critical_files[:5]:
                upgrades.append(f"#   - {file_info['path']}")
                for r in file_info['reasons'][:2]:
                    upgrades.append(f"#     {r}")
            upgrades.append("")

        if self.php_issues:
            upgrades.append("# PHP SECURITY RECOMMENDATIONS:")
            for issue in self.php_issues[:5]:
                upgrades.append(f"# PHP {issue['version']}:")
                for item in issue['issues'][:2]:
                    upgrades.append(f"#   - {item}")
            upgrades.append("")

        if self.new_patterns:
            self.save_learning_data()
            self.log.info(f"✓ Learning data updated with {len(self.new_patterns)} new patterns")

        if upgrades:
            upgrade_log = f"{CONFIG['backup_dir']}/upgrade_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(upgrade_log, 'w') as f:
                f.write("\n".join(upgrades))
            self.log.info(f"✓ Upgrade log saved: {upgrade_log}")

            self.log.info("=== UPGRADE SUMMARY ===")
            for line in upgrades[:15]:
                self.log.info(f"  {line}")
            self.log.info("=== END UPGRADE SUMMARY ===")

            self.script_upgrades = upgrades
            self.upgrade_applied = True
            return True
        else:
            self.log.info("No upgrades needed")
            return True

    # ============================================
    # GENERATE REPORT (enhanced dengan ML & VT)
    # ============================================
    def generate_report(self):
        lines = []
        lines.append("="*70)
        lines.append("SECURITY SCAN REPORT (Enhanced Edition)")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("="*70)
        lines.append("")

        # SPAM SUMMARY
        lines.append("SPAM SUMMARY:")
        lines.append("-"*50)
        lines.append(f"Spam Emails Found: {len(self.spam_emails)}")
        lines.append(f"Spam Sources Identified: {len(self.spam_sources)}")
        lines.append(f"Blocked Domains Found: {len(self.blocked_domains_found)}")
        lines.append("")

        if self.spam_sources:
            lines.append("TOP SPAM SOURCES:")
            source_counts = {}
            for source in self.spam_sources:
                source_counts[source] = source_counts.get(source, 0) + 1
            sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
            for source, count in sorted_sources[:10]:
                lines.append(f"  - {source}: {count} times")
            lines.append("")

        # CRITICAL FILES (dengan ML & VT)
        if self.critical_files:
            lines.append("💀 CRITICAL FILES FOUND:")
            lines.append("-"*50)
            for i, item in enumerate(self.critical_files, 1):
                lines.append(f"{i}. {item.get('path', 'Unknown')}")
                reasons = item.get('reasons', [])
                if reasons:
                    lines.append(f"   Reasons: {', '.join(reasons[:5])}")
                lines.append(f"   Hash: {item.get('hash', 'N/A')}")
                lines.append(f"   Size: {item.get('size', 0)} bytes")
                # ML Probability
                if item.get('ml_proba') is not None:
                    lines.append(f"   ML Probability: {item['ml_proba']:.2f}")
                # VT Result
                vt = item.get('vt_result')
                if vt and vt.get('malicious', 0) > 0:
                    lines.append(f"   VirusTotal: {vt['malicious']}/{vt['total']} malicious")
                    lines.append(f"   VT Link: {vt.get('permalink', 'N/A')}")
                lines.append("")

        # SUSPICIOUS FILES
        if self.suspicious_files:
            lines.append("⚠️ SUSPICIOUS FILES FOUND:")
            lines.append("-"*50)
            for i, item in enumerate(self.suspicious_files[:20], 1):
                lines.append(f"{i}. {item.get('path', 'Unknown')}")
                reasons = item.get('reasons', [])
                if reasons:
                    lines.append(f"   Reasons: {', '.join(reasons[:3])}")
                lines.append("")
        else:
            if not self.critical_files:
                lines.append("No suspicious files found.")
        lines.append("")

        # PHP Versions
        lines.append("PHP VERSIONS DETECTED:")
        lines.append("-"*50)
        if self.php_versions:
            for version, info in self.php_versions.items():
                lines.append(f"  - PHP {version}")
                if info.get('ini_file'):
                    lines.append(f"    Config: {info['ini_file']}")
        else:
            lines.append("  No PHP versions detected")
        lines.append("")

        # PHP Issues
        if self.php_issues:
            lines.append("PHP CONFIGURATION ISSUES:")
            lines.append("-"*50)
            for issue in self.php_issues:
                lines.append(f"  PHP {issue['version']}:")
                for item in issue['issues']:
                    lines.append(f"    - {item}")
            lines.append("")

        # Spam Emails Detail
        if self.spam_emails:
            lines.append("SPAM EMAILS DETAIL (first 20):")
            lines.append("-"*50)
            for i, email in enumerate(self.spam_emails[:20], 1):
                lines.append(f"{i}. From: {email.get('sender', 'Unknown')}")
                lines.append(f"   To: {email.get('recipient', 'Unknown')}")
                lines.append(f"   Subject: {email.get('subject', 'No subject')}")
                lines.append(f"   Score: {email.get('score', 0):.2f}")
                lines.append(f"   Reason: {email.get('reason', 'N/A')[:100]}")
                if email.get('source_ip'):
                    lines.append(f"   Source IP: {email.get('source_ip')}")
                lines.append("")

        # New Patterns
        if self.new_patterns:
            lines.append("NEW PATTERNS LEARNED:")
            lines.append("-"*50)
            for i, pattern in enumerate(self.new_patterns[:20], 1):
                lines.append(f"{i}. {pattern}")
            lines.append("")

        # Upgrade Status
        if self.upgrade_applied:
            lines.append("UPGRADE STATUS:")
            lines.append("-"*50)
            lines.append("✓ Learning data has been updated!")
            lines.append(f"  Upgrade time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"  New patterns added: {len(self.new_patterns)}")
            lines.append(f"  Spam sources identified: {len(self.spam_sources)}")
            lines.append("")

        # ML & VT Status
        lines.append("ENHANCED FEATURES STATUS:")
        lines.append("-"*50)
        lines.append(f"  Machine Learning: {'✓ Active' if self.ml_model is not None else '✗ Not trained'}")
        lines.append(f"  VirusTotal Integration: {'✓ Enabled' if CONFIG.get('virustotal_api_key') else '✗ Disabled (no API key)'}")
        lines.append(f"  Signature Update: {'✓ Available' if REQUESTS_AVAILABLE else '✗ requests missing'}")
        lines.append("")

        lines.append("="*70)
        lines.append("END OF REPORT")
        lines.append("="*70)

        report = "\n".join(lines)
        with open(CONFIG['report_file'], 'w') as f:
            f.write(report)

        self.log.info(f"Report saved: {CONFIG['report_file']}")
        print("\n" + report)

    # ============================================
    # RUN SCAN (Enhanced)
    # ============================================
    def run_scan(self):
        self.log.info("="*60)
        self.log.info("STARTING SECURITY SCAN (Enhanced with ML & VT)")
        self.log.info("="*60)

        # 1. Update signature database (jika tersedia)
        if REQUESTS_AVAILABLE:
            self.update_signatures()

        # 2. Scan spam
        self.scan_spam()

        # 3. Scan PHP (dengan ML & VT)
        self.scan_php_files()

        # 4. Training ML model (jika ada cukup data)
        self.train_ml_model()

        # 5. Learning
        self.learn_from_findings()

        # 6. Report
        self.generate_report()

        self.log.info("="*60)
        self.log.info("SCAN COMPLETED")
        self.log.info("="*60)
        self.log.info(f"Spam emails found: {len(self.spam_emails)}")
        self.log.info(f"Spam sources: {len(self.spam_sources)}")
        self.log.info(f"Suspicious files: {len(self.suspicious_files)}")
        self.log.info(f"Critical files: {len(self.critical_files)}")
        self.log.info(f"New patterns: {len(self.new_patterns)}")
        self.log.info(f"PHP versions: {len(self.php_versions)}")
        self.log.info(f"PHP issues: {len(self.php_issues)}")
        self.log.info("="*60)

    # ============================================
    # MAIN RUN
    # ============================================
    def run(self):
        if len(sys.argv) > 1:
            if sys.argv[1] == '--upgrade':
                self.log.info("="*60)
                self.log.info("AUTO-UPGRADE MODE")
                self.log.info("="*60)
                self.load_learning_data()
                self.run_scan()
                success = self.upgrade_script()
                if success:
                    self.log.info("="*60)
                    self.log.info("✓ AUTO-UPGRADE COMPLETED SUCCESSFULLY")
                    self.log.info(f"✓ New patterns added: {len(self.new_patterns)}")
                    self.log.info(f"✓ Spam sources: {len(self.spam_sources)}")
                    self.log.info("="*60)
                else:
                    self.log.info("="*60)
                    self.log.info("✗ AUTO-UPGRADE FAILED")
                    self.log.info("="*60)
                return

            elif sys.argv[1] == '--once':
                self.run_scan()
                return

            elif sys.argv[1] == '--update-signatures':
                self.log.info("="*60)
                self.log.info("SIGNATURE UPDATE MODE")
                self.log.info("="*60)
                self.load_learning_data()
                success = self.update_signatures()
                if success:
                    self.log.info("✓ Signatures updated successfully")
                else:
                    self.log.info("✗ Signature update failed")
                return

            elif sys.argv[1] == '--train-ml':
                self.log.info("="*60)
                self.log.info("ML TRAINING MODE")
                self.log.info("="*60)
                self.load_learning_data()
                # Kumpulkan sample dari file yang ada
                self.scan_php_files()
                self.train_ml_model()
                return

            elif sys.argv[1] == '--help':
                self.show_help()
                return

        # Continuous mode
        while True:
            try:
                self.run_scan()
                self.log.info("Waiting 3600 seconds...")
                time.sleep(3600)
            except KeyboardInterrupt:
                self.log.info("Shutting down...")
                break
            except Exception as e:
                self.log.error(f"Error: {e}")
                time.sleep(60)

    def show_help(self):
        print("""
========================================
SECURITY MONITOR - HELP (Enhanced)
========================================

Usage:
  python3 sgtcop.py [OPTIONS]

Options:
  --once                Run scan once and exit
  --upgrade             Auto-upgrade learning data
  --update-signatures   Update signature database from remote server
  --train-ml            Train ML model from existing findings
  --help                Show this help

Scan Priority:
  1. SPAM EMAILS & SOURCES (Primary)
  2. PHP FILES (WebShell + ML + VirusTotal)
  3. LEARNING FROM FINDINGS
  4. AUTO-UPGRADE (learning data only)

Enhanced Features:
  - Machine Learning: RandomForest with 8 features
  - VirusTotal Integration: Query file hash (set VIRUSTOTAL_API_KEY)
  - Signature Database: Auto-update from remote server

Environment Variables:
  VIRUSTOTAL_API_KEY   Set your VirusTotal API key

Examples:
  # Run scan once
  python3 sgtcop.py --once

  # Update signatures
  python3 sgtcop.py --update-signatures

  # Train ML model
  python3 sgtcop.py --train-ml

  # Continuous monitoring (default)
  python3 sgtcop.py

========================================
""")

# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    monitor = SecurityMonitor()
    monitor.run()
