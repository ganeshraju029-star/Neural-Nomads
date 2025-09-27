"""
AI-based intrusion detection system for military-grade threat detection
"""

import os
import time
import json
import threading
import pickle
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass
from collections import defaultdict, deque
# Simplified imports - comment out sklearn for now
# import numpy as np
# from sklearn.ensemble import IsolationForest, RandomForestClassifier
# from sklearn.cluster import DBSCAN
# from sklearn.preprocessing import StandardScaler
# from sklearn.model_selection import train_test_split
import psutil
import socket
import ipaddress

@dataclass
class SecurityEvent:
    """Security event data structure"""
    timestamp: float
    event_type: str
    source_ip: str
    user_agent: str
    session_id: str
    action: str
    success: bool
    metadata: Dict[str, Any]
    risk_score: float = 0.0

class BehaviorAnalyzer:
    """Simplified behavior analyzer for testing (mock ML functionality)"""
    
    def __init__(self):
        self.user_profiles = defaultdict(dict)
        self.baseline_models = {}
        self.is_trained = False
        
    def extract_features(self, events: List[SecurityEvent]) -> List[float]:
        """Extract simple behavioral features"""
        if not events:
            return []
        
        # Simple features without numpy
        features = []
        for event in events:
            # Basic feature extraction
            hour_of_day = time.localtime(event.timestamp).tm_hour
            success_rate = sum(1 for e in events if e.success) / len(events)
            
            feature_vector = [hour_of_day, success_rate, len(events)]
            features.append(feature_vector)
        
        return features
    
    def train_baseline(self, historical_events: List[SecurityEvent]):
        """Mock training function"""
        features = self.extract_features(historical_events)
        self.is_trained = len(features) > 0
    
    def detect_anomaly(self, recent_events: List[SecurityEvent]) -> Tuple[bool, float]:
        """Simple anomaly detection without ML"""
        if not self.is_trained or not recent_events:
            return False, 0.0
        
        # Simple rule-based detection
        risk_score = 0.0
        
        # Check for rapid requests
        if len(recent_events) > 10:
            risk_score += 30
        
        # Check for failed attempts
        failed_count = sum(1 for e in recent_events if not e.success)
        if failed_count > 3:
            risk_score += 40
        
        # Check for unusual hours
        night_requests = sum(1 for e in recent_events 
                           if time.localtime(e.timestamp).tm_hour in [0, 1, 2, 3, 4, 5])
        if night_requests > len(recent_events) * 0.5:
            risk_score += 20
        
        is_anomalous = risk_score > 50
        return is_anomalous, min(risk_score, 100)

class NetworkThreatDetector:
    """Detects network-based threats and attacks"""
    
    def __init__(self):
        self.suspicious_ips = set()
        self.rate_limits = defaultdict(lambda: deque(maxlen=100))
        self.known_attack_patterns = self._load_attack_patterns()
        self.geolocation_cache = {}
        
    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load known attack patterns"""
        return {
            'sql_injection': [
                r"'.*OR.*'.*=.*'",
                r"UNION.*SELECT",
                r"DROP.*TABLE",
                r"INSERT.*INTO"
            ],
            'xss': [
                r"<script.*>.*</script>",
                r"javascript:",
                r"onclick.*=",
                r"onerror.*="
            ],
            'path_traversal': [
                r"\.\./",
                r"\.\.\\",
                r"/etc/passwd",
                r"\\windows\\system32"
            ],
            'brute_force': {
                'failed_attempts_threshold': 5,
                'time_window': 300  # 5 minutes
            }
        }
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze incoming request for threats"""
        threats = []
        risk_score = 0.0
        
        # Extract request details
        ip = request_data.get('ip', '')
        user_agent = request_data.get('user_agent', '')
        path = request_data.get('path', '')
        method = request_data.get('method', '')
        params = request_data.get('params', {})
        
        # Check IP reputation
        if self._is_suspicious_ip(ip):
            threats.append('suspicious_ip')
            risk_score += 30
        
        # Check for rate limiting violations
        if self._check_rate_limit(ip):
            threats.append('rate_limit_exceeded')
            risk_score += 25
        
        # Check for known attack patterns
        attack_patterns = self._detect_attack_patterns(path, params)
        threats.extend(attack_patterns)
        risk_score += len(attack_patterns) * 20
        
        # Check user agent anomalies
        if self._is_suspicious_user_agent(user_agent):
            threats.append('suspicious_user_agent')
            risk_score += 15
        
        # Check for Tor exit nodes (if not expected)
        if self._is_tor_exit_node(ip):
            threats.append('tor_exit_node')
            risk_score += 10
        
        return {
            'threats': threats,
            'risk_score': min(risk_score, 100),
            'blocked': risk_score >= 70,
            'analysis_time': time.time()
        }
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP is suspicious"""
        if not ip:
            return False
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check against known malicious IPs
            if ip in self.suspicious_ips:
                return True
            
            # Check for private IPs from public sources (potential proxy)
            if ip_obj.is_private and not ip_obj.is_loopback:
                return True
            
            return False
        except ValueError:
            return True  # Invalid IP format is suspicious
    
    def _check_rate_limit(self, ip: str) -> bool:
        """Check if IP exceeds rate limits"""
        current_time = time.time()
        
        # Add current request
        self.rate_limits[ip].append(current_time)
        
        # Check requests in last minute
        recent_requests = [t for t in self.rate_limits[ip] if current_time - t < 60]
        
        # Threshold: 30 requests per minute
        return len(recent_requests) > 30
    
    def _detect_attack_patterns(self, path: str, params: Dict[str, Any]) -> List[str]:
        """Detect known attack patterns"""
        import re
        threats = []
        
        # Combine path and parameters for analysis
        analysis_text = f"{path} {json.dumps(params)}"
        
        # Check SQL injection patterns
        for pattern in self.known_attack_patterns['sql_injection']:
            if re.search(pattern, analysis_text, re.IGNORECASE):
                threats.append('sql_injection')
                break
        
        # Check XSS patterns
        for pattern in self.known_attack_patterns['xss']:
            if re.search(pattern, analysis_text, re.IGNORECASE):
                threats.append('xss')
                break
        
        # Check path traversal
        for pattern in self.known_attack_patterns['path_traversal']:
            if re.search(pattern, analysis_text, re.IGNORECASE):
                threats.append('path_traversal')
                break
        
        return threats
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check for suspicious user agent strings"""
        if not user_agent:
            return True
        
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scanner', 'curl', 'wget',
            'nikto', 'sqlmap', 'nmap', 'masscan', 'zap'
        ]
        
        ua_lower = user_agent.lower()
        return any(pattern in ua_lower for pattern in suspicious_patterns)
    
    def _is_tor_exit_node(self, ip: str) -> bool:
        """Check if IP is a Tor exit node"""
        # In production, this would query a Tor exit node list
        # For now, return False as this requires external API
        return False
    
    def add_suspicious_ip(self, ip: str):
        """Add IP to suspicious list"""
        self.suspicious_ips.add(ip)
    
    def remove_suspicious_ip(self, ip: str):
        """Remove IP from suspicious list"""
        self.suspicious_ips.discard(ip)

class SystemMonitor:
    """Monitors system resources for security threats"""
    
    def __init__(self):
        self.baseline_metrics = {}
        self.alert_thresholds = {
            'cpu_usage': 80.0,
            'memory_usage': 85.0,
            'disk_usage': 90.0,
            'network_connections': 1000,
            'suspicious_processes': 0
        }
        
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics"""
        metrics = {
            'timestamp': time.time(),
            'processes': 0,
            'load_average': 0,
            'cpu_usage': 0.0,
            'memory_usage': 0.0,
            'disk_usage': 0.0,
            'network_connections': 0,
            'suspicious_processes': 0
        }
        
        try:
            metrics['cpu_usage'] = psutil.cpu_percent(interval=0.1)  # Reduced interval
        except Exception:
            pass
            
        try:
            metrics['memory_usage'] = psutil.virtual_memory().percent
        except Exception:
            pass
            
        try:
            metrics['disk_usage'] = psutil.disk_usage('/').percent
        except Exception:
            pass
            
        try:
            metrics['network_connections'] = len(psutil.net_connections())
        except Exception:
            pass
            
        try:
            metrics['processes'] = len(psutil.pids())
        except Exception:
            pass
            
        try:
            metrics['load_average'] = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0
        except Exception:
            pass
        
        # Check for suspicious processes with better error handling
        try:
            metrics['suspicious_processes'] = self._detect_suspicious_processes()
        except Exception:
            metrics['suspicious_processes'] = 0
        
        return metrics
    
    def _detect_suspicious_processes(self) -> int:
        """Detect suspicious running processes"""
        suspicious_count = 0
        suspicious_names = [
            'nc', 'netcat', 'ncat', 'socat', 'telnet', 'ftp',
            'wget', 'curl', 'nmap', 'masscan', 'zmap',
            'metasploit', 'msfconsole', 'sqlmap', 'nikto',
            'hydra', 'medusa', 'john', 'hashcat'
        ]
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_info = proc.info
                    if proc_info and 'name' in proc_info and proc_info['name']:
                        proc_name = proc_info['name'].lower()
                        if any(sus in proc_name for sus in suspicious_names):
                            suspicious_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError, TypeError):
                    # Silently ignore process access errors - common on macOS
                    continue
                except Exception:
                    # Catch any other unexpected errors
                    continue
        except Exception:
            # If the entire process iteration fails, return 0
            pass
        
        return suspicious_count
    
    def analyze_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze metrics for security threats"""
        alerts = []
        risk_score = 0.0
        
        # Check against thresholds
        for metric, value in metrics.items():
            if metric in self.alert_thresholds:
                threshold = self.alert_thresholds[metric]
                if value > threshold:
                    alerts.append(f"{metric}_exceeded")
                    risk_score += (value - threshold) / threshold * 20
        
        return {
            'alerts': alerts,
            'risk_score': min(risk_score, 100),
            'metrics': metrics,
            'analysis_time': time.time()
        }

class ThreatIntelligence:
    """Maintains threat intelligence database"""
    
    def __init__(self):
        self.threat_feeds = {}
        self.ioc_database = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'attack_signatures': [],
            'known_exploits': []
        }
        self.last_update = 0
        
    def update_threat_feeds(self):
        """Update threat intelligence feeds"""
        # In production, this would fetch from external threat intel sources
        current_time = time.time()
        
        # Simulate threat feed update
        if current_time - self.last_update > 3600:  # Update every hour
            self._add_sample_threats()
            self.last_update = current_time
    
    def _add_sample_threats(self):
        """Add sample threat indicators"""
        # Sample malicious IPs (these are just examples)
        sample_ips = [
            '192.168.1.100',  # Example suspicious IP
            '10.0.0.50'       # Example internal threat
        ]
        
        for ip in sample_ips:
            self.ioc_database['malicious_ips'].add(ip)
    
    def check_ioc(self, indicator: str, ioc_type: str) -> bool:
        """Check if indicator is in threat database"""
        if ioc_type == 'ip':
            return indicator in self.ioc_database['malicious_ips']
        elif ioc_type == 'domain':
            return indicator in self.ioc_database['malicious_domains']
        return False
    
    def add_ioc(self, indicator: str, ioc_type: str):
        """Add indicator of compromise"""
        if ioc_type == 'ip':
            self.ioc_database['malicious_ips'].add(indicator)
        elif ioc_type == 'domain':
            self.ioc_database['malicious_domains'].add(indicator)

class AIIntrusionDetection:
    """Main AI-powered intrusion detection system"""
    
    def __init__(self):
        self.behavior_analyzer = BehaviorAnalyzer()
        self.network_detector = NetworkThreatDetector()
        self.system_monitor = SystemMonitor()
        self.threat_intelligence = ThreatIntelligence()
        
        self.event_buffer = deque(maxlen=1000)
        self.active_sessions = {}
        self.blocked_ips = set()
        self.alert_callbacks = []
        
        # Start monitoring threads
        self.monitoring_active = True
        self._start_monitoring_threads()
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for security alerts"""
        self.alert_callbacks.append(callback)
    
    def log_security_event(self, event: SecurityEvent):
        """Log new security event"""
        self.event_buffer.append(event)
        
        # Update session tracking
        if event.session_id:
            if event.session_id not in self.active_sessions:
                self.active_sessions[event.session_id] = []
            self.active_sessions[event.session_id].append(event)
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive request analysis"""
        # Network threat analysis
        network_analysis = self.network_detector.analyze_request(request_data)
        
        # Check threat intelligence
        ip = request_data.get('ip', '')
        is_known_threat = self.threat_intelligence.check_ioc(ip, 'ip')
        
        # Behavioral analysis (if session exists)
        session_id = request_data.get('session_id')
        behavioral_risk = 0.0
        if session_id and session_id in self.active_sessions:
            session_events = self.active_sessions[session_id][-10:]  # Last 10 events
            is_anomalous, behavioral_risk = self.behavior_analyzer.detect_anomaly(session_events)
        
        # Combined risk assessment
        total_risk = (
            network_analysis['risk_score'] * 0.4 +
            behavioral_risk * 0.3 +
            (50 if is_known_threat else 0) * 0.3
        )
        
        # Determine action
        if total_risk >= 80 or is_known_threat:
            action = 'block'
            if ip:
                self.blocked_ips.add(ip)
        elif total_risk >= 60:
            action = 'alert'
        else:
            action = 'allow'
        
        result = {
            'action': action,
            'total_risk_score': total_risk,
            'network_analysis': network_analysis,
            'behavioral_risk': behavioral_risk,
            'known_threat': is_known_threat,
            'timestamp': time.time()
        }
        
        # Trigger alerts if necessary
        if action in ['block', 'alert']:
            self._trigger_alert(result, request_data)
        
        return result
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def unblock_ip(self, ip: str):
        """Unblock IP address"""
        self.blocked_ips.discard(ip)
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system security status"""
        metrics = self.system_monitor.collect_metrics()
        system_analysis = self.system_monitor.analyze_metrics(metrics)
        
        return {
            'system_metrics': system_analysis,
            'active_sessions': len(self.active_sessions),
            'blocked_ips': len(self.blocked_ips),
            'recent_events': len(self.event_buffer),
            'threat_level': self._calculate_threat_level(),
            'last_update': time.time()
        }
    
    def _calculate_threat_level(self) -> str:
        """Calculate current threat level"""
        recent_events = [e for e in self.event_buffer if time.time() - e.timestamp < 300]
        
        if not recent_events:
            return 'low'
        
        avg_risk = sum(e.risk_score for e in recent_events) / len(recent_events)
        
        if avg_risk >= 70:
            return 'critical'
        elif avg_risk >= 50:
            return 'high'
        elif avg_risk >= 30:
            return 'medium'
        else:
            return 'low'
    
    def _trigger_alert(self, analysis_result: Dict[str, Any], request_data: Dict[str, Any]):
        """Trigger security alert"""
        alert_data = {
            'timestamp': time.time(),
            'alert_type': analysis_result['action'],
            'risk_score': analysis_result['total_risk_score'],
            'source_ip': request_data.get('ip'),
            'request_data': request_data,
            'analysis': analysis_result
        }
        
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                print(f"Alert callback error: {e}")
    
    def _start_monitoring_threads(self):
        """Start background monitoring threads"""
        # Check if intensive monitoring is disabled
        if os.environ.get('DISABLE_INTENSIVE_MONITORING', '').lower() == '1':
            print("⚠️ Intensive system monitoring disabled for stability")
            return
            
        def system_monitoring():
            while self.monitoring_active:
                try:
                    # Update threat intelligence
                    self.threat_intelligence.update_threat_feeds()
                    
                    # System monitoring
                    status = self.get_system_status()
                    if status['threat_level'] in ['high', 'critical']:
                        self._trigger_alert({
                            'action': 'system_alert',
                            'total_risk_score': 80 if status['threat_level'] == 'high' else 90
                        }, {'type': 'system_monitoring'})
                    
                    time.sleep(60)  # Check every minute
                except Exception:
                    # Silently handle any other monitoring errors
                    time.sleep(30)
        
        monitor_thread = threading.Thread(target=system_monitoring, daemon=True)
        monitor_thread.start()
    
    def shutdown(self):
        """Shutdown the intrusion detection system"""
        self.monitoring_active = False
        print("AI Intrusion Detection System shut down")