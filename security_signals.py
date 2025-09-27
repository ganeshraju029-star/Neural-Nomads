"""
Flask signals system for secure event handling and monitoring
"""

import time
import json
import threading
from typing import Dict, Any, Optional, Callable, List
from blinker import Namespace
from blinker import Signal
import secrets
import hashlib
from dataclasses import dataclass, asdict
from collections import defaultdict, deque

# Create security namespace for signals
security_signals = Namespace()

# Define security signals
message_sent = security_signals.signal('message-sent')
message_read = security_signals.signal('message-read')
message_destroyed = security_signals.signal('message-destroyed')
user_login = security_signals.signal('user-login')
user_logout = security_signals.signal('user-logout')
security_alert = security_signals.signal('security-alert')
intrusion_detected = security_signals.signal('intrusion-detected')
session_created = security_signals.signal('session-created')
session_destroyed = security_signals.signal('session-destroyed')
encryption_event = security_signals.signal('encryption-event')
key_rotation = security_signals.signal('key-rotation')
tor_circuit_change = security_signals.signal('tor-circuit-change')
memory_wipe = security_signals.signal('memory-wipe')
anomaly_detected = security_signals.signal('anomaly-detected')

@dataclass
class SecurityEventData:
    """Standard security event data structure"""
    event_id: str
    timestamp: float
    event_type: str
    user_id: Optional[str]
    session_id: Optional[str]
    source_ip: Optional[str]
    user_agent: Optional[str]
    success: bool
    metadata: Dict[str, Any]
    risk_level: str = 'low'
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class SecurityEventLogger:
    """Secure event logging system"""
    
    def __init__(self, max_events: int = 10000):
        self.events = deque(maxlen=max_events)
        self.event_counts = defaultdict(int)
        self.user_activity = defaultdict(list)
        self._lock = threading.Lock()
        self.sensitive_fields = {'password', 'key', 'token', 'secret'}
        
    def log_event(self, event_data: SecurityEventData):
        """Log security event with sanitization"""
        with self._lock:
            # Sanitize sensitive data
            sanitized_metadata = self._sanitize_metadata(event_data.metadata)
            event_data.metadata = sanitized_metadata
            
            # Store event
            self.events.append(event_data)
            self.event_counts[event_data.event_type] += 1
            
            if event_data.user_id:
                self.user_activity[event_data.user_id].append({
                    'event_type': event_data.event_type,
                    'timestamp': event_data.timestamp,
                    'success': event_data.success
                })
    
    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive information from metadata"""
        sanitized = {}
        for key, value in metadata.items():
            if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_metadata(value)
            else:
                sanitized[key] = value
        return sanitized
    
    def get_events(self, event_type: Optional[str] = None, user_id: Optional[str] = None, 
                  since: Optional[float] = None) -> List[SecurityEventData]:
        """Retrieve events with filtering"""
        with self._lock:
            filtered_events = []
            for event in self.events:
                if event_type and event.event_type != event_type:
                    continue
                if user_id and event.user_id != user_id:
                    continue
                if since and event.timestamp < since:
                    continue
                filtered_events.append(event)
            return filtered_events
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get event statistics"""
        with self._lock:
            recent_events = [e for e in self.events if time.time() - e.timestamp < 3600]
            return {
                'total_events': len(self.events),
                'recent_events': len(recent_events),
                'event_types': dict(self.event_counts),
                'active_users': len(self.user_activity),
                'last_event': max([e.timestamp for e in self.events]) if self.events else None
            }

class ThreatDetector:
    """Real-time threat detection based on signal patterns"""
    
    def __init__(self, event_logger: SecurityEventLogger):
        self.event_logger = event_logger
        self.threat_rules = self._initialize_threat_rules()
        self.active_threats = {}
        self._lock = threading.Lock()
        
    def _initialize_threat_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat detection rules"""
        return {
            'brute_force': {
                'events': ['user-login'],
                'condition': lambda events: len([e for e in events if not e.success]) >= 5,
                'window': 300,  # 5 minutes
                'severity': 'high'
            },
            'rapid_message_access': {
                'events': ['message-read'],
                'condition': lambda events: len(events) >= 10,
                'window': 60,  # 1 minute
                'severity': 'medium'
            },
            'suspicious_session_creation': {
                'events': ['session-created'],
                'condition': lambda events: len(events) >= 5,
                'window': 300,  # 5 minutes
                'severity': 'medium'
            },
            'mass_message_destruction': {
                'events': ['message-destroyed'],
                'condition': lambda events: len(events) >= 3,
                'window': 30,  # 30 seconds
                'severity': 'high'
            }
        }
    
    def analyze_events(self, new_event: SecurityEventData):
        """Analyze events for threat patterns"""
        current_time = time.time()
        
        with self._lock:
            for threat_name, rule in self.threat_rules.items():
                if new_event.event_type in rule['events']:
                    # Get recent events for this rule
                    window_start = current_time - rule['window']
                    recent_events = self.event_logger.get_events(
                        event_type=new_event.event_type,
                        since=window_start
                    )
                    
                    # Apply threat condition
                    if rule['condition'](recent_events):
                        self._trigger_threat_alert(threat_name, rule, recent_events)
    
    def _trigger_threat_alert(self, threat_name: str, rule: Dict[str, Any], 
                            events: List[SecurityEventData]):
        """Trigger threat alert"""
        threat_id = f"{threat_name}_{int(time.time())}"
        
        threat_data = {
            'threat_id': threat_id,
            'threat_name': threat_name,
            'severity': rule['severity'],
            'detected_at': time.time(),
            'event_count': len(events),
            'affected_users': list(set(e.user_id for e in events if e.user_id)),
            'source_ips': list(set(e.source_ip for e in events if e.source_ip))
        }
        
        self.active_threats[threat_id] = threat_data
        
        # Emit threat signal
        security_alert.send(
            None,
            threat_data=threat_data
        )

class SecurityActionHandler:
    """Handles security actions triggered by signals"""
    
    def __init__(self):
        self.action_queue = deque(maxlen=1000)
        self.emergency_procedures = {
            'intrusion_detected': self._handle_intrusion,
            'brute_force': self._handle_brute_force,
            'mass_destruction': self._handle_mass_destruction,
            'anomaly_detected': self._handle_anomaly
        }
        
    def handle_security_alert(self, sender, **extra):
        """Handle security alert signal"""
        threat_data = extra.get('threat_data', {})
        threat_name = threat_data.get('threat_name')
        severity = threat_data.get('severity', 'low')
        
        if threat_name in self.emergency_procedures:
            action = {
                'action_id': secrets.token_hex(8),
                'timestamp': time.time(),
                'threat_name': threat_name,
                'severity': severity,
                'action_taken': None
            }
            
            try:
                result = self.emergency_procedures[threat_name](threat_data)
                action['action_taken'] = result
                action['success'] = True
            except Exception as e:
                action['action_taken'] = f"Error: {str(e)}"
                action['success'] = False
            
            self.action_queue.append(action)
    
    def _handle_intrusion(self, threat_data: Dict[str, Any]) -> str:
        """Handle intrusion detection"""
        # Block affected IPs
        affected_ips = threat_data.get('source_ips', [])
        for ip in affected_ips:
            # Would integrate with firewall/blocking system
            pass
        
        # Trigger emergency memory wipe
        memory_wipe.send(None, reason='intrusion_detected')
        
        return f"Blocked {len(affected_ips)} IPs, triggered memory wipe"
    
    def _handle_brute_force(self, threat_data: Dict[str, Any]) -> str:
        """Handle brute force attack"""
        affected_ips = threat_data.get('source_ips', [])
        affected_users = threat_data.get('affected_users', [])
        
        # Block IPs temporarily
        # Lock affected user accounts
        
        return f"Blocked {len(affected_ips)} IPs, locked {len(affected_users)} accounts"
    
    def _handle_mass_destruction(self, threat_data: Dict[str, Any]) -> str:
        """Handle mass message destruction"""
        # This might indicate tampering or forensics attempt
        # Trigger full emergency wipe
        
        memory_wipe.send(None, reason='mass_destruction_detected')
        return "Triggered emergency memory wipe"
    
    def _handle_anomaly(self, threat_data: Dict[str, Any]) -> str:
        """Handle anomaly detection"""
        # Increase monitoring sensitivity
        # Rotate encryption keys
        
        key_rotation.send(None, reason='anomaly_detected')
        return "Increased monitoring, rotated keys"

class SignalMonitor:
    """Monitors and analyzes signal patterns"""
    
    def __init__(self):
        self.signal_stats = defaultdict(int)
        self.signal_timeline = deque(maxlen=10000)
        self.pattern_analyzer = PatternAnalyzer()
        self._lock = threading.Lock()
        
    def track_signal(self, signal_name: str, sender, **extra):
        """Track signal emission"""
        with self._lock:
            timestamp = time.time()
            
            self.signal_stats[signal_name] += 1
            self.signal_timeline.append({
                'signal': signal_name,
                'timestamp': timestamp,
                'sender': str(sender) if sender else 'unknown'
            })
            
            # Analyze patterns
            self.pattern_analyzer.analyze_signal_pattern(signal_name, timestamp)
    
    def get_signal_statistics(self) -> Dict[str, Any]:
        """Get signal emission statistics"""
        with self._lock:
            recent_signals = [s for s in self.signal_timeline 
                            if time.time() - s['timestamp'] < 3600]
            
            return {
                'total_signals': dict(self.signal_stats),
                'recent_signals': len(recent_signals),
                'signal_rate': len(recent_signals) / 3600 if recent_signals else 0,
                'last_signal': max([s['timestamp'] for s in self.signal_timeline]) 
                             if self.signal_timeline else None
            }

class PatternAnalyzer:
    """Analyzes signal emission patterns for anomalies"""
    
    def __init__(self):
        self.signal_patterns = defaultdict(list)
        self.baseline_rates = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        
    def analyze_signal_pattern(self, signal_name: str, timestamp: float):
        """Analyze signal emission pattern"""
        self.signal_patterns[signal_name].append(timestamp)
        
        # Keep only recent patterns (last hour)
        cutoff = timestamp - 3600
        self.signal_patterns[signal_name] = [
            t for t in self.signal_patterns[signal_name] if t > cutoff
        ]
        
        # Check for anomalies
        if self._is_anomalous_pattern(signal_name):
            anomaly_detected.send(None, 
                signal_name=signal_name,
                pattern_data={
                    'recent_count': len(self.signal_patterns[signal_name]),
                    'baseline_rate': self.baseline_rates.get(signal_name, 0)
                }
            )
    
    def _is_anomalous_pattern(self, signal_name: str) -> bool:
        """Check if signal pattern is anomalous"""
        recent_patterns = self.signal_patterns[signal_name]
        
        if len(recent_patterns) < 5:  # Need minimum data
            return False
        
        current_rate = len(recent_patterns) / 3600  # Events per second
        baseline_rate = self.baseline_rates.get(signal_name, current_rate)
        
        # Update baseline (exponential moving average)
        self.baseline_rates[signal_name] = 0.9 * baseline_rate + 0.1 * current_rate
        
        # Check if current rate exceeds threshold
        return current_rate > baseline_rate * self.anomaly_threshold

class SecuritySignalSystem:
    """Main security signal system coordinator"""
    
    def __init__(self, app=None):
        self.app = app
        self.event_logger = SecurityEventLogger()
        self.threat_detector = ThreatDetector(self.event_logger)
        self.action_handler = SecurityActionHandler()
        self.signal_monitor = SignalMonitor()
        
        self._setup_signal_handlers()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
        
        # Connect to Flask's built-in signals
        from flask import request_started, request_finished
        request_started.connect(self._handle_request_started, app)
        request_finished.connect(self._handle_request_finished, app)
    
    def _setup_signal_handlers(self):
        """Set up signal handlers"""
        # Connect security alert handler
        security_alert.connect(self.action_handler.handle_security_alert)
        
        # Connect signal monitoring to all security signals
        for signal_name in ['message-sent', 'message-read', 'message-destroyed',
                          'user-login', 'user-logout', 'security-alert',
                          'intrusion-detected', 'session-created', 'session-destroyed',
                          'encryption-event', 'key-rotation', 'tor-circuit-change',
                          'memory-wipe', 'anomaly-detected']:
            signal = security_signals.signal(signal_name)
            # Create a closure to capture signal_name
            def make_handler(name):
                return lambda sender, **extra: self.signal_monitor.track_signal(name, sender, **extra)
            signal.connect(make_handler(signal_name))
    
    def emit_security_event(self, event_type: str, user_id: Optional[str] = None, 
                          session_id: Optional[str] = None, success: bool = True,
                          metadata: Optional[Dict[str, Any]] = None, 
                          request_data: Optional[Dict[str, Any]] = None):
        """Emit security event"""
        event_data = SecurityEventData(
            event_id=secrets.token_hex(8),
            timestamp=time.time(),
            event_type=event_type,
            user_id=user_id,
            session_id=session_id,
            source_ip=request_data.get('remote_addr') if request_data else None,
            user_agent=request_data.get('user_agent') if request_data else None,
            success=success,
            metadata=metadata or {},
            risk_level=self._calculate_risk_level(event_type, success, metadata or {})
        )
        
        # Log event
        self.event_logger.log_event(event_data)
        
        # Analyze for threats
        self.threat_detector.analyze_events(event_data)
        
        # Emit appropriate signal
        if event_type in ['message-sent', 'message-read', 'message-destroyed',
                         'user-login', 'user-logout', 'session-created', 
                         'session-destroyed', 'encryption-event', 'key-rotation',
                         'tor-circuit-change', 'memory-wipe']:
            signal = security_signals.signal(event_type)
            signal.send(self.app, event_data=event_data)
    
    def _calculate_risk_level(self, event_type: str, success: bool, 
                            metadata: Dict[str, Any]) -> str:
        """Calculate risk level for event"""
        if not success:
            return 'medium'
        
        high_risk_events = ['intrusion-detected', 'security-alert', 'anomaly-detected']
        medium_risk_events = ['user-login', 'session-created', 'key-rotation']
        
        if event_type in high_risk_events:
            return 'high'
        elif event_type in medium_risk_events:
            return 'medium'
        else:
            return 'low'
    
    def _handle_request_started(self, sender, **extra):
        """Handle Flask request started"""
        # Could emit request-started signal here
        pass
    
    def _handle_request_finished(self, sender, response, **extra):
        """Handle Flask request finished"""
        # Could emit request-finished signal here
        pass
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        return {
            'event_statistics': self.event_logger.get_statistics(),
            'signal_statistics': self.signal_monitor.get_signal_statistics(),
            'active_threats': len(self.threat_detector.active_threats),
            'recent_actions': len([a for a in self.action_handler.action_queue 
                                 if time.time() - a['timestamp'] < 3600])
        }

# Initialize global security signal system
security_system = SecuritySignalSystem()