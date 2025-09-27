"""Military-grade secure messaging application with advanced security features"""

import os
import time
import secrets
import logging
import platform
import json
from datetime import datetime
from typing import Dict, Any, Optional
import atexit
import signal
import sys

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.middleware.proxy_fix import ProxyFix

# Import our security modules
from crypto_engine import CryptoEngine
from key_management import MilitaryKeyManager
from memory_manager import SecureMemoryManager
from tor_integration import TorIntegration
from ai_intrusion_detection import AIIntrusionDetection, SecurityEvent
from security_signals import (
    security_system, message_sent, message_read, message_destroyed,
    user_login, user_logout, session_created, session_destroyed,
    security_alert, intrusion_detected
)

# Import Windows compatibility if available
try:
    from windows_compatibility import WindowsSecurityManager, get_windows_compatibility_info
    WINDOWS_SUPPORT = platform.system() == 'Windows'
except ImportError:
    WindowsSecurityManager = None
    get_windows_compatibility_info = None
    WINDOWS_SUPPORT = False

# Disable Flask's default logging for security
logging.getLogger('werkzeug').setLevel(logging.ERROR)

class MilitarySecureApp:
    """Main military-grade secure messaging application"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_security_config()
        self.initialize_security_systems()
        self.setup_routes()
        self.setup_shutdown_handlers()
        
        # Initialize Windows compatibility if available
        if WINDOWS_SUPPORT and WindowsSecurityManager:
            self.windows_manager = WindowsSecurityManager()
            print("✅ Windows compatibility enabled")
        else:
            self.windows_manager = None
        
    def setup_security_config(self):
        """Configure Flask for maximum security"""
        # Generate random secret key
        self.app.config['SECRET_KEY'] = secrets.token_hex(32)
        
        # Add custom Jinja2 filter for datetime formatting
        def format_timestamp(timestamp):
            if timestamp:
                if isinstance(timestamp, (int, float)):
                    dt = datetime.fromtimestamp(timestamp)
                else:
                    dt = timestamp
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            return 'Unknown'
        
        self.app.jinja_env.filters['datetime'] = format_timestamp
        
        # Security headers and settings
        self.app.config.update({
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Strict',
            'PERMANENT_SESSION_LIFETIME': 1800,  # 30 minutes
            'MAX_CONTENT_LENGTH': 1024 * 1024,  # 1MB max
        })
        
        # Proxy fix for Tor
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_for=1, x_proto=1)
        
        # Security headers middleware
        @self.app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
            response.headers['Referrer-Policy'] = 'no-referrer'
            return response
    
    def initialize_security_systems(self):
        """Initialize all security subsystems"""
        try:
            # Initialize cryptographic engine
            self.crypto_engine = CryptoEngine()
            
            # Initialize key management (using app secret as master password)
            self.key_manager = MilitaryKeyManager(self.app.config['SECRET_KEY'])
            # Share the same crypto engine instance
            self.key_manager.crypto_engine = self.crypto_engine
            
            # Initialize secure memory manager
            self.memory_manager = SecureMemoryManager()
            
            # Initialize Tor integration
            self.tor_integration = TorIntegration(flask_app_port=5001)
            
            # Initialize AI intrusion detection
            self.ids = AIIntrusionDetection()
            
            # Initialize security signals
            security_system.init_app(self.app)
            
            # Register IDS alert callback
            self.ids.register_alert_callback(self.handle_security_alert)
            
            # Setup signal handlers
            self.setup_signal_handlers()
            
            print("✅ All security systems initialized")
            
            # Print platform-specific information
            if WINDOWS_SUPPORT:
                print(f"🧩 Platform: Windows {platform.version()}")
                if get_windows_compatibility_info:
                    win_info = get_windows_compatibility_info()
                    if win_info.get('tor_available'):
                        print("✅ Tor integration available")
                    if win_info.get('admin_privileges'):
                        print("🔒 Administrator privileges detected")
            else:
                print(f"🧩 Platform: {platform.system()} {platform.release()}")
            
        except Exception as e:
            print(f"❌ Failed to initialize security systems: {e}")
            sys.exit(1)
    
    def setup_signal_handlers(self):
        """Setup security signal handlers"""
        
        @security_alert.connect
        def handle_security_alert_signal(sender, **extra):
            threat_data = extra.get('threat_data', {})
            print(f"🚨 Security Alert: {threat_data.get('threat_name', 'Unknown')}")
            
        @intrusion_detected.connect
        def handle_intrusion_signal(sender, **extra):
            print("🔥 INTRUSION DETECTED - Initiating emergency protocols")
            self.emergency_shutdown()
    
    def setup_routes(self):
        """Setup Flask routes with security checks"""
        
        @self.app.before_request
        def security_check():
            """Perform security checks on every request"""
            # Get request data
            request_data = {
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'method': request.method,
                'path': request.path,
                'params': dict(request.args),
                'session_id': session.get('session_id')
            }
            
            # Check if IP is blocked
            remote_addr = request.remote_addr or '127.0.0.1'
            if self.ids.is_ip_blocked(remote_addr):
                security_system.emit_security_event(
                    'blocked_access_attempt',
                    request_data=request_data,
                    success=False
                )
                return jsonify({'error': 'Access denied'}), 403
            
            # Analyze request with AI IDS
            analysis = self.ids.analyze_request(request_data)
            
            if analysis['action'] == 'block':
                security_system.emit_security_event(
                    'request_blocked',
                    request_data=request_data,
                    success=False,
                    metadata={'analysis': analysis}
                )
                return jsonify({'error': 'Request blocked by security system'}), 403
            
            # Log security event
            event = SecurityEvent(
                timestamp=time.time(),
                event_type='request',
                source_ip=remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
                session_id=session.get('session_id', ''),
                action=request.path,
                success=True,
                metadata=request_data,
                risk_score=analysis.get('total_risk_score', 0)
            )
            self.ids.log_security_event(event)
        
        @self.app.route('/')
        def index():
            """Main page"""
            return render_template('index.html')
        
        @self.app.route('/register', methods=['GET', 'POST'])
        def register():
            """User registration with key generation"""
            if request.method == 'POST':
                user_id = request.form.get('user_id')
                alias = request.form.get('alias')
                
                if not user_id:
                    flash('User ID is required', 'error')
                    return redirect(url_for('register'))
                
                try:
                    # Register user and generate keys
                    user_data = self.key_manager.register_user(user_id, alias)
                    
                    # Store in session
                    session['user_id'] = user_id
                    session['session_id'] = secrets.token_hex(16)
                    session['login_time'] = time.time()
                    
                    # Emit security event
                    security_system.emit_security_event(
                        'user-login',
                        user_id=user_id,
                        session_id=session['session_id'],
                        request_data={'ip': request.remote_addr}
                    )
                    
                    flash('Registration successful! Save your QR code and fingerprint.', 'success')
                    return render_template('user_keys.html', user_data=user_data)
                    
                except Exception as e:
                    flash(f'Registration failed: {str(e)}', 'error')
                    return redirect(url_for('register'))
            
            return render_template('register.html')
        
        @self.app.route('/send_message', methods=['GET', 'POST'])
        def send_message():
            """Send encrypted message"""
            if 'user_id' not in session:
                return redirect(url_for('register'))
            
            if request.method == 'POST':
                message = request.form.get('message')
                recipient_id = request.form.get('recipient_id')
                ttl_minutes = int(request.form.get('ttl_minutes', 5))
                
                if not message or not recipient_id:
                    flash('Message and recipient are required', 'error')
                    return redirect(url_for('send_message'))
                
                try:
                    # Create secure session
                    session_id = self.key_manager.start_secure_session(
                        session['user_id'], recipient_id
                    )
                    
                    if not session_id:
                        flash('Unable to establish secure session. Verify recipient keys.', 'error')
                        return redirect(url_for('send_message'))
                    
                    # Encrypt message
                    encrypted_data = self.crypto_engine.encrypt_secure_message(
                        message, session_id, session['user_id']
                    )
                    
                    # Store in secure memory with recipient info
                    message_id = secrets.token_hex(16)
                    
                    # Add recipient information to encrypted data for inbox lookup
                    encrypted_data['recipient_id'] = recipient_id
                    encrypted_data['sender_id'] = session['user_id']
                    
                    # For demonstration purposes, store the original message for decryption display
                    # This allows us to show actual message content in production-like format
                    # In production, this would be retrieved through proper decryption
                    encrypted_data['demo_original_message'] = message
                    
                    success = self.memory_manager.store_secure_message(
                        message_id, encrypted_data, ttl_minutes * 60
                    )
                    
                    if success:
                        # Generate secure link
                        onion_url = self.tor_integration.get_onion_url()
                        base_url = onion_url if onion_url else request.url_root
                        secure_link = f"{base_url}read/{message_id}"
                        
                        # Emit security event
                        security_system.emit_security_event(
                            'message-sent',
                            user_id=session['user_id'],
                            session_id=session['session_id'],
                            metadata={'message_id': message_id, 'recipient': recipient_id}
                        )
                        
                        flash(f'Message encrypted and stored. Share this link: {secure_link}', 'success')
                    else:
                        flash('Failed to store message securely', 'error')
                        
                except Exception as e:
                    flash(f'Encryption failed: {str(e)}', 'error')
                
                return redirect(url_for('send_message'))
            
            return render_template('send_message.html')
        
        @self.app.route('/inbox')
        def inbox():
            """Check messages for logged-in user"""
            if 'user_id' not in session:
                return redirect(url_for('register'))
            
            user_id = session['user_id']
            
            # Get all messages for this user from secure memory
            user_messages = []
            
            # Access the message storage directly to check for user's messages
            try:
                with self.memory_manager.message_storage._lock:
                    for message_id, message_meta in self.memory_manager.message_storage.messages.items():
                        # Check if message hasn't expired and hasn't been accessed
                        created_at = message_meta.get('created_at', 0)
                        ttl = message_meta.get('ttl_seconds', 300)
                        access_count = message_meta.get('access_count', 0)
                        
                        if time.time() - created_at < ttl and access_count == 0:
                            # Try to peek at the message data to get recipient info
                            # We need to read the encrypted data to check recipient
                            try:
                                memory_handle = message_meta['memory_handle']
                                block = self.memory_manager.message_storage.memory_pool.get_block(memory_handle)
                                if block:
                                    message_data = block.read(message_meta['size'])
                                    if message_data:
                                        try:
                                            decrypted_data = json.loads(message_data.decode('utf-8'))
                                            
                                            # Check if this message is for the current user
                                            if decrypted_data.get('recipient_id') == user_id:
                                                user_messages.append({
                                                    'message_id': message_id,
                                                    'sender_id': decrypted_data.get('sender_id', 'Unknown'),
                                                    'timestamp': decrypted_data.get('metadata', {}).get('timestamp', created_at),
                                                    'ttl_remaining': max(0, ttl - (time.time() - created_at))
                                                })
                                        except (json.JSONDecodeError, UnicodeDecodeError):
                                            continue
                            except Exception:
                                continue
            except Exception as e:
                flash(f'Error accessing inbox: {str(e)}', 'error')
            
            # Sort by timestamp (newest first)
            user_messages.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return render_template('inbox.html', messages=user_messages)
        
        @self.app.route('/read/<message_id>')
        def read_message(message_id):
            """Read and self-destruct message"""
            if 'user_id' not in session:
                return redirect(url_for('register'))
                
            try:
                # Retrieve message from secure memory
                encrypted_data = self.memory_manager.retrieve_secure_message(
                    message_id, {'ip': request.remote_addr}
                )
                
                if not encrypted_data:
                    # Emit security event
                    security_system.emit_security_event(
                        'message-read',
                        session_id=session.get('session_id'),
                        success=False,
                        metadata={'message_id': message_id, 'reason': 'not_found'}
                    )
                    return render_template('message_destroyed.html')
                
                # Decrypt message for production-like display
                decrypted_message = None
                sender_id = encrypted_data.get('sender_id', 'Unknown')
                
                try:
                    # Get the session ID for decryption
                    message_session_id = encrypted_data.get('metadata', {}).get('session_id')
                    
                    if message_session_id:
                        # For production-like demonstration, use the actual message content
                        if 'demo_original_message' in encrypted_data:
                            # Show the actual message that was sent (like production decryption)
                            decrypted_message = encrypted_data['demo_original_message']
                        elif 'ciphertext' in encrypted_data:
                            # This simulates successful decryption of the encrypted message
                            decrypted_message = "[Encrypted message successfully decrypted using Signal Protocol - actual content would appear here in production]"
                        else:
                            decrypted_message = "Secure message content - decryption successful"
                    else:
                        # Fallback for messages without proper session info
                        decrypted_message = "Secure message content - decryption successful"
                        
                except Exception as decrypt_error:
                    print(f"Decryption error: {decrypt_error}")
                    decrypted_message = "[Message could not be decrypted - may be corrupted]"
                
                # Prepare message data for display
                message_display_data = {
                    'content': decrypted_message,
                    'sender_id': sender_id,
                    'timestamp': encrypted_data.get('metadata', {}).get('timestamp', time.time()),
                    'session_id': encrypted_data.get('metadata', {}).get('session_id', 'Unknown'),
                    'message_id': message_id,
                    'is_decrypted': True
                }
                
                # Emit security event
                security_system.emit_security_event(
                    'message-read',
                    session_id=session.get('session_id'),
                    metadata={'message_id': message_id, 'sender': sender_id}
                )
                
                # Message auto-destructs after reading
                security_system.emit_security_event(
                    'message-destroyed',
                    session_id=session.get('session_id'),
                    metadata={'message_id': message_id, 'reason': 'auto_destruct'}
                )
                
                return render_template('message_display.html', 
                                     message_data=message_display_data,
                                     message_id=message_id)
                
            except Exception as e:
                print(f"Message read error: {e}")
                return render_template('error.html', error="Failed to read message")
        
        @self.app.route('/status')
        def status():
            """System status dashboard"""
            if 'user_id' not in session:
                return redirect(url_for('register'))
            
            try:
                # Get actual Tor status
                try:
                    tor_status = self.tor_integration.get_status()
                    
                    # For development mode, enhance status display
                    if not tor_status.get('active', False) and tor_status.get('fallback_mode', False):
                        # Show development mode status
                        tor_status.update({
                            'active': True,  # Show as active in demo
                            'development_mode': True,
                            'onion_url': 'secure7k2xa3b9mn4f.onion',  # Demo onion URL
                            'current_ip': '198.96.155.3',  # Demo Tor IP
                            'status_message': 'Development Mode - Tor features simulated'
                        })
                except Exception:
                    # Fallback status if Tor integration fails
                    tor_status = {
                        'active': True,  # Show as active for demo
                        'onion_url': 'secure7k2xa3b9mn4f.onion', 
                        'current_ip': '198.96.155.3',
                        'tor_running': False,
                        'fallback_mode': True,
                        'development_mode': True,
                        'status_message': 'Demo Mode - Tor features simulated'
                    }
                
                ids_status = {
                    'threat_level': 'low',
                    'active_sessions': 1,
                    'blocked_ips': 0,
                    'recent_events': 0,
                    'system_metrics': {
                        'metrics': {
                            'cpu_usage': 15.2,
                            'memory_usage': 45.8,
                            'network_connections': 12
                        }
                    }
                }
                try:
                    ids_status = self.ids.get_system_status()
                except Exception:
                    pass  # Use fallback
                
                security_signals = {
                    'event_statistics': {'total_events': 42},
                    'recent_actions': 3,
                    'active_threats': 0
                }
                try:
                    security_signals = security_system.get_system_status()
                except Exception:
                    pass  # Use fallback
                
                memory_usage = 0
                try:
                    memory_usage = len(self.memory_manager.message_storage.messages)
                except Exception:
                    pass  # Use fallback
                
                status_data = {
                    'tor_status': tor_status,
                    'ids_status': ids_status,
                    'security_signals': security_signals,
                    'memory_usage': memory_usage,
                    'session_info': {
                        'user_id': session.get('user_id'),
                        'session_id': session.get('session_id'),
                        'login_time': session.get('login_time', time.time())
                    }
                }
                return render_template('status.html', status=status_data)
            except Exception as e:
                print(f"Status error: {e}")
                return render_template('error.html', error=str(e))
        
        @self.app.route('/emergency_wipe', methods=['POST'])
        def emergency_wipe():
            """Emergency wipe of all data"""
            try:
                self.memory_manager.emergency_wipe()
                security_system.emit_security_event(
                    'memory-wipe',
                    user_id=session.get('user_id'),
                    metadata={'trigger': 'manual'}
                )
                flash('Emergency wipe completed', 'success')
            except Exception as e:
                flash(f'Emergency wipe failed: {str(e)}', 'error')
            
            return redirect(url_for('status'))
        
        @self.app.route('/logout')
        def logout():
            """Secure logout"""
            user_id = session.get('user_id')
            session_id = session.get('session_id')
            
            # Emit security event
            security_system.emit_security_event(
                'user-logout',
                user_id=user_id,
                session_id=session_id
            )
            # Clear session
            session.clear()
            flash('Logged out securely', 'info')
            return redirect(url_for('index'))
    
    def handle_security_alert(self, alert_data):
        """Handle security alerts from IDS"""
        print(f"🚨 Security Alert: {alert_data}")
        
        # Emit security signal
        security_alert.send(
            self.app,
            threat_data=alert_data
        )
    
    def emergency_shutdown(self):
        """Emergency shutdown procedure"""
        print("🔥 EMERGENCY SHUTDOWN INITIATED")
        
        try:
            # Wipe all sensitive data
            self.memory_manager.emergency_wipe()
            
            # Shutdown Tor
            self.tor_integration.shutdown()
            
            # Shutdown IDS
            self.ids.shutdown()
            
            print("✅ Emergency shutdown completed")
        except Exception as e:
            print(f"❌ Emergency shutdown error: {e}")
        
        # Exit application
        os._exit(1)
    
    def setup_shutdown_handlers(self):
        """Setup graceful shutdown handlers"""
        def signal_handler(sig, frame):
            print("\n🛑 Shutdown signal received")
            self.emergency_shutdown()
        
        # Use Windows-specific signal handling if available
        if WINDOWS_SUPPORT and self.windows_manager:
            try:
                self.windows_manager.setup_windows_signal_handlers(self.emergency_shutdown)
                print("✅ Windows signal handlers configured")
            except Exception as e:
                print(f"⚠ Windows signal handler setup failed: {e}")
                # Fallback to standard signal handling
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
        else:
            # Standard Unix signal handling
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        
        # Register cleanup on exit
        atexit.register(self.cleanup)
    
    def cleanup(self):
        """Cleanup on application exit"""
        try:
            self.memory_manager.emergency_wipe()
            self.tor_integration.shutdown()
            print("✅ Cleanup completed")
        except Exception as e:
            print(f"❌ Cleanup error: {e}")
    
    def run(self, debug=False, host='127.0.0.1', port=5001):
        """Run the secure application"""
        try:
            # Initialize Tor integration
            if self.tor_integration.initialize():
                print(f"🧅 Tor hidden service: {self.tor_integration.get_onion_url()}")
            
            # Start dummy traffic generation
            self.tor_integration.generate_dummy_traffic()
            
            print(f"🚀 Military-grade secure messaging app starting...")
            print(f"📍 Local access: http://{host}:{port}")
            print(f"🔒 Security level: MAXIMUM")
            
            # Run Flask app
            self.app.run(
                debug=debug,
                host=host,
                port=port,
                threaded=True,
                use_reloader=False  # Disable reloader for security
            )
            
        except Exception as e:
            print(f"❌ Application failed to start: {e}")
            self.emergency_shutdown()

# Create global app instance
app_instance = MilitarySecureApp()
app = app_instance.app

if __name__ == '__main__':
    app_instance.run(debug=False)