"""
Tor integration for metadata resistance and traffic obfuscation
"""

import os
import time
import threading
import secrets
import json
import socket
import socks
import requests
from typing import Dict, Optional, Any, Callable, List
import stem
from stem import Signal
from stem.control import Controller
from stem.process import launch_tor_with_config
import subprocess
import tempfile
import random

class TorController:
    """Manages Tor process and configuration"""
    
    def __init__(self, data_directory: Optional[str] = None):
        self.data_directory = data_directory or tempfile.mkdtemp(prefix='tor_secure_')
        self.tor_process = None
        self.controller = None
        self.socks_port = self._get_random_port()
        self.control_port = self._get_random_port()
        self.hidden_service_port = self._get_random_port()
        self.hidden_service_dir = None
        self.onion_address = None
        self.is_running = False
        
    def _check_tor_availability(self) -> bool:
        """Check if Tor is available on the system"""
        try:
            import shutil
            # Check common Tor installation paths
            tor_paths = [
                '/opt/homebrew/bin/tor',  # macOS Homebrew ARM
                '/usr/local/bin/tor',     # macOS Homebrew Intel
                '/usr/bin/tor',           # System installations
                'tor'                     # PATH lookup
            ]
            
            for tor_path in tor_paths:
                if os.path.exists(tor_path) or shutil.which(tor_path):
                    return True
            return False
        except Exception:
            return False
    
    def _get_random_port(self) -> int:
        """Get random available port"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]
    
    def start_tor(self) -> bool:
        """Start Tor process with secure configuration"""
        try:
            # Check if Tor is available
            if not self._check_tor_availability():
                print("Tor is not available on this system. Running in mock mode.")
                self.is_running = False  # Set to False for mock mode
                return False  # Return False to indicate Tor not available
            
            # For development, provide option to skip full Tor initialization
            if os.environ.get('TOR_SKIP_INIT', '').lower() == '1':
                print("Tor available but initialization skipped (TOR_SKIP_INIT=1).")
                self.is_running = False
                return False
            
            print("🔄 Starting Tor with optimized configuration...")
            
            # Create Tor configuration with shorter timeouts for development
            tor_config = {
                'SocksPort': str(self.socks_port),
                'ControlPort': str(self.control_port),
                'DataDirectory': self.data_directory,
                'CookieAuthentication': '1',
                'ExitPolicy': 'reject *:*',  # No exit traffic
                'DisableDebuggerAttachment': '1',
                'SafeLogging': '1',
                'Log': 'notice stdout',
                'ClientRejectInternalAddresses': '1',
                'ClientUseIPv6': '0',  # Disable IPv6 for anonymity
                'NewCircuitPeriod': '60',  # New circuit every 60 seconds
                'MaxCircuitDirtiness': '300',  # Max circuit age
                'EnforceDistinctSubnets': '1',
                'StrictNodes': '1',
                'FascistFirewall': '1',
                'AvoidDiskWrites': '1',  # Minimize disk writes
                # Optimizations for faster startup
                'LearnCircuitBuildTimeout': '0',
                'CircuitBuildTimeout': '30',  # Shorter timeout
                'CircuitStreamTimeout': '30',
            }
            
            # Add common Tor paths to environment
            tor_binary_path = None
            tor_paths = [
                '/opt/homebrew/bin/tor',  # macOS Homebrew ARM
                '/usr/local/bin/tor',     # macOS Homebrew Intel
                '/usr/bin/tor'            # System installations
            ]
            
            for tor_path in tor_paths:
                if os.path.exists(tor_path):
                    tor_binary_path = tor_path
                    break
            
            # Launch Tor with specific binary path if found
            if tor_binary_path:
                self.tor_process = launch_tor_with_config(
                    config=tor_config,
                    init_msg_handler=self._tor_init_handler,
                    tor_cmd=tor_binary_path,
                    timeout=45  # Reduced timeout for development
                )
            else:
                # Fallback to default (may fail if not in PATH)
                self.tor_process = launch_tor_with_config(
                    config=tor_config,
                    init_msg_handler=self._tor_init_handler,
                    timeout=45  # Reduced timeout
                )
            
            # Connect to controller with shorter timeout
            self.controller = Controller.from_port(port=str(self.control_port))
            self.controller.authenticate()
            
            self.is_running = True
            print("✅ Tor started successfully")
            return True
            
        except Exception as e:
            print(f"Failed to start Tor: {e}")
            print("Running in fallback mode without Tor.")
            self.is_running = False
            return False  # Return False to indicate failure
    
    def _tor_init_handler(self, line: str):
        """Handle Tor initialization messages"""
        if 'Bootstrapped 100%' in line:
            print("Tor fully bootstrapped")
    
    def create_hidden_service(self, local_port: int) -> Optional[str]:
        """Create hidden service for the Flask app"""
        if not self.controller:
            return None
        
        try:
            # Create hidden service
            response = self.controller.create_ephemeral_hidden_service({
                80: local_port  # Map port 80 to local Flask port
            }, detached=False)
            
            self.onion_address = f"{response.service_id}.onion"
            return self.onion_address
            
        except Exception as e:
            print(f"Failed to create hidden service: {e}")
            return None
    
    def new_identity(self) -> bool:
        """Request new Tor identity (new circuit)"""
        if not self.controller:
            return False
        
        try:
            self.controller.signal('NEWNYM')  # Use string instead of Signal.NEWNYM
            time.sleep(5)  # Wait for new circuit
            return True
        except Exception:
            return False
    
    def get_current_ip(self) -> Optional[str]:
        """Get current IP address through Tor"""
        try:
            # Configure requests to use Tor SOCKS proxy
            session = requests.Session()
            session.proxies = {
                'http': f'socks5://127.0.0.1:{self.socks_port}',
                'https': f'socks5://127.0.0.1:{self.socks_port}'
            }
            
            response = session.get('https://httpbin.org/ip', timeout=30)
            return response.json().get('origin')
            
        except Exception:
            return None
    
    def stop_tor(self):
        """Stop Tor process"""
        if self.controller:
            try:
                self.controller.close()
            except Exception:
                pass
        
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=10)
            except Exception:
                try:
                    self.tor_process.kill()
                except Exception:
                    pass
        
        self.is_running = False

class TrafficObfuscation:
    """Traffic obfuscation techniques"""
    
    def __init__(self, tor_controller: TorController):
        self.tor_controller = tor_controller
        self.padding_enabled = True
        self.delay_enabled = True
        
    def add_padding(self, data: bytes, target_size: Optional[int] = None) -> bytes:
        """Add random padding to data"""
        if not self.padding_enabled:
            return data
        
        if target_size is None:
            # Random padding between 100-500 bytes
            target_size = len(data) + random.randint(100, 500)
        
        if len(data) >= target_size:
            return data
        
        padding_size = target_size - len(data)
        padding = os.urandom(padding_size)
        
        # Add padding marker
        padded_data = data + b'|PADDING|' + padding
        return padded_data
    
    def remove_padding(self, data: bytes) -> bytes:
        """Remove padding from data"""
        if b'|PADDING|' in data:
            return data.split(b'|PADDING|')[0]
        return data
    
    def add_timing_delay(self):
        """Add random timing delay"""
        if not self.delay_enabled:
            return
        
        # Random delay between 0.1-2.0 seconds
        delay = random.uniform(0.1, 2.0)
        time.sleep(delay)
    
    def create_dummy_traffic(self, duration_seconds: int = 60):
        """Generate dummy traffic to obfuscate real patterns"""
        def generate_traffic():
            session = requests.Session()
            session.proxies = {
                'http': f'socks5://127.0.0.1:{self.tor_controller.socks_port}',
                'https': f'socks5://127.0.0.1:{self.tor_controller.socks_port}'
            }
            
            dummy_urls = [
                'https://httpbin.org/delay/1',
                'https://httpbin.org/bytes/1024',
                'https://httpbin.org/html',
                'https://www.example.com',
            ]
            
            end_time = time.time() + duration_seconds
            while time.time() < end_time:
                try:
                    url = random.choice(dummy_urls)
                    session.get(url, timeout=10)
                    time.sleep(random.uniform(5, 15))
                except Exception:
                    continue
        
        traffic_thread = threading.Thread(target=generate_traffic, daemon=True)
        traffic_thread.start()

class MetadataResistance:
    """Advanced metadata resistance techniques"""
    
    def __init__(self, tor_controller: TorController):
        self.tor_controller = tor_controller
        self.session_aliases = {}
        self.ephemeral_identities = {}
        
    def generate_session_alias(self, user_id: str) -> str:
        """Generate ephemeral alias for session"""
        alias = f"user_{secrets.token_hex(8)}"
        self.session_aliases[user_id] = {
            'alias': alias,
            'created_at': time.time(),
            'expires_at': time.time() + 3600  # 1 hour
        }
        return alias
    
    def get_session_alias(self, user_id: str) -> Optional[str]:
        """Get current session alias"""
        if user_id in self.session_aliases:
            alias_data = self.session_aliases[user_id]
            if time.time() < alias_data['expires_at']:
                return alias_data['alias']
            else:
                del self.session_aliases[user_id]
        return None
    
    def rotate_identity(self, user_id: str) -> str:
        """Rotate user identity and get new Tor circuit"""
        # Request new Tor identity
        self.tor_controller.new_identity()
        
        # Generate new session alias
        return self.generate_session_alias(user_id)
    
    def obfuscate_message_metadata(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Obfuscate message metadata"""
        obfuscated = message_data.copy()
        
        # Remove/obfuscate identifying metadata
        if 'timestamp' in obfuscated:
            # Add random offset to timestamp (±5 minutes)
            offset = random.randint(-300, 300)
            obfuscated['timestamp'] = obfuscated['timestamp'] + offset
        
        # Add fake metadata
        obfuscated['fake_session_id'] = secrets.token_hex(16)
        obfuscated['decoy_flag'] = random.choice([True, False])
        
        return obfuscated

class TorSecureProxy:
    """Secure proxy wrapper for HTTP requests through Tor"""
    
    def __init__(self, tor_controller: TorController):
        self.tor_controller = tor_controller
        self.session = requests.Session()
        self._configure_session()
        
    def _configure_session(self):
        """Configure session for Tor"""
        self.session.proxies = {
            'http': f'socks5://127.0.0.1:{self.tor_controller.socks_port}',
            'https': f'socks5://127.0.0.1:{self.tor_controller.socks_port}'
        }
        
        # Security headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
        })
    
    def secure_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make secure request through Tor"""
        try:
            # Add random delay
            time.sleep(random.uniform(0.5, 2.0))
            
            response = self.session.request(method, url, timeout=30, **kwargs)
            return response
            
        except Exception as e:
            print(f"Secure request failed: {e}")
            return None

class TorIntegration:
    """Main Tor integration system"""
    
    def __init__(self, flask_app_port: int = 5000):
        self.flask_app_port = flask_app_port
        self.tor_controller = TorController()
        self.traffic_obfuscation = None
        self.metadata_resistance = None
        self.secure_proxy = None
        self.onion_service_url = None
        self.monitoring_thread = None
        self.is_active = False
        
    def initialize(self) -> bool:
        """Initialize Tor integration"""
        try:
            # Start Tor
            tor_started = self.tor_controller.start_tor()
            
            if tor_started:
                # Create hidden service only if Tor actually started
                self.onion_service_url = self.tor_controller.create_hidden_service(self.flask_app_port)
                if self.onion_service_url:
                    print(f"🧜 Tor hidden service available at: {self.onion_service_url}")
                
                # Initialize components
                self.traffic_obfuscation = TrafficObfuscation(self.tor_controller)
                self.metadata_resistance = MetadataResistance(self.tor_controller)
                self.secure_proxy = TorSecureProxy(self.tor_controller)
                
                # Start monitoring
                self._start_monitoring()
                
                self.is_active = True
                return True
            else:
                # Tor failed to start, but continue in fallback mode
                print("⚠️ Tor integration unavailable - continuing in secure fallback mode")
                self.is_active = False
                return True  # Still return True to allow app to continue
            
        except Exception as e:
            print(f"Failed to initialize Tor integration: {e}")
            print("Continuing in secure fallback mode without Tor")
            self.is_active = False
            return True  # Return True to allow app to continue
    
    def get_onion_url(self) -> Optional[str]:
        """Get the onion service URL"""
        return self.onion_service_url
    
    def create_secure_session(self, user_id: str) -> Dict[str, Any]:
        """Create secure session with metadata resistance"""
        if not self.is_active or not self.metadata_resistance:
            return {}
        
        # Generate session alias
        alias = self.metadata_resistance.generate_session_alias(user_id)
        
        # Get current Tor IP
        tor_ip = self.tor_controller.get_current_ip()
        
        return {
            'session_alias': alias,
            'tor_ip': tor_ip,
            'onion_url': self.onion_service_url,
            'created_at': time.time()
        }
    
    def rotate_circuit(self) -> bool:
        """Rotate Tor circuit for enhanced anonymity"""
        if not self.is_active:
            return False
        
        return self.tor_controller.new_identity()
    
    def generate_dummy_traffic(self, duration: int = 300):
        """Generate dummy traffic for 5 minutes"""
        if self.traffic_obfuscation:
            self.traffic_obfuscation.create_dummy_traffic(duration)
    
    def obfuscate_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply full message obfuscation"""
        if not self.metadata_resistance:
            return message_data
        
        return self.metadata_resistance.obfuscate_message_metadata(message_data)
    
    def _start_monitoring(self):
        """Start monitoring thread"""
        def monitor_tor():
            while self.is_active:
                try:
                    # Check if Tor is still running
                    if not self.tor_controller.is_running:
                        print("Tor process died, attempting restart...")
                        self.tor_controller.start_tor()
                    
                    # Rotate circuit periodically
                    if random.random() < 0.1:  # 10% chance every check
                        self.tor_controller.new_identity()
                    
                    time.sleep(60)  # Check every minute
                    
                except Exception as e:
                    print(f"Tor monitoring error: {e}")
                    time.sleep(30)
        
        self.monitoring_thread = threading.Thread(target=monitor_tor, daemon=True)
        self.monitoring_thread.start()
    
    def shutdown(self):
        """Shutdown Tor integration"""
        self.is_active = False
        
        if self.tor_controller:
            self.tor_controller.stop_tor()
        
        print("Tor integration shut down")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current Tor status"""
        tor_running = self.tor_controller.is_running if self.tor_controller else False
        current_ip = None
        
        # Only try to get IP if Tor is actually running
        if tor_running and self.tor_controller:
            try:
                current_ip = self.tor_controller.get_current_ip()
            except Exception:
                current_ip = "Unable to determine"
        
        return {
            'active': self.is_active and tor_running,
            'onion_url': self.onion_service_url,
            'tor_running': tor_running,
            'socks_port': self.tor_controller.socks_port if self.tor_controller else None,
            'current_ip': current_ip or "Not connected",
            'fallback_mode': not self.is_active
        }