"""
Windows-specific security compatibility layer
Provides Windows-specific security features and signal handling
"""

import platform
import os
import subprocess
import sys
import threading
from typing import Dict, Any, Optional

# Check if running on Windows
WINDOWS = platform.system() == 'Windows'

class WindowsSecurityManager:
    """Windows-specific security manager with signal handling"""
    
    def _init_(self):
        self.signal_handlers_registered = False
        self.shutdown_callback = None
        
    def setup_windows_signal_handlers(self, shutdown_callback):
        """Setup Windows-specific signal handlers for graceful shutdown"""
        if not self.signal_handlers_registered:
            try:
                # Import Windows-specific modules
                import win32api
                import win32con
                import win32event
                
                # Store the shutdown callback
                self.shutdown_callback = shutdown_callback
                
                # Create a thread to monitor for shutdown events
                def monitor_shutdown_events():
                    while True:
                        # Wait for shutdown signals
                        result = win32api.WaitForSingleObject(
                            win32event.CreateEvent(None, True, False, None),
                            1000  # 1 second timeout
                        )
                        
                        if result == win32con.WAIT_OBJECT_0:
                            # Shutdown signal received
                            if self.shutdown_callback:
                                self.shutdown_callback()
                            break
                        
                        # Check for Ctrl+C or other termination signals
                        if self.check_for_termination():
                            if self.shutdown_callback:
                                self.shutdown_callback()
                            break
                
                # Start the monitoring thread
                shutdown_thread = threading.Thread(target=monitor_shutdown_events)
                shutdown_thread.daemon = True
                shutdown_thread.start()
                
                self.signal_handlers_registered = True
                print("✅ Windows signal handlers registered")
                
            except Exception as e:
                print(f"⚠ Failed to register Windows signal handlers: {e}")
                raise
    
    def check_for_termination(self) -> bool:
        """Check if termination signals are present"""
        try:
            # Check for Ctrl+C or other termination signals
            import signal
            return signal.getsignal(signal.SIGINT) is not None
        except:
            return False


def get_windows_compatibility_info() -> Dict[str, Any]:
    """
    Get information about Windows compatibility status
    
    Returns:
        Dictionary containing Windows compatibility information
    """
    info = {
        'platform': 'Windows',
        'version': platform.version(),
        'tor_available': False,
        'admin_privileges': False,
        'security_features': []
    }
    
    # Check if Tor is available
    try:
        # Try to detect Tor installation
        result = subprocess.run(['tor', '--version'], 
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            info['tor_available'] = True
    except:
        pass
    
    # Check for admin privileges
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            info['admin_privileges'] = True
    except:
        pass
    
    # Add security features
    info['security_features'].append('Windows-specific signal handling')
    info['security_features'].append('Administrator privilege detection')
    info['security_features'].append('Tor integration detection')
    
    return info


# Export the Windows security manager and compatibility info function
if WINDOWS:
    # Make sure we can import the Windows-specific modules
    try:
        import win32api
        import win32con
        import win32event
        # These imports are just to ensure they're available
    except ImportError:
        # If we can't import the Windows-specific modules, disable Windows support
        WindowsSecurityManager = None
        get_windows_compatibility_info = None
        WINDOWS_SUPPORT = False
else:
    # On non-Windows platforms, set these to None
    WindowsSecurityManager = None
    get_windows_compatibility_info = None
    WINDOWS_SUPPORT = False