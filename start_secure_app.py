#!/usr/bin/env python3
"""
Simplified startup script for the military-grade secure messaging app
This script addresses the system monitoring and Tor integration issues
"""

import os
import sys
import signal
import time
import subprocess
from flask import Flask

def kill_existing_processes():
    """Kill any existing app processes"""
    try:
        # Kill processes on ports 5000 and 5001
        for port in [5000, 5001]:
            try:
                result = subprocess.run(['lsof', '-ti', f':{port}'], 
                                      capture_output=True, text=True)
                if result.stdout.strip():
                    pids = result.stdout.strip().split('\n')
                    for pid in pids:
                        try:
                            subprocess.run(['kill', '-9', pid], check=False)
                        except:
                            pass
            except:
                pass
    except:
        pass

def check_tor_availability():
    """Check if Tor is available"""
    tor_paths = [
        '/opt/homebrew/bin/tor',
        '/usr/local/bin/tor', 
        '/usr/bin/tor'
    ]
    
    for path in tor_paths:
        if os.path.exists(path):
            return True, path
    
    # Check PATH
    try:
        result = subprocess.run(['which', 'tor'], capture_output=True, text=True)
        if result.returncode == 0:
            return True, result.stdout.strip()
    except:
        pass
    
    return False, None

def main():
    """Main startup function"""
    print("🛡️ MILITARY-GRADE SECURE MESSAGING SYSTEM")
    print("=" * 60)
    
    # Clean up existing processes
    print("🧹 Cleaning up existing processes...")
    kill_existing_processes()
    time.sleep(2)
    
    # Check Tor availability
    tor_available, tor_path = check_tor_availability()
    if tor_available:
        print(f"✅ Tor found at: {tor_path}")
        os.environ['TOR_BINARY_PATH'] = tor_path
    else:
        print("⚠️ Tor not found - running without Tor integration")
    
    # Set environment variables for better stability
    os.environ['DISABLE_INTENSIVE_MONITORING'] = '1'
    os.environ['PYTHONUNBUFFERED'] = '1'
    
    # Import and start the app
    try:
        # Try the full app first
        print("🚀 Starting military-grade secure messaging app...")
        from app import app
        
        # Configure for stability
        app.config['DEBUG'] = False
        app.config['TESTING'] = False
        
        # Start the server
        print("📍 Server starting at: http://127.0.0.1:5001")
        print("🔒 Security level: MAXIMUM")
        app.run(host='127.0.0.1', port=5001, debug=False, threaded=True)
        
    except Exception as e:
        print(f"❌ Failed to start full app: {e}")
        print("🔄 Falling back to demo app...")
        
        try:
            from demo_app import app as demo_app
            demo_app.run(host='127.0.0.1', port=5001, debug=False, threaded=True)
        except Exception as e2:
            print(f"❌ Demo app also failed: {e2}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down...")
        kill_existing_processes()
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        kill_existing_processes()
        sys.exit(1)