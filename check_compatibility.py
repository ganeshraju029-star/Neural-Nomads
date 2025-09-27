#!/usr/bin/env python3
"""
Platform Compatibility Checker for Military-Grade Secure Messaging
Checks system compatibility and provides setup guidance
"""

import sys
import platform
import subprocess
import importlib
import os
from typing import Dict, Any

def check_python_version() -> Dict[str, Any]:
    """Check Python version compatibility"""
    version = sys.version_info
    is_compatible = version >= (3, 8)
    
    return {
        'version': f"{version.major}.{version.minor}.{version.micro}",
        'compatible': is_compatible,
        'minimum_required': '3.8.0'
    }

def check_required_packages() -> Dict[str, bool]:
    """Check if required packages are available"""
    required_packages = [
        'flask', 'nacl', 'cryptography', 'sklearn', 'numpy', 
        'blinker', 'qrcode', 'stem', 'psutil', 'werkzeug', 
        'jinja2', 'requests'
    ]
    
    package_status = {}
    for package in required_packages:
        try:
            importlib.import_module(package)
            package_status[package] = True
        except ImportError:
            package_status[package] = False
    
    return package_status

def check_platform_specific() -> Dict[str, Any]:
    """Check platform-specific features"""
    system = platform.system()
    
    platform_info: Dict[str, Any] = {
        'system': system,
        'version': platform.version(),
        'architecture': platform.architecture()[0],
        'machine': platform.machine()
    }
    
    if system == 'Windows':
        # Check Windows-specific features
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() == 1
            platform_info['admin_privileges'] = is_admin
        except Exception:
            platform_info['admin_privileges'] = False
        
        # Check for Windows-specific packages
        try:
            import win32api
            platform_info['pywin32_available'] = True
        except ImportError:
            platform_info['pywin32_available'] = False
    
    elif system == 'Darwin':  # macOS
        platform_info['macos_version'] = platform.mac_ver()[0]
        
    elif system == 'Linux':
        try:
            with open('/etc/os-release', 'r') as f:
                platform_info['distribution'] = f.read()
        except Exception:
            platform_info['distribution'] = 'Unknown'
    
    return platform_info

def check_tor_availability() -> Dict[str, Any]:
    """Check if Tor is available"""
    tor_info = {'available': False, 'path': None, 'version': None}
    
    # Common Tor executable names and paths
    tor_commands = ['tor', 'tor.exe']
    
    if platform.system() == 'Windows':
        # Windows-specific Tor paths
        windows_paths = [
            r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
            r"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
            "tor.exe"
        ]
        tor_commands.extend(windows_paths)
    
    for tor_cmd in tor_commands:
        try:
            if os.path.exists(tor_cmd):
                result = subprocess.run([tor_cmd, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    tor_info['available'] = True
                    tor_info['path'] = tor_cmd
                    tor_info['version'] = result.stdout.strip().split('\n')[0]
                    break
        except Exception:
            continue
    
    return tor_info

def check_port_availability(port: int = 5001) -> bool:
    """Check if the default port is available"""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('127.0.0.1', port))
            return True
    except OSError:
        return False

def generate_setup_instructions(results: Dict[str, Any]) -> str:
    """Generate platform-specific setup instructions"""
    system = results['platform']['system']
    instructions = []
    
    instructions.append(f"# Setup Instructions for {system}")
    instructions.append("=" * 50)
    
    # Python version check
    if not results['python']['compatible']:
        instructions.append(f"⚠️  Python {results['python']['minimum_required']}+ required")
        instructions.append(f"   Current version: {results['python']['version']}")
        instructions.append(f"   Please upgrade Python first!")
        instructions.append("")
    
    # Platform-specific instructions
    if system == 'Windows':
        instructions.extend([
            "## Windows Setup:",
            "1. Ensure Python 3.8+ is installed",
            "2. Open Command Prompt or PowerShell",
            "3. Navigate to application directory:",
            "   cd C:\\path\\to\\your\\app",
            "4. Create virtual environment:",
            "   python -m venv .venv",
            "5. Activate virtual environment:",
            "   .venv\\Scripts\\activate",
            "6. Install dependencies:",
            "   pip install -r requirements.txt",
            "7. Run the application:",
            "   python app.py"
        ])
        
        if not results['platform'].get('admin_privileges', False):
            instructions.append("💡 Consider running as Administrator for enhanced features")
            
    elif system == 'Darwin':  # macOS
        instructions.extend([
            "## macOS Setup:",
            "1. Open Terminal",
            "2. Navigate to application directory:",
            "   cd /path/to/your/app",
            "3. Create virtual environment:",
            "   python3 -m venv .venv",
            "4. Activate virtual environment:",
            "   source .venv/bin/activate",
            "5. Install dependencies:",
            "   pip install -r requirements.txt",
            "6. Run the application:",
            "   python3 app.py"
        ])
        
        if not results['port_available']:
            instructions.append("⚠️  Port 5001 may be used by AirPlay - the app will handle this automatically")
            
    elif system == 'Linux':
        instructions.extend([
            "## Linux Setup:",
            "1. Open terminal",
            "2. Install Python 3.8+ if needed:",
            "   sudo apt install python3 python3-pip python3-venv  # Ubuntu/Debian",
            "   sudo yum install python3 python3-pip              # CentOS/RHEL",
            "3. Navigate to application directory:",
            "   cd /path/to/your/app",
            "4. Create virtual environment:",
            "   python3 -m venv .venv",
            "5. Activate virtual environment:",
            "   source .venv/bin/activate",
            "6. Install dependencies:",
            "   pip install -r requirements.txt",
            "7. Run the application:",
            "   python3 app.py"
        ])
    
    # Missing packages
    missing_packages = [pkg for pkg, available in results['packages'].items() if not available]
    if missing_packages:
        instructions.extend([
            "",
            "## Missing Packages:",
            "Install missing packages with:",
            f"pip install {' '.join(missing_packages)}"
        ])
    
    # Tor instructions
    if not results['tor']['available']:
        instructions.extend([
            "",
            "## Optional: Tor Installation",
            "For enhanced anonymity, install Tor:",
            "- Download from: https://www.torproject.org/download/",
        ])
        
        if system == 'Windows':
            instructions.append("- Install Tor Browser to C:\\Program Files\\Tor Browser\\")
        else:
            instructions.append("- Install via package manager or from source")
    
    return "\n".join(instructions)

def main():
    """Main compatibility check function"""
    print("🔍 Military-Grade Secure Messaging - Compatibility Check")
    print("=" * 60)
    
    # Perform all checks
    results = {
        'python': check_python_version(),
        'packages': check_required_packages(),
        'platform': check_platform_specific(),
        'tor': check_tor_availability(),
        'port_available': check_port_availability()
    }
    
    # Display results
    print(f"Platform: {results['platform']['system']} {results['platform']['version']}")
    print(f"Architecture: {results['platform']['architecture']}")
    print(f"Python: {results['python']['version']} ({'✅ Compatible' if results['python']['compatible'] else '❌ Incompatible'})")
    
    # Package status
    available_packages = sum(results['packages'].values())
    total_packages = len(results['packages'])
    print(f"Required Packages: {available_packages}/{total_packages} available")
    
    # Tor status
    tor_status = "✅ Available" if results['tor']['available'] else "⚠️ Not found"
    print(f"Tor: {tor_status}")
    
    # Port status
    port_status = "✅ Available" if results['port_available'] else "⚠️ In use"
    print(f"Port 5001: {port_status}")
    
    # Overall compatibility
    is_compatible = (
        results['python']['compatible'] and
        all(results['packages'].values())
    )
    
    print("\n" + "=" * 60)
    if is_compatible:
        print("🎉 SYSTEM IS FULLY COMPATIBLE!")
        print("Your system can run the military-grade secure messaging application.")
    else:
        print("⚠️ COMPATIBILITY ISSUES DETECTED")
        print("Please address the issues below before running the application.")
    
    # Generate setup instructions
    print("\n")
    print(generate_setup_instructions(results))
    
    # Create compatibility report
    try:
        with open('compatibility_report.txt', 'w') as f:
            f.write("Military-Grade Secure Messaging - Compatibility Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Platform: {results['platform']['system']} {results['platform']['version']}\n")
            f.write(f"Python: {results['python']['version']}\n")
            f.write(f"Packages: {available_packages}/{total_packages} available\n")
            f.write(f"Tor: {'Available' if results['tor']['available'] else 'Not found'}\n")
            f.write(f"Compatible: {'Yes' if is_compatible else 'No'}\n\n")
            f.write(generate_setup_instructions(results))
        
        print("\n📄 Compatibility report saved to: compatibility_report.txt")
    except Exception:
        pass

if __name__ == "__main__":
    main()