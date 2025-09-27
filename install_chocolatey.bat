@echo off
REM Batch script to install Chocolatey package manager on Windows
REM Run this script as Administrator

echo.
echo 🍫 CHOCOLATEY INSTALLATION SCRIPT
echo =================================

REM Check if running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ This script must be run as Administrator!
    echo Right-click this file and select "Run as administrator"
    pause
    exit /b 1
)

echo ✅ Running as Administrator

REM Check if Chocolatey is already installed
where choco >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ Chocolatey is already installed!
    choco --version
    echo To upgrade Chocolatey, run: choco upgrade chocolatey
    goto :end
)

echo 📥 Installing Chocolatey...

REM Install Chocolatey using PowerShell
powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command ^
"[System.Net.ServicePointManager]::SecurityProtocol = 3072; ^
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

if %errorlevel% neq 0 (
    echo ❌ Failed to install Chocolatey
    pause
    exit /b 1
)

echo ✅ Chocolatey installed successfully!

REM Refresh environment variables
call refreshenv

REM Verify installation
echo 🔍 Verifying installation...
choco --version

if %errorlevel% equ 0 (
    echo ✅ Installation complete!
) else (
    echo ⚠️ Installation may have issues. Try restarting your command prompt.
)

:end
echo.
echo 🎉 CHOCOLATEY READY FOR USE!
echo =============================
echo Common commands:
echo   choco install ^<package^>     - Install a package
echo   choco list --local-only     - List installed packages  
echo   choco upgrade ^<package^>     - Upgrade a package
echo   choco uninstall ^<package^>   - Remove a package
echo   choco search ^<package^>      - Search for packages
echo.
echo Example: choco install git python nodejs
echo.

pause