# PowerShell script to install Chocolatey package manager on Windows
# Run this script as Administrator in PowerShell

Write-Host "🍫 CHOCOLATEY INSTALLATION SCRIPT" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "✅ Running as Administrator" -ForegroundColor Green

# Check if Chocolatey is already installed
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "✅ Chocolatey is already installed!" -ForegroundColor Green
    choco --version
    Write-Host "To upgrade Chocolatey, run: choco upgrade chocolatey" -ForegroundColor Yellow
} else {
    Write-Host "📥 Installing Chocolatey..." -ForegroundColor Yellow
    
    # Set execution policy
    Write-Host "Setting execution policy..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    
    # Download and install Chocolatey
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        Write-Host "✅ Chocolatey installed successfully!" -ForegroundColor Green
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Verify installation
        Write-Host "🔍 Verifying installation..." -ForegroundColor Yellow
        choco --version
        
        Write-Host "✅ Installation complete!" -ForegroundColor Green
        
    } catch {
        Write-Host "❌ Failed to install Chocolatey: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "🎉 CHOCOLATEY READY FOR USE!" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green
Write-Host "Common commands:" -ForegroundColor Cyan
Write-Host "  choco install <package>     - Install a package" -ForegroundColor White
Write-Host "  choco list --local-only     - List installed packages" -ForegroundColor White
Write-Host "  choco upgrade <package>     - Upgrade a package" -ForegroundColor White
Write-Host "  choco uninstall <package>   - Remove a package" -ForegroundColor White
Write-Host "  choco search <package>      - Search for packages" -ForegroundColor White
Write-Host ""
Write-Host "Example: choco install git python nodejs" -ForegroundColor Yellow
Write-Host ""

pause