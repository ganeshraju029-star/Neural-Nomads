# Windows Setup Script for Military-Grade Secure Messaging App
# Run this script as Administrator in PowerShell

param(
    [switch]$SkipChocolatey,
    [switch]$SkipPython,
    [switch]$SkipTor,
    [switch]$InstallAll
)

Write-Host "🛡️ MILITARY-GRADE SECURE MESSAGING - WINDOWS SETUP" -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "✅ Running as Administrator" -ForegroundColor Green

# Function to install Chocolatey
function Install-Chocolatey {
    Write-Host "📥 Installing Chocolatey package manager..." -ForegroundColor Yellow
    
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "✅ Chocolatey already installed" -ForegroundColor Green
        return
    }
    
    try {
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        
        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        Write-Host "✅ Chocolatey installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "❌ Failed to install Chocolatey: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
    return $true
}

# Function to install package via Chocolatey
function Install-ChocoPackage {
    param([string]$PackageName, [string]$Description)
    
    Write-Host "📦 Installing $Description..." -ForegroundColor Yellow
    
    try {
        choco install $PackageName -y
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ $Description installed successfully!" -ForegroundColor Green
            return $true
        } else {
            Write-Host "❌ Failed to install $Description" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "❌ Error installing $Description: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Main installation process
Write-Host ""
Write-Host "🔧 STARTING INSTALLATION PROCESS" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Step 1: Install Chocolatey
if (-not $SkipChocolatey) {
    Write-Host ""
    Write-Host "Step 1: Installing Chocolatey" -ForegroundColor Magenta
    if (-not (Install-Chocolatey)) {
        Write-Host "❌ Setup failed at Chocolatey installation" -ForegroundColor Red
        exit 1
    }
}

# Step 2: Install Python
if (-not $SkipPython -or $InstallAll) {
    Write-Host ""
    Write-Host "Step 2: Installing Python" -ForegroundColor Magenta
    Install-ChocoPackage "python" "Python Programming Language"
}

# Step 3: Install Git
if ($InstallAll) {
    Write-Host ""
    Write-Host "Step 3: Installing Git" -ForegroundColor Magenta
    Install-ChocoPackage "git" "Git Version Control"
}

# Step 4: Install Tor
if (-not $SkipTor -or $InstallAll) {
    Write-Host ""
    Write-Host "Step 4: Installing Tor" -ForegroundColor Magenta
    Install-ChocoPackage "tor" "Tor Network Client"
}

# Step 5: Install additional security tools
if ($InstallAll) {
    Write-Host ""
    Write-Host "Step 5: Installing Additional Tools" -ForegroundColor Magenta
    Install-ChocoPackage "openssl" "OpenSSL Cryptography Tools"
    Install-ChocoPackage "nodejs" "Node.js Runtime"
    Install-ChocoPackage "vscode" "Visual Studio Code Editor"
}

# Refresh environment variables
Write-Host ""
Write-Host "🔄 Refreshing environment variables..." -ForegroundColor Yellow
refreshenv

# Final verification
Write-Host ""
Write-Host "🔍 VERIFYING INSTALLATION" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan

# Check Python
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonVersion = python --version
    Write-Host "✅ Python: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "❌ Python not found" -ForegroundColor Red
}

# Check Pip
if (Get-Command pip -ErrorAction SilentlyContinue) {
    $pipVersion = pip --version
    Write-Host "✅ Pip: $pipVersion" -ForegroundColor Green
} else {
    Write-Host "❌ Pip not found" -ForegroundColor Red
}

# Check Tor
if (Get-Command tor -ErrorAction SilentlyContinue) {
    Write-Host "✅ Tor: Available" -ForegroundColor Green
} else {
    Write-Host "⚠️ Tor not found in PATH" -ForegroundColor Yellow
}

# Check Git
if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitVersion = git --version
    Write-Host "✅ Git: $gitVersion" -ForegroundColor Green
} else {
    Write-Host "⚠️ Git not found" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 SETUP COMPLETE!" -ForegroundColor Green
Write-Host "==================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps for Military-Grade Secure Messaging:" -ForegroundColor Cyan
Write-Host "1. Clone or download the application source code" -ForegroundColor White
Write-Host "2. Open PowerShell in the project directory" -ForegroundColor White
Write-Host "3. Create Python virtual environment:" -ForegroundColor White
Write-Host "   python -m venv .venv" -ForegroundColor Yellow
Write-Host "4. Activate virtual environment:" -ForegroundColor White
Write-Host "   .venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "5. Install Python dependencies:" -ForegroundColor White
Write-Host "   pip install -r requirements.txt" -ForegroundColor Yellow
Write-Host "6. Run the application:" -ForegroundColor White
Write-Host "   python app.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "🔒 Your system is now ready for military-grade secure messaging!" -ForegroundColor Green

pause