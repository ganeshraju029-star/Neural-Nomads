# Windows Tor Installation Script
# Comprehensive Tor installation for Military-Grade Secure Messaging

Write-Host "🧅 TOR INSTALLATION FOR WINDOWS" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "✅ Running as Administrator" -ForegroundColor Green

# Function to test Tor installation
function Test-TorInstallation {
    $torPaths = @(
        "C:\tor\tor.exe",
        "C:\tor\Tor\tor.exe",
        (Get-Command tor -ErrorAction SilentlyContinue).Source
    )
    
    foreach ($path in $torPaths) {
        if ($path -and (Test-Path $path)) {
            Write-Host "✅ Tor found at: $path" -ForegroundColor Green
            return $path
        }
    }
    return $null
}

# Check if Tor is already installed
$existingTor = Test-TorInstallation
if ($existingTor) {
    Write-Host "✅ Tor is already installed!" -ForegroundColor Green
    Write-Host "Location: $existingTor" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Your system is ready for the military-grade messaging app!" -ForegroundColor Green
    pause
    exit 0
}

Write-Host "📥 Tor not found. Starting installation process..." -ForegroundColor Yellow
Write-Host ""

# Method 1: Try Chocolatey
Write-Host "METHOD 1: Chocolatey Installation" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Host "📦 Installing Tor via Chocolatey..." -ForegroundColor Yellow
    try {
        choco install tor -y
        
        # Refresh environment
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        $torAfterChoco = Test-TorInstallation
        if ($torAfterChoco) {
            Write-Host "✅ Tor installed successfully via Chocolatey!" -ForegroundColor Green
            Write-Host "Location: $torAfterChoco" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Your system is ready for the military-grade messaging app!" -ForegroundColor Green
            pause
            exit 0
        }
    } catch {
        Write-Host "❌ Chocolatey installation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "⚠ Chocolatey not found. Skipping Chocolatey method." -ForegroundColor Yellow
}

# Method 2: Download Tor Expert Bundle
Write-Host ""
Write-Host "METHOD 2: Tor Expert Bundle Installation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

try {
    $torDir = "C:\tor"
    $torBinDir = "$torDir\Tor"
    
    # Create directory
    Write-Host "📁 Creating Tor directory at $torDir..." -ForegroundColor Yellow
    if (-not (Test-Path $torDir)) {
        New-Item -ItemType Directory -Path $torDir -Force | Out-Null
    }
    
    # Download Tor Expert Bundle
    $torUrl = "https://dist.torproject.org/torbrowser/13.0.8/tor-expert-bundle-windows-x86_64-13.0.8.tar.gz"
    $torArchive = "$torDir\tor-expert-bundle.tar.gz"
    
    Write-Host "📥 Downloading Tor Expert Bundle..." -ForegroundColor Yellow
    Write-Host "URL: $torUrl" -ForegroundColor Cyan
    
    # Use TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    Invoke-WebRequest -Uri $torUrl -OutFile $torArchive -UseBasicParsing
    
    if (Test-Path $torArchive) {
        Write-Host "✅ Download completed!" -ForegroundColor Green
        
        # Extract using Windows 10+ built-in tar
        Write-Host "📦 Extracting Tor..." -ForegroundColor Yellow
        tar -xzf $torArchive -C $torDir
        
        # Verify extraction
        if (Test-Path "$torBinDir\tor.exe") {
            Write-Host "✅ Tor extracted successfully!" -ForegroundColor Green
            
            # Add to system PATH
            Write-Host "🔧 Adding Tor to system PATH..." -ForegroundColor Yellow
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            if ($currentPath -notlike "$torBinDir") {
                [Environment]::SetEnvironmentVariable("Path", "$currentPath;$torBinDir", "Machine")
                $env:Path += ";$torBinDir"
                Write-Host "✅ Added $torBinDir to system PATH" -ForegroundColor Green
            }
            
            # Clean up
            Remove-Item $torArchive -Force
            
            Write-Host ""
            Write-Host "🎉 TOR INSTALLATION COMPLETED!" -ForegroundColor Green
            Write-Host "==============================" -ForegroundColor Green
            Write-Host "Tor installed at: $torBinDir\tor.exe" -ForegroundColor Cyan
            Write-Host "Added to system PATH for command line access" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Your system is ready for the military-grade messaging app!" -ForegroundColor Green
            pause
            exit 0
            
        } else {
            Write-Host "❌ Extraction failed - tor.exe not found" -ForegroundColor Red
        }
    } else {
        Write-Host "❌ Download failed" -ForegroundColor Red
    }
    
} catch {
    Write-Host "❌ Expert Bundle installation failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 3: Manual Installation Instructions
Write-Host ""
Write-Host "METHOD 3: Manual Installation Required" -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Automatic installation failed. Please install Tor manually:" -ForegroundColor Red
Write-Host ""
Write-Host "OPTION A: Tor Browser Method" -ForegroundColor Cyan
Write-Host "1. Download Tor Browser from: https://www.torproject.org/download/" -ForegroundColor White
Write-Host "2. Install Tor Browser (default location is fine)" -ForegroundColor White
Write-Host "3. Find the Tor Browser installation directory:" -ForegroundColor White
Write-Host "   Usually: C:\Users\[YourName]\Desktop\Tor Browser\Browser\TorBrowser\Tor\" -ForegroundColor Yellow
Write-Host "4. Copy tor.exe to C:\tor\tor.exe" -ForegroundColor White
Write-Host "5. Add C:\tor to your system PATH" -ForegroundColor White
Write-Host ""
Write-Host "OPTION B: Expert Bundle Method" -ForegroundColor Cyan
Write-Host "1. Go to: https://dist.torproject.org/torbrowser/" -ForegroundColor White
Write-Host "2. Download the latest tor-expert-bundle-windows-x86_64-[version].tar.gz" -ForegroundColor White
Write-Host "3. Extract to C:\tor\" -ForegroundColor White
Write-Host "4. Ensure tor.exe is at C:\tor\Tor\tor.exe" -ForegroundColor White
Write-Host "5. Add C:\tor\Tor to your system PATH" -ForegroundColor White
Write-Host ""
Write-Host "To add to PATH:" -ForegroundColor Cyan
Write-Host "1. Press Win+X, select 'System'" -ForegroundColor White
Write-Host "2. Click 'Advanced system settings'" -ForegroundColor White
Write-Host "3. Click 'Environment Variables'" -ForegroundColor White
Write-Host "4. Under 'System variables', find and select 'Path', click 'Edit'" -ForegroundColor White
Write-Host "5. Click 'New' and add: C:\tor\Tor (or C:\tor if using option A)" -ForegroundColor White
Write-Host "6. Click 'OK' to save" -ForegroundColor White
Write-Host ""
Write-Host "After installation, restart PowerShell and run: tor --version" -ForegroundColor Green
Write-Host ""

pause