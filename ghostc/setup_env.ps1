# PowerShell script to set up GhostC development environment

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "This script requires administrator privileges."
    Write-Host "Please follow these steps:"
    Write-Host "1. Press Win + X"
    Write-Host "2. Select 'Windows PowerShell (Admin)' or 'Terminal (Admin)'"
    Write-Host "3. Navigate to this directory: cd e:/ghostOS/ghostc"
    Write-Host "4. Run: Set-ExecutionPolicy Bypass -Scope Process -Force; .\setup_env.ps1"
    exit
}

Write-Host "Setting up GhostC development environment..."

# Install Chocolatey if not already installed
if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Create directories
Write-Host "Creating directories..."
New-Item -ItemType Directory -Force -Path "tools"
New-Item -ItemType Directory -Force -Path "build"
New-Item -ItemType Directory -Force -Path "ide/build"
New-Item -ItemType Directory -Force -Path "include/build"

# Install required packages
Write-Host "Installing required packages..."
choco install -y make --force
choco install -y ninja --force
choco install -y cmake --force
choco install -y gcc-arm-embedded --force
refreshenv

# Verify ARM toolchain installation
Write-Host "Verifying ARM toolchain installation..."
$armGccPath = (Get-Command arm-none-eabi-gcc -ErrorAction SilentlyContinue).Source

if (-not $armGccPath) {
    # Try to find it in Program Files
    $possiblePaths = @(
        "${env:ProgramFiles}\GNU Arm Embedded Toolchain\*\bin\arm-none-eabi-gcc.exe",
        "${env:ProgramFiles(x86)}\GNU Arm Embedded Toolchain\*\bin\arm-none-eabi-gcc.exe",
        "${env:ProgramFiles}\GNU Tools Arm Embedded\*\bin\arm-none-eabi-gcc.exe",
        "${env:ProgramFiles(x86)}\GNU Tools Arm Embedded\*\bin\arm-none-eabi-gcc.exe"
    )

    foreach ($path in $possiblePaths) {
        $found = Get-Item $path -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1
        if ($found) {
            $armGccPath = $found.FullName
            $armBinPath = Split-Path $armGccPath
            
            # Add to PATH if not already there
            $currentPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
            if ($currentPath -notlike "*$armBinPath*") {
                Write-Host "Adding ARM toolchain to PATH..."
                [Environment]::SetEnvironmentVariable("Path", "$currentPath;$armBinPath", [System.EnvironmentVariableTarget]::User)
                $env:Path = "$env:Path;$armBinPath"
            }
            break
        }
    }
}

if ($armGccPath) {
    Write-Host "ARM toolchain found at: $armGccPath"
    Write-Host "Testing ARM toolchain..."
    $version = & $armGccPath --version
    Write-Host $version
    Write-Host "ARM toolchain installed successfully!"
} else {
    Write-Host "ERROR: ARM toolchain not found!"
    Write-Host "Please try the following:"
    Write-Host "1. Restart this terminal with administrator privileges"
    Write-Host "2. Run: choco install gcc-arm-embedded --force"
    Write-Host "3. Close and reopen the terminal"
    Write-Host "4. Run this script again"
    exit 1
}

Write-Host "`nSetup complete! The development environment is now configured."
Write-Host "IMPORTANT: You must restart your terminal for PATH changes to take effect."
Write-Host "After restarting, you can build GhostC using 'make' or 'make ide'"

# Wait for user input
pause
