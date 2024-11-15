# GhostOS Build Environment Setup Script for Windows
# This script sets up the complete build environment for Raspberry Pi Zero W development

$ErrorActionPreference = "Stop"

# Configuration
$toolchainVersion = "10.3-2021.10"
$cmakeVersion = "3.26.4"
$pythonVersion = "3.11.0"
$ninjaVersion = "1.11.1"

# Directories
$buildTools = "E:\ghostOS\tools"
$toolchainDir = "$buildTools\gcc-arm-none-eabi"
$cmakeDir = "$buildTools\cmake"
$pythonDir = "$buildTools\python"
$ninjaDir = "$buildTools\ninja"

# Create directories
New-Item -ItemType Directory -Force -Path $buildTools
New-Item -ItemType Directory -Force -Path $toolchainDir
New-Item -ItemType Directory -Force -Path $cmakeDir
New-Item -ItemType Directory -Force -Path $pythonDir
New-Item -ItemType Directory -Force -Path $ninjaDir

# Download URLs
$toolchainUrl = "https://developer.arm.com/-/media/Files/downloads/gnu-rm/$toolchainVersion/gcc-arm-none-eabi-$toolchainVersion-win32.zip"
$cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v$cmakeVersion/cmake-$cmakeVersion-windows-x86_64.zip"
$pythonUrl = "https://www.python.org/ftp/python/$pythonVersion/python-$pythonVersion-embed-amd64.zip"
$ninjaUrl = "https://github.com/ninja-build/ninja/releases/download/v$ninjaVersion/ninja-win.zip"

function Download-And-Extract {
    param (
        [string]$url,
        [string]$destination
    )
    
    $tempFile = [System.IO.Path]::GetTempFileName() + ".zip"
    Write-Host "Downloading from $url..."
    Invoke-WebRequest -Uri $url -OutFile $tempFile
    
    Write-Host "Extracting to $destination..."
    Expand-Archive -Path $tempFile -DestinationPath $destination -Force
    Remove-Item $tempFile
}

Write-Host "Setting up GhostOS build environment..."

# Download and install ARM toolchain
Write-Host "Installing ARM GCC Toolchain..."
Download-And-Extract -url $toolchainUrl -destination $toolchainDir

# Download and install CMake
Write-Host "Installing CMake..."
Download-And-Extract -url $cmakeUrl -destination $cmakeDir

# Download and install Python
Write-Host "Installing Python..."
Download-And-Extract -url $pythonUrl -destination $pythonDir

# Download and install Ninja
Write-Host "Installing Ninja..."
Download-And-Extract -url $ninjaUrl -destination $ninjaDir

# Update System PATH
$envPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
$pathsToAdd = @(
    "$toolchainDir\bin",
    "$cmakeDir\bin",
    "$pythonDir",
    "$ninjaDir"
)

foreach ($path in $pathsToAdd) {
    if ($envPath -notlike "*$path*") {
        $envPath = "$envPath;$path"
    }
}

[System.Environment]::SetEnvironmentVariable("Path", $envPath, [System.EnvironmentVariableTarget]::User)

# Create build directory structure
Write-Host "Creating build directory structure..."
New-Item -ItemType Directory -Force -Path "E:\ghostOS\build"
New-Item -ItemType Directory -Force -Path "E:\ghostOS\build\debug"
New-Item -ItemType Directory -Force -Path "E:\ghostOS\build\release"

# Generate initial CMake configuration
Write-Host "Generating initial CMake configuration..."
$Env:PATH = $envPath
Set-Location -Path "E:\ghostOS\build\debug"

cmake -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="E:\ghostOS\config\build.cmake" `
    -DCMAKE_BUILD_TYPE=Debug `
    -DTARGET_BOARD=raspberry_pi_zero_w `
    "E:\ghostOS"

Write-Host "Build environment setup complete!"
Write-Host @"

GhostOS Build Environment has been configured:
- ARM GCC Toolchain: $toolchainVersion
- CMake: $cmakeVersion
- Python: $pythonVersion
- Ninja: $ninjaVersion

To build GhostOS:
1. Open PowerShell
2. Navigate to build directory: cd E:\ghostOS\build\debug
3. Run build: ninja

For release builds, use: E:\ghostOS\build\release
"@
