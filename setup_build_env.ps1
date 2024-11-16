# GhostOS Build Environment Setup Script for Windows
# This script sets up the complete build environment for Raspberry Pi Zero W development

$ErrorActionPreference = "Stop"

# Configuration
$toolchainVersion = "10.3-2021.10"
$cmakeVersion = "3.26.4"
$pythonVersion = "3.11.0"
$ninjaVersion = "1.11.1"
$ddVersion = "5.3.0"

# Directories
$scriptPath = $PSScriptRoot
$buildTools = Join-Path $scriptPath "tools"
$toolchainDir = Join-Path $buildTools "gcc-arm-none-eabi"
$cmakeDir = Join-Path $buildTools "cmake"
$pythonDir = Join-Path $buildTools "python"
$ninjaDir = Join-Path $buildTools "ninja"
$ddDir = Join-Path $buildTools "bin"

# Clean up existing directories
Write-Host "Cleaning up existing directories..."
if (Test-Path $buildTools) {
    Remove-Item -Path $buildTools -Recurse -Force
}

# Create directories
Write-Host "Creating directories..."
New-Item -ItemType Directory -Force -Path $buildTools
New-Item -ItemType Directory -Force -Path $toolchainDir
New-Item -ItemType Directory -Force -Path $cmakeDir
New-Item -ItemType Directory -Force -Path $pythonDir
New-Item -ItemType Directory -Force -Path $ninjaDir
New-Item -ItemType Directory -Force -Path $ddDir

# Download URLs
$toolchainUrl = "https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/10.3-2021.10/gcc-arm-none-eabi-10.3-2021.10-win32.zip"
$cmakeUrl = "https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4-windows-x86_64.zip"
$pythonUrl = "https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-amd64.zip"
$ninjaUrl = "https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-win.zip"
$ddUrl = "https://sourceforge.net/projects/gnuwin32/files/coreutils/5.3.0/coreutils-5.3.0-bin.zip"

function Download-File {
    param (
        [string]$url,
        [string]$output
    )
    
    Write-Host "Downloading from $url..."
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($url, $output)
}

function Extract-And-Move {
    param (
        [string]$zipFile,
        [string]$destination,
        [string]$innerDir = ""
    )
    
    Write-Host "Extracting to $destination..."
    $tempDir = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
    
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile, $tempDir)
    
    if ($innerDir -ne "") {
        $sourcePath = Join-Path $tempDir $innerDir
        if (Test-Path $sourcePath) {
            Copy-Item -Path "$sourcePath\*" -Destination $destination -Recurse -Force
        }
    } else {
        Copy-Item -Path "$tempDir\*" -Destination $destination -Recurse -Force
    }
    
    Remove-Item -Path $tempDir -Recurse -Force
}

Write-Host "Setting up GhostOS build environment..."

try {
    # ARM GCC Toolchain
    Write-Host "Installing ARM GCC Toolchain..."
    $toolchainZip = Join-Path $env:TEMP "gcc-arm-none-eabi.zip"
    Download-File -url $toolchainUrl -output $toolchainZip
    Extract-And-Move -zipFile $toolchainZip -destination $toolchainDir -innerDir "gcc-arm-none-eabi-10.3-2021.10"
    Remove-Item $toolchainZip
    
    # CMake
    Write-Host "Installing CMake..."
    $cmakeZip = Join-Path $env:TEMP "cmake.zip"
    Download-File -url $cmakeUrl -output $cmakeZip
    Extract-And-Move -zipFile $cmakeZip -destination $cmakeDir -innerDir "cmake-3.26.4-windows-x86_64"
    Remove-Item $cmakeZip
    
    # Python
    Write-Host "Installing Python..."
    $pythonZip = Join-Path $env:TEMP "python.zip"
    Download-File -url $pythonUrl -output $pythonZip
    Extract-And-Move -zipFile $pythonZip -destination $pythonDir
    Remove-Item $pythonZip
    
    # Ninja
    Write-Host "Installing Ninja..."
    $ninjaZip = Join-Path $env:TEMP "ninja.zip"
    Download-File -url $ninjaUrl -output $ninjaZip
    Extract-And-Move -zipFile $ninjaZip -destination $ninjaDir
    Remove-Item $ninjaZip
    
    # dd utility
    Write-Host "Installing dd utility..."
    $ddZip = Join-Path $env:TEMP "dd.zip"
    Download-File -url $ddUrl -output $ddZip
    Extract-And-Move -zipFile $ddZip -destination $ddDir
    Remove-Item $ddZip
    
    # Add tools to PATH
    $env:Path = "$toolchainDir\bin;$cmakeDir\bin;$pythonDir;$ninjaDir;$ddDir;" + $env:Path
    
    Write-Host "Build environment setup complete!"
}
catch {
    Write-Error "Failed to set up build environment: $_"
    exit 1
}

# Verify installations
Write-Host "Verifying installations..."
$tools = @(
    @{name="ARM GCC"; cmd="arm-none-eabi-gcc"; arg="--version"},
    @{name="CMake"; cmd="cmake"; arg="--version"},
    @{name="Python"; cmd="python"; arg="--version"},
    @{name="Ninja"; cmd="ninja"; arg="--version"},
    @{name="dd"; cmd="dd"; arg="--version"}
)

foreach ($tool in $tools) {
    try {
        $result = & $tool.cmd $tool.arg
        Write-Host "$($tool.name) installed successfully: $result"
    }
    catch {
        Write-Error "Failed to verify $($tool.name) installation"
        exit 1
    }
}

# Create build directory structure
Write-Host "Creating build directory structure..."
New-Item -ItemType Directory -Force -Path "build"
New-Item -ItemType Directory -Force -Path "build\debug"
New-Item -ItemType Directory -Force -Path "build\release"

# Generate initial CMake configuration
Write-Host "Generating initial CMake configuration..."
$Env:PATH = $env:Path
Set-Location -Path "build\debug"

cmake -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$scriptPath\config\build.cmake" `
    -DCMAKE_BUILD_TYPE=Debug `
    -DTARGET_BOARD=raspberry_pi_zero_w `
    ".."

Write-Host "Build environment setup complete!"
Write-Host @"

GhostOS Build Environment has been configured:
- ARM GCC Toolchain: $toolchainVersion
- CMake: $cmakeVersion
- Python: $pythonVersion
- Ninja: $ninjaVersion
- dd: $ddVersion

To build GhostOS:
1. Open PowerShell
2. Navigate to build directory: cd build\debug
3. Run build: ninja

For release builds, use: build\release
"@
