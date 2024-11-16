# GhostOS Build Script
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Debug', 'Release')]
    [string]$BuildType = 'Debug',
    
    [Parameter(Mandatory=$false)]
    [switch]$Clean,
    
    [Parameter(Mandatory=$false)]
    [switch]$Package
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$BuildDir = Join-Path $ProjectRoot "build\$BuildType"

# Clean build directory if requested
if ($Clean) {
    Write-Host "Cleaning build directory..."
    if (Test-Path $BuildDir) {
        Remove-Item -Recurse -Force $BuildDir
    }
}

# Create build directory if it doesn't exist
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}

# Configure build
Write-Host "Configuring $BuildType build..."
Push-Location $BuildDir
try {
    # Use CMake to configure the build
    $cmakeArgs = @(
        "-G", "Ninja",
        "-DCMAKE_TOOLCHAIN_FILE=`"$ProjectRoot\config\toolchain.cmake`"",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DTARGET_BOARD=raspberry_pi_zero_w",
        "`"$ProjectRoot`""
    )
    
    $process = Start-Process -FilePath "cmake" -ArgumentList $cmakeArgs -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "CMake configuration failed"
    }

    # Build
    Write-Host "Building GhostOS..."
    $process = Start-Process -FilePath "ninja" -NoNewWindow -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Build failed"
    }

    # Package if requested
    if ($Package) {
        Write-Host "Packaging GhostOS..."
        
        # Create output directory
        $OutputDir = Join-Path $ProjectRoot "output\$BuildType"
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        
        # Copy kernel and bootloader
        Copy-Item (Join-Path $BuildDir "bin\ghostos.bin") $OutputDir
        Copy-Item (Join-Path $BuildDir "bin\boot.bin") $OutputDir
        
        Write-Host @"
Build completed successfully!

Output files:
- Kernel: $OutputDir\ghostos.bin
- Bootloader: $OutputDir\boot.bin

To flash to SD card:
1. Insert SD card
2. Run: .\tools\flash_sd.ps1 -ImagePath $OutputDir\ghostos.bin
"@
    }
} finally {
    Pop-Location
}
