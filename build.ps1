# GhostOS Build Script
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('debug', 'release')]
    [string]$BuildType = 'debug',
    
    [Parameter(Mandatory=$false)]
    [switch]$Clean,
    
    [Parameter(Mandatory=$false)]
    [switch]$Package
)

$ErrorActionPreference = "Stop"
$BuildDir = "E:\ghostOS\build\$BuildType"

# Clean build directory if requested
if ($Clean) {
    Write-Host "Cleaning build directory..."
    if (Test-Path $BuildDir) {
        Remove-Item -Recurse -Force $BuildDir
    }
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}

# Create build directory if it doesn't exist
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
}

# Configure build
Write-Host "Configuring $BuildType build..."
Push-Location $BuildDir
try {
    cmake -G Ninja `
        -DCMAKE_TOOLCHAIN_FILE="E:\ghostOS\config\toolchain.cmake" `
        -DCMAKE_BUILD_TYPE=$BuildType `
        -DTARGET_BOARD=raspberry_pi_zero_w `
        "E:\ghostOS"

    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }

    # Build
    Write-Host "Building GhostOS..."
    ninja
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    # Package if requested
    if ($Package) {
        Write-Host "Packaging GhostOS..."
        
        # Create output directory
        $OutputDir = "E:\ghostOS\output\$BuildType"
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        
        # Copy kernel and bootloader
        Copy-Item "kernel\ghostos.bin" $OutputDir
        Copy-Item "bootloader\boot.bin" $OutputDir
        
        # Create SD card image
        Write-Host "Creating SD card image..."
        $ImagePath = "$OutputDir\ghostos.img"
        
        # Generate 2GB image file
        $Size = 2GB
        $Buffer = New-Object byte[] 1MB
        $Stream = [System.IO.File]::Create($ImagePath)
        try {
            for ($i = 0; $i -lt $Size/1MB; $i++) {
                $Stream.Write($Buffer, 0, $Buffer.Length)
            }
        } finally {
            $Stream.Close()
        }
        
        Write-Host @"
Build completed successfully!

Output files:
- Kernel: $OutputDir\ghostos.bin
- Bootloader: $OutputDir\boot.bin
- SD Card Image: $OutputDir\ghostos.img

To flash to SD card:
1. Insert SD card
2. Use Win32DiskImager or DD to write ghostos.img to the card
3. Boot Raspberry Pi Zero W with the SD card
"@
    }
} finally {
    Pop-Location
}
