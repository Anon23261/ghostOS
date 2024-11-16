# GhostOS Test Runner Script
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('all', 'memory', 'security', 'boot')]
    [string]$TestType = 'all',
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Debug', 'Release')]
    [string]$BuildType = 'Debug'
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$BuildDir = Join-Path $ProjectRoot "build\$BuildType"

# Ensure we're in the project root
Push-Location $ProjectRoot

try {
    Write-Host "Building GhostOS for testing..."
    
    # Build the project
    & .\build.ps1 -BuildType $BuildType -Clean
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }
    
    # Build test suite
    Write-Host "Building test suite..."
    Push-Location $BuildDir
    try {
        # Use CMake to configure the build
        $cmakeArgs = @(
            "-G", "Ninja",
            "-DCMAKE_TOOLCHAIN_FILE=`"$ProjectRoot\config\toolchain.cmake`"",
            "-DCMAKE_BUILD_TYPE=$BuildType",
            "-DBUILD_TESTS=ON",
            "-DTEST_TYPE=$TestType",
            "`"$ProjectRoot`""
        )
        
        $process = Start-Process -FilePath "cmake" -ArgumentList $cmakeArgs -NoNewWindow -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Test suite configuration failed"
        }
        
        $process = Start-Process -FilePath "ninja" -NoNewWindow -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Test suite build failed"
        }
    }
    finally {
        Pop-Location
    }
    
    # Run tests
    Write-Host "Running tests..."
    & "$BuildDir\bin\ghost_tests.exe"
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed with exit code $LASTEXITCODE"
    }
    
    Write-Host "Test suite completed successfully"
}
catch {
    Write-Error "Test suite failed: $_"
    exit 1
}
finally {
    Pop-Location
}
