# GhostOS Deployment Script
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Debug', 'Release')]
    [string]$BuildType = 'Release',
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "output",
    
    [Parameter(Mandatory=$false)]
    [switch]$Clean,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# Setup environment variables
$toolsDir = Join-Path $ProjectRoot "tools"
$gccPath = Join-Path $toolsDir "gcc-arm-none-eabi-10.3-2021.10\bin"
$cmakePath = Join-Path $toolsDir "cmake-3.26.4-windows-x86_64\bin"
$ninjaPath = Join-Path $toolsDir "ninja-1.11.1"

# Add tools to PATH
$env:Path = "$gccPath;$cmakePath;$ninjaPath;$env:Path"

# Set compiler environment variables
$env:CC = Join-Path $gccPath "arm-none-eabi-gcc.exe"
$env:CXX = Join-Path $gccPath "arm-none-eabi-g++.exe"
$env:ASM = $env:CC

# 1. Verify environment
Write-Host "Verifying build environment..."
$requiredTools = @(
    @{ Name = "C Compiler"; Cmd = $env:CC; Args = @("--version") },
    @{ Name = "CMake"; Cmd = "cmake"; Args = @("--version") },
    @{ Name = "Ninja"; Cmd = "ninja"; Args = @("--version") }
)

foreach ($tool in $requiredTools) {
    try {
        $result = & $tool.Cmd $tool.Args
        Write-Host "$($tool.Name) found: $($result[0])"
    } catch {
        throw "Required tool not found: $($tool.Name)"
    }
}

# 2. Clean if requested
if ($Clean) {
    Write-Host "Cleaning previous builds..."
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue `
        @("$ProjectRoot/build", "$ProjectRoot/$OutputPath")
}

# 3. Create build directory
$BuildDir = Join-Path $ProjectRoot "build/$BuildType"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

# 4. Configure and build
Push-Location $BuildDir
try {
    Write-Host "Configuring build..."
    $cmakeArgs = @(
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=$BuildType",
        "-DCMAKE_TOOLCHAIN_FILE=$ProjectRoot/config/toolchain.cmake",
        "-DCMAKE_C_COMPILER=$env:CC",
        "-DCMAKE_CXX_COMPILER=$env:CXX",
        "-DCMAKE_ASM_COMPILER=$env:ASM",
        "-DENABLE_STACK_PROTECTOR=ON",
        "-DENABLE_POSITION_INDEPENDENT_CODE=ON",
        "-DENABLE_FORTIFY_SOURCE=ON",
        "-DENABLE_SECURITY_CHECKS=ON",
        "-DENABLE_LINK_TIME_OPTIMIZATION=ON",
        "-DENABLE_DEAD_CODE_ELIMINATION=ON",
        $ProjectRoot
    )
    
    & cmake $cmakeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }

    # 5. Build
    Write-Host "Building GhostOS..."
    & cmake --build . --config $BuildType
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    # 6. Run tests if not skipped
    if (!$SkipTests) {
        Write-Host "Running tests..."
        & ctest --output-on-failure
    }

    # 7. Create deployment package
    Write-Host "Creating deployment package..."
    $OutputDir = Join-Path $ProjectRoot $OutputPath
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    # Copy binaries if they exist
    $binDir = Join-Path $BuildDir "bin"
    if (Test-Path $binDir) {
        Copy-Item "$binDir/*" -Destination $OutputDir -Recurse
    } else {
        Write-Warning "No binaries found in $binDir"
    }

    # Create version info file
    $versionInfo = @"
GhostOS Version Information
--------------------------
Build Type: $BuildType
Build Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Compiler: $((& $env:CC --version)[0])
CMake: $((& cmake --version)[0])
Ninja: $((& ninja --version)[0])
"@
    Set-Content -Path "$OutputDir/version.txt" -Value $versionInfo

    # Create deployment package
    $packagePath = Join-Path $OutputDir "GhostOS-$BuildType.zip"
    if (Test-Path "$OutputDir/*") {
        Compress-Archive -Path "$OutputDir/*" -DestinationPath $packagePath -Force
        Write-Host @"
Deployment package created successfully!

Package location: $packagePath
Version info: $OutputDir/version.txt

To deploy:
1. Extract the package contents
2. Flash kernel.bin and bootloader.bin to the target device
3. Verify version.txt matches expected version
"@
    } else {
        Write-Error "No files found to package in $OutputDir"
    }

} catch {
    Write-Error "Deployment failed: $_"
    exit 1
} finally {
    Pop-Location
}
