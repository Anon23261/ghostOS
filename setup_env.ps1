# GhostOS Environment Setup Script

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

# Define tool versions and URLs
$tools = @{
    "gcc-arm" = @{
        "version" = "10.3-2021.10"
        "url" = "https://developer.arm.com/-/media/Files/downloads/gnu-rm/10.3-2021.10/gcc-arm-none-eabi-10.3-2021.10-win32.zip"
        "folder" = "gcc-arm-none-eabi-10.3-2021.10"
    }
    "cmake" = @{
        "version" = "3.26.4"
        "url" = "https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4-windows-x86_64.zip"
        "folder" = "cmake-3.26.4-windows-x86_64"
    }
    "ninja" = @{
        "version" = "1.11.1"
        "url" = "https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-win.zip"
        "folder" = "ninja-1.11.1"
    }
}

# Create tools directory
$toolsDir = Join-Path $ProjectRoot "tools"
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null

foreach ($tool in $tools.GetEnumerator()) {
    $toolPath = Join-Path $toolsDir $tool.Value.folder
    
    # Skip if tool is already installed
    if (Test-Path $toolPath) {
        Write-Host "$($tool.Key) is already installed"
        continue
    }
    
    Write-Host "Installing $($tool.Key) version $($tool.Value.version)..."
    
    # Download and extract tool
    $zipPath = Join-Path $toolsDir "$($tool.Key).zip"
    Invoke-WebRequest -Uri $tool.Value.url -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $toolsDir -Force
    Remove-Item $zipPath
}

# Add tools to PATH
$env:Path = "$toolsDir\$($tools['gcc-arm'].folder)\bin;$toolsDir\$($tools['cmake'].folder)\bin;$toolsDir\$($tools['ninja'].folder);$env:Path"

# Verify installation
Write-Host "`nVerifying tool installation..."
$requiredCommands = @(
    @{ Command = "arm-none-eabi-gcc"; Args = @("--version") },
    @{ Command = "cmake"; Args = @("--version") },
    @{ Command = "ninja"; Args = @("--version") }
)

foreach ($cmd in $requiredCommands) {
    try {
        $result = & $cmd.Command $cmd.Args
        Write-Host "$($cmd.Command) is installed: $($result[0])"
    } catch {
        Write-Error "Failed to verify $($cmd.Command)"
        exit 1
    }
}

Write-Host "`nEnvironment setup completed successfully!"
Write-Host "You can now run: .\deploy.ps1 -BuildType Release -Clean"
