#requires -Version 5.1
<#
.SYNOPSIS
    Build and package WinApkInfo as a standalone Windows executable.

.DESCRIPTION
    Pipeline steps:
      1. Verify Python and build dependencies.
      2. Run quick regression checks (verify_fixes.py --quick).
      3. Generate Windows version resources from version.py.
      4. Locate aapt2.exe and bundle it with the application.
      5. Build with PyInstaller (onedir or onefile).
      6. Run the packaged exe with --self-test.
      7. Create a versioned zip in dist/ plus a SHA256 checksum.

.EXAMPLE
    .\build.ps1 -Clean

.EXAMPLE
    .\build.ps1 -Mode onefile -Aapt2Path "D:\Android\Sdk\build-tools\35.0.0\aapt2.exe"

.EXAMPLE
    .\build.ps1 -Aapt2Path .\tools\aapt2.exe -SkipTests -NoZip
#>
[CmdletBinding()]
param(
    [ValidateSet("onedir", "onefile")]
    [string]$Mode = "onedir",

    [string]$Version = "",

    [string]$Aapt2Path = "",

    [string]$Python = "python",

    [switch]$Clean,

    [switch]$SkipTests,

    [switch]$FullTests,

    [switch]$AllowMissingAapt2,

    [switch]$NoZip
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Surface the real failure in GitHub Actions annotations. Without this the
# step can show only "Process completed with exit code 1", while full logs
# require a signed-in GitHub session.
trap {
    $message = $_.Exception.Message
    if ($env:GITHUB_ACTIONS -eq "true") {
        Write-Host "::error::$message"
    }
    else {
        Write-Host "ERROR: $message" -ForegroundColor Red
    }
    Write-Host $_.ScriptStackTrace
    exit 1
}

$ProjectRoot = $PSScriptRoot
$BuildRoot = Join-Path $ProjectRoot "build"
$DistRoot = Join-Path $ProjectRoot "dist"
$WorkRoot = Join-Path $BuildRoot "pyinstaller"
$SpecFile = Join-Path $ProjectRoot "WinApkInfo.spec"

# Windows runners default to a legacy console code page (cp1252). The test
# suite and version-info scripts print Chinese, so force UTF-8 for children.
$env:PYTHONIOENCODING = "utf-8"

$runningApp = @(Get-Process -Name "WinApkInfo" -ErrorAction SilentlyContinue)
if ($runningApp.Count -gt 0) {
    $pids = ($runningApp | ForEach-Object { $_.Id }) -join ", "
    throw "WinApkInfo.exe is running (PID: $pids). Close it before building; Windows locks the old exe."
}

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Assert-LastExitCode {
    param([string]$Action)
    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE."
    }
}

function Resolve-Aapt2Path {
    param([string]$Explicit)

    $candidates = New-Object System.Collections.Generic.List[string]
    if ($Explicit) {
        if (Test-Path -LiteralPath $Explicit -PathType Container) {
            $candidates.Add((Join-Path $Explicit "aapt2.exe"))
        }
        else {
            $candidates.Add($Explicit)
        }
    }

    # Project-local convention: put aapt2.exe under tools/ (ignored by git).
    $candidates.Add((Join-Path $ProjectRoot "tools\aapt2.exe"))

    $command = Get-Command "aapt2" -ErrorAction SilentlyContinue
    if ($command -and $command.Source) {
        $candidates.Add($command.Source)
    }

    $localSdk = $null
    if ($env:LOCALAPPDATA) {
        $localSdk = Join-Path $env:LOCALAPPDATA "Android\Sdk"
    }
    $sdkRoots = @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT, $localSdk)
    foreach ($root in $sdkRoots) {
        if (-not $root) { continue }
        $buildToolsRoot = Join-Path $root "build-tools"
        if (-not (Test-Path -LiteralPath $buildToolsRoot -PathType Container)) { continue }
        $buildTools = Get-ChildItem -LiteralPath $buildToolsRoot -Directory |
            Sort-Object -Property Name -Descending
        foreach ($dir in $buildTools) {
            $candidate = Join-Path $dir.FullName "aapt2.exe"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $candidates.Add($candidate)
            }
        }
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    return $null
}

Write-Step "Checking Python and dependencies"
& $Python --version
Assert-LastExitCode "python --version"

$dependencyCheck = @'
import importlib.util
import sys

missing = [name for name in ('PyInstaller', 'PyQt6', 'PIL', 'ruff', 'pytest')
           if importlib.util.find_spec(name) is None]
if missing:
    sys.stderr.write('Missing Python packages: ' + ', '.join(missing) + '\n')
    sys.stderr.write('Install them with: python -m pip install -r requirements-dev.txt\n')
    raise SystemExit(1)
print(sys.version.split()[0])
'@
$pythonVersion = (& $Python -c $dependencyCheck).Trim()
Assert-LastExitCode "dependency check"

if (-not $Version) {
    $Version = (& $Python -c "import sys; sys.path.insert(0, sys.argv[1]); import version; print(version.__version__)" $ProjectRoot).Trim()
    Assert-LastExitCode "read version.py"
}
if ($Version -notmatch '^\d+(\.\d+){1,3}$') {
    throw "Invalid version '$Version'. Expected a numeric version such as 1.1.2."
}

if (-not (Test-Path -LiteralPath $SpecFile -PathType Leaf)) {
    throw "Missing PyInstaller spec: $SpecFile"
}

if ($Clean) {
    Write-Step "Cleaning build and dist directories"
    foreach ($path in @($BuildRoot, $DistRoot)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
}
New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null
New-Item -ItemType Directory -Force -Path $DistRoot | Out-Null

# Resolve aapt2 before the regression checks: verify_fixes.py calls
# find_aapt2(), which only looks at the script directory and PATH. CI runners
# have aapt2 in the Android SDK but usually not on PATH, so export the
# resolved directory to child processes or the test run aborts immediately.
Write-Step "Locating aapt2.exe"
$resolvedAapt2 = Resolve-Aapt2Path -Explicit $Aapt2Path
if (-not $resolvedAapt2) {
    if (-not $AllowMissingAapt2) {
        throw @"
aapt2.exe was not found.

Put it at tools\aapt2.exe, pass -Aapt2Path <file>, install it on PATH,
or install the Android SDK build-tools. To build an incomplete package
anyway, pass -AllowMissingAapt2.
"@
    }
    Write-Warning "aapt2.exe not found; the package will rely on aapt2 from PATH."
}
else {
    Write-Host "aapt2: $resolvedAapt2"
    $aapt2Dir = Split-Path -Parent $resolvedAapt2
    $env:PATH = "$aapt2Dir;$env:PATH"
}

if (-not $SkipTests) {
    Write-Step "Running linter (ruff check)"
    & $Python -m ruff check $ProjectRoot
    Assert-LastExitCode "ruff check"

    Write-Step "Running regression checks (pytest)"
    & $Python -m pytest (Join-Path $ProjectRoot "tests") -v
    Assert-LastExitCode "pytest"
}
else {
    Write-Host "Skipping tests and linting (-SkipTests)." -ForegroundColor Yellow
}

Write-Step "Generating Windows version resources"
$versionFile = Join-Path $BuildRoot "version_info.txt"
& $Python (Join-Path $ProjectRoot "scripts\gen_version_info.py") $Version $versionFile
Assert-LastExitCode "generate version_info.txt"

Write-Step "Building with PyInstaller ($Mode)"
$env:WINAPKINFO_VERSION = $Version
$env:WINAPKINFO_VERSION_FILE = $versionFile
$env:WINAPKINFO_MODE = $Mode
if ($resolvedAapt2) {
    $env:WINAPKINFO_AAPT2 = $resolvedAapt2
}
else {
    Remove-Item Env:\WINAPKINFO_AAPT2 -ErrorAction SilentlyContinue
}

& $Python -m PyInstaller --noconfirm --clean --distpath $DistRoot --workpath $WorkRoot $SpecFile
Assert-LastExitCode "PyInstaller"

if ($Mode -eq "onedir") {
    $exePath = Join-Path $DistRoot "WinApkInfo\WinApkInfo.exe"
}
else {
    $exePath = Join-Path $DistRoot "WinApkInfo.exe"
}
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    throw "Build output not found: $exePath"
}

Write-Step "Running packaged self-test"
$selfTestArgument = "--self-test"
$sample = $null
$sampleDir = Join-Path $ProjectRoot "testSample"
if (Test-Path -LiteralPath $sampleDir -PathType Container) {
    $sample = Get-ChildItem -LiteralPath $sampleDir -Filter "*.apk" -File -ErrorAction SilentlyContinue |
        Sort-Object -Property Length |
        Select-Object -First 1
}
if (-not $sample) {
    # testSample/ 不入库：退化到仓库内置的迷你固件，保证 CI 上也能验证
    # 打包产物的图标提取链路（自适应图标 + 矢量栅格化），而不是只查资源。
    $fixture = Join-Path $ProjectRoot "tests\fixtures\mini.apk"
    if (Test-Path -LiteralPath $fixture -PathType Leaf) {
        $sample = Get-Item -LiteralPath $fixture
    }
}
if ($sample) {
    $selfTestArgument = '--self-test "{0}"' -f ($sample.FullName -replace '"', '\"')
    Write-Host "Sample APK: $($sample.FullName)"
}
$selfTest = Start-Process -FilePath $exePath -ArgumentList $selfTestArgument `
    -WorkingDirectory (Split-Path -Parent $exePath) -Wait -PassThru
if ($selfTest.ExitCode -ne 0) {
    $logPath = if ($env:LOCALAPPDATA) {
        Join-Path $env:LOCALAPPDATA "WinApkInfo\winapkinfo.log"
    } else {
        Join-Path $env:TEMP "winapkinfo.log"
    }
    throw "Packaged self-test failed (exit $($selfTest.ExitCode)). See $logPath"
}
Write-Host "Self-test passed."

if (-not $NoZip) {
    Write-Step "Creating release archive"
    $stageParent = Join-Path $BuildRoot "package-$Mode"
    $stageDir = Join-Path $stageParent "WinApkInfo"
    if (Test-Path -LiteralPath $stageParent) {
        Remove-Item -LiteralPath $stageParent -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $stageDir | Out-Null

    if ($Mode -eq "onedir") {
        Copy-Item -Path (Join-Path $DistRoot "WinApkInfo\*") -Destination $stageDir -Recurse -Force
    }
    else {
        Copy-Item -LiteralPath $exePath -Destination $stageDir -Force
    }
    foreach ($doc in @("README.md", "LICENSE")) {
        $source = Join-Path $ProjectRoot $doc
        if (Test-Path -LiteralPath $source) {
            Copy-Item -LiteralPath $source -Destination $stageDir -Force
        }
    }

    $bundledAapt2 = Get-ChildItem -LiteralPath $stageDir -Recurse -Filter "aapt2.exe" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($Mode -eq "onedir") {
        if ($resolvedAapt2 -and -not $bundledAapt2) {
            throw "aapt2.exe was resolved but is missing from the staged package."
        }
        if (-not $bundledAapt2) {
            Write-Warning "The staged package does not contain aapt2.exe."
        }
    }
    # onefile: aapt2 is inside the exe archive, and the --self-test above
    # already exercised it; there is no loose aapt2.exe to inspect here.

    $commit = ""
    $git = Get-Command "git" -ErrorAction SilentlyContinue
    if ($git) {
        $commit = (& git -C $ProjectRoot rev-parse --short HEAD 2>$null)
        if ($LASTEXITCODE -ne 0) { $commit = "" }
    }
    $buildInfo = @(
        "WinApkInfo $Version",
        "Mode: $Mode",
        "Python: $pythonVersion",
        "aapt2: $(if ($resolvedAapt2) { $resolvedAapt2 } else { 'not bundled' })",
        "Commit: $(if ($commit) { $commit } else { 'unknown' })",
        "Built: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
    )
    $buildInfo | Set-Content -LiteralPath (Join-Path $stageDir "BUILD_INFO.txt") -Encoding UTF8

    $archiveName = "WinApkInfo-$Version-windows-x64-$Mode.zip"
    $archivePath = Join-Path $DistRoot $archiveName
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    Compress-Archive -Path $stageDir -DestinationPath $archivePath -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumPath = "$archivePath.sha256"
    "$hash  $archiveName" | Set-Content -LiteralPath $checksumPath -Encoding ASCII

    Write-Step "Build complete"
    Write-Host "Executable : $exePath"
    Write-Host "Archive    : $archivePath"
    Write-Host "Checksum   : $checksumPath"
    Write-Host "SHA256     : $hash"
}
else {
    Write-Step "Build complete"
    Write-Host "Executable : $exePath"
    Write-Host "Archive    : skipped (-NoZip)"
}
