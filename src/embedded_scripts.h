#pragma once

// Runtime PowerShell helpers are compiled into EasyWG.exe.
// EasyWG materializes them only as short-lived files under %TEMP%,
// executes them, and deletes them immediately.

namespace EmbeddedScripts
{
inline constexpr char kImportZipScript[] = R"EWGZIP(
param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [Parameter(Mandatory = $true)]
    [string]$ResultFile
)

$ErrorActionPreference = "Stop"
$Utf8NoBom = New-Object Text.UTF8Encoding($false)

function Get-UniqueDestination {
    param([string]$Directory, [string]$FileName)

    $candidate = Join-Path $Directory $FileName
    if (-not (Test-Path -LiteralPath $candidate)) {
        return $candidate
    }

    $base = [IO.Path]::GetFileNameWithoutExtension($FileName)
    $ext = [IO.Path]::GetExtension($FileName)

    for ($i = 1; $i -lt 10000; $i++) {
        $candidate = Join-Path $Directory ("{0}_{1}{2}" -f $base, $i, $ext)
        if (-not (Test-Path -LiteralPath $candidate)) {
            return $candidate
        }
    }

    throw "Unable to create a unique output filename."
}

try {
    if (-not (Test-Path -LiteralPath $ZipPath -PathType Leaf)) {
        throw "ZIP file not found: $ZipPath"
    }

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $shell = New-Object -ComObject Shell.Application
    $zipNs = $shell.NameSpace($ZipPath)

    if ($null -eq $zipNs) {
        throw "Windows ZIP shell namespace could not open the archive."
    }

    $found = @()

    foreach ($item in @($zipNs.Items())) {
        if ($item.IsFolder) {
            continue
        }

        $name = [IO.Path]::GetFileName([string]$item.Name)
        if ([IO.Path]::GetExtension($name).Equals(".conf", [StringComparison]::OrdinalIgnoreCase)) {
            $found += $item
        }
    }

    if ($found.Count -eq 0) {
        # Search nested folders recursively using Shell Namespace.
        function Find-ConfItems($folder) {
            $result = @()
            foreach ($item in @($folder.Items())) {
                if ($item.IsFolder) {
                    $sub = $item.GetFolder
                    if ($sub) {
                        $result += Find-ConfItems $sub
                    }
                }
                else {
                    $name = [IO.Path]::GetFileName([string]$item.Name)
                    if ([IO.Path]::GetExtension($name).Equals(".conf", [StringComparison]::OrdinalIgnoreCase)) {
                        $result += $item
                    }
                }
            }
            return $result
        }

        $found = @(Find-ConfItems $zipNs)
    }

    if ($found.Count -eq 0) {
        throw "No .conf file was found in the ZIP archive."
    }

    $destNs = $shell.NameSpace($OutputDir)
    if ($null -eq $destNs) {
        throw "Windows ZIP destination namespace could not be opened."
    }

    $outputFiles = @()

    foreach ($item in $found) {
        $safeName = [IO.Path]::GetFileName([string]$item.Name)
        if ($null -eq $safeName -or $safeName.Trim().Length -eq 0) {
            continue
        }

        $destination = Get-UniqueDestination $OutputDir $safeName
        $tempFolder = Join-Path ([IO.Path]::GetTempPath()) ("EasyWG-ZIP-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $tempFolder | Out-Null

        try {
            $tempNs = $shell.NameSpace($tempFolder)
            $tempNs.CopyHere($item, 20)

            $source = Join-Path $tempFolder $safeName
            for ($i = 0; $i -lt 100; $i++) {
                if (Test-Path -LiteralPath $source -PathType Leaf) {
                    break
                }
                Start-Sleep -Milliseconds 100
            }

            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "Failed to extract: $safeName"
            }

            Move-Item -LiteralPath $source -Destination $destination -Force
            $outputFiles += [IO.Path]::GetFullPath($destination)
        }
        finally {
            Remove-Item -LiteralPath $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    if ($outputFiles.Count -eq 0) {
        throw "No usable .conf file could be extracted."
    }

    [IO.File]::WriteAllLines($ResultFile, $outputFiles, $Utf8NoBom)
    exit 0
}
catch {
    [IO.File]::WriteAllText($ResultFile, $_.Exception.Message, $Utf8NoBom)
    exit 1
}
)EWGZIP";

inline constexpr char kCoreUpdateScript[] = R"EWGUPDATE(
param(
    [Parameter(Mandatory = $true)]
    [string]$AppDir,

    [Parameter(Mandatory = $true)]
    [string]$ProjectDir,

    [Parameter(Mandatory = $true)]
    [string]$ResultFile
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Utf8NoBom = New-Object Text.UTF8Encoding($false)

function Write-Result {
    param([Parameter(Mandatory = $true)] [string]$Text)
    [IO.File]::WriteAllText($ResultFile, $Text, $Utf8NoBom)
}

function Get-LatestWireGuardNt {
    $baseUrl = "https://download.wireguard.com/wireguard-nt/"
    $response = Invoke-WebRequest -UseBasicParsing -Uri $baseUrl
    $regex = [regex]'wireguard-nt-(?<version>[0-9]+(?:\.[0-9]+)*)\.zip'
    $items = @()

    foreach ($match in $regex.Matches($response.Content)) {
        try {
            $items += [pscustomobject]@{
                FileName = $match.Value
                Version = [version]$match.Groups["version"].Value
                VersionText = $match.Groups["version"].Value
            }
        }
        catch {
        }
    }

    if ($items.Count -eq 0) {
        throw "Unable to determine the latest WireGuardNT SDK version."
    }

    return $items | Sort-Object Version -Descending | Select-Object -First 1
}

function Stage-LatestWireGuardNt {
    param([Parameter(Mandatory = $true)] $Latest)

    $baseUrl = "https://download.wireguard.com/wireguard-nt/"
    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("EasyWG-WGNT-CHECK-" + [guid]::NewGuid().ToString("N"))
    $zipPath = Join-Path $tempRoot $Latest.FileName
    $extractDir = Join-Path $tempRoot "extract"

    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    Invoke-WebRequest -UseBasicParsing -Uri ($baseUrl + $Latest.FileName) -OutFile $zipPath
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force

    $dll = Get-ChildItem -Path $extractDir -Recurse -Filter "wireguard.dll" |
        Where-Object { -not $_.PSIsContainer } |
        Where-Object { $_.FullName -match '[\\/]bin[\\/]amd64[\\/]wireguard\.dll$' } |
        Select-Object -First 1

    if (-not $dll) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        throw "amd64 wireguard.dll was not found in the official SDK archive."
    }

    return [pscustomobject]@{
        TempRoot = $tempRoot
        DllPath = $dll.FullName
        Hash = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256).Hash
    }
}

function Install-StagedWireGuardNt {
    param(
        [Parameter(Mandatory = $true)] $Staged,
        [Parameter(Mandatory = $true)] [string]$DestinationDir
    )

    New-Item -ItemType Directory -Force -Path $DestinationDir | Out-Null

    $destination = Join-Path $DestinationDir "wireguard.dll"
    $tempDestination = $destination + ".easywg.tmp." + $PID

    Copy-Item -LiteralPath $Staged.DllPath -Destination $tempDestination -Force
    Move-Item -LiteralPath $tempDestination -Destination $destination -Force
}

function Get-CurrentText {
    param([Parameter(Mandatory = $true)] [string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ""
    }
    return ([IO.File]::ReadAllText($Path)).Trim()
}

$stagedNt = $null

try {
    New-Item -ItemType Directory -Force -Path $AppDir | Out-Null

    # Legacy metadata file is intentionally no longer used.
    Remove-Item -LiteralPath (Join-Path $AppDir "wireguard-nt-version.txt") -Force -ErrorAction SilentlyContinue

    $latestNt = Get-LatestWireGuardNt
    $stagedNt = Stage-LatestWireGuardNt -Latest $latestNt

    $currentNtPath = Join-Path $AppDir "wireguard.dll"
    $needNt = $true

    if (Test-Path -LiteralPath $currentNtPath -PathType Leaf) {
        $currentHash = (Get-FileHash -LiteralPath $currentNtPath -Algorithm SHA256).Hash
        $needNt = -not $currentHash.Equals($stagedNt.Hash, [StringComparison]::OrdinalIgnoreCase)
    }

    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    $latestTunnelCommit = ""
    $currentTunnelCommit = Get-CurrentText (Join-Path $AppDir "wireguard-windows-commit.txt")
    $needTunnel = $false

    if ($git) {
        $remoteLine = & $git.Source ls-remote https://git.zx2c4.com/wireguard-windows HEAD 2>$null | Select-Object -First 1
        if ($null -ne $remoteLine -and $remoteLine.Trim().Length -gt 0) {
            $latestTunnelCommit = ($remoteLine -split '\s+')[0].Trim()
            if ($null -ne $latestTunnelCommit -and $latestTunnelCommit.Trim().Length -gt 0) {
                $needTunnel = ($null -eq $currentTunnelCommit -or $currentTunnelCommit.Trim().Length -eq 0) -or
                    -not $latestTunnelCommit.Equals($currentTunnelCommit, [StringComparison]::OrdinalIgnoreCase)
            }
        }
    }

    if (-not $needNt -and -not $needTunnel) {
        Write-Result "NO_UPDATE"
        exit 0
    }

    $updateBat = Join-Path $ProjectDir "update_official_core.bat"

    if ($needTunnel) {
        if ((Test-Path -LiteralPath $updateBat -PathType Leaf) -and $git) {
            $process = Start-Process -FilePath $env:ComSpec -ArgumentList @('/d', '/c', ('"{0}"' -f $updateBat)) -Wait -PassThru -WindowStyle Hidden
            if ($process.ExitCode -ne 0) {
                throw "update_official_core.bat failed with exit code $($process.ExitCode)."
            }

            Write-Result "UPDATED"
            exit 10
        }

        if ($needNt) {
            Install-StagedWireGuardNt -Staged $stagedNt -DestinationDir $AppDir
        }

        Write-Result "TUNNEL_UPDATE_AVAILABLE"
        exit 20
    }

    if ($needNt) {
        Install-StagedWireGuardNt -Staged $stagedNt -DestinationDir $AppDir
        Write-Result "UPDATED"
        exit 10
    }

    Write-Result "NO_UPDATE"
    exit 0
}
catch {
    Write-Result ("ERROR: " + $_.Exception.Message)
    exit 1
}
finally {
    if ($stagedNt -and (Test-Path -LiteralPath $stagedNt.TempRoot)) {
        Remove-Item -LiteralPath $stagedNt.TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
)EWGUPDATE";

inline constexpr char kBootstrapWireGuardNtScript[] = R"EWGWGNT(
param(
    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [Parameter(Mandatory = $true)]
    [string]$ResultFile
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Utf8NoBom = New-Object Text.UTF8Encoding($false)

function Write-Result {
    param([Parameter(Mandatory = $true)] [string]$Text)
    [IO.File]::WriteAllText($ResultFile, $Text, $Utf8NoBom)
}

$baseUrl = "https://download.wireguard.com/wireguard-nt/"
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("EasyWG-WGNT-" + [guid]::NewGuid().ToString("N"))

try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $baseUrl
    $regex = [regex]'wireguard-nt-(?<version>[0-9]+(?:\.[0-9]+)*)\.zip'
    $items = @()

    foreach ($match in $regex.Matches($response.Content)) {
        try {
            $items += [pscustomobject]@{
                FileName = $match.Value
                Version = [version]$match.Groups["version"].Value
                VersionText = $match.Groups["version"].Value
            }
        }
        catch {
        }
    }

    if ($items.Count -eq 0) {
        throw "Unable to determine the latest WireGuardNT SDK version from the official index."
    }

    $latest = $items | Sort-Object Version -Descending | Select-Object -First 1
    $zipPath = Join-Path $tempRoot $latest.FileName
    $extractDir = Join-Path $tempRoot "extract"
    $downloadUrl = $baseUrl + $latest.FileName

    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $zipPath
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

    $shell = New-Object -ComObject Shell.Application
    $zipNs = $shell.NameSpace($zipPath)
    $destNs = $shell.NameSpace($extractDir)

    if ($null -eq $zipNs -or $null -eq $destNs) {
        throw "Windows ZIP shell namespace could not open the WireGuardNT SDK archive."
    }

    $destNs.CopyHere($zipNs.Items(), 20)

    for ($i = 0; $i -lt 300; $i++) {
        $candidate = Get-ChildItem -Path $extractDir -Recurse -Filter "wireguard.dll" -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            Where-Object { $_.FullName -match '[\\/]bin[\\/]amd64[\\/]wireguard\.dll$' } |
            Select-Object -First 1

        if ($candidate) {
            break
        }

        Start-Sleep -Milliseconds 100
    }

    $dll = Get-ChildItem -Path $extractDir -Recurse -Filter "wireguard.dll" |
        Where-Object { -not $_.PSIsContainer } |
        Where-Object { $_.FullName -match '[\\/]bin[\\/]amd64[\\/]wireguard\.dll$' } |
        Select-Object -First 1

    if (-not $dll) {
        throw "amd64 wireguard.dll was not found inside the official WireGuardNT SDK archive."
    }

    $destination = Join-Path $OutputDir "wireguard.dll"
    $tempDestination = $destination + ".easywg.tmp." + $PID

    Copy-Item -LiteralPath $dll.FullName -Destination $tempDestination -Force
    Move-Item -LiteralPath $tempDestination -Destination $destination -Force

    Write-Result ("OK|" + $latest.VersionText + "|" + $downloadUrl)
    exit 0
}
catch {
    Write-Result ("ERROR|" + $_.Exception.Message)
    exit 1
}
finally {
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
)EWGWGNT";


inline constexpr char kExtractWintunScript[] = R"EWGWINTUN(
param(
    [Parameter(Mandatory = $true)]
    [string]$ZipPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputDir,

    [Parameter(Mandatory = $true)]
    [string]$ResultFile
)

$ErrorActionPreference = "Stop"
$Utf8NoBom = New-Object Text.UTF8Encoding($false)

try {
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("EasyWG-WINTUN-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

    try {
        $shell = New-Object -ComObject Shell.Application
        $zipNs = $shell.NameSpace($ZipPath)
        $destNs = $shell.NameSpace($tempRoot)

        if ($null -eq $zipNs -or $null -eq $destNs) {
            throw "Windows ZIP shell namespace could not open the Wintun archive."
        }

        $destNs.CopyHere($zipNs.Items(), 20)

        $dll = $null
        for ($i = 0; $i -lt 300; $i++) {
            $dll = Get-ChildItem -Path $tempRoot -Recurse -Filter "wintun.dll" -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } |
                Where-Object {
                    $_.FullName -match '[\\/]bin[\\/]amd64[\\/]wintun\.dll$' -or
                    ($_.Name -ieq 'wintun.dll' -and $_.Directory.Name -ieq 'amd64')
                } |
                Select-Object -First 1

            if ($dll) {
                break
            }

            Start-Sleep -Milliseconds 100
        }

        if (-not $dll) {
            throw "amd64 wintun.dll was not found in the official Wintun archive."
        }

        Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $OutputDir "wintun.dll") -Force
        [IO.File]::WriteAllText($ResultFile, "OK", $Utf8NoBom)
        exit 0
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
catch {
    [IO.File]::WriteAllText($ResultFile, ("ERROR|" + $_.Exception.Message), $Utf8NoBom)
    exit 1
}
)EWGWINTUN";

} // namespace EmbeddedScripts
