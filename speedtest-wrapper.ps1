<#
    Speedtest Wrapper v1.666
    ------------------------
    Copyright (c) 2025 Benny Hult
    Licensed under the BSD 3-Clause License. See LICENSE file in the project root for details.

    A lightweight wrapper around speedtest.exe for running and parsing speed tests in PowerShell.
#>

param(
    # Where speedtest.exe is installed / searched
    [string]$InstallPath = 'C:\Temp\Speedtest',

    # Optional explicit path to speedtest.exe
    [string]$ExecutablePath,

    # List servers as a table
    [switch]$ListServers,

    # PowerShell-side server id, passed as --server-id X
    [int]$ServerId,

    # Everything else is passed directly to speedtest.exe
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$SpeedtestArgs
)

# --------------------------------------------------------
# Encoding + common settings
# --------------------------------------------------------
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8 } catch {}

$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference  = 'None'

# --------------------------------------------------------
# Helpers
# --------------------------------------------------------
function Invoke-WebRequestCompat {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$OutFile,
        [switch]$ReturnContent
    )

    $useBasicParsing = $PSVersionTable.PSVersion.Major -lt 6
    $params = @{
        Uri         = $Uri
        ErrorAction = 'Stop'
    }
    if ($useBasicParsing) {
        $params.UseBasicParsing = $true
    }

    if ($OutFile) {
        $params.OutFile = $OutFile
        Invoke-WebRequest @params | Out-Null
        return
    }

    $resp = Invoke-WebRequest @params
    if ($ReturnContent) {
        return $resp.Content
    } else {
        return $resp
    }
}

function Get-SpeedTestDownloadLink {
    param()

    $url = 'https://www.speedtest.net/apps/cli'
    $content = Invoke-WebRequestCompat -Uri $url -ReturnContent

    if ($content -match 'href="(https://install\.speedtest\.net/app/cli/ookla-speedtest-[\d\.]+-win64\.zip)"') {
        return $matches[1]
    }

    throw "Speedtest download link not found on page."
}

function Remove-FileSafe {
    param(
        [Parameter(Mandatory)][string]$Path
    )

    try {
        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
    } catch {
        Write-Verbose "Could not remove '$Path': $_"
    }
}

function Extract-Zip {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$Destination
    )

    if (-not (Test-Path -LiteralPath $ZipPath)) {
        throw "Zip file not found: $ZipPath"
    }

    if (Test-Path -LiteralPath $Destination) {
        # Clear destination to avoid any leftover files
        Remove-FileSafe -Path $Destination
    }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    # Use Expand-Archive with -Force so existing files won't cause errors
    Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force
}

function Ensure-SpeedtestInstalled {
    param(
        [Parameter(Mandatory)][string]$InstallPath
    )

    $exePath = Join-Path $InstallPath 'speedtest.exe'

    if (Test-Path -LiteralPath $exePath) {
        Write-Verbose "speedtest.exe already exists at: $exePath"
        return $exePath
    }

    Write-Host "speedtest.exe not found. Installing to: $InstallPath"

    $tmpZip     = Join-Path $env:TEMP 'speedtest-win64.zip'
    $tmpExtract = Join-Path $env:TEMP 'speedtest-win64-unzip'

    Remove-FileSafe -Path $tmpZip
    Remove-FileSafe -Path $tmpExtract

    $url = Get-SpeedTestDownloadLink
    Write-Host "Downloading Speedtest CLI..."
    Invoke-WebRequestCompat -Uri $url -OutFile $tmpZip

    Write-Host "Extracting zip..."
    Extract-Zip -ZipPath $tmpZip -Destination $tmpExtract

    if (-not (Test-Path -LiteralPath $InstallPath)) {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }

    $downloadedExe = Get-ChildItem -Path $tmpExtract -Recurse -Filter 'speedtest.exe' | Select-Object -First 1
    if (-not $downloadedExe) {
        throw "speedtest.exe not found inside extracted package."
    }

    Copy-Item -LiteralPath $downloadedExe.FullName -Destination $exePath -Force

    Write-Host "Cleaning temporary files..."
    Remove-FileSafe -Path $tmpZip
    Remove-FileSafe -Path $tmpExtract

    Write-Host "Speedtest installed: $exePath"
    return $exePath
}

function Run-SpeedtestCli {
    param(
        [Parameter(Mandatory)][string]$ExePath,
        [string[]]$Args,
        [switch]$CaptureOutput
    )

    if (-not (Test-Path -LiteralPath $ExePath)) {
        throw "speedtest.exe not found at path: $ExePath"
    }

    if (-not ($Args -contains '--accept-license')) {
        $Args += '--accept-license'
    }
    if (-not ($Args -contains '--accept-gdpr')) {
        $Args += '--accept-gdpr'
    }

    Write-Verbose "Running: `"$ExePath`" $($Args -join ' ')"

    if ($CaptureOutput) {
        $result = & $ExePath @Args 2>&1
        return $result
    } else {
        & $ExePath @Args
        return
    }
}

function Parse-SpeedtestServers {
    param(
        [string[]]$Lines
    )

    $servers = @()

    foreach ($line in $Lines) {
        if (-not $line) { continue }
        if ($line -match 'Closest servers:') { continue }
        if ($line -notmatch '^\s*\d+') { continue }

        $trim = $line.Trim()
        $regex = '^\s*(\d+)\s+(.+?)\s{2,}(.+?)\s{2,}(\S+)\s*$'
        $m = [regex]::Match($trim, $regex)
        if (-not $m.Success) { continue }

        $servers += [pscustomobject]@{
            Id       = [int]$m.Groups[1].Value
            Name     = $m.Groups[2].Value.Trim()
            Location = $m.Groups[3].Value.Trim()
            Country  = $m.Groups[4].Value.Trim()
        }
    }

    return $servers
}

# --------------------------------------------------------
# Main
# --------------------------------------------------------
try {
    # Resolve exe path
    if ($ExecutablePath) {
        $exe = $ExecutablePath
    } else {
        $exe = Ensure-SpeedtestInstalled -InstallPath $InstallPath
    }

    # Map -ServerId to Ookla argument
    if ($ServerId) {
        $SpeedtestArgs += '--server-id'
        $SpeedtestArgs += $ServerId
    }

    if ($ListServers) {
        Write-Host "Fetching Speedtest server list..."
        $raw = Run-SpeedtestCli -ExePath $exe -Args @('--servers') -CaptureOutput
        $servers = Parse-SpeedtestServers -Lines $raw

        if ($servers -and $servers.Count -gt 0) {
            $servers |
                Sort-Object Id |
                Format-Table Id, Name, Location, Country -AutoSize
        } else {
            $raw
        }

        return
    }

    Write-Host "Running Speedtest CLI..."
    Run-SpeedtestCli -ExePath $exe -Args $SpeedtestArgs
}
catch {
    Write-Error "Error in Speedtest-wrapper: $_"
}
