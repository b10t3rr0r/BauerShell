<#
 Workstation Backuper v22b555
  ------------------------------------
  Copyright (c) 2025 Benny Hult
  Licensed under the BSD 3-Clause License. See LICENSE file in the project root for details.

  Workstation backup (OneDrive-aware, registry-driven known folders, optional VSS).

.PARAMETER DestinationRoot
  Destination drive or path (e.g. E:\ or \\server\share). If omitted, prompts.

.PARAMETER Users
  Optional explicit list of usernames (profile folder names) to back up.

.PARAMETER IncludeDeviceOpt
  Include C:\opt => device_root\opt (default: On).

.PARAMETER LogToFile
  Log robocopy output to Logs\backup_yyyyMMdd_HHmmss.log (default: $true).

.PARAMETER ExcludeBrowserCaches
  Exclude browser cache subfolders (default: $true).

.PARAMETER AutoApprove
  Skip the Y/N prompt after the plan.

.PARAMETER SkipCloudOnly
  Do not hydrate OneDrive; skip cloud-only files (/SL /XJ).

.PARAMETER UseVss
  Use VSS snapshots for AppData jobs (requires Admin). Snapshots are mounted via junctions for robocopy.

.PARAMETER ChattyUI
  Verbose robocopy output (/V /ETA /TEE).

.EXAMPLES
  .\Backup-Workstation.ps1
  .\Backup-Workstation.ps1 -DestinationRoot D:\ -AutoApprove
  .\Backup-Workstation.ps1 -UseVss -AutoApprove
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationRoot,

    [Parameter(Mandatory=$false)]
    [string[]]$Users,

    [switch]$IncludeDeviceOpt = $true,

    [bool]$LogToFile = $true,
    [bool]$ExcludeBrowserCaches = $true,

    [switch]$AutoApprove,
    [switch]$SkipCloudOnly,
    [switch]$UseVss,
    [switch]$ChattyUI
)

# --------------------- Helpers ---------------------
function Write-Info    { param([string]$m) Write-Host "[INFO]    $m" -ForegroundColor Yellow }
function Write-Success { param([string]$m) Write-Host "[SUCCESS] $m" -ForegroundColor Green }
function Write-Warn    { param([string]$m) Write-Host "[WARN]    $m" -ForegroundColor Red }
function Write-Debug2  { param([string]$m) Write-Host "[DEBUG]   $m" -ForegroundColor Cyan }

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, "Create directory")) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    }
}

function Resolve-PhysicalPath {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $maxHops = 8
        for ($i = 0; $i -lt $maxHops; $i++) {
            if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { break }
            $target = $item.Target
            if (-not $target) { break }
            if (-not [System.IO.Path]::IsPathRooted($target)) {
                $target = Join-Path $item.DirectoryName $target
            }
            $item = Get-Item -LiteralPath $target -Force -ErrorAction Stop
        }
        return $item.FullName
    } catch { return $Path }
}

function Hydrate-IfOneDrivePath {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $parent = $Path
        for ($i = 0; $i -lt 8 -and $parent; $i++) {
            if ([string]::IsNullOrEmpty($parent)) { break }
            if (Split-Path -Path $parent -Leaf -like "OneDrive*") {
                Write-Info ("Hydrating OneDrive content under: {0}" -f $Path)
                cmd /c "attrib +P -U `"$Path`" /S /D" | Out-Null
                break
            }
            $parent = Split-Path -Path $parent -Parent
        }
    } catch { }
}

function Test-PathUnderAny {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Roots
    )
    foreach ($r in $Roots) {
        if ($Path.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

# Elevation check and robocopy mode
$global:RobocopyModeArgs = @()
$script:IsAdmin = $false
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $script:IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

if ($script:IsAdmin) {
    Write-Info "Running as Administrator - enabling robocopy /ZB (backup mode)."
    $global:RobocopyModeArgs = @("/ZB")
} else {
    Write-Warn "Not running as Administrator. Some profiles may be unreadable; run elevated if needed."
    $global:RobocopyModeArgs = @()
}

function Invoke-RoboCopySafe {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination,
        [string]$Label,
        [string[]]$ExcludeDirs,
        [string[]]$ExcludeFiles,
        [switch]$IsOneDriveJob
    )

    $labelText = if ($Label) { " ($Label)" } else { "" }
    Write-Info ("Copy: ""{0}"" --> ""{1}""{2}" -f $Source, $Destination, $labelText)

    if ($PSBoundParameters.ContainsKey('WhatIf') -or $WhatIfPreference) {
        Write-Info "WhatIf: robocopy would run here."
        return 0
    }

    Ensure-Directory -Path $Destination

    if ($IsOneDriveJob -and -not $SkipCloudOnly) {
        Hydrate-IfOneDrivePath -Path $Source
    }

    $baseArgs = @("/E","/COPY:DAT","/DCOPY:DAT","/R:3","/W:3","/MT:16","/FFT") + $global:RobocopyModeArgs
    if ($ChattyUI) { $baseArgs += @("/V","/ETA","/TEE") } else { $baseArgs += @("/NFL","/NDL","/NP") }
    if ($SkipCloudOnly) { $baseArgs += @("/SL","/XJ") }

    $args = @($Source, $Destination) + $baseArgs
    if ($ExcludeDirs -and $ExcludeDirs.Count -gt 0) { $args += "/XD"; $args += $ExcludeDirs }
    if ($ExcludeFiles -and $ExcludeFiles.Count -gt 0) { $args += "/XF"; $args += $ExcludeFiles }
    if ($script:RobocopyLogPath -and $LogToFile)       { $args += "/TEE"; $args += "/LOG+:$script:RobocopyLogPath" }

    $null = & robocopy @args
    $exitCode = $LASTEXITCODE

    if ($exitCode -ge 8) {
        Write-Warn ("Robocopy failed (exit code {0}) for: {1}" -f $exitCode, $Source)
    } else {
        Write-Success ("Robocopy completed (exit code {0}) for: {1}" -f $exitCode, $Source)
    }
    return $exitCode
}

# ------- Registry-based known folder resolution -------
function Get-UserSidFromProfilePath {
    param([Parameter(Mandatory)][string]$UserRoot)
    try {
        $prof = Get-CimInstance Win32_UserProfile -Filter ("LocalPath = '{0}'" -f $UserRoot.Replace('\','\\')) -ErrorAction Stop
        return $prof.SID
    } catch { return $null }
}

function Read-UserRegValue {
    param(
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName
    )
    $path = "Registry::HKEY_USERS\$Sid\$SubKey"
    try {
        if (Test-Path $path) {
            $val = (Get-ItemProperty -LiteralPath $path -Name $ValueName -ErrorAction Stop).$ValueName
            return [string]$val
        }
    } catch { }
    return $null
}

function Expand-UserPathTokens {
    param(
        [Parameter(Mandatory)][string]$Raw,
        [Parameter(Mandatory)][string]$UserRoot,
        [string]$OneDriveRoot
    )
    $out = $Raw
    if ([string]::IsNullOrWhiteSpace($out)) { return $null }

    $out = $out -replace '%USERPROFILE%', $UserRoot
    $out = $out -replace '%HOMEDRIVE%%HOMEPATH%', $UserRoot
    if ($OneDriveRoot) {
        $out = $out -replace '%OneDriveCommercial%', $OneDriveRoot
        $out = $out -replace '%OneDrive%', $OneDriveRoot
    }
    $out = $out -replace '%([^%]+)%',''
    return $out
}

function Get-KnownFolderFromUserRegistry {
    param(
        [Parameter(Mandatory)][string]$FolderKey,      # Desktop, Documents, Pictures, Downloads, Music, Videos
        [Parameter(Mandatory)][string]$Sid,
        [Parameter(Mandatory)][string]$UserRoot,
        [string]$OneDrivePreferredRoot
    )

    $map = @{
        "Desktop"   = "Desktop"
        "Documents" = "Personal"
        "Pictures"  = "My Pictures"
        "Downloads" = "{374DE290-123F-4565-9164-39C4925E467B}"
        "Music"     = "My Music"
        "Videos"    = "My Video"
    }

    $valName = $map[$FolderKey]
    if (-not $valName) { return $null }

    $raw = Read-UserRegValue -Sid $Sid -SubKey "Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -ValueName $valName
    if (-not $raw) { return $null }

    $expanded = Expand-UserPathTokens -Raw $raw -UserRoot $UserRoot -OneDriveRoot $OneDrivePreferredRoot
    if (-not $expanded) { return $null }

    try { $full = [System.IO.Path]::GetFullPath($expanded) } catch { $full = $expanded }
    if (Test-Path -LiteralPath $full) { return $full }
    return $null
}

# ------- Users root & profiles -------
function Get-UsersRootCandidates {
    $candidates = @(
        "C:\Users", "C:\Käyttäjät", "C:\käyttäjät",
        (Split-Path $env:USERPROFILE -Parent)
    ) | Where-Object { $_ } | Select-Object -Unique

    $existing = $candidates | Where-Object { Test-Path -LiteralPath $_ }
    if (-not $existing) { throw "Could not find a Users root. Checked: $($candidates -join ', ')" }
    return $existing
}

function Get-ProfileDirs {
    param([string[]]$Roots)

    $excludeNames = @(
        "Default","Default User","Public","All Users","DefaultAppPool",
        "WDAGUtilityAccount","Administrator","$Recycle.Bin","System Volume Information"
    )

    $profiles = foreach ($r in $Roots) {
        if (Test-Path -LiteralPath $r) {
            Get-ChildItem -LiteralPath $r -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
                $excludeNames -notcontains $_.Name -and
                -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)
            }
        }
    }

    $profiles | Sort-Object FullName -Unique
}

function Select-DestinationRootInteractively {
    $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object {
        $_.IsReady -and $_.DriveType -in @([System.IO.DriveType]::Fixed, [System.IO.DriveType]::Removable) -and
        $_.Name -notmatch '^[ABab]:\\$'
    } | Sort-Object Name

    Write-Host ""
    Write-Host "Select a destination drive or enter a custom path:" -ForegroundColor White
    for ($i = 0; $i -lt $drives.Count; $i++) {
        $d = $drives[$i]
        $freeGB = [math]::Round($d.AvailableFreeSpace / 1GB, 2)
        $totalGB = [math]::Round($d.TotalSize / 1GB, 2)
        $driveLetter = $d.Name.TrimEnd('\').TrimEnd(':')
        $label = try { (Get-Volume -DriveLetter $driveLetter -ErrorAction SilentlyContinue).FileSystemLabel } catch { $null }
        if (-not $label) { $label = "" }
        Write-Host ("[{0}] {1}  {2}  Free: {3} GB / {4} GB" -f $i, $d.Name, $label, $freeGB, $totalGB)
    }
    Write-Host "[X] Enter a custom path (e.g., \\server\share\Backups or D:\Backups)" -ForegroundColor White
    $choice = Read-Host "Pick index or 'X' for custom"

    if ($choice -match '^[Xx]$') {
        $p = Read-Host "Enter full destination path"
        if ([string]::IsNullOrWhiteSpace($p)) { return $null }
        try { return [System.IO.Path]::GetFullPath($p) } catch { Write-Warn "Invalid path."; return $null }
    }

    if ($choice -as [int] -ge 0 -and $choice -as [int] -lt $drives.Count) {
        return $drives[[int]$choice].RootDirectory.FullName
    }

    Write-Warn "Invalid selection."
    return $null
}

# ------- VSS helpers (snapshot + junction mount for robocopy) -------
function New-VolumeShadowCopy {
    param([Parameter(Mandatory)][string]$DriveLetterOrRoot) # e.g. 'C:' or 'C:\'
    if ($DriveLetterOrRoot -match '^[A-Za-z]:$') { $DriveLetterOrRoot = "$DriveLetterOrRoot\" }

    $class = [wmiclass]"root\cimv2:Win32_ShadowCopy"
    foreach ($ctx in @("ClientAccessible","ClientAccessibleWriters")) {
        try {
            $result = $class.Create($DriveLetterOrRoot, $ctx)
            if ($result.ReturnValue -eq 0) {
                return Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $result.ShadowID }
            } else {
                Write-Warn ("VSS Create() on {0} with context {1} returned {2}" -f $DriveLetterOrRoot, $ctx, $result.ReturnValue)
            }
        } catch {
            Write-Warn ("VSS Create() threw for {0} with context {1}: {2}" -f $DriveLetterOrRoot, $ctx, $_.Exception.Message)
        }
    }
    throw ("VSS create failed on {0} with all contexts." -f $DriveLetterOrRoot)
}

function Remove-VolumeShadowCopy {
    param([Parameter(Mandatory)][string]$ID)
    try { (Get-WmiObject Win32_ShadowCopy -Filter ("ID='{0}'" -f $ID)).Delete() | Out-Null } catch { }
}

function Mount-ShadowToJunction {
    param(
        [Parameter(Mandatory)][string]$ShadowDevice,   # \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN
        [Parameter(Mandatory)][string]$DriveRoot,      # e.g. C:
        [Parameter(Mandatory)][string]$BaseDir         # e.g. C:\_shadow
    )
    $driveLetter = $DriveRoot.TrimEnd('\').TrimEnd(':')
    $mountRoot   = Join-Path $BaseDir $driveLetter

    if (-not (Test-Path $BaseDir)) { New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null }
    if (Test-Path $mountRoot) { cmd /c "rmdir `"$mountRoot`"" | Out-Null }

    $target = $ShadowDevice
    if ($target -notmatch '\\$') { $target = $target + '\' }

    Write-Info ("Mounting VSS {0} -> {1}" -f $target, $mountRoot)
    $rc = cmd /c "mklink /d `"$mountRoot`" `"$target`""
    if ($LASTEXITCODE -ne 0) { throw ("Failed to create junction {0} -> {1}" -f $mountRoot, $target) }
    return $mountRoot
}

function Convert-ToShadowMountedPath {
    param(
        [Parameter(Mandatory)][string]$OriginalPath,   # C:\Users\...\AppData\...
        [Parameter(Mandatory)][hashtable]$ShadowMap,   # 'C:' -> \\?\GLOBALROOT\Device\...
        [Parameter(Mandatory)][hashtable]$MountMap     # 'C:' -> C:\_shadow\C
    )
    $root = ([System.IO.Path]::GetPathRoot($OriginalPath)).TrimEnd('\')
    if (-not $ShadowMap.ContainsKey($root)) { return $null }
    if (-not $MountMap.ContainsKey($root))  { return $null }
    $rel = $OriginalPath.Substring($root.Length)  # includes leading backslash
    return ($MountMap[$root] + $rel)
}

function Dismount-ShadowJunctions {
    param([Parameter(Mandatory)][hashtable]$MountMap)
    foreach ($kv in $MountMap.GetEnumerator()) {
        $m = $kv.Value
        try {
            if (Test-Path $m) {
                Write-Info ("Removing junction {0}" -f $m)
                cmd /c "rmdir `"$m`"" | Out-Null
            }
        } catch { }
    }
}

# ------- Plan builder -------
function Build-UserBackupPlan {
    param(
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$Profile,
        [Parameter(Mandatory)][string]$UsersRootOut,
        [Parameter(Mandatory)][hashtable]$KnownFoldersFallbacks,
        [Parameter(Mandatory)][string[]]$AppDataLocalTargets,
        [Parameter(Mandatory)][string[]]$AppDataRoamingTargets,
        [Parameter(Mandatory)][string[]]$PsDocTargets,
        [Parameter(Mandatory)][string[]]$BrowserCacheDirs
    )

    $userName = $Profile.Name
    $userRoot = $Profile.FullName
    $plan = @()

    # OneDrive roots (dynamic)
    $oneDriveDirs = Get-ChildItem -Path $userRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "OneDrive*" -and (Test-Path $_.FullName) }
    $oneDriveRoots = @()
    if ($oneDriveDirs) {
        $oneDriveRoots = $oneDriveDirs.FullName
        Write-Info ("[PLAN] OneDrive roots for {0}:{1}{2}" -f $userName, [Environment]::NewLine, ($oneDriveRoots -join [Environment]::NewLine))
    } else {
        Write-Info ("[PLAN] No OneDrive roots for {0} - using local paths where available." -f $userName)
    }
    $oneDrivePref = $oneDriveDirs | Where-Object { $_.Name -like "OneDrive -*" } | Select-Object -First 1
    if (-not $oneDrivePref -and $oneDriveDirs) { $oneDrivePref = $oneDriveDirs | Select-Object -First 1 }

    # Known folders from registry
    $sid = Get-UserSidFromProfilePath -UserRoot $userRoot
    $resolvedKnown = @{}
    foreach ($fk in @("Desktop","Documents","Pictures","Downloads","Music","Videos")) {
        $regPath = $null
        if ($sid) {
            $regPath = Get-KnownFolderFromUserRegistry -FolderKey $fk -Sid $sid -UserRoot $userRoot -OneDrivePreferredRoot $oneDrivePref.FullName
        }
        if ($regPath) { $resolvedKnown[$fk] = $regPath }
    }

    # Known folders: registry-first, then OneDrive/local heuristics
    foreach ($folderKey in @("Documents","Desktop","Pictures","Downloads","Music","Videos")) {
        $src = $null

        if ($resolvedKnown.ContainsKey($folderKey)) {
            $src = $resolvedKnown[$folderKey]
            if (-not (Test-Path -LiteralPath $src)) { $src = $null }
        }

        if (-not $src) {
            $folderNames = $KnownFoldersFallbacks[$folderKey]
            $candidates = @()
            foreach ($od in $oneDriveDirs) { foreach ($fn in $folderNames) { $candidates += (Join-Path $od.FullName $fn) } }
            foreach ($fn in $folderNames) { $candidates += (Join-Path $userRoot $fn) }
            $src = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        }

        if (-not $src) {
            Write-Warn ("[PLAN] Missing source for {0} for {1} - skipping" -f $folderKey, $userName)
            continue
        }

        $srcResolved = Resolve-PhysicalPath -Path $src
        if ($srcResolved -ne $src) {
            Write-Info ("[PLAN] Resolved reparse to physical path: {0} -> {1}" -f $src, $srcResolved)
            $src = $srcResolved
        }

        $dst = Join-Path (Join-Path $UsersRootOut $userName) $folderKey
        $plan += @{
            User = $userName
            Label = ("Users\{0}\{1}" -f $userName,$folderKey)
            Source = $src
            Destination = $dst
            ExcludeDirs = $null
            OneDriveRoots = $oneDriveRoots
        }
    }

    # AppData\Local (Chrome, Edge)
    $appLocal = Join-Path $userRoot "AppData\Local"
    foreach ($sub in $AppDataLocalTargets) {
        $src = Join-Path $appLocal $sub
        if (Test-Path -LiteralPath $src) {
            $srcResolved = Resolve-PhysicalPath -Path $src
            if ($srcResolved -ne $src) {
                Write-Info ("[PLAN] Resolved reparse to physical path: {0} -> {1}" -f $src, $srcResolved)
                $src = $srcResolved
            }
            $dst = Join-Path (Join-Path $usersRootOut $userName) ("AppData\Local\" + $sub)
            $excludeDirsThis = @()
            if ($BrowserCacheDirs.Count -gt 0) {
                foreach ($bd in $BrowserCacheDirs) { $excludeDirsThis += (Join-Path $src $bd) }
                Get-ChildItem -LiteralPath $src -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    foreach ($bd in $BrowserCacheDirs) { $excludeDirsThis += (Join-Path $_.FullName $bd) }
                }
            }
            $plan += @{
                User = $userName
                Label = ("Users\{0}\AppData\Local\{1}" -f $userName,$sub)
                Source = $src
                Destination = $dst
                ExcludeDirs = $excludeDirsThis
                OneDriveRoots = $oneDriveRoots
            }
        } else {
            Write-Info ("[PLAN] Not found (OK): {0}" -f $src)
        }
    }

    # AppData\Roaming (Firefox)
    $appRoam = Join-Path $userRoot "AppData\Roaming"
    foreach ($sub in $AppDataRoamingTargets) {
        $src = Join-Path $appRoam $sub
        if (Test-Path -LiteralPath $src) {
            $srcResolved = Resolve-PhysicalPath -Path $src
            if ($srcResolved -ne $src) {
                Write-Info ("[PLAN] Resolved reparse to physical path: {0} -> {1}" -f $src, $srcResolved)
                $src = $srcResolved
            }
            $dst = Join-Path (Join-Path $usersRootOut $userName) ("AppData\Roaming\" + $sub)
            $plan += @{
                User = $userName
                Label = ("Users\{0}\AppData\Roaming\{1}" -f $userName,$sub)
                Source = $src
                Destination = $dst
                ExcludeDirs = $null
                OneDriveRoots = $oneDriveRoots
            }
        } else {
            Write-Info ("[PLAN] Not found (OK): {0}" -f $src)
        }
    }

    # PowerShell profiles/modules under Documents
    $docs = Join-Path $userRoot "Documents"
    foreach ($psSub in $PsDocTargets) {
        $src = Join-Path $docs $psSub
        if (Test-Path -LiteralPath $src) {
            $srcResolved = Resolve-PhysicalPath -Path $src
            if ($srcResolved -ne $src) {
                Write-Info ("[PLAN] Resolved reparse to physical path: {0} -> {1}" -f $src, $srcResolved)
                $src = $srcResolved
            }
            $dst = Join-Path (Join-Path $usersRootOut $userName) ("Documents\" + $psSub)
            $plan += @{
                User = $userName
                Label = ("Users\{0}\Documents\{1}" -f $userName,$psSub)
                Source = $src
                Destination = $dst
                ExcludeDirs = $null
                OneDriveRoots = $oneDriveRoots
            }
        } else {
            Write-Info ("[PLAN] Not found (OK): {0}" -f $src)
        }
    }

    return ,$plan
}

# --------------------- Main ---------------------
try {
    if (-not $DestinationRoot) {
        $DestinationRoot = Select-DestinationRootInteractively
        if (-not $DestinationRoot) {
            $DestinationRoot = Read-Host "Enter destination drive or folder (e.g. E:\ or \\server\share\) (last chance)"
        }
    }

    if ([string]::IsNullOrWhiteSpace($DestinationRoot)) { throw "DestinationRoot is required." }

    try {
        $DestinationRoot = [System.IO.Path]::GetFullPath($DestinationRoot)
    } catch {
        throw "DestinationRoot is not a valid path."
    }

    if (-not (Test-Path -LiteralPath $DestinationRoot)) {
        if ($PSCmdlet.ShouldProcess($DestinationRoot, "Create destination root")) {
            New-Item -ItemType Directory -Path $DestinationRoot -Force | Out-Null
        }
    }

    $backupRoot   = Join-Path $DestinationRoot "Backup"
    $computerRoot = Join-Path $backupRoot $env:COMPUTERNAME
    $deviceRoot   = Join-Path $computerRoot "device_root"
    $usersRootOut = Join-Path $computerRoot "Users"
    $logRoot      = Join-Path $computerRoot "Logs"

    foreach ($p in @($backupRoot, $computerRoot, $deviceRoot, $usersRootOut, $logRoot)) { Ensure-Directory -Path $p }

    if ($LogToFile) {
        $script:RobocopyLogPath = Join-Path $logRoot ("backup_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        Write-Info ("Logging Robocopy output to: {0}" -f $script:RobocopyLogPath)
    } else {
        $script:RobocopyLogPath = $null
    }

    Write-Info ("Backup root: {0}" -f $backupRoot)
    Write-Info ("Computer root: {0}" -f $computerRoot)

    # Fallback names if registry missing (ASCII only)
    $knownFoldersFallbacks = @{
        "Documents" = @("Documents","Asiakirjat","Tiedostot")
        "Desktop"   = @("Desktop","Tyopoyta")
        "Pictures"  = @("Pictures","Kuvat")
        "Downloads" = @("Downloads","Lataukset")
        "Music"     = @("Music","Musiikki")
        "Videos"    = @("Videos","Videot")
    }

    $appDataLocalTargets   = @("Google\Chrome\User Data","Microsoft\Edge\User Data")
    $appDataRoamingTargets = @("Mozilla\Firefox")
    $psDocTargets          = @("WindowsPowerShell","PowerShell")

    # Browser cache exclusions
    $browserCacheDirs = @()
    if ($ExcludeBrowserCaches) {
        $browserCacheDirs = @("Cache","Code Cache","GPUCache","ShaderCache","Service Worker\CacheStorage","GrShaderCache")
    }

    # --------- BUILD PLAN ----------
    $roots = Get-UsersRootCandidates
    Write-Info ("User roots available: {0}" -f ($roots -join ', '))

    $profileDirs = Get-ProfileDirs -Roots $roots
    if (-not $profileDirs -or $profileDirs.Count -eq 0) { throw "No user profiles discovered." }

    # Resolve users
    $selectedProfiles = @()
    if ($Users -and $Users.Count -gt 0) {
        foreach ($u in $Users) {
            $match = $profileDirs | Where-Object { $_.Name -ieq $u }
            if ($match) { $selectedProfiles += $match } else { Write-Warn ("User '{0}' not found under: {1}" -f $u, ($roots -join ', ')) }
        }
    } else {
        Write-Host ""
        Write-Host "Discovered user profiles:" -ForegroundColor White
        for ($i = 0; $i -lt $profileDirs.Count; $i++) {
            Write-Host ("[{0}] {1}" -f $i, $profileDirs[$i].FullName)
        }
        Write-Host ""
        Write-Host "Type comma-separated indexes to select (e.g. 0,2,3), or 'all' to include all." -ForegroundColor White
        $resp = Read-Host "Selection"
        if ([string]::IsNullOrWhiteSpace($resp)) { throw "No users selected. Exiting." }
        if ($resp.Trim().ToLower() -eq 'all') {
            $selectedProfiles = $profileDirs
        } else {
            $indexes = $resp.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
            foreach ($idx in $indexes) {
                if ($idx -as [int] -ge 0 -and $idx -as [int] -lt $profileDirs.Count) {
                    $selectedProfiles += $profileDirs[[int]$idx]
                } else {
                    Write-Warn ("Ignoring invalid index: {0}" -f $idx)
                }
            }
        }
    }

    if (-not $selectedProfiles -or $selectedProfiles.Count -eq 0) { throw "No users selected. Exiting." }
    Write-Success ("Selected users: {0}" -f ($selectedProfiles.Name -join ', '))

    $plan = @()

    # device_root\opt
    if ($IncludeDeviceOpt) {
        $srcOpt = "C:\opt"
        if (Test-Path -LiteralPath $srcOpt) {
            $srcOpt = Resolve-PhysicalPath -Path $srcOpt
            $dstOpt = Join-Path $deviceRoot "opt"
            $plan += @{
                User = "_machine"; Label = "device_root\opt";
                Source = $srcOpt; Destination = $dstOpt; ExcludeDirs = $null; OneDriveRoots = @()
            }
        } else {
            Write-Info "C:\opt not found. Skipping device_root\opt (OK)."
        }
    }

    foreach ($prof in $selectedProfiles) {
        Write-Info ("Planning user: {0} ({1})" -f $prof.Name, $prof.FullName)
        $plan += Build-UserBackupPlan -Profile $prof -UsersRootOut $usersRootOut -KnownFoldersFallbacks $knownFoldersFallbacks `
                 -AppDataLocalTargets $appDataLocalTargets -AppDataRoamingTargets $appDataRoamingTargets -PsDocTargets $psDocTargets `
                 -BrowserCacheDirs $browserCacheDirs
    }

    if (-not $plan -or $plan.Count -eq 0) { throw "Plan is empty; nothing to back up." }

    # Show plan
    Write-Host ""
    Write-Host "==================== BACKUP PLAN ====================" -ForegroundColor White
    $plan | ForEach-Object { Write-Host ("{0} :: {1}" -f $_.Label, $_.Source) -ForegroundColor Gray }
    Write-Host "=====================================================" -ForegroundColor White
    Write-Host ""

    $proceed = $true
    if (-not $AutoApprove) {
        $ans = Read-Host "Proceed with backup? (Y/N)"
        if ($ans -notmatch '^(Y|y)$') { $proceed = $false }
    }
    if (-not $proceed) { Write-Warn "User canceled after plan review. Exiting."; exit 0 }

    # --------- VSS snapshots (optional) ----------
    $shadowMap  = @{}   # Drive-root -> device path
    $shadowIds  = @()
    $mountMap   = @{}   # Drive-root -> junction path (e.g. C:\_shadow\C)
    $shadowBase = "C:\_shadow"   # temp mount root

    if ($UseVss) {
        $vols = ($plan.Source | ForEach-Object { ([System.IO.Path]::GetPathRoot($_)).TrimEnd('\') }) |
                Select-Object -Unique | Where-Object { $_ -match '^[A-Z]:' }
        foreach ($v in $vols) {
            try {
                Write-Info ("Creating VSS snapshot for {0} ..." -f $v)
                $sh = New-VolumeShadowCopy -DriveLetterOrRoot $v
                $shadowMap[$v] = $sh.DeviceObject
                $shadowIds     += $sh.ID
                Write-Success ("VSS ready for {0} -> {1}" -f $v, $sh.DeviceObject)

                $mountPath = Mount-ShadowToJunction -ShadowDevice $sh.DeviceObject -DriveRoot $v -BaseDir $shadowBase
                $mountMap[$v] = $mountPath
                Write-Info ("Mounted {0} at {1}" -f $v, $mountPath)
            } catch {
                Write-Warn ("VSS snapshot failed for {0}: {1}" -f $v, $_.Exception.Message)
            }
        }
    }

    # --------- EXECUTE PLAN ----------
    foreach ($job in $plan) {
        $isOD = $false
        if ($job.OneDriveRoots -and $job.OneDriveRoots.Count -gt 0) {
            $isOD = Test-PathUnderAny -Path $job.Source -Roots $job.OneDriveRoots
        }

        $sourceForCopy = $job.Source

        # Use VSS (mounted path) for AppData jobs
        $isLikelyLocked = ($job.Label -like "Users*\AppData\*")
        if ($UseVss -and $isLikelyLocked -and $shadowMap.Count -gt 0) {
            $mountedPath = Convert-ToShadowMountedPath -OriginalPath $job.Source -ShadowMap $shadowMap -MountMap $mountMap
            if ($mountedPath) {
                Write-Info ("Using VSS (mounted) source for {0}" -f $job.Label)
                $sourceForCopy = $mountedPath
                $isOD = $false
            }
        }

        if ($PSCmdlet.ShouldProcess(("{0} -> {1}" -f $sourceForCopy, $job.Destination), ("Backup {0}" -f $job.Label))) {
            $code = Invoke-RoboCopySafe -Source $sourceForCopy -Destination $job.Destination -Label $job.Label `
                    -ExcludeDirs $job.ExcludeDirs -IsOneDriveJob:($isOD)

            if ($isOD -and -not $UseVss -and -not $SkipCloudOnly -and $code -eq 9) {
                Write-Warn "OneDrive cloud operation failed (exit code 9). Retrying after hydration..."
                Start-Sleep -Seconds 5
                Hydrate-IfOneDrivePath -Path $job.Source
                $null = Invoke-RoboCopySafe -Source $job.Source -Destination $job.Destination -Label ($job.Label + " (retry)") `
                        -ExcludeDirs $job.ExcludeDirs -IsOneDriveJob:($true)
            }
        }
    }

    # Cleanup VSS and junctions
    if ($UseVss -and $shadowIds.Count -gt 0) {
        Write-Info "Cleaning up VSS snapshots..."
        foreach ($id in $shadowIds) {
            try { Remove-VolumeShadowCopy -ID $id } catch { }
        }
    }
    if ($UseVss -and $mountMap.Count -gt 0) {
        Dismount-ShadowJunctions -MountMap $mountMap
    }

    Write-Success "All requested backups completed."
    Write-Info ("Output under: {0}" -f $computerRoot)
    if ($LogToFile -and $script:RobocopyLogPath) { Write-Info ("Robocopy log saved to: {0}" -f $script:RobocopyLogPath) }
}
catch {
    Write-Warn $_.Exception.Message
    exit 1
}
