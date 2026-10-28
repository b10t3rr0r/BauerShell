<#
  Mobile Broadband Monitor v22b555
  -------------------------------
  Copyright (c) 2025 Benny Hult
  Licensed under the BSD 3-Clause License. See LICENSE file in the project root for details.

  - Continuous Mobile Broadband (MBN) status + throughput
  - PowerShell 5 compatible
  - No external modules (only netsh + built-in cmdlets)
  - Header, separators and long values scale to the current console width

  PARAMETERS
    -Interval <int>
        Refresh interval in seconds (1-3600).
        Default: 5 seconds.

    -Interface <string>
        Optional mobile broadband interface name such as "Matkapuhelinverkko 12".
        If omitted, automatically selects the first CONNECTED MBN interface.

    -Duration <int>
        Total runtime in seconds.
        0 = infinite (until Ctrl-C).
        Otherwise exits after ~Duration seconds.

    -NoCellInfo
        Skip the serving cell section (band, channel, PCI, cell ID, RSRP/RSRQ).
        Cell info is read through the Windows MobileBroadbandCellsInfo API. It works
        only if the modem driver supports it, and in PowerShell 7 the query is run in a
        short-lived powershell.exe child process (WinRT is not available in pwsh).

  EXAMPLES
    .\mbn-monitor.ps1
    .\mbn-monitor.ps1 -Interval 2
    .\mbn-monitor.ps1 -Duration 30
    .\mbn-monitor.ps1 -Interface "Matkapuhelinverkko 12"

  NOTES
    - Parsing relies on English `netsh mbn` output labels. On localized Windows
      versions most fields will come back empty.
    - Serving cell info (EARFCN, PCI, cell ID, RSRP/RSRQ) comes from the Windows
      MobileBroadbandCellsInfo API. SINR, bandwidth and carrier aggregation are not
      exposed by it. The 5G NR part of an NSA connection is only shown if the driver reports it.
    - RSRP/RSRQ colors follow the Teltonika signal strength recommendations.
#>

param(
  [ValidateRange(1, 3600)]
  [int]$Interval = 5,

  [string]$Interface,

  [ValidateRange(0, [int]::MaxValue)]
  [int]$Duration = 0,

  [switch]$NoCellInfo
)

# Version variable - change this in one place, it updates the banner automatically
$Script:MbnMonitorVersion = '22b555'

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8 } catch {}

# --- netsh helpers ---
function Invoke-NetshMbnInterfaces { (netsh mbn show interfaces) -join [Environment]::NewLine }

# --- Regex options for PS5/PS7 ---
$script:RegexIgnoreCaseMultiline = `
  [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
  [System.Text.RegularExpressions.RegexOptions]::Multiline

# "Connected" must match exactly - a plain -match "connected" also matches "Disconnected"
$script:ConnectedPattern = '^\s*connected\s*$'

# Serving cell info (WinRT MobileBroadbandCellsInfo). Disabled automatically after 3 failed queries.
$script:CellInfoEnabled  = -not $NoCellInfo
$script:CellInfoFailures = 0
$script:CellQueryCode = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Networking.NetworkOperators.MobileBroadbandModem,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
$null = [Windows.Networking.NetworkOperators.MobileBroadbandCellsInfo,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
  $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
$modem = [Windows.Networking.NetworkOperators.MobileBroadbandModem]::GetDefault()
$op    = $modem.CurrentNetwork.GetCellsInfoAsync()
$cells = $asTask.MakeGenericMethod([Windows.Networking.NetworkOperators.MobileBroadbandCellsInfo]).Invoke($null,@($op)).GetAwaiter().GetResult()
@{
  Lte = @($cells.ServingCellsLte | ForEach-Object { $_ | Select-Object * })
  Nr  = @($cells.ServingCellsNR  | ForEach-Object { $_ | Select-Object * })
} | ConvertTo-Json -Depth 4 -Compress
'@
$script:CellQueryEnc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script:CellQueryCode))

# ====================================================================
#                           PARSING HELPERS
# ====================================================================

function Get-MbnInterfaceList {

  $raw = Invoke-NetshMbnInterfaces
  if (-not $raw) { return @() }

  # Split into blocks by "Name :" lines
  # (no "There is N interface" check: the plural form "There are N interfaces" would not match it)
  $lines  = $raw -split "`r?`n"
  $blocks = @()
  $current = @()

  foreach ($ln in $lines) {
    if ($ln -match "^\s*Name\s*:") {
      if ($current.Count -gt 0) {
        $blocks += ,(@($current -join "`n"))
        $current = @()
      }
    }
    if ($ln.Trim().Length -gt 0) {
      $current += $ln
    }
  }
  if ($current.Count -gt 0) {
    $blocks += ,(@($current -join "`n"))
  }

  $list = @()

  foreach ($b in $blocks) {

    $get = {
      param($pattern, $block)
      $m = [regex]::Match($block, $pattern, $script:RegexIgnoreCaseMultiline)
      if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
    }

    $name    = & $get "^\s*Name\s*:\s*(.+?)\s*$"             $b
    $desc    = & $get "^\s*Description\s*:\s*(.+?)$"         $b
    $guid    = & $get "^\s*GUID\s*:\s*(.+?)$"                $b
    $state   = & $get "^\s*State\s*:\s*(.+?)$"               $b
    $prov    = & $get "^\s*Provider\s+Name\s*:\s*(.+?)$"     $b
    $roam    = & $get "^\s*Roaming\s*:\s*(.+?)$"             $b
    $signal  = & $get "^\s*Signal\s*:\s*(\d+)"               $b
    $rssiraw = & $get "^\s*RSSI\s*/\s*RSCP\s*:\s*.+\((-?\d+)\s*dBm\)" $b
    $devType = & $get "^\s*Device\s+type\s*:\s*(.+?)$"       $b
    $cellCls = & $get "^\s*Cellular\s+class\s*:\s*(.+?)$"    $b
    $model   = & $get "^\s*Model\s*:\s*(.+?)$"               $b
    $man     = & $get "^\s*Manufacturer\s*:\s*(.+?)$"        $b
    $fw      = & $get "^\s*Firmware\s+Version\s*:\s*(.+?)$"  $b

    if (-not $name) { continue }

    # All properties are created up front (with $null defaults), so later code can
    # simply assign to them and never has to Add-Member (no "member already exists" errors).
    $list += [pscustomobject]@{
      Name          = $name
      Description   = $desc
      Guid          = $guid
      State         = $state
      Provider      = $prov
      Roaming       = $roam
      SignalPercent = [int]($signal -as [int])
      RssiDbm       = ($rssiraw -as [int])
      DeviceType    = $devType
      CellularClass = $cellCls
      Manufacturer  = $man
      Model         = $model
      Firmware      = $fw

      # filled in later by Update-MbnExtendedInfo
      NetworkType   = $null
      DataClass     = $null
      IMEI          = $null
      PhoneNumber   = $null
      IMSI          = $null
      SimIcc        = $null

      # filled in later by Get-MbnInterfaceInfo
      IPv4          = $null
      IPv6          = $null
      Gateway4      = $null
      Gateway6      = $null
      Dns4          = $null
      Dns6          = $null
      RxBytes       = $null
      TxBytes       = $null

      # serving cell info (see Get-MbnCellInfo)
      CellInfo      = $null
    }
  }

  return $list
}

# parse "netsh mbn show interface/readyinfo/connection"
function Update-MbnExtendedInfo {
  param([psobject]$iface)

  if (-not $iface -or -not $iface.Name) { return }

  $lines = @()
  try { $lines += netsh mbn show interface name="$($iface.Name)" } catch {}
  try { $lines += netsh mbn show readyinfo interface="$($iface.Name)" } catch {}
  try { $lines += netsh mbn show connection interface="$($iface.Name)" } catch {}

  if ($lines) {
    foreach ($ln in $lines) {
      if (-not $ln -or -not ($ln -like "*:*")) { continue }

      $parts = $ln.Split(":", 2)
      if ($parts.Count -lt 2) { continue }

      $key = $parts[0].Trim()
      $val = $parts[1].Trim()
      if (-not $val) { continue }

      switch -Wildcard ($key) {
        "Network type*"       { $iface.NetworkType = $val }
        "Data class*"         { $iface.DataClass   = $val }
        "Provider Data Class*"{ $iface.DataClass   = $val }   # from "show connection" - current data class (LTE/5G/etc.)
        "Device Id*"          { $iface.IMEI        = $val }
        "Subscriber Id*"      { $iface.IMSI        = $val }
        "SIM ICC Id*"         { $iface.SimIcc      = $val }
        "Telephone #1*"       { $iface.PhoneNumber = $val }
        default { }
      }
    }
  }

  # If NetworkType is still empty, default to 3GPP (matches Windows UI for these modems)
  if (-not $iface.NetworkType -or -not $iface.NetworkType.Trim()) {
    $iface.NetworkType = "3GPP"
  }
}

# ====================================================================
#                           FORMAT HELPERS
# ====================================================================

function Format-Bytes {
  param([Nullable[long]]$n)
  if ($null -eq $n) { return "-" }
  switch ($n) {
    {$_ -ge 1TB} {return "{0:N2} TB" -f ($n/1TB)}
    {$_ -ge 1GB} {return "{0:N2} GB" -f ($n/1GB)}
    {$_ -ge 1MB} {return "{0:N2} MB" -f ($n/1MB)}
    {$_ -ge 1KB} {return "{0:N2} KB" -f ($n/1KB)}
    default      {return "$n B"}
  }
}

# Returns only the inner bar (no brackets); the caller draws the brackets.
function New-SignalBar {
  param([int]$Percent, [int]$Width = 25)

  $filled = [int][math]::Floor(($Percent * $Width) / 100)
  if ($filled -lt 0) { $filled = 0 }
  if ($filled -gt $Width) { $filled = $Width }
  $empty = $Width - $filled

  ("=" * $filled) + (" " * $empty)
}

function Get-RadioColor {
  param([string]$Class)

  if ($Class -match "5G")                  { return "Magenta" }
  elseif ($Class -match "LTE|4G")          { return "Green" }
  elseif ($Class -match "UMTS|HSPA|3G")    { return "Cyan" }
  elseif ($Class -match "GSM|2G")          { return "Yellow" }
  elseif ($Class -match "\S")              { return "Yellow" }
  else                                     { return "Gray" }
}

function Limit-Text {
  # Truncate text to Max characters, ending with an ellipsis if shortened.
  param([string]$Text, [int]$Max)
  if ($Max -le 0) { return '' }
  if ($null -eq $Text) { return '' }
  if ($Text.Length -le $Max) { return $Text }
  if ($Max -le 1) { return [string][char]0x2026 }
  return $Text.Substring(0, $Max - 1) + [char]0x2026
}

function Get-ConsoleWidth {
  # Usable console width (one column kept free so the last column never wraps).
  try {
    $w = $Host.UI.RawUI.WindowSize.Width
    if ($w -lt 1) { return 80 }
    return [Math]::Max(40, $w - 1)
  } catch { return 80 }
}

function Write-Field {
  # "Label             : value" line; the value is truncated so it never wraps.
  param(
    [string]$Label,
    $Value,
    [string]$Color = 'White',
    [int]$Width = 80
  )
  Write-Host ("{0,-18}: " -f $Label) -ForegroundColor DarkGray -NoNewline
  $text = if ($null -eq $Value) { '' } else { [string]$Value }
  Write-ColorText (Limit-Text $text ($Width - 20)) $Color
  Write-Host ''
}

function Write-ColorText {
  # Writes text without a newline. 'Orange' is not a console color: it is drawn with a
  # 256-color ANSI escape in Windows Terminal, and falls back to DarkYellow elsewhere.
  param([string]$Text, [string]$Color = 'White')
  if ($Color -eq 'Orange') {
    if ($env:WT_SESSION) {
      $e = [char]27
      Write-Host ("{0}[38;5;208m{1}{0}[0m" -f $e, $Text) -NoNewline
    } else {
      Write-Host $Text -ForegroundColor DarkYellow -NoNewline
    }
  } else {
    Write-Host $Text -ForegroundColor $Color -NoNewline
  }
}

function Write-BarField {
  # "Label             : value    [=====     ]  (text)" line, bar and text colored with Color.
  param(
    [string]$Label,
    [string]$ValueText,
    [int]$Percent,
    [string]$Color,
    [string]$Suffix,
    [int]$BarWidth,
    [int]$Width = 80
  )
  Write-Host ("{0,-18}: " -f $Label) -ForegroundColor DarkGray -NoNewline
  Write-ColorText ("{0,-9}" -f $ValueText) $Color
  Write-Host "[" -ForegroundColor White -NoNewline
  Write-ColorText (New-SignalBar -Percent $Percent -Width $BarWidth) $Color
  Write-Host "]" -ForegroundColor White -NoNewline
  # the level text is dropped / shortened when the console is too narrow
  Write-ColorText (Limit-Text $Suffix ($Width - (20 + 9 + 2 + $BarWidth))) $Color
  Write-Host ''
}

# Maps a value onto 0-100 % for the bar: Low -> 0 %, High -> 100 %
function ConvertTo-BarPercent {
  param([double]$Value, [double]$Low, [double]$High)
  $pct = ($Value - $Low) / ($High - $Low) * 100
  return [int][Math]::Max(0, [Math]::Min(100, [Math]::Round($pct)))
}

# ====================================================================
#                         CELL INFO HELPERS
# ====================================================================

# LTE EARFCN (downlink) -> band + downlink frequency.
# F_DL = F_low + 0.1 * (N_DL - N_start). Common bands only.
function Get-LteBandInfo {
  param([int]$Earfcn)

  # Band, F_low (MHz), N_start, N_end
  $bands = @(
    @(1, 2110, 0, 599),        @(2, 1930, 600, 1199),     @(3, 1805, 1200, 1949),
    @(4, 2110, 1950, 2399),    @(5, 869, 2400, 2649),     @(7, 2620, 2750, 3449),
    @(8, 925, 3450, 3799),     @(12, 729, 5010, 5179),    @(13, 746, 5180, 5279),
    @(14, 758, 5280, 5379),    @(17, 734, 5730, 5849),    @(18, 860, 5850, 5999),
    @(19, 875, 6000, 6149),    @(20, 791, 6150, 6449),    @(21, 1495.9, 6450, 6599),
    @(25, 1930, 8040, 8689),   @(26, 859, 8690, 9039),    @(28, 758, 9210, 9659),
    @(29, 717, 9660, 9769),    @(30, 2350, 9770, 9869),   @(32, 1452, 9920, 10359),
    @(38, 2570, 37750, 38249), @(39, 1880, 38250, 38649), @(40, 2300, 38650, 39649),
    @(41, 2496, 39650, 41589), @(42, 3400, 41590, 43589), @(43, 3600, 43590, 45589),
    @(46, 5150, 46790, 54539), @(66, 2110, 66436, 67335), @(71, 617, 68586, 68935)
  )

  foreach ($b in $bands) {
    if ($Earfcn -ge $b[2] -and $Earfcn -le $b[3]) {
      return [pscustomobject]@{ Band = $b[0]; DlMHz = ($b[1] + 0.1 * ($Earfcn - $b[2])) }
    }
  }
  return $null
}

# NR-ARFCN -> frequency in MHz (global frequency raster)
function Get-NrFreqMHz {
  param([double]$Arfcn)
  if ($Arfcn -lt 600000)       { return 0.005 * $Arfcn }
  elseif ($Arfcn -lt 2016667)  { return 3000 + 0.015 * ($Arfcn - 600000) }
  else                         { return 24250.08 + 0.06 * ($Arfcn - 2016667) }
}

# Teltonika "Mobile Signal Strength Recommendations" levels -> console color + text
function Get-RsrpLevel {
  param($Value)
  if     ($Value -ge -80)  { return @('Green',      'excellent') }
  elseif ($Value -ge -90)  { return @('Yellow',     'good') }
  elseif ($Value -ge -100) { return @('Orange',     'fair to poor') }
  else                     { return @('Red',        'poor') }
}

function Get-RsrqLevel {
  param($Value)
  if     ($Value -ge -10)  { return @('Green',      'excellent') }
  elseif ($Value -ge -15)  { return @('Yellow',     'good') }
  elseif ($Value -ge -20)  { return @('Orange',     'fair to poor') }
  else                     { return @('Red',        'poor') }
}

function Get-SinrLevel {
  param($Value)
  if     ($Value -ge 20) { return @('Green',  'excellent') }
  elseif ($Value -ge 13) { return @('Yellow', 'good') }
  elseif ($Value -gt 0)  { return @('Orange', 'fair to poor') }
  else                   { return @('Red',    'poor') }
}

# Reads the serving cell(s) through the Windows MobileBroadbandCellsInfo API.
# Windows PowerShell: in-process. PowerShell 7: WinRT is unavailable, so a short-lived
# powershell.exe child process does the query.
function Get-MbnCellInfo {
  if (-not $script:CellInfoEnabled) { return $null }

  try {
    if ($PSVersionTable.PSEdition -eq 'Core') {
      $out  = & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $script:CellQueryEnc 2>$null
      if ($LASTEXITCODE -ne 0) { throw "cell query failed ($LASTEXITCODE)" }
      $json = $out -join ''
    } else {
      $json = & ([scriptblock]::Create($script:CellQueryCode))
    }

    $data = $json | ConvertFrom-Json
    $script:CellInfoFailures = 0

    return [pscustomobject]@{
      Lte = @($data.Lte) | Select-Object -First 1
      Nr  = @($data.Nr)  | Select-Object -First 1
    }
  }
  catch {
    $script:CellInfoFailures++
    if ($script:CellInfoFailures -ge 3) { $script:CellInfoEnabled = $false }
    return $null
  }
}

# ====================================================================
#                         GET MBN INTERFACE INFO
# ====================================================================

function Get-MbnInterfaceInfo {
  param([string]$PreferredName)

  $ifaces = @(Get-MbnInterfaceList)
  if ($ifaces.Count -eq 0) { return $null }

  if ($PreferredName) {
    $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredName -and $_.State -match $script:ConnectedPattern } | Select-Object -First 1
    if (-not $chosen) {
      $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredName } | Select-Object -First 1
    }
  } else {
    $chosen = $ifaces | Where-Object { $_.State -match $script:ConnectedPattern } | Select-Object -First 1
    if (-not $chosen) { $chosen = $ifaces | Select-Object -First 1 }
  }

  if (-not $chosen) { return $null }

  # Extended info (network type, IMEI, SIM, etc.) comes from several slow netsh calls,
  # so do it BEFORE reading the byte counters: the counters are then the last thing read
  # and the sample timestamp taken by the caller stays close to them.
  Update-MbnExtendedInfo -iface $chosen

  # Serving cell info (band, channel, PCI, RSRP/RSRQ), only while connected
  if ($chosen.State -match $script:ConnectedPattern) {
    $chosen.CellInfo = Get-MbnCellInfo
  }

  # IP configuration
  try {
    $ip = Get-NetIPConfiguration -InterfaceAlias $chosen.Name -ErrorAction Stop

    # IPv4 address
    if ($ip.IPv4Address) {
      $chosen.IPv4 = $ip.IPv4Address.IPAddress | Select-Object -First 1
    }

    # IPv6 - first global if available, else first IPv6
    if ($ip.IPv6Address) {
      $ipv6Global = $ip.IPv6Address.IPAddress |
        Where-Object { $_ -notlike "fe80::*" } |
        Select-Object -First 1
      if (-not $ipv6Global) {
        $ipv6Global = $ip.IPv6Address.IPAddress | Select-Object -First 1
      }
      $chosen.IPv6 = $ipv6Global
    }

    # IPv4 gateway
    if ($ip.IPv4DefaultGateway) {
      $chosen.Gateway4 = $ip.IPv4DefaultGateway.NextHop | Select-Object -First 1
    }

    # IPv6 gateway - prefer non-link-local
    if ($ip.IPv6DefaultGateway) {
      $gws = @()
      foreach ($g in $ip.IPv6DefaultGateway) {
        if (-not $g) { continue }
        if ($g.PSObject.Properties.Name -contains 'NextHop') {
          $gws += $g.NextHop
        } else {
          $gws += [string]$g
        }
      }
      $gw6 = $gws | Where-Object { $_ -and $_ -notlike "fe80::*" } | Select-Object -First 1
      if (-not $gw6) {
        $gw6 = $gws | Where-Object { $_ } | Select-Object -First 1
      }
      $chosen.Gateway6 = $gw6
    }

    # DNS (first v4 + first v6 if present)
    if ($ip.DNSServer) {
      $chosen.Dns4 = $ip.DNSServer.ServerAddresses |
        Where-Object { $_ -notlike "*:*" } |
        Select-Object -First 1
      $chosen.Dns6 = $ip.DNSServer.ServerAddresses |
        Where-Object { $_ -like "*:*" } |
        Select-Object -First 1
    }
  } catch {}

  # Traffic counters (own try: an IP lookup failure must not lose the counters, and vice versa)
  try {
    $stats = Get-NetAdapterStatistics -Name $chosen.Name -ErrorAction Stop
    $chosen.RxBytes = $stats.ReceivedBytes
    $chosen.TxBytes = $stats.SentBytes
  } catch {}

  return $chosen
}

# ====================================================================
#                              SCREEN
# ====================================================================

# Draws the whole screen from already collected data. No queries are made here,
# so it can also be used to redraw the last data when the console is resized.
function Show-MbnScreen {
  param(
    $Info,
    $Adapter,
    $RxRate,
    $TxRate,
    [datetime]$Time,
    [string]$PreferredName,
    [int]$Interval,
    [int]$Width
  )

  Clear-Host

  if (-not $Info) {
    if ($PreferredName) {
      Write-Host (Limit-Text "Interface '$PreferredName' not found. Check the name with: netsh mbn show interfaces" ($Width * 2)) -ForegroundColor Yellow
    } else {
      Write-Host "No mobile broadband interface found. Check that the device is enabled or inserted." -ForegroundColor Yellow
    }
    return
  }

  $width   = $Width
  $adapter = $Adapter
  $rxRate  = $RxRate
  $txRate  = $TxRate
  $info    = $Info

  # --- signal ---
  $sigPct = if ($null -ne $info.SignalPercent) { $info.SignalPercent } else { 0 }

  # "~" only when the value is an estimate; a dBm value parsed from netsh is shown as-is
  if ($null -ne $info.RssiDbm) {
    $rssi     = $info.RssiDbm
    $rssiText = "$rssi dBm"
  } else {
    $rssi     = [int](($sigPct / 2) - 100)
    $rssiText = "~$rssi dBm"
  }

  $radioColor = Get-RadioColor $info.CellularClass

  # Bar rows (Signal / RSRP / RSRQ): 20 (label) + 9 (value) + 2 (brackets) + ~21 ("  (35%, fair to poor)") around the bar
  $barWidth = [Math]::Max(8, [Math]::Min(25, $width - 54))

  $line = "".PadRight([Math]::Min(80, $width), '-')

  # -------------------- HEADER (scales to the console width) --------------------
  $timePart    = "{0:yyyy-MM-dd HH:mm:ss}" -f $Time
  $adapterName = if ($info.Name)  { [string]$info.Name }  else { '(unknown)' }
  $adapterDesc = if ($info.Model) { [string]$info.Model } else { '' }

  $headerPrefix = "Mobile Broadband Monitor v{0} |  {1}  |  Adapter: " -f $Script:MbnMonitorVersion, $timePart
  if ($headerPrefix.Length + 8 -gt $width) {
    # Narrow window: use a compact prefix
    $headerPrefix = "v{0} | {1} | " -f $Script:MbnMonitorVersion, $timePart
  }
  $avail = [Math]::Max(0, $width - $headerPrefix.Length)

  $nameShown = Limit-Text $adapterName $avail
  $descShown = ''
  $descAvail = $avail - $nameShown.Length - 3          # " (" + ")"
  if (-not [string]::IsNullOrWhiteSpace($adapterDesc) -and $descAvail -ge 4) {
    $descShown = Limit-Text $adapterDesc $descAvail
  }

  Write-Host $headerPrefix -ForegroundColor Green -NoNewline
  if ($descShown) {
    Write-Host $nameShown -ForegroundColor Yellow -NoNewline
    Write-Host " ($descShown)" -ForegroundColor Yellow
  } else {
    Write-Host $nameShown -ForegroundColor Yellow
  }

  $headerLen = $headerPrefix.Length + $nameShown.Length
  if ($descShown) { $headerLen += $descShown.Length + 3 }
  Write-Host ("".PadRight([Math]::Min($headerLen, $width), '=')) -ForegroundColor Gray
  "" | Out-Host

  # -------------------- CONNECTION --------------------
  Write-Host "[ Connection ]" -ForegroundColor Cyan
  Write-Host $line -ForegroundColor Gray

  $stateColor = if ($info.State -match $script:ConnectedPattern) { "Green" } else { "Yellow" }

  Write-Field "State"        $info.State    $stateColor $width
  Write-Field "Provider"     $info.Provider 'White'     $width
  Write-Field "Roaming"      $info.Roaming  'White'     $width

  # Signal uses the same dBm scale and Teltonika levels as RSRP, so the rows agree with each other
  # (the modem's own percentage is shown in the text, but no longer decides the color)
  $sigLvl = Get-RsrpLevel $rssi
  Write-BarField "Signal" $rssiText (ConvertTo-BarPercent -Value $rssi -Low -110 -High -70) $sigLvl[0] ("  ({0}%, {1})" -f $sigPct, $sigLvl[1]) $barWidth $width

  Write-Field "Device"       $info.DeviceType    'Gray'      $width
  Write-Field "Radio class"  $info.CellularClass $radioColor $width
  $netTypeColor = if ($info.NetworkType -match '^3GPP$') { 'DarkCyan' } elseif ($info.NetworkType -match '\S') { 'Yellow' } else { 'Gray' }
  Write-Field "Network type" $info.NetworkType   $netTypeColor $width
  Write-Field "Data class"   $info.DataClass     (Get-RadioColor $info.DataClass) $width

  # IP address (v4 + first global v6 if present)
  $ipSummary = $info.IPv4
  if ($info.IPv6) {
    $ipSummary = "{0}  |  {1}" -f $info.IPv4, $info.IPv6
  }
  Write-Field "IP address" $ipSummary 'White' $width

  # Gateway summary (v4 + v6)
  $gw4 = $info.Gateway4
  $gw6 = $info.Gateway6
  if ($gw4 -and $gw6) {
    $gwSummary = "{0}  |  {1}" -f $gw4, $gw6
  } elseif ($gw4) {
    $gwSummary = $gw4
  } else {
    $gwSummary = $gw6
  }
  Write-Field "Gateway" $gwSummary 'White' $width

  # Compact DNS line if we have anything
  if ($info.Dns4 -or $info.Dns6) {
    if ($info.Dns4 -and $info.Dns6) {
      $dnsSummary = "{0}  |  {1}" -f $info.Dns4, $info.Dns6
    } elseif ($info.Dns4) {
      $dnsSummary = $info.Dns4
    } else {
      $dnsSummary = $info.Dns6
    }
    Write-Field "DNS" $dnsSummary 'White' $width
  }

  Write-Field "Model"    $info.Model 'Gray' $width
  Write-Field "Mfr / FW" ("{0} / {1}" -f $info.Manufacturer, $info.Firmware) 'Gray' $width

  "" | Out-Host

  # -------------------- SERVING CELL --------------------
  $cell = $info.CellInfo
  if ($cell -or $script:CellInfoEnabled) {
    Write-Host "[ Serving cell ]" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Gray

    $lte = if ($cell) { $cell.Lte } else { $null }
    $nr  = if ($cell) { $cell.Nr }  else { $null }

    if ($lte) {
      $earfcn   = $lte.ChannelNumber
      $bandInfo = $null
      if ($null -ne $earfcn) { $bandInfo = Get-LteBandInfo ([int]$earfcn) }

      if ($bandInfo) {
        Write-Field "LTE band" ("B{0}  ({1:F1} MHz DL)" -f $bandInfo.Band, $bandInfo.DlMHz) 'White' $width
      }
      Write-Field "EARFCN / PCI" ("{0} / {1}" -f $earfcn, $lte.PhysicalCellId) 'White' $width

      if ($null -ne $lte.CellId) {
        $cid = [long]$lte.CellId
        Write-Field "Cell ID" ("{0}  (eNB {1}, cell {2})" -f $cid, ($cid -shr 8), ($cid -band 255)) 'White' $width
      }

      $prov = [string]$lte.ProviderId
      $plmn = if ($prov.Length -ge 5) { "{0}-{1}" -f $prov.Substring(0,3), $prov.Substring(3) } else { '-' }
      Write-Field "TAC / MCC-MNC" ("{0} / {1}" -f $lte.TrackingAreaCode, $plmn) 'White' $width

      # Bars: RSRP -110..-70 dBm and RSRQ -25..-5 dB, so the four Teltonika levels fall on quarters
      if ($null -ne $lte.ReferenceSignalReceivedPowerInDBm) {
        $v   = $lte.ReferenceSignalReceivedPowerInDBm
        $lvl = Get-RsrpLevel $v
        Write-BarField "RSRP" ("{0} dBm" -f $v) (ConvertTo-BarPercent -Value $v -Low -110 -High -70) $lvl[0] ("  ({0})" -f $lvl[1]) $barWidth $width
      }
      if ($null -ne $lte.ReferenceSignalReceivedQualityInDBm) {
        $v   = $lte.ReferenceSignalReceivedQualityInDBm
        $lvl = Get-RsrqLevel $v
        Write-BarField "RSRQ" ("{0} dB" -f $v) (ConvertTo-BarPercent -Value $v -Low -25 -High -5) $lvl[0] ("  ({0})" -f $lvl[1]) $barWidth $width
      }
    } else {
      Write-Field "LTE" "not reported by the driver" 'Gray' $width
    }

    if ($nr) {
      # NR property names are read defensively, since drivers differ in what they report
      $nrProp = { param($n) $pp = $nr.PSObject.Properties[$n]; if ($pp) { $pp.Value } else { $null } }
      $nrArfcn = & $nrProp 'ChannelNumber'
      $nrPci   = & $nrProp 'PhysicalCellId'
      $nrRsrp  = & $nrProp 'ReferenceSignalReceivedPowerInDBm'
      $nrRsrq  = & $nrProp 'ReferenceSignalReceivedQualityInDBm'
      $nrSinr  = & $nrProp 'SignalToNoiseRatioInDB'

      if ($null -ne $nrArfcn) {
        Write-Field "NR-ARFCN" ("{0}  ({1:F1} MHz)" -f $nrArfcn, (Get-NrFreqMHz $nrArfcn)) 'White' $width
      }
      if ($null -ne $nrPci) { Write-Field "NR PCI" $nrPci 'White' $width }
      if ($null -ne $nrRsrp) {
        $lvl = Get-RsrpLevel $nrRsrp
        Write-BarField "NR RSRP" ("{0} dBm" -f $nrRsrp) (ConvertTo-BarPercent -Value $nrRsrp -Low -110 -High -70) $lvl[0] ("  ({0})" -f $lvl[1]) $barWidth $width
      }
      if ($null -ne $nrRsrq) {
        $lvl = Get-RsrqLevel $nrRsrq
        Write-BarField "NR RSRQ" ("{0} dB" -f $nrRsrq) (ConvertTo-BarPercent -Value $nrRsrq -Low -25 -High -5) $lvl[0] ("  ({0})" -f $lvl[1]) $barWidth $width
      }
      if ($null -ne $nrSinr) {
        $lvl = Get-SinrLevel $nrSinr
        Write-BarField "NR SINR" ("{0} dB" -f $nrSinr) (ConvertTo-BarPercent -Value $nrSinr -Low -5 -High 25) $lvl[0] ("  ({0})" -f $lvl[1]) $barWidth $width
      }
    }
    elseif ($info.DataClass -match '5G') {
      Write-Field "5G NR" "not reported by the driver" 'Gray' $width
    }

    "" | Out-Host
  }

  # -------------------- LINK / TRAFFIC --------------------
  Write-Host "[ Link / Traffic ]" -ForegroundColor Cyan
  Write-Host $line -ForegroundColor Gray

  # Link rate: just show whatever Windows reports (string or number)
  $linkRateText = "N/A"
  if ($adapter -and $adapter.LinkSpeed) {
    $linkRateText = [string]$adapter.LinkSpeed
  }
  Write-Field "Link rate" $linkRateText 'White' $width

  Write-Host ("{0,-18}: " -f "Throughput") -ForegroundColor DarkGray -NoNewline
  if ($null -ne $rxRate -and $null -ne $txRate) {
    Write-Host ("{0:N2} Mbit/s (down) | {1:N2} Mbit/s (up)" -f $rxRate, $txRate) -ForegroundColor White
  } else {
    Write-Host "(warming up... or unavailable)" -ForegroundColor Yellow
  }

  Write-Field "Data total" ("{0} (rx) | {1} (tx)" -f (Format-Bytes $info.RxBytes), (Format-Bytes $info.TxBytes)) 'White' $width

  "" | Out-Host

  # -------------------- DEVICE / IDENTITY --------------------
  Write-Host "[ Device / Identity ]" -ForegroundColor Cyan
  Write-Host $line -ForegroundColor Gray

  # --- DEVICE FIRST ---
  if ($adapter) {
    Write-Field "Description" $adapter.InterfaceDescription 'White' $width
    Write-Field "MAC"         $adapter.MacAddress          'White' $width
    Write-Field "Driver info" $adapter.DriverInformation   'White' $width
    Write-Field "Driver file" $adapter.DriverFileName      'White' $width
  }

  "" | Out-Host

  # --- THEN SIM / SUBSCRIBER ---
  Write-Field "IMEI"          $info.IMEI        'White' $width
  Write-Field "Phone number"  $info.PhoneNumber 'White' $width
  Write-Field "IMSI / Sub ID" $info.IMSI        'White' $width
  Write-Field "SIM ICC ID"    $info.SimIcc      'White' $width

  "" | Out-Host
  Write-Host ("Press Ctrl-C to exit. Refresh: {0}s" -f $Interval) -ForegroundColor Cyan
}

# ====================================================================
#                              MAIN LOOP
# ====================================================================

$sw            = [Diagnostics.Stopwatch]::StartNew()
$lastRx        = $null
$lastTx        = $null
$lastSampleSec = $null

# Last collected data, kept so the screen can be redrawn on resize without new queries
$screen     = $null
$drawnWidth = $null

Write-Host ("Starting Mobile Broadband monitor v{0}. Press Ctrl-C to stop.`n" -f $Script:MbnMonitorVersion) -ForegroundColor Green

while ($true) {

  # Duration check at the top of the loop, so it also applies after errors / "no interface"
  if ($Duration -gt 0 -and $sw.Elapsed.TotalSeconds -ge $Duration) {
    Write-Host ("`nDuration reached (~{0}s). Exiting..." -f [int]$sw.Elapsed.TotalSeconds) -ForegroundColor Cyan
    break
  }

  try {
    # ---- collect ----
    $info      = Get-MbnInterfaceInfo -PreferredName $Interface
    $sampleSec = $sw.Elapsed.TotalSeconds      # timestamp right next to the byte counters
    $now       = Get-Date

    $rxRate = $null; $txRate = $null
    $adapter = $null

    if ($info) {
      # --- throughput (Mbit/s, decimal: 1 Mbit = 1,000,000 bits) ---
      if ($null -ne $lastRx -and $null -ne $lastTx -and $null -ne $lastSampleSec -and
          $null -ne $info.RxBytes -and $null -ne $info.TxBytes) {
        $dt  = $sampleSec - $lastSampleSec
        $dRx = $info.RxBytes - $lastRx
        $dTx = $info.TxBytes - $lastTx
        # A negative delta means the counters were reset (reconnect / adapter reset)
        if ($dt -gt 0 -and $dRx -ge 0 -and $dTx -ge 0) {
          $rxRate = $dRx * 8 / $dt / 1e6
          $txRate = $dTx * 8 / $dt / 1e6
        }
      }
      $lastRx        = $info.RxBytes
      $lastTx        = $info.TxBytes
      $lastSampleSec = $sampleSec

      # grab NIC once (for link rate + driver info)
      try {
        $adapter = Get-NetAdapter -Name $info.Name -ErrorAction Stop
      } catch { $adapter = $null }
    }
    else {
      $lastRx = $null; $lastTx = $null; $lastSampleSec = $null
    }

    $screen = @{
      Info          = $info
      Adapter       = $adapter
      RxRate        = $rxRate
      TxRate        = $txRate
      Time          = $now
      PreferredName = $Interface
      Interval      = $Interval
    }

    # ---- draw ----
    $drawnWidth = Get-ConsoleWidth
    Show-MbnScreen @screen -Width $drawnWidth

    # ---- wait (never past the Duration limit); redraw the stored data if the window is resized ----
    $deadline = $sw.Elapsed.TotalSeconds + $Interval
    if ($Duration -gt 0) { $deadline = [Math]::Min($deadline, $Duration) }

    while ($sw.Elapsed.TotalSeconds -lt $deadline) {
      $remainingMs = ($deadline - $sw.Elapsed.TotalSeconds) * 1000
      Start-Sleep -Milliseconds ([int][Math]::Max(10, [Math]::Min(200, $remainingMs)))

      $w = Get-ConsoleWidth
      if ($w -ne $drawnWidth) {
        $drawnWidth = $w
        Show-MbnScreen @screen -Width $drawnWidth
      }
    }
  }
  catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Start-Sleep -Seconds $Interval
  }
}
