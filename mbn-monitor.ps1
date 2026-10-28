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

  EXAMPLES
    .\mbn-monitor.ps1
    .\mbn-monitor.ps1 -Interval 2
    .\mbn-monitor.ps1 -Duration 30
    .\mbn-monitor.ps1 -Interface "Matkapuhelinverkko 12"

  NOTES
    - Parsing relies on English `netsh mbn` output labels. On localized Windows
      versions most fields will come back empty.
#>

param(
  [ValidateRange(1, 3600)]
  [int]$Interval = 5,

  [string]$Interface,

  [ValidateRange(0, [int]::MaxValue)]
  [int]$Duration = 0
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

function Get-SignalColor {
  param([int]$Percent)
  if ($Percent -ge 67) { "Green" }
  elseif ($Percent -ge 34) { "Yellow" }
  else { "Red" }
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
  Write-Host (Limit-Text $text ($Width - 20)) -ForegroundColor $Color
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

  $sigText    = "{0,3}%" -f $sigPct
  $sigColor   = Get-SignalColor $sigPct
  $radioColor = Get-RadioColor $info.CellularClass

  # Signal line: 20 (label) + 5 (" 32% ") + 2 (brackets) + ~14 ("  (~-93 dBm)") = ~41 columns around the bar
  $barWidth = [Math]::Max(8, [Math]::Min(25, $width - 44))
  $barInner = New-SignalBar -Percent $sigPct -Width $barWidth

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

  # Signal line
  Write-Host ("{0,-18}: " -f "Signal")       -ForegroundColor DarkGray -NoNewline
  Write-Host (" {0} " -f $sigText)           -ForegroundColor $sigColor -NoNewline
  Write-Host "["                             -ForegroundColor White -NoNewline
  Write-Host $barInner                       -ForegroundColor $sigColor -NoNewline
  Write-Host "]"                             -ForegroundColor White -NoNewline
  Write-Host ("  ({0})" -f $rssiText)        -ForegroundColor $sigColor

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
