#Requires -Version 7.0
<#
  
  Wi-Fi Monitor
  ------------------------------------
  Copyright (c) 2025 Benny Hult
  Licensed under the BSD 3-Clause License. See LICENSE file in the project root for details.
  
  A lightweight, netsh-based Wi-Fi monitor for PowerShell 7.
  (Version number: see $Script:WifiMonitorVersion below.)

  Features
  --------
  - Shows current Wi-Fi connection details (SSID, BSSID, channel, radio type, auth/cipher, IP, gateway, MAC)
  - Displays link rate (rx/tx) and a colored signal-strength bar with dBm estimate / RSSI
  - Tracks per-interval throughput (down/up Mbit/s) and total bytes transferred
  - Lists nearby SSIDs, merging 2.4 GHz, 5 GHz and 6 GHz information for each network
  - Header, separators and lists scale to the current console width
  - Requires no external modules or tools – only `netsh` and built-in cmdlets

  Parameters
  ----------
  -Interval <int>
      Refresh interval in seconds (1-3600).
      Default: 5

      Examples:
        .\wifi-monitor.ps1
            Run continuously, refreshing every 5 seconds.

        .\wifi-monitor.ps1 -Interval 2
            Run continuously, refreshing every 2 seconds.

  -Interface <string>
      Preferred Wi-Fi interface name (as shown by `netsh wlan show interfaces` "Name" field).
      If omitted, the script picks the first connected Wi-Fi interface, or falls back to the first one found.

      Examples:
        .\wifi-monitor.ps1 -Interface "WLAN"
            Monitor the adapter named "WLAN".

  -Duration <int>
      Total runtime in seconds before the script exits automatically.
      - 0 means "run until Ctrl-C" (infinite mode).
      - >0 means "run until that many seconds have elapsed" from script start.

      Examples:
        .\wifi-monitor.ps1 -Duration 15
            Run for about 15 seconds (with the default 5s refresh) and then exit.

        .\wifi-monitor.ps1 -Interval 1 -Duration 10
            Refresh every 1 second for about 10 seconds, then exit.

        .\wifi-monitor.ps1 -Interface "WLAN" -Interval 2 -Duration 20
            Monitor adapter "WLAN", refresh every 2 seconds, stop after ~20 seconds.

  -ScanInterval <int>
      How often (seconds) the script asks Windows to rescan for Wi-Fi networks, 0-3600.
      Default: 10. 0 = never trigger a scan (only read Windows' cached list).
      Without a scan request `netsh` only returns cached results, which Windows refreshes
      rarely – the same thing as pressing the refresh button in the Wi-Fi flyout.

      Examples:
        .\wifi-monitor.ps1 -ScanInterval 5
            Request a fresh scan every 5 seconds.

  Notes
  -----
  - Newer Windows versions only let `netsh wlan show interfaces` / `netsh wlan show networks`
    return WLAN details when Windows location services are on. If they are off, the script
    detects it, shows a warning, and falls back to what works without location: adapter name,
    state, MAC, IP/gateway, link speed, traffic counters and the network profile name.
    SSID, BSSID, channel, signal and the nearby-networks list are unavailable in that mode.
  - Parsing relies on English `netsh` output labels. On localized Windows versions
    most fields will come back empty.
  - Nearby SSIDs list is limited to the top 6 networks, sorted by signal strength.
  - Fresh scans are requested with the Windows WlanScan API (wlanapi.dll, via Add-Type).
    A scan takes a few seconds, so the list is read ~4 s after each request. Scanning very
    often can briefly disturb the connected adapter, so don't set -ScanInterval too low.
  - The currently connected SSID is marked with * in the nearby list.
#>

param(
  [ValidateRange(1, 3600)]
  [int]$Interval = 5,            # refresh interval in seconds

  [string]$Interface,            # optional adapter name, e.g. "WLAN"

  [ValidateRange(0, [int]::MaxValue)]
  [int]$Duration = 0,            # total run time in seconds (0 = infinite)

  [ValidateRange(0, 3600)]
  [int]$ScanInterval = 10        # seconds between active Wi-Fi scans (0 = off)
)

# Version variable – change this in one place, it updates the banner automatically
$Script:WifiMonitorVersion = '1.666'

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8 } catch {}

# ---- Active Wi-Fi scan (same as the refresh button in the Windows Wi-Fi flyout) ----
$Script:WlanScanAvailable = $true
try {
  if (-not ([System.Management.Automation.PSTypeName]'WlanScanner').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WlanScanner {
  [DllImport("wlanapi.dll")] static extern int WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);
  [DllImport("wlanapi.dll")] static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);
  [DllImport("wlanapi.dll")] static extern int WlanScan(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, IntPtr pIeData, IntPtr pReserved);

  // Returns 0 on success, otherwise a Win32 error code.
  public static int Scan(Guid interfaceGuid) {
    uint ver; IntPtr h;
    int r = WlanOpenHandle(2, IntPtr.Zero, out ver, out h);
    if (r != 0) return r;
    try { return WlanScan(h, ref interfaceGuid, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero); }
    finally { WlanCloseHandle(h, IntPtr.Zero); }
  }
}
'@
  }
} catch { $Script:WlanScanAvailable = $false }

function Invoke-NetshWlanInterfaces { (netsh wlan show interfaces) -join [Environment]::NewLine }
function Invoke-NetshWlanNetworks   { (netsh wlan show networks mode=bssid) -join [Environment]::NewLine }

# ---- Helpers ---------------------------------------------------------------

$Script:LocationBlocked = $false

function Test-WlanLocationBlocked {
  # netsh prints a "needs location permission" message instead of the data when location is off.
  param([string]$Text)
  return [bool]($Text -match '(?i)privacy-location|location\s+(permission|services)|sijainti')
}

function Get-WifiAdapterFallback {
  # Wi-Fi adapter info that does not need location permission (used when netsh is blocked).
  param([string]$PreferredAlias)

  $ad = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.PhysicalMediaType -match '802\.11' })
  if ($PreferredAlias) { $ad = @($ad | Where-Object { $_.Name -eq $PreferredAlias }) }
  $a = $ad | Sort-Object @{Expression={ $_.Status -eq 'Up' }; Descending=$true} | Select-Object -First 1
  if (-not $a) { return $null }

  $prof = (Get-NetConnectionProfile -InterfaceAlias $a.Name -ErrorAction SilentlyContinue | Select-Object -First 1).Name

  [pscustomobject]@{
    Name             = $a.Name
    Description      = $a.InterfaceDescription
    State            = if ($a.Status -eq 'Up') { 'connected' } else { "$($a.Status)".ToLower() }
    SSID             = $null
    BSSID            = $null
    SignalPct        = $null
    Channel          = $null
    RadioType        = $null
    Auth             = $null
    Cipher           = $null
    Profile          = $prof
    PhysicalAddress  = $a.MacAddress
    ReceiveRateMbps  = if ($a.ReceiveLinkSpeed)  { [math]::Round($a.ReceiveLinkSpeed  / 1e6, 1) } else { $null }
    TransmitRateMbps = if ($a.TransmitLinkSpeed) { [math]::Round($a.TransmitLinkSpeed / 1e6, 1) } else { $null }
    Rssi             = $null
    Guid             = $a.InterfaceGuid
  }
}

function Get-WlanInterfaceList {
  # Parse `netsh wlan show interfaces` into objects.
  $t = Invoke-NetshWlanInterfaces
  if (-not $t) { return @() }

  $Script:LocationBlocked = Test-WlanLocationBlocked $t
  if ($Script:LocationBlocked) { return @() }

  $blocks = ($t -split "(?:\r?\n){2,}") | Where-Object { $_ -match ":" }

  $ifaces = @()
  foreach ($b in $blocks) {

    $get = {
      param($pattern)
      $m = [regex]::Match($b, $pattern, 'IgnoreCase, Multiline')
      if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
    }

    $name        = & $get "^\s*Name\s*:\s*(.+)$"
    $desc        = & $get "^\s*Description\s*:\s*(.+)$"
    $state       = & $get "^\s*State\s*:\s*(.+)$"
    $ssid        = & $get "^\s*SSID\s*:\s*(.+)$"
    $bssid       = & $get "^\s*(?:AP\s+)?BSSID\s*:\s*(.+)$"
    $signal      = & $get "^\s*Signal\s*:\s*(\d+)\s*%"
    $channel     = & $get "^\s*Channel\s*:\s*(\d+)"
    $radio       = & $get "^\s*Radio\s*type\s*:\s*(.+)$"
    $auth        = & $get "^\s*Authentication\s*:\s*(.+)$"
    $cipher      = & $get "^\s*Cipher\s*:\s*(.+)$"
    $profile     = & $get "^\s*Profile\s*:\s*(.+)$"
    $mac         = & $get "^\s*Physical\s*address\s*:\s*([0-9A-Fa-f:\-]+)"
    $rssi        = & $get "^\s*Rssi\s*:\s*(-?\d+)"
    $guid        = & $get "^\s*GUID\s*:\s*([0-9A-Fa-f\-]{36})"

    # integer or decimal Mbps (e.g. 866 or 866.7)
    $rateMatches = [regex]::Matches($b, "^\s*.*?\(Mbps\)\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*$", 'IgnoreCase, Multiline')
    $rxRate = $null; $txRate = $null
    if ($rateMatches.Count -ge 1) { $rxRate = [double]$rateMatches[0].Groups[1].Value }
    if ($rateMatches.Count -ge 2) { $txRate = [double]$rateMatches[1].Groups[1].Value }

    $ifaces += [pscustomobject]@{
      Name            = $name
      Description     = $desc
      State           = $state
      SSID            = $ssid
      BSSID           = $bssid
      SignalPct       = if ($signal) { [int]$signal } else { $null }
      Channel         = $channel
      RadioType       = $radio
      Auth            = $auth
      Cipher          = $cipher
      Profile         = $profile
      PhysicalAddress = $mac
      ReceiveRateMbps = $rxRate
      TransmitRateMbps= $txRate
      Rssi            = if ($rssi) { [int]$rssi } else { $null }
      Guid            = $guid
      __raw           = $b
    }
  }
  return $ifaces
}

function Format-Bytes {
  param([Nullable[long]]$n)
  if ($null -eq $n) { return '-' }
  switch ($n) {
    {$_ -ge 1TB} { return '{0:N2} TB' -f ($n/1TB) }
    {$_ -ge 1GB} { return '{0:N2} GB' -f ($n/1GB) }
    {$_ -ge 1MB} { return '{0:N2} MB' -f ($n/1MB) }
    {$_ -ge 1KB} { return '{0:N2} KB' -f ($n/1KB) }
    default      { return "$n B" }
  }
}

function New-SignalBar {
  param([int]$Percent, [int]$Width = 30)
  $filled = [int][math]::Floor(($Percent * $Width) / 100.0)
  if ($filled -lt 0) { $filled = 0 }
  elseif ($filled -gt $Width) { $filled = $Width }
  $empty  = $Width - $filled
  ('█' * $filled) + ('░' * $empty)
}

function Format-SignalColor {
  param([int]$Percent, [string]$Text)
  if ($PSStyle) {
    if ($Percent -ge 67) { return "$($PSStyle.Foreground.Green)$Text$($PSStyle.Reset)" }
    elseif ($Percent -ge 34) { return "$($PSStyle.Foreground.Yellow)$Text$($PSStyle.Reset)" }
    else { return "$($PSStyle.Foreground.Red)$Text$($PSStyle.Reset)" }
  } else { return $Text }
}

function Limit-Text {
  # Truncate text to Max characters, ending with an ellipsis if shortened.
  param([string]$Text, [int]$Max)
  if ($Max -le 0) { return '' }
  if ($Text.Length -le $Max) { return $Text }
  if ($Max -le 1) { return '…' }
  return $Text.Substring(0, $Max - 1) + '…'
}

function Get-ConsoleWidth {
  # Usable console width (one column kept free so the last column never wraps).
  try {
    $w = $Host.UI.RawUI.WindowSize.Width
    if ($w -lt 1) { return 80 }
    return [Math]::Max(40, $w - 1)
  } catch { return 80 }
}

function Get-WifiInterfaceInfo {
  param([string]$PreferredAlias)

  $ifaces = Get-WlanInterfaceList
  if (-not $ifaces) {
    if ($Script:LocationBlocked) { $ifaces = @(Get-WifiAdapterFallback -PreferredAlias $PreferredAlias) | Where-Object { $_ } }
    if (-not $ifaces) { return $null }
  }

  $chosen = $null
  if ($PreferredAlias) {
    $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredAlias -and $_.State -match '(?i)^connected$' } | Select-Object -First 1
    if (-not $chosen) { $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredAlias } | Select-Object -First 1 }
  } else {
    $chosen = $ifaces | Where-Object { $_.State -match '(?i)^connected$' } | Select-Object -First 1
    if (-not $chosen) { $chosen = $ifaces | Select-Object -First 1 }
  }

  if (-not $chosen) { return $null }

  # Defaults first, so the properties always exist even if the lookups below fail
  foreach ($p in 'IPv4','Gateway','RxBytes','TxBytes') {
    $chosen | Add-Member -NotePropertyName $p -NotePropertyValue $null -Force
  }

  if ($chosen.Name) {
    try {
      $ip = Get-NetIPConfiguration -InterfaceAlias $chosen.Name -ErrorAction Stop
      $chosen.IPv4    = $ip.IPv4Address.IPAddress     | Select-Object -First 1
      $chosen.Gateway = $ip.IPv4DefaultGateway.NextHop | Select-Object -First 1
    } catch {}

    try {
      $stats = Get-NetAdapterStatistics -Name $chosen.Name -ErrorAction Stop
      $chosen.RxBytes = $stats.ReceivedBytes
      $chosen.TxBytes = $stats.SentBytes
    } catch {}
  }

  return $chosen
}

function Get-NearbyNetworks {
  # Per-BSSID parsing from `netsh wlan show networks mode=bssid`,
  # then aggregate per SSID with separate 2.4 / 5 / 6 GHz info.
  $t = Invoke-NetshWlanNetworks
  if (-not $t) { return @() }

  if (Test-WlanLocationBlocked $t) { $Script:LocationBlocked = $true; return @() }

  $lines = $t -split "\r?\n"
  $entries = @()

  $currentSsid   = $null
  $pendingSignal = $null
  $pendingBand   = $null   # "2.4", "5" or "6"

  foreach ($ln in $lines) {

    # New SSID block
    $mSsid = [regex]::Match($ln, "^\s*SSID\s+\d+\s*:\s*(.*?)\s*$")
    if ($mSsid.Success) {
      $currentSsid   = $mSsid.Groups[1].Value.Trim()
      $pendingSignal = $null
      $pendingBand   = $null
      continue
    }

    # Signal line inside BSSID block
    $mSig = [regex]::Match($ln, "^\s*Signal\s*:\s*(\d+)\s*%")
    if ($mSig.Success) {
      $pendingSignal = [int]$mSig.Groups[1].Value
      continue
    }

    # Band line (e.g. "Band : 2.4 GHz", "Band : 5 GHz", "Band : 6 GHz")
    $mBand = [regex]::Match($ln, "^\s*Band\s*:\s*(.+?)\s*$")
    if ($mBand.Success) {
      $bandStr = $mBand.Groups[1].Value.Trim()
      if     ($bandStr -like "2.4*") { $pendingBand = "2.4" }
      elseif ($bandStr -like "5*")   { $pendingBand = "5"   }
      elseif ($bandStr -like "6*")   { $pendingBand = "6"   }
      else                           { $pendingBand = $null }
      continue
    }

    # Channel line (belongs to the last pendingSignal/Band)
    $mChan = [regex]::Match($ln, "^\s*Channel\s*:\s*(\d+)")
    if ($mChan.Success) {
      $chan = [int]$mChan.Groups[1].Value
      if ($currentSsid -and $null -ne $pendingSignal) {
        # Older Windows versions have no "Band" line: fall back to a channel-based guess
        $band = $pendingBand
        if (-not $band) { $band = if ($chan -le 14) { "2.4" } else { "5" } }

        $entries += [pscustomobject]@{
          SSID    = $currentSsid
          Signal  = $pendingSignal
          Channel = $chan
          BandGHz = $band
        }
        $pendingSignal = $null
        $pendingBand   = $null
      }
      continue
    }
  }

  if ($entries.Count -eq 0) { return @() }

  # Aggregate per SSID: best signal per band, overall best (for color)
  $agg = @()
  $groups = $entries | Group-Object SSID
  foreach ($g in $groups) {
    $rows = $g.Group

    $best24 = $rows | Where-Object { $_.BandGHz -eq '2.4' } | Sort-Object Signal -Descending | Select-Object -First 1
    $best5  = $rows | Where-Object { $_.BandGHz -eq '5'   } | Sort-Object Signal -Descending | Select-Object -First 1
    $best6  = $rows | Where-Object { $_.BandGHz -eq '6'   } | Sort-Object Signal -Descending | Select-Object -First 1
    $overall= $rows | Sort-Object Signal -Descending | Select-Object -First 1

    $agg += [pscustomobject]@{
      SSID          = $g.Name
      OverallSignal = $overall.Signal
      Ch24          = if ($best24) { $best24.Channel } else { $null }
      Sig24         = if ($best24) { $best24.Signal  } else { $null }
      Ch5           = if ($best5)  { $best5.Channel  } else { $null }
      Sig5          = if ($best5)  { $best5.Signal   } else { $null }
      Ch6           = if ($best6)  { $best6.Channel  } else { $null }
      Sig6          = if ($best6)  { $best6.Signal   } else { $null }
    }
  }

  # Sort by overall signal desc, then SSID (hidden networks have an empty SSID and are never added above)
  $agg | Sort-Object -Property @{Expression='OverallSignal';Descending=$true},SSID
}

# ---- Main loop -------------------------------------------------------------

$sw = [Diagnostics.Stopwatch]::StartNew()

$lastRx        = $null
$lastTx        = $null
$lastSampleSec = $null

$nets            = @()
$lastReadSec     = $null   # when the nearby list was last read with netsh
$lastScanReqSec  = $null   # when an active scan was last requested
$pendingRead     = $false  # a requested scan is waiting to be read
$scanWaitSec     = 4       # a scan needs a few seconds before netsh shows the new results
$scanStatus      = ''

Write-Host "Starting Wi-Fi monitor v$WifiMonitorVersion. Press Ctrl-C to stop.`n"

while ($true) {

  # Duration check at the top of the loop, so it also applies after errors / "no WLAN info"
  if ($Duration -gt 0 -and $sw.Elapsed.TotalSeconds -ge $Duration) {
    Write-Host "`nDuration limit reached (~$([int]$sw.Elapsed.TotalSeconds)s). Exiting..." -ForegroundColor Cyan
    break
  }

  try {
    $info      = Get-WifiInterfaceInfo -PreferredAlias $Interface
    $sampleSec = $sw.Elapsed.TotalSeconds     # timestamp right next to the byte counters
    $now       = Get-Date
    $width     = Get-ConsoleWidth

    if (-not $info) {
      Clear-Host
      if ($Interface) {
        Write-Host (Limit-Text "Interface '$Interface' not found (or no WLAN info). Check the name with: netsh wlan show interfaces" ($width * 2)) -ForegroundColor Yellow
      } else {
        Write-Host "No WLAN info found. Are you on Wi-Fi, and is the adapter enabled?" -ForegroundColor Yellow
      }
      $lastRx = $null; $lastTx = $null; $lastSampleSec = $null
    }
    else {

      $sigPct = if ($null -ne $info.SignalPct) { [int]$info.SignalPct } else { 0 }

      if ($null -ne $info.Rssi) {
        $rssi     = $info.Rssi
        $rssiText = "$rssi dBm"
      } else {
        $rssi     = [int]([math]::Round(($sigPct / 2) - 100))
        $rssiText = "~$rssi dBm"
      }

      # Throughput (Mbit/s, decimal: 1 Mbit = 1,000,000 bits)
      $rxRate = $null; $txRate = $null
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

      # Nearby networks: ask Windows for a fresh scan, then read the list a few seconds later
      $t = $sw.Elapsed.TotalSeconds

      if ($ScanInterval -gt 0 -and $Script:WlanScanAvailable -and $info.Guid -and -not $Script:LocationBlocked -and
          ($null -eq $lastScanReqSec -or ($t - $lastScanReqSec) -ge $ScanInterval)) {
        try {
          $rc = [WlanScanner]::Scan([Guid]$info.Guid)
          if ($rc -eq 0) { $scanStatus = '' } else { $scanStatus = "scan request failed (error $rc), showing cached list" }
        } catch { $scanStatus = 'scan request failed, showing cached list' }
        $lastScanReqSec = $t
        $pendingRead    = $true
      }

      $needRead = ($null -eq $lastReadSec) -or
                  ($pendingRead -and ($t - $lastScanReqSec) -ge $scanWaitSec) -or
                  (-not $pendingRead -and $ScanInterval -eq 0 -and ($t - $lastReadSec) -ge 5)

      if ($needRead -and -not $Script:LocationBlocked) {
        try { $nets = @(Get-NearbyNetworks) } catch { $nets = @() }
        $lastReadSec = $sw.Elapsed.TotalSeconds
        $pendingRead = $false
      }

      # ---- All data collected; now draw the whole screen in one go ----
      $barWidth = [Math]::Max(10, [Math]::Min(30, $width - 34))
      $sigBar   = New-SignalBar -Percent $sigPct -Width $barWidth
      $sigText  = "{0,3}%" -f $sigPct
      $sigLine  = if ($null -eq $info.SignalPct -and $null -eq $info.Rssi) { '-' }
                  else { Format-SignalColor -Percent $sigPct -Text "$sigText  $sigBar  ($rssiText)" }

      $line = "".PadRight([Math]::Min(80, $width), '-')

      Clear-Host

      # ===== HEADER: scales to the console width =====
      $timePart     = "{0:yyyy-MM-dd HH:mm:ss}" -f $now
      $adapterName  = ($info.Name        ?? '(unknown)')
      $adapterDesc  = ($info.Description ?? '')

      $headerPrefix = "Wi-Fi Monitor v$WifiMonitorVersion |  $timePart  |  Adapter: "
      if ($headerPrefix.Length + 8 -gt $width) {
        # Narrow window: use a compact prefix
        $headerPrefix = "v$WifiMonitorVersion | $timePart | "
      }
      $avail = [Math]::Max(0, $width - $headerPrefix.Length)

      $nameShown = Limit-Text $adapterName $avail
      $descShown = ''
      $descAvail = $avail - $nameShown.Length - 3        # " (" + ")"
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

      $headerLen = $headerPrefix.Length + $nameShown.Length + $(if ($descShown) { $descShown.Length + 3 } else { 0 })
      Write-Host ("".PadRight([Math]::Min($headerLen, $width), '=')) -ForegroundColor DarkGray
      "" | Out-Host

      if ($Script:LocationBlocked) {
        Write-Host (Limit-Text "!! LOCATION SERVICES ARE NOT ENABLED - fix your shit! !!" $width) -ForegroundColor Red
        Write-Host (Limit-Text "  netsh can't return SSID, BSSID, signal or nearby networks without it." $width) -ForegroundColor Yellow
        Write-Host (Limit-Text "  Enable: Settings > Privacy & security > Location  (ms-settings:privacy-location)" $width) -ForegroundColor Yellow
        "" | Out-Host
      }

      # Connection section
      Write-Host "[ Connection ]" -ForegroundColor Cyan
      Write-Host $line

      Write-Host ("{0,-12}: " -f 'State') -NoNewline
      Write-Host ($info.State       ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'SSID') -NoNewline
      Write-Host ($info.SSID        ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'BSSID') -NoNewline
      Write-Host ($info.BSSID       ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'Channel') -NoNewline
      Write-Host ($info.Channel     ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'Radio') -NoNewline
      Write-Host ($info.RadioType   ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'Auth/Cipher') -NoNewline
      $ac = if ($info.Auth -and $info.Cipher) { "$($info.Auth) / $($info.Cipher)" } else { '-' }
      Write-Host $ac -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'IPv4') -NoNewline
      Write-Host ($info.IPv4        ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'Gateway') -NoNewline
      Write-Host ($info.Gateway     ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'Profile') -NoNewline
      Write-Host ($info.Profile     ?? '-') -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'MAC') -NoNewline
      Write-Host ($info.PhysicalAddress ?? '-') -ForegroundColor White

      "" | Out-Host

      # Link / Traffic section
      Write-Host "[ Link / Traffic ]" -ForegroundColor Cyan
      Write-Host $line

      $rxText = if ($null -ne $info.ReceiveRateMbps)  { '{0:0.0}' -f $info.ReceiveRateMbps } else { '-' }
      $txText = if ($null -ne $info.TransmitRateMbps) { '{0:0.0}' -f $info.TransmitRateMbps } else { '-' }

      Write-Host ("{0,-12}: " -f 'Link rate') -NoNewline
      Write-Host ("{0} Mbps (rx) | {1} Mbps (tx)" -f $rxText, $txText) -ForegroundColor White

      Write-Host ("{0,-12}: " -f 'Signal') -NoNewline
      Write-Host $sigLine

      Write-Host ("{0,-12}: " -f 'Throughput') -NoNewline
      if ($null -ne $rxRate -and $null -ne $txRate) {
        Write-Host ("{0:N2} Mbit/s (down) | {1:N2} Mbit/s (up)" -f $rxRate, $txRate) -ForegroundColor White
      } else {
        Write-Host "(warming up … or unavailable)" -ForegroundColor Yellow
      }

      Write-Host ("{0,-12}: " -f 'Data total') -NoNewline
      Write-Host ("{0} / {1}" -f (Format-Bytes $info.RxBytes), (Format-Bytes $info.TxBytes)) -ForegroundColor White

      "" | Out-Host

      # Nearby SSIDs (merged 2.4 / 5 / 6 GHz)
      Write-Host "[ Nearby SSIDs ]" -ForegroundColor Cyan -NoNewline
      if ($ScanInterval -gt 0 -and $null -ne $lastReadSec -and -not $Script:LocationBlocked) {
        $age = [int]($sw.Elapsed.TotalSeconds - $lastReadSec)
        Write-Host (Limit-Text ("  (updated {0}s ago)" -f $age) ($width - 16)) -ForegroundColor DarkGray -NoNewline
      }
      Write-Host ""
      if ($scanStatus) { Write-Host (Limit-Text "  $scanStatus" $width) -ForegroundColor Yellow }
      Write-Host $line

      if ($Script:LocationBlocked) {
        Write-Host "  (unavailable: location services are off)" -ForegroundColor Yellow
      } elseif ($nets.Count -gt 0) {
        foreach ($n in ($nets | Select-Object -First 6)) {
          $sigVal     = if ($null -ne $n.OverallSignal) { $n.OverallSignal } else { 0 }
          $coloredMax = Format-SignalColor -Percent $sigVal -Text ("{0,3}%" -f $sigVal)

          $parts = @()
          if ($n.Ch24) { $parts += ("2.4GHz ch {0}, {1}%" -f $n.Ch24, $n.Sig24) }
          if ($n.Ch5)  { $parts += ("5GHz ch {0}, {1}%"   -f $n.Ch5,  $n.Sig5)  }
          if ($n.Ch6)  { $parts += ("6GHz ch {0}, {1}%"   -f $n.Ch6,  $n.Sig6)  }
          if ($parts.Count -eq 0) { $parts += "band unknown" }

          $bandsText = [string]::Join("; ", $parts)
          $mark      = if ($info.SSID -and $n.SSID -eq $info.SSID) { '*' } else { '-' }

          # Visible suffix "  [100%]" is 8 characters; truncate the left part to fit the console
          $left = Limit-Text ("  {0} {1} ({2})" -f $mark, $n.SSID, $bandsText) ($width - 8)
          Write-Host ("{0}  [{1}]" -f $left, $coloredMax)
        }
      } else {
        Write-Host "  (none reported)" -ForegroundColor Yellow
      }

      "" | Out-Host
      Write-Host ("Press Ctrl-C to exit. Refresh: {0}s" -f $Interval) -ForegroundColor Cyan
    }

    # Sleep (never past the Duration limit)
    $sleepMs = $Interval * 1000
    if ($Duration -gt 0) {
      $remainingMs = ($Duration - $sw.Elapsed.TotalSeconds) * 1000
      $sleepMs = [Math]::Min($sleepMs, [Math]::Max(100, $remainingMs))
    }
    Start-Sleep -Milliseconds ([int]$sleepMs)
  }
  catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Start-Sleep -Seconds $Interval
  }
}
