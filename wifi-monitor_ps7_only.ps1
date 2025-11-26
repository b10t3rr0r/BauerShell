<#
  Wi-Fi Monitor v1.666
  ------------------------------------
  A lightweight, netsh-based Wi-Fi monitor for PowerShell 7.

  Features
  --------
  - Shows current Wi-Fi connection details (SSID, BSSID, channel, radio type, auth/cipher, IP, gateway, MAC)
  - Displays link rate (rx/tx) and a colored signal-strength bar with dBm estimate / RSSI
  - Tracks per-interval throughput (down/up Mbit/s) and total bytes transferred
  - Lists nearby SSIDs, merging 2.4 GHz and 5 GHz information for each network
  - Requires no external modules or tools – only `netsh` and built-in cmdlets

  Parameters
  ----------
  -Interval <int>
      Refresh interval in seconds.
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

  Notes
  -----
  - On some systems, `netsh wlan show interfaces` / `netsh wlan show networks mode=bssid`
    may require location permission and/or administrator privileges.
  - Nearby SSIDs list is limited to the top 6 networks, sorted by signal strength.
#>

param(
  [int]$Interval = 5,            # refresh interval in seconds
  [string]$Interface,            # optional adapter name, e.g. "WLAN"
  [int]$Duration = 0             # total run time in seconds (0 = infinite)
)

# Version variable – change this in one place, it updates the banner automatically
$Script:WifiMonitorVersion = '1.666'

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8 } catch {}

function Invoke-NetshWlanInterfaces { (netsh wlan show interfaces) -join [Environment]::NewLine }
function Invoke-NetshWlanNetworks   { (netsh wlan show networks mode=bssid) -join [Environment]::NewLine }

# ---- Helpers ---------------------------------------------------------------

function Parse-WlanInterfaces {
  # Parse `netsh wlan show interfaces` into objects.
  $t = Invoke-NetshWlanInterfaces
  if (-not $t) { return @() }

  $blocks = ($t -split "(\r?\n){2,}") | Where-Object { $_ -match ":" }

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

function Signal-Bar {
  param([int]$Percent, [int]$Width = 30)
  $filled = [int][math]::Floor(($Percent * $Width) / 100.0)
  if ($filled -lt 0) { $filled = 0 }
  elseif ($filled -gt $Width) { $filled = $Width }
  $empty  = $Width - $filled
  ('█' * $filled) + ('░' * $empty)
}

function Colorize {
  param([int]$Percent, [string]$Text)
  if ($PSStyle) {
    if ($Percent -ge 67) { return "$($PSStyle.Foreground.Green)$Text$($PSStyle.Reset)" }
    elseif ($Percent -ge 34) { return "$($PSStyle.Foreground.Yellow)$Text$($PSStyle.Reset)" }
    else { return "$($PSStyle.Foreground.Red)$Text$($PSStyle.Reset)" }
  } else { return $Text }
}

function Get-WifiInterfaceInfo {
  param([string]$PreferredAlias)

  $ifaces = Parse-WlanInterfaces
  if (-not $ifaces) { return $null }

  $chosen = $null
  if ($PreferredAlias) {
    $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredAlias -and $_.State -match '(?i)connected' } | Select-Object -First 1
    if (-not $chosen) { $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredAlias } | Select-Object -First 1 }
  } else {
    $chosen = $ifaces | Where-Object { $_.State -match '(?i)connected' } | Select-Object -First 1
    if (-not $chosen) { $chosen = $ifaces | Select-Object -First 1 }
  }

  try {
    if ($chosen.Name) {
      $ip = Get-NetIPConfiguration -InterfaceAlias $chosen.Name -ErrorAction Stop
      $chosen | Add-Member -NotePropertyName IPv4 -NotePropertyValue ($ip.IPv4Address.IPAddress | Select-Object -First 1)
      $chosen | Add-Member -NotePropertyName Gateway -NotePropertyValue ($ip.IPv4DefaultGateway.NextHop | Select-Object -First 1)
      $stats = Get-NetAdapterStatistics -Name $chosen.Name -ErrorAction Stop
      $chosen | Add-Member -NotePropertyName RxBytes -NotePropertyValue ($stats.ReceivedBytes)
      $chosen | Add-Member -NotePropertyName TxBytes -NotePropertyValue ($stats.SentBytes)
    } else {
      $chosen | Add-Member IPv4 $null
      $chosen | Add-Member Gateway $null
      $chosen | Add-Member RxBytes $null
      $chosen | Add-Member TxBytes $null
    }
  } catch {
    if (-not ($chosen.PSObject.Properties.Name -contains 'RxBytes')) {
      $chosen | Add-Member RxBytes $null
      $chosen | Add-Member TxBytes $null
    }
  }

  return $chosen
}

function Get-NearbyNetworks {
  # Per-BSSID parsing from `netsh wlan show networks mode=bssid`,
  # then aggregate per SSID with separate 2.4GHz and 5GHz info.
  $t = Invoke-NetshWlanNetworks
  if (-not $t) { return @() }

  $lines = $t -split "`n"
  $entries = @()

  $currentSsid   = $null
  $pendingSignal = $null
  $pendingBand   = $null   # "2.4" or "5"

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

    # Band line (e.g. "Band : 2.4 GHz" or "Band : 5 GHz")
    $mBand = [regex]::Match($ln, "^\s*Band\s*:\s*(.+?)\s*$")
    if ($mBand.Success) {
      $bandStr = $mBand.Groups[1].Value.Trim()
      if     ($bandStr -like "2.4*") { $pendingBand = "2.4" }
      elseif ($bandStr -like "5*")   { $pendingBand = "5"   }
      else                           { $pendingBand = $null }
      continue
    }

    # Channel line (belongs to the last pendingSignal/Band)
    $mChan = [regex]::Match($ln, "^\s*Channel\s*:\s*(\d+)")
    if ($mChan.Success) {
      $chan = [int]$mChan.Groups[1].Value
      if ($currentSsid -and $pendingSignal -ne $null) {
        $entries += [pscustomobject]@{
          SSID    = $currentSsid
          Signal  = $pendingSignal
          Channel = $chan
          BandGHz = $pendingBand   # "2.4" or "5" or $null
        }
        $pendingSignal = $null
        $pendingBand   = $null
      }
      continue
    }
  }

  if ($entries.Count -eq 0) { return @() }

  # Aggregate per SSID: best 2.4GHz, best 5GHz, overall best (for color)
  $agg = @()
  $groups = $entries | Group-Object SSID
  foreach ($g in $groups) {
    $ssid = $g.Name
    $rows = $g.Group

    $best24 = $rows | Where-Object { $_.BandGHz -eq '2.4' } | Sort-Object Signal -Descending | Select-Object -First 1
    $best5  = $rows | Where-Object { $_.BandGHz -eq '5'   } | Sort-Object Signal -Descending | Select-Object -First 1
    $overall= $rows | Sort-Object Signal -Descending | Select-Object -First 1

    $agg += [pscustomobject]@{
      SSID          = $ssid
      OverallSignal = $overall.Signal
      Ch24          = if ($best24) { $best24.Channel } else { $null }
      Sig24         = if ($best24) { $best24.Signal  } else { $null }
      Ch5           = if ($best5)  { $best5.Channel  } else { $null }
      Sig5          = if ($best5)  { $best5.Signal   } else { $null }
    }
  }

  # Sort by overall signal desc, then SSID
  $agg |
    Where-Object { $_.SSID -and -not $_.SSID.StartsWith('Hidden') } |
    Sort-Object -Property @{Expression='OverallSignal';Descending=$true},SSID
}

# ---- Main loop -------------------------------------------------------------

$lastRx = $null
$lastTx = $null
$lastTS = Get-Date
$scriptStartTime = Get-Date

Write-Host "Starting Wi-Fi monitor v$WifiMonitorVersion. Press Ctrl-C to stop.`n"

while ($true) {
  try {
    $info = Get-WifiInterfaceInfo -PreferredAlias $Interface
    Clear-Host
    $now = Get-Date

    if (-not $info) {
      Write-Host "No WLAN info found. Are you on Wi-Fi, and is the adapter enabled?" -ForegroundColor Yellow
      Start-Sleep -Seconds $Interval
      continue
    }

    $sigPct = if ($info.SignalPct -ne $null) { [int]$info.SignalPct } else { 0 }

    if ($info.PSObject.Properties.Name -contains 'Rssi' -and $info.Rssi -ne $null) {
      $rssi = $info.Rssi
    } else {
      $rssi = [int]([math]::Round(($sigPct / 2) - 100))
    }

    $dt = ($now - $lastTS).TotalSeconds
    $rxRate = $null; $txRate = $null
    if ($lastRx -ne $null -and $lastTx -ne $null -and $dt -gt 0 -and $info.RxBytes -ne $null -and $info.TxBytes -ne $null) {
      $rxRate = ($info.RxBytes - $lastRx) * 8 / $dt / 1MB
      $txRate = ($info.TxBytes - $lastTx) * 8 / $dt / 1MB
    }
    $lastRx = $info.RxBytes
    $lastTx = $info.TxBytes
    $lastTS = $now

    $sigBar  = Signal-Bar -Percent $sigPct
    $sigText = "{0,3}%" -f $sigPct
    $sigLine = Colorize -Percent $sigPct -Text "$sigText  $sigBar  (~$rssi dBm)"

    $line = "".PadRight(80,'-')

    # ===== HEADER: includes version, adapter name in yellow, description in parentheses =====
    $timePart    = "{0:yyyy-MM-dd HH:mm:ss}" -f $now
    $adapterName = ($info.Name        ?? '(unknown)')
    $adapterDesc = ($info.Description ?? '')

    $headerPrefix = "Wi-Fi Monitor v$WifiMonitorVersion |  $timePart  |  Adapter: "

    if ([string]::IsNullOrWhiteSpace($adapterDesc)) {
      $fullHeader = $headerPrefix + $adapterName
    } else {
      $fullHeader = $headerPrefix + $adapterName + " ($adapterDesc)"
    }

    Write-Host $headerPrefix -ForegroundColor Green -NoNewline
    Write-Host $adapterName -ForegroundColor Yellow -NoNewline
    if (-not [string]::IsNullOrWhiteSpace($adapterDesc)) {
      Write-Host (" ({0})" -f $adapterDesc) -ForegroundColor Yellow
    } else {
      Write-Host ""
    }

    Write-Host ("".PadRight($fullHeader.Length,'=')) -ForegroundColor DarkGray
    "" | Out-Host

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

    $rxText = if ($info.ReceiveRateMbps -ne $null) { '{0:0.0}' -f $info.ReceiveRateMbps } else { '-' }
    $txText = if ($info.TransmitRateMbps -ne $null) { '{0:0.0}' -f $info.TransmitRateMbps } else { '-' }

    Write-Host ("{0,-12}: " -f 'Link rate') -NoNewline
    Write-Host ("{0} Mbps (rx) | {1} Mbps (tx)" -f $rxText, $txText) -ForegroundColor White

    Write-Host ("{0,-12}: " -f 'Signal') -NoNewline
    Write-Host $sigLine

    Write-Host ("{0,-12}: " -f 'Throughput') -NoNewline
    if ($rxRate -ne $null -and $txRate -ne $null) {
      Write-Host ("{0:N2} Mbit/s (down) | {1:N2} Mbit/s (up)" -f $rxRate, $txRate) -ForegroundColor White
    } else {
      Write-Host "(warming up … or unavailable)" -ForegroundColor Yellow
    }

    Write-Host ("{0,-12}: " -f 'Data total') -NoNewline
    Write-Host ("{0} / {1}" -f (Format-Bytes $info.RxBytes), (Format-Bytes $info.TxBytes)) -ForegroundColor White

    "" | Out-Host

    # Nearby SSIDs (merged 2.4GHz / 5GHz)
    Write-Host "[ Nearby SSIDs ]" -ForegroundColor Cyan
    Write-Host $line

    $nets = @()
    try { $nets = Get-NearbyNetworks } catch { $nets = @() }

    if ($nets.Count -gt 0) {
      $i = 0
      foreach ($n in $nets) {
        $sigVal     = if ($n.OverallSignal -ne $null) { $n.OverallSignal } else { 0 }
        $sigText2   = "{0,3}%" -f $sigVal
        $coloredMax = Colorize -Percent $sigVal -Text $sigText2

        $parts = @()
        if ($n.Ch24) {
          $parts += ("2.4GHz ch {0}, {1}%" -f $n.Ch24, $n.Sig24)
        }
        if ($n.Ch5) {
          $parts += ("5GHz ch {0}, {1}%" -f $n.Ch5, $n.Sig5)
        }
        if ($parts.Count -eq 0) {
          $parts += "band unknown"
        }

        $bandsText = [string]::Join("; ", $parts)

        Write-Host ("  - {0} ({1})  [{2}]" -f $n.SSID, $bandsText, $coloredMax)
        $i++
        if ($i -ge 6) { break }
      }
    } else {
      Write-Host "  (none reported)" -ForegroundColor Yellow
    }

    "" | Out-Host
    Write-Host ("Press Ctrl-C to exit. Refresh: {0}s" -f $Interval) -ForegroundColor Cyan

    # Sleep, then check duration if requested
    Start-Sleep -Seconds $Interval

    if ($Duration -gt 0) {
      $elapsed = (Get-Date) - $scriptStartTime
      if ($elapsed.TotalSeconds -ge $Duration) {
        Write-Host "`nDuration limit reached (~$([int]$elapsed.TotalSeconds)s). Exiting..." -ForegroundColor Cyan
        break
      }
    }
  }
  catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Start-Sleep -Seconds $Interval
  }
}
