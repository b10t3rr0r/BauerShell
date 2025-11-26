<# 
  
  Wi-Fi Monitor v1.666 (FINAL)
  ----------------------------
  Copyright (c) 2025 Benny Hult
  Licensed under the BSD 3-Clause License. See LICENSE file in the project root for details.

  - Continuous Wi-Fi status + throughput + nearby SSIDs
  - PowerShell 5 compatible
  - No external modules (only netsh + built-in cmdlets)

  PARAMETERS
    -Interval <int>
        Refresh interval in seconds.
        Default: 5 seconds.

    -Interface <string>
        Optional adapter name/alias such as "WLAN".
        If omitted, automatically selects the first connected Wi-Fi interface.

    -Duration <int>
        Total runtime in seconds.
        0 = infinite (until Ctrl-C).
        Otherwise exits after ~Duration seconds.

  EXAMPLES
    .\wifi-monitor.ps1
    .\wifi-monitor.ps1 -Interval 2
    .\wifi-monitor.ps1 -Duration 15
    .\wifi-monitor.ps1 -Interval 1 -Duration 10
    .\wifi-monitor.ps1 -Interface "WLAN" -Duration 20
#>

param(
  [int]$Interval,
  [string]$Interface,
  [int]$Duration
)

# Version variable – change this in one place, it updates the banner automatically
$Script:WifiMonitorVersion = '1.666'

# --- Default parameter values (PowerShell 5-safe) ---
if (-not $PSBoundParameters.ContainsKey('Interval') -or $Interval -le 0) {
  $Interval = 5
}
if (-not $PSBoundParameters.ContainsKey('Duration')) {
  $Duration = 0
}

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8 } catch {}

# --- netsh helpers ---
function Invoke-NetshWlanInterfaces { (netsh wlan show interfaces) -join [Environment]::NewLine }
function Invoke-NetshWlanNetworks   { (netsh wlan show networks mode=bssid) -join [Environment]::NewLine }

# --- Regex options for PS5 ---
$script:RegexIgnoreCaseMultiline = `
  [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
  [System.Text.RegularExpressions.RegexOptions]::Multiline


# ====================================================================
#                           PARSING HELPERS
# ====================================================================

function Parse-WlanInterfaces {
  $t = Invoke-NetshWlanInterfaces
  if (-not $t) { return @() }

  $blocks = ($t -split "(\r?\n){2,}") | Where-Object { $_ -match ":" }
  $list = @()

  foreach ($b in $blocks) {

    $get = {
      param($pattern, $block)
      $m = [regex]::Match($block, $pattern, $script:RegexIgnoreCaseMultiline)
      if ($m.Success) { $m.Groups[1].Value.Trim() } else { $null }
    }

    $signal = & $get "^\s*Signal\s*:\s*(\d+)\s*%" $b
    $rssi   = & $get "^\s*Rssi\s*:\s*(-?\d+)"    $b

    # link speed parsing
    $rateMatches = [regex]::Matches($b,
      "^\s*.*?\(Mbps\)\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*$",
      $script:RegexIgnoreCaseMultiline)

    $rxRate = if ($rateMatches.Count -ge 1) { [double]$rateMatches[0].Groups[1].Value } else { $null }
    $txRate = if ($rateMatches.Count -ge 2) { [double]$rateMatches[1].Groups[1].Value } else { $null }

    $list += [pscustomobject]@{
      Name            = & $get "^\s*Name\s*:\s*(.+)$"            $b
      Description     = & $get "^\s*Description\s*:\s*(.+)$"     $b
      State           = & $get "^\s*State\s*:\s*(.+)$"           $b
      SSID            = & $get "^\s*SSID\s*:\s*(.+)$"            $b
      BSSID           = & $get "^\s*(?:AP\s+)?BSSID\s*:\s*(.+)$" $b
      SignalPct       = if ($signal) { [int]$signal } else { $null }
      Channel         = & $get "^\s*Channel\s*:\s*(\d+)"         $b
      RadioType       = & $get "^\s*Radio\s*type\s*:\s*(.+)$"    $b
      Auth            = & $get "^\s*Authentication\s*:\s*(.+)$"  $b
      Cipher          = & $get "^\s*Cipher\s*:\s*(.+)$"          $b
      Profile         = & $get "^\s*Profile\s*:\s*(.+)$"         $b
      PhysicalAddress = & $get "^\s*Physical\s*address\s*:\s*([0-9A-Fa-f:\-]+)" $b
      ReceiveRateMbps = $rxRate
      TransmitRateMbps= $txRate
      Rssi            = if ($rssi) { [int]$rssi } else { $null }
    }
  }

  return $list
}


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


# --- ASCII signal bar ---
function Signal-Bar {
  param([int]$Percent, [int]$Width = 25)

  $filled = [math]::Floor(($Percent * $Width) / 100)
  if ($filled -lt 0) { $filled = 0 }
  if ($filled -gt $Width) { $filled = $Width }
  $empty = $Width - $filled

  "[" + ("=" * $filled) + (" " * $empty) + "]"
}

function Get-SignalColor {
  param([int]$Percent)
  if ($Percent -ge 67) { "Green" }
  elseif ($Percent -ge 34) { "Yellow" }
  else { "Red" }
}


# ====================================================================
#                           GET WIFI INFO
# ====================================================================

function Get-WifiInterfaceInfo {
  param([string]$PreferredAlias)

  $ifaces = Parse-WlanInterfaces
  if (-not $ifaces) { return $null }

  if ($PreferredAlias) {
    $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredAlias -and $_.State -imatch "connected" } | Select-Object -First 1
    if (-not $chosen) {
      $chosen = $ifaces | Where-Object { $_.Name -eq $PreferredAlias } | Select-Object -First 1
    }
  } else {
    $chosen = $ifaces | Where-Object { $_.State -imatch "connected" } | Select-Object -First 1
    if (-not $chosen) { $chosen = $ifaces | Select-Object -First 1 }
  }

  if (-not $chosen) { return $null }

  try {
    $ip = Get-NetIPConfiguration -InterfaceAlias $chosen.Name -ErrorAction Stop

    if ($ip.IPv4Address) {
      $chosen | Add-Member IPv4 ($ip.IPv4Address.IPAddress | Select-Object -First 1)
    } else { $chosen | Add-Member IPv4 $null }

    if ($ip.IPv4DefaultGateway) {
      $chosen | Add-Member Gateway ($ip.IPv4DefaultGateway.NextHop | Select-Object -First 1)
    } else { $chosen | Add-Member Gateway $null }

    $stats = Get-NetAdapterStatistics -Name $chosen.Name -ErrorAction Stop
    $chosen | Add-Member RxBytes $stats.ReceivedBytes
    $chosen | Add-Member TxBytes $stats.SentBytes
  }
  catch {
    $chosen | Add-Member IPv4 $null
    $chosen | Add-Member Gateway $null
    $chosen | Add-Member RxBytes $null
    $chosen | Add-Member TxBytes $null
  }

  return $chosen
}


# ====================================================================
#                           SCAN NEARBY SSIDS
# ====================================================================

function Get-NearbyNetworks {
  $t = Invoke-NetshWlanNetworks
  if (-not $t) { return @() }

  $lines = $t -split "`n"
  $entries = @()

  $currentSsid = $null
  $pendingSignal = $null
  $pendingBand = $null

  foreach ($ln in $lines) {

    $mSsid = [regex]::Match($ln, "^\s*SSID\s+\d+\s*:\s*(.*?)\s*$")
    if ($mSsid.Success) {
      $currentSsid = $mSsid.Groups[1].Value.Trim()
      $pendingSignal = $null
      $pendingBand = $null
      continue
    }

    $mSig = [regex]::Match($ln, "^\s*Signal\s*:\s*(\d+)")
    if ($mSig.Success) {
      $pendingSignal = [int]$mSig.Groups[1].Value
      continue
    }

    $mBand = [regex]::Match($ln, "^\s*Band\s*:\s*(.+?)\s*$")
    if ($mBand.Success) {
      $band = $mBand.Groups[1].Value.Trim()
      if ($band -like "2.4*") { $pendingBand = "2.4" }
      elseif ($band -like "5*") { $pendingBand = "5" }
      else { $pendingBand = $null }
      continue
    }

    $mChan = [regex]::Match($ln, "^\s*Channel\s*:\s*(\d+)")
    if ($mChan.Success) {
      if ($currentSsid -and $pendingSignal -ne $null) {
        $entries += [pscustomobject]@{
          SSID    = $currentSsid
          Signal  = $pendingSignal
          Channel = [int]$mChan.Groups[1].Value
          BandGHz = $pendingBand
        }
      }
      $pendingSignal = $null
      $pendingBand   = $null
      continue
    }
  }

  if ($entries.Count -eq 0) { return @() }

  $groups = $entries | Group-Object SSID
  $agg = @()

  foreach ($g in $groups) {
    $ssid = $g.Name
    $rows = $g.Group

    $best24 = $rows | Where-Object { $_.BandGHz -eq "2.4" } | Sort-Object Signal -Descending | Select-Object -First 1
    $best5  = $rows | Where-Object { $_.BandGHz -eq "5" }   | Sort-Object Signal -Descending | Select-Object -First 1
    $max    = $rows | Sort-Object Signal -Descending | Select-Object -First 1

    $agg += [pscustomobject]@{
      SSID          = $ssid
      OverallSignal = $max.Signal
      Ch24          = if ($best24) { $best24.Channel } else { $null }
      Sig24         = if ($best24) { $best24.Signal }  else { $null }
      Ch5           = if ($best5)  { $best5.Channel }   else { $null }
      Sig5          = if ($best5)  { $best5.Signal }    else { $null }
    }
  }

  $agg |
    Where-Object { $_.SSID -and -not $_.SSID.StartsWith("Hidden") } |
    Sort-Object -Property @{Expression='OverallSignal';Descending=$true},SSID
}


# ====================================================================
#                                MAIN LOOP
# ====================================================================

$lastRx = $null
$lastTx = $null
$lastTS = Get-Date
$startTime = Get-Date

Write-Host ("Starting Wi-Fi monitor v{0}. Press Ctrl-C to stop.`n" -f $Script:WifiMonitorVersion) -ForegroundColor Green

while ($true) {
  try {
    $info = Get-WifiInterfaceInfo -PreferredAlias $Interface
    Clear-Host
    $now = Get-Date

    if (-not $info) {
      Write-Host "No Wi-Fi interface found. Check that the adapter is enabled." -ForegroundColor Yellow
      Start-Sleep -Seconds $Interval
      continue
    }

    # --- signal ---
    $sigPct = if ($info.SignalPct -ne $null) { $info.SignalPct } else { 0 }

    if ($info.PSObject.Properties.Name -contains "Rssi" -and $info.Rssi -ne $null) {
      $rssi = $info.Rssi
    } else {
      # approximate RSSI from percentage
      $rssi = [int](($sigPct / 2) - 100)
    }

    # throughput calc
    $dt = ($now - $lastTS).TotalSeconds
    $rxRate=$null; $txRate=$null

    if ($lastRx -ne $null -and $dt -gt 0 `
        -and $info.RxBytes -ne $null -and $info.TxBytes -ne $null) {

      $rxRate = ($info.RxBytes - $lastRx) * 8 / $dt / 1MB
      $txRate = ($info.TxBytes - $lastTx) * 8 / $dt / 1MB
    }

    $lastRx = $info.RxBytes
    $lastTx = $info.TxBytes
    $lastTS = $now

    # bar
    $sigBar = Signal-Bar -Percent $sigPct
    if ($sigBar.Length -ge 2) {
      $barInner = $sigBar.Substring(1, $sigBar.Length - 2)
    } else {
      $barInner = $sigBar
    }

    $sigColor = Get-SignalColor $sigPct
    $sigText  = "{0,3}%" -f $sigPct

    $line = "".PadRight(80,"-")

    # -------------------- HEADER --------------------
    $timePart = "{0:yyyy-MM-dd HH:mm:ss}" -f $now

    $headerTitle = "Wi-Fi Monitor v{0}" -f $Script:WifiMonitorVersion
    Write-Host ("{0} |  {1}  |  Adapter: " -f $headerTitle, $timePart) -ForegroundColor Green -NoNewline
    Write-Host $info.Name -ForegroundColor Yellow -NoNewline
    if ($info.Description) { Write-Host " ($($info.Description))" -ForegroundColor Yellow } else { Write-Host "" }

    Write-Host ("".PadRight(70,'=')) -ForegroundColor Gray
    "" | Out-Host

    # -------------------- CONNECTION --------------------
    Write-Host "[ Connection ]" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Gray

    Write-Host ("{0,-12}: " -f "State")        -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.State)                   -ForegroundColor White

    Write-Host ("{0,-12}: " -f "SSID")         -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.SSID)                    -ForegroundColor White

    Write-Host ("{0,-12}: " -f "BSSID")        -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.BSSID)                   -ForegroundColor White

    Write-Host ("{0,-12}: " -f "Channel")      -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.Channel)                 -ForegroundColor White

    Write-Host ("{0,-12}: " -f "Radio")        -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.RadioType)               -ForegroundColor White

    Write-Host ("{0,-12}: " -f "Auth/Cipher")  -ForegroundColor DarkGray -NoNewline
    Write-Host ("$($info.Auth) / $($info.Cipher)") -ForegroundColor White

    Write-Host ("{0,-12}: " -f "IPv4")         -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.IPv4)                    -ForegroundColor White

    Write-Host ("{0,-12}: " -f "Gateway")      -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.Gateway)                 -ForegroundColor White

    Write-Host ("{0,-12}: " -f "Profile")      -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.Profile)                 -ForegroundColor White

    Write-Host ("{0,-12}: " -f "MAC")          -ForegroundColor DarkGray -NoNewline
    Write-Host ($info.PhysicalAddress)         -ForegroundColor White

    "" | Out-Host

    # -------------------- LINK / TRAFFIC --------------------
    Write-Host "[ Link / Traffic ]" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Gray

    $rxText = if ($info.ReceiveRateMbps -ne $null) { "{0:0.0}" -f $info.ReceiveRateMbps } else { "-" }
    $txText = if ($info.TransmitRateMbps -ne $null) { "{0:0.0}" -f $info.TransmitRateMbps } else { "-" }

    Write-Host ("{0,-12}: " -f "Link rate") -ForegroundColor DarkGray -NoNewline
    Write-Host ("{0} Mbps (rx) | {1} Mbps (tx)" -f $rxText, $txText) -ForegroundColor White

    # --- signal line: brackets white, inside colored ---
    Write-Host ("{0,-12}: " -f "Signal") -ForegroundColor DarkGray -NoNewline
    Write-Host (" {0} " -f $sigText) -ForegroundColor $sigColor -NoNewline
    Write-Host "[" -ForegroundColor White -NoNewline
    Write-Host $barInner -ForegroundColor $sigColor -NoNewline
    Write-Host "]" -ForegroundColor White -NoNewline
    Write-Host ("  (~{0} dBm)" -f $rssi) -ForegroundColor $sigColor

    Write-Host ("{0,-12}: " -f "Throughput") -ForegroundColor DarkGray -NoNewline
    if ($rxRate -ne $null -and $txRate -ne $null) {
      Write-Host ("{0:N2} Mbit/s (down) | {1:N2} Mbit/s (up)" -f $rxRate, $txRate) -ForegroundColor White
    } else {
      Write-Host "(warming up... or unavailable)" -ForegroundColor Yellow
    }

    Write-Host ("{0,-12}: " -f "Data total") -ForegroundColor DarkGray -NoNewline
    Write-Host ("{0} / {1}" -f (Format-Bytes $info.RxBytes), (Format-Bytes $info.TxBytes)) -ForegroundColor White

    "" | Out-Host

    # -------------------- NEARBY SSIDs --------------------
    Write-Host "[ Nearby SSIDs ]" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Gray

    $nets = Get-NearbyNetworks

    if ($nets.Count -gt 0) {
      $i = 0
      foreach ($n in $nets) {
        $sigVal   = if ($n.OverallSignal -ne $null) { $n.OverallSignal } else { 0 }
        $sigText2 = "{0,3}%" -f $sigVal
        $sigCol2  = Get-SignalColor $sigVal

        $parts = @()
        if ($n.Ch24) { $parts += ("2.4GHz ch {0}, {1}%" -f $n.Ch24, $n.Sig24) }
        if ($n.Ch5)  { $parts += ("5GHz ch {0}, {1}%" -f $n.Ch5,  $n.Sig5)  }
        if ($parts.Count -eq 0) { $parts += "band unknown" }

        $bands = [string]::Join("; ", $parts)

        Write-Host ("  - {0} ({1})  [" -f $n.SSID, $bands) -NoNewline
        Write-Host $sigText2 -ForegroundColor $sigCol2 -NoNewline
        Write-Host "]"
        $i++
        if ($i -ge 6) { break }
      }
    } else {
      Write-Host "  (none reported)" -ForegroundColor Yellow
    }

    "" | Out-Host
    Write-Host ("Press Ctrl-C to exit. Refresh: {0}s" -f $Interval) -ForegroundColor Cyan

    # Duration check
    if ($Duration -gt 0) {
      $elapsed = (Get-Date) - $startTime
      if ($elapsed.TotalSeconds -ge $Duration) {
        Write-Host ("`nDuration reached (~{0}s). Exiting..." -f [int]$elapsed.TotalSeconds) -ForegroundColor Cyan
        break
      }
    }

    Start-Sleep -Seconds $Interval
  }
  catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Start-Sleep -Seconds $Interval
  }
}
