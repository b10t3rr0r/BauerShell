#Requires -Version 5.1
<#
  
  Wi-Fi Monitor
  ------------------------------------
  Copyright (c) 2025 Benny Hult
  Licensed under the BSD 3-Clause License. See LICENSE file in the project root for details.
  
  A lightweight, netsh-based Wi-Fi monitor. One script for Windows PowerShell 5.1 and PowerShell 7:
  the edition is detected at start-up and the display is adjusted accordingly (see -BarStyle).
  (Version number: see $Script:WifiMonitorVersion below.)

  Features
  --------
  - Shows current Wi-Fi connection details (SSID, BSSID, channel, radio type, auth/cipher, IP, gateway, MAC)
  - Displays link rate (rx/tx) and a colored signal-strength bar with dBm estimate / RSSI
  - Tracks per-interval throughput (down/up Mbit/s) and total bytes transferred
  - Lists nearby SSIDs, merging 2.4 GHz, 5 GHz and 6 GHz information for each network
  - Shows the channel width (20/40/80/160/320 MHz) the connected AP is operating on
  - Header, separators and lists scale to the current console width
  - Flicker-free: the screen is redrawn in place instead of cleared on every refresh
  - Requires no external modules or tools - only `netsh` and built-in cmdlets

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
      rarely - the same thing as pressing the refresh button in the Wi-Fi flyout.

      Examples:
        .\wifi-monitor.ps1 -ScanInterval 5
            Request a fresh scan every 5 seconds.

  -BarStyle <Auto|Block|Braille|Ascii>
      Style of the signal bar. Auto (default): braille bars in PowerShell 7 and in Windows
      Terminal (also with Windows PowerShell 5.1), plain ASCII bars ([=====   ]) in the old
      console host. Braille draws half-character steps and needs a font with braille glyphs;
      Block draws full block characters; Ascii forces plain ASCII.

  -NearbyCount <int>
      How many networks to list under "Nearby SSIDs" (1-50). Default: 6.
      The connected network is always listed (first), then the strongest others.
      Raise it only if the console window is tall enough for the whole display.

  Notes
  -----
  - The source file is plain ASCII (non-ASCII characters are built from [char] codes), so
    Windows PowerShell 5.1 reads it correctly even though the file has no BOM.
  - Newer Windows versions only let `netsh wlan show interfaces` / `netsh wlan show networks`
    return WLAN details when Windows location services are on. If they are off, the script
    detects it, shows a warning, and falls back to what works without location: adapter name,
    state, MAC, IP/gateway, link speed, traffic counters and the network profile name.
    SSID, BSSID, channel, signal and the nearby-networks list are unavailable in that mode.
  - Parsing relies on English `netsh` output labels. On localized Windows versions
    most fields will come back empty.
  - Nearby SSIDs is a table with one column per band (channel and signal of the strongest BSSID),
    plus the number of BSSIDs seen for the SSID. Sorted by strongest signal; the connected
    network is listed first and the band the adapter is currently on is shaded.
  - Fresh scans are requested with the Windows WlanScan API (wlanapi.dll, via Add-Type).
    A scan takes a few seconds, so the list is read ~4 s after each request. Scanning very
    often can briefly disturb the connected adapter, so don't set -ScanInterval too low.
  - The currently connected SSID is marked with * in the nearby list.
  - Channel width is not reported by netsh. It is decoded from the AP's beacon (HT/VHT/HE/EHT
    operation elements) via the Windows WLAN API, so it is the width the AP operates on;
    a client can end up using less. If it can't be read, only the channel number is shown.
  - In-place redraw needs a console window tall enough for the whole display (~35 rows).
    If it is too short, the script falls back to clearing the screen on every refresh.
#>

param(
  [ValidateRange(1, 3600)]
  [int]$Interval = 5,            # refresh interval in seconds

  [string]$Interface,            # optional adapter name, e.g. "WLAN"

  [ValidateRange(0, [int]::MaxValue)]
  [int]$Duration = 0,            # total run time in seconds (0 = infinite)

  [ValidateRange(0, 3600)]
  [int]$ScanInterval = 10,       # seconds between active Wi-Fi scans (0 = off)

  [ValidateSet('Auto', 'Block', 'Braille', 'Ascii')]
  [string]$BarStyle = 'Auto',

  [ValidateRange(1, 50)]
  [int]$NearbyCount = 6          # number of networks in the nearby list
)

# Version variable - change this in one place, it updates the banner automatically
$Script:WifiMonitorVersion = '1.666'

try { [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8 } catch {}

# Bar style. Auto = braille bars in PowerShell 7 or in Windows Terminal (WT_SESSION is set,
# also with Windows PowerShell 5.1), ASCII bars in the old console host.
$script:ResolvedBarStyle = $BarStyle
if ($BarStyle -eq 'Auto') {
  $script:ResolvedBarStyle = if ($PSVersionTable.PSEdition -eq 'Core' -or $env:WT_SESSION) { 'Braille' } else { 'Ascii' }
}

# Regex options (string -> enum conversion avoided, to be safe on both editions)
$script:RegexOpts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
                    [System.Text.RegularExpressions.RegexOptions]::Multiline

function Nz {
  # Null-coalescing without the PowerShell 7 null-coalescing operator.
  param($Value, $Default = '-')
  if ($null -eq $Value) { return $Default }
  return $Value
}

# ---- Active Wi-Fi scan (same as the refresh button in the Windows Wi-Fi flyout) ----
$Script:WlanScanAvailable = $true
$Script:WlanScanError = ''
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
} catch { $Script:WlanScanAvailable = $false; $Script:WlanScanError = $_.Exception.Message }

# ---- Channel width of the connected AP (from the beacon information elements) ----
# netsh does not report channel width, so it is read from the AP's HT/VHT/HE/EHT operation
# elements via WlanGetNetworkBssList. Kept in its own class so a failure here never affects scanning.
$Script:WlanWidthAvailable = $true
try {
  if (-not ([System.Management.Automation.PSTypeName]'WlanChannelWidth').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class WlanChannelWidth {
  [DllImport("wlanapi.dll")] static extern int WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);
  [DllImport("wlanapi.dll")] static extern int WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);
  [DllImport("wlanapi.dll")] static extern int WlanGetNetworkBssList(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pDot11Ssid, int dot11BssType, [MarshalAs(UnmanagedType.Bool)] bool bSecurityEnabled, IntPtr pReserved, out IntPtr ppWlanBssList);
  [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr pMemory);

  // WLAN_BSS_LIST: DWORD dwTotalSize; DWORD dwNumberOfItems; WLAN_BSS_ENTRY[] (360 bytes each)
  const int EntrySize   = 360;
  const int OffBssid    = 40;    // DOT11_MAC_ADDRESS dot11Bssid
  const int OffIeOffset = 352;   // ULONG ulIeOffset
  const int OffIeSize   = 356;   // ULONG ulIeSize

  static string Label(int mhz) { return mhz == 8080 ? "80+80 MHz" : mhz + " MHz"; }

  // VHT-style channel width field (also used for the VHT info inside the HE operation element)
  static int VhtWidth(int w, int c0, int c1) {
    if (w == 1) {
      if (c1 == 0) return 80;
      return Math.Abs(c1 - c0) == 8 ? 160 : 8080;
    }
    if (w == 2) return 160;
    if (w == 3) return 8080;
    return 0;   // 0 = 20/40 MHz, decided by the HT operation element
  }

  static byte[] ParseMac(string s) {
    if (string.IsNullOrEmpty(s)) return null;
    string[] parts = s.Trim().Split(new char[] { ':', '-' });
    if (parts.Length != 6) return null;
    byte[] r = new byte[6];
    for (int i = 0; i < 6; i++) {
      try { r[i] = Convert.ToByte(parts[i], 16); } catch { return null; }
    }
    return r;
  }

  static string Parse(byte[] b) {
    int ht = 0, vht = 0, he6 = 0, eht = 0;
    int p = 0;
    while (p + 2 <= b.Length) {
      int id = b[p], len = b[p + 1], d = p + 2;
      if (d + len > b.Length) break;

      if (id == 61 && len >= 2) {                      // HT Operation
        int info = b[d + 1];
        ht = ((info & 0x04) != 0 && (info & 0x03) != 0) ? 40 : 20;
      }
      else if (id == 192 && len >= 3) {                // VHT Operation
        vht = VhtWidth(b[d], b[d + 1], b[d + 2]);
      }
      else if (id == 255 && len >= 1) {                // Element ID Extension
        int ext = b[d];
        if (ext == 36 && len >= 7) {                   // HE Operation
          int prm = b[d + 1] | (b[d + 2] << 8) | (b[d + 3] << 16);
          int q = d + 7;
          if ((prm & (1 << 14)) != 0) {                // VHT Operation Information present
            if (vht == 0 && q + 3 <= d + len) vht = VhtWidth(b[q], b[q + 1], b[q + 2]);
            q += 3;
          }
          if ((prm & (1 << 15)) != 0) q += 1;          // Co-Hosted BSS present
          if ((prm & (1 << 17)) != 0 && q + 5 <= d + len) {   // 6 GHz Operation Information present
            int w6 = b[q + 1] & 0x03;
            int c0 = b[q + 2], c1 = b[q + 3];
            if (w6 == 0) he6 = 20;
            else if (w6 == 1) he6 = 40;
            else if (w6 == 2) he6 = 80;
            else he6 = (c1 != 0 && Math.Abs(c1 - c0) > 8) ? 8080 : 160;
          }
        }
        else if (ext == 106 && len >= 7) {             // EHT Operation (Wi-Fi 7)
          if ((b[d + 1] & 0x01) != 0) {                // EHT Operation Information present
            int we = b[d + 6] & 0x07;
            if (we == 0) eht = 20;
            else if (we == 1) eht = 40;
            else if (we == 2) eht = 80;
            else if (we == 3) eht = 160;
            else if (we == 4) eht = 320;
          }
        }
      }
      p = d + len;
    }
    int res = eht != 0 ? eht : (he6 != 0 ? he6 : (vht != 0 ? vht : ht));
    return res == 0 ? null : Label(res);
  }

  // Returns e.g. "80 MHz", or null if it could not be determined.
  public static string Get(Guid ifGuid, string bssid) {
    byte[] want = ParseMac(bssid);
    if (want == null) return null;
    uint ver; IntPtr h;
    if (WlanOpenHandle(2, IntPtr.Zero, out ver, out h) != 0) return null;
    IntPtr list = IntPtr.Zero;
    try {
      if (WlanGetNetworkBssList(h, ref ifGuid, IntPtr.Zero, 3, false, IntPtr.Zero, out list) != 0 || list == IntPtr.Zero) return null;
      int count = Marshal.ReadInt32(list, 4);
      for (int i = 0; i < count; i++) {
        long entry = list.ToInt64() + 8 + (long)i * EntrySize;
        bool match = true;
        for (int k = 0; k < 6; k++) {
          if (Marshal.ReadByte(new IntPtr(entry + OffBssid + k)) != want[k]) { match = false; break; }
        }
        if (!match) continue;
        int ieOff = Marshal.ReadInt32(new IntPtr(entry + OffIeOffset));
        int ieLen = Marshal.ReadInt32(new IntPtr(entry + OffIeSize));
        if (ieLen <= 0 || ieLen > 65535) return null;
        byte[] ies = new byte[ieLen];
        Marshal.Copy(new IntPtr(entry + ieOff), ies, 0, ieLen);
        return Parse(ies);
      }
      return null;
    }
    finally {
      if (list != IntPtr.Zero) WlanFreeMemory(list);
      WlanCloseHandle(h, IntPtr.Zero);
    }
  }
}
'@
  }
} catch { $Script:WlanWidthAvailable = $false }

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
      $m = [regex]::Match($b, $pattern, $script:RegexOpts)
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
    $bandIf      = & $get "^\s*Band\s*:\s*(.+)$"

    # integer or decimal Mbps (e.g. 866 or 866.7)
    $rateMatches = [regex]::Matches($b, "^\s*.*?\(Mbps\)\s*:\s*([0-9]+(?:\.[0-9]+)?)\s*$", $script:RegexOpts)
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
      Band            = $bandIf
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
  # Plain ASCII bar (used for -BarStyle Ascii).
  param([int]$Percent, [int]$Width = 25)
  $filled = [int][math]::Floor(($Percent * $Width) / 100.0)
  if ($filled -lt 0) { $filled = 0 }
  elseif ($filled -gt $Width) { $filled = $Width }
  ('=' * $filled) + (' ' * ($Width - $filled))
}

function Get-SignalColor {
  param([int]$Percent)
  if ($Percent -ge 67) { return 'Green' }
  elseif ($Percent -ge 34) { return 'Yellow' }
  else { return 'Red' }
}

function Write-SignalBar {
  # Writes "<Prefix><bar><Suffix>" and a newline; bar and texts in $Color, empty part dim.
  # Block/braille characters are built from [char] codes (the file is plain ASCII).
  param([int]$Percent, [int]$BarWidth, [string]$Color, [string]$Prefix, [string]$Suffix)

  Write-Host $Prefix -ForegroundColor $Color -NoNewline
  switch ($script:ResolvedBarStyle) {
    'Block' {
      $filled = [int][Math]::Floor(($Percent * $BarWidth) / 100.0)
      $filled = [Math]::Max(0, [Math]::Min($BarWidth, $filled))
      Write-Host (([string][char]0x2588) * $filled) -ForegroundColor $Color -NoNewline
      Write-Host (([string][char]0x2591) * ($BarWidth - $filled)) -ForegroundColor DarkGray -NoNewline
    }
    'Braille' {
      # full cell U+28FF, half cell U+2847 (left column only), empty part = spaces; half-cell resolution
      $units = [int][Math]::Floor(($Percent * $BarWidth * 2) / 100.0)
      $units = [Math]::Max(0, [Math]::Min($BarWidth * 2, $units))
      $full  = [int][Math]::Floor($units / 2)
      $half  = $units % 2
      $empty = $BarWidth - $full - $half
      $filledText = ([string][char]0x28FF) * $full
      if ($half -eq 1) { $filledText += [string][char]0x2847 }
      Write-Host $filledText -ForegroundColor $Color -NoNewline
      Write-Host (' ' * $empty) -NoNewline    # empty part left blank; the padding keeps the suffix in a fixed column
    }
    default {
      Write-Host '[' -ForegroundColor White -NoNewline
      Write-Host (New-SignalBar -Percent $Percent -Width $BarWidth) -ForegroundColor $Color -NoNewline
      Write-Host ']' -ForegroundColor White -NoNewline
    }
  }
  Write-Host $Suffix -ForegroundColor $Color
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
      Bssids        = $rows.Count
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

# ---- Flicker-free redraw ---------------------------------------------------
# Instead of clearing the screen every refresh, the cursor is moved to the top-left and every
# line is overwritten in place. Write-Host is wrapped so that, inside a frame, each line is
# padded with spaces up to the console width (this erases leftovers from the previous frame
# without needing ANSI escape sequences, so it also works in the old Windows PowerShell 5.1
# console host). Lines left over from a taller previous frame are blanked in Stop-Frame.

$Script:InFrame = $false
$Script:LineLen = 0
$Script:LineCount = 0
$Script:PrevLineCount = 0
$Script:PadTo = 79
$Script:FrameW = 0
$Script:FrameH = 0
$Script:FirstFrame = $true
$Script:UseClear = $false    # set if the frame does not fit the window (in-place redraw can't work then)

function Write-Host {
  [CmdletBinding()]
  param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)][object[]]$Object,
    [object]$Separator = ' ',
    [ConsoleColor]$ForegroundColor,
    [ConsoleColor]$BackgroundColor,
    [switch]$NoNewline
  )
  $text = (($Object | ForEach-Object { "$_" }) -join "$Separator")
  if ($Script:InFrame) {
    $Script:LineLen += $text.Length
    if (-not $NoNewline) {
      $pad = $Script:PadTo - $Script:LineLen
      if ($pad -gt 0) { $text += (' ' * $pad) }
      $Script:LineLen = 0
      $Script:LineCount++
    }
  }
  $splat = @{ Object = $text; NoNewline = $NoNewline }
  if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $splat.ForegroundColor = $ForegroundColor }
  if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $splat.BackgroundColor = $BackgroundColor }
  Microsoft.PowerShell.Utility\Write-Host @splat
}

function Start-Frame {
  $w = 80; $h = 30
  try { $ws = $Host.UI.RawUI.WindowSize; $w = $ws.Width; $h = $ws.Height } catch {}

  if ($Script:FirstFrame -or $Script:UseClear -or $w -ne $Script:FrameW -or $h -ne $Script:FrameH) {
    Clear-Host
    $Script:PrevLineCount = 0
  } else {
    try { [Console]::SetCursorPosition(0, 0) } catch { Clear-Host; $Script:PrevLineCount = 0 }
  }

  $Script:FirstFrame = $false
  $Script:FrameW = $w
  $Script:FrameH = $h
  $Script:PadTo = [Math]::Max(1, $w - 1)
  $Script:LineLen = 0
  $Script:LineCount = 0
  $Script:InFrame = $true
}

function Stop-Frame {
  $Script:InFrame = $false
  try {
    $h = $Host.UI.RawUI.WindowSize.Height
    if ($Script:LineCount -ge ($h - 1)) {
      # taller than the window: fall back to clearing the screen on every refresh
      $Script:UseClear = $true
    }
    elseif ($Script:PrevLineCount -gt $Script:LineCount) {
      # previous frame was taller: blank the leftover lines, then park the cursor under the frame
      $blank = ' ' * $Script:PadTo
      for ($i = $Script:LineCount; $i -lt $Script:PrevLineCount; $i++) {
        Microsoft.PowerShell.Utility\Write-Host $blank
      }
      [Console]::SetCursorPosition(0, $Script:LineCount)
    }
  } catch {}
  $Script:PrevLineCount = $Script:LineCount
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

try { [Console]::CursorVisible = $false } catch {}
try {
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
        Start-Frame
        if ($Interface) {
          Write-Host (Limit-Text "Interface '$Interface' not found (or no WLAN info). Check the name with: netsh wlan show interfaces" ($width * 2)) -ForegroundColor Yellow
        } else {
          Write-Host "No WLAN info found. Are you on Wi-Fi, and is the adapter enabled?" -ForegroundColor Yellow
        }
        Stop-Frame
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

        # Channel width of the connected AP (null when unknown / unavailable)
        $chanWidth = $null
        if ($Script:WlanWidthAvailable -and $info.Guid -and $info.BSSID -and -not $Script:LocationBlocked) {
          try { $chanWidth = [WlanChannelWidth]::Get([Guid]$info.Guid, [string]$info.BSSID) } catch { $chanWidth = $null }
        }
        $chanText = Nz $info.Channel '-'
        if ($chanWidth -and $info.Channel) { $chanText = "$($info.Channel) ($chanWidth)" }

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

        # No active scanning possible (disabled, API unavailable, no adapter GUID): just re-read the cached list
        $noScan = ($ScanInterval -eq 0) -or (-not $Script:WlanScanAvailable) -or (-not $info.Guid)
        if ($ScanInterval -gt 0 -and -not $Script:WlanScanAvailable) {
          $scanStatus = Limit-Text ("active scan unavailable ({0}), showing cached list" -f $Script:WlanScanError) 200
        }

        $needRead = ($null -eq $lastReadSec) -or
                    ($pendingRead -and ($t - $lastScanReqSec) -ge $scanWaitSec) -or
                    (-not $pendingRead -and $noScan -and ($t - $lastReadSec) -ge 5)

        if ($needRead -and -not $Script:LocationBlocked) {
          try { $nets = @(Get-NearbyNetworks) } catch { $nets = @() }
          $lastReadSec = $sw.Elapsed.TotalSeconds
          $pendingRead = $false
        }

        # ---- All data collected; now draw the whole screen in one go ----
        # Label (14) + "100%  " (6) + bar (+2 brackets in ASCII style) + "  (-100 dBm)" must fit the console
        $barWidth = [Math]::Max(5, [Math]::Min(30, $width - 38))
        $sigColor = Get-SignalColor -Percent $sigPct

        $line = "".PadRight([Math]::Min(80, $width), '-')

        Start-Frame

        # ===== HEADER: scales to the console width =====
        $timePart     = "{0:yyyy-MM-dd HH:mm:ss}" -f $now
        $adapterName  = (Nz $info.Name '(unknown)')
        $adapterDesc  = (Nz $info.Description '')

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
        Write-Host ''

        if ($Script:LocationBlocked) {
          Write-Host (Limit-Text "!! LOCATION SERVICES ARE NOT ENABLED - fix your shit! !!" $width) -ForegroundColor Red
          Write-Host (Limit-Text "  netsh can't return SSID, BSSID, signal or nearby networks without it." $width) -ForegroundColor Yellow
          Write-Host (Limit-Text "  Enable: Settings > Privacy & security > Location  (ms-settings:privacy-location)" $width) -ForegroundColor Yellow
          Write-Host ''
        }

        # Connection section
        Write-Host "[ Connection ]" -ForegroundColor Cyan
        Write-Host $line

        Write-Host ("{0,-12}: " -f 'State') -NoNewline
        Write-Host (Nz $info.State '-') -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'SSID') -NoNewline
        Write-Host (Nz $info.SSID '-') -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'BSSID') -NoNewline
        Write-Host (Nz $info.BSSID '-') -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'Channel') -NoNewline
        Write-Host $chanText -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'Radio') -NoNewline
        Write-Host (Nz $info.RadioType '-') -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'Auth/Cipher') -NoNewline
        $ac = if ($info.Auth -and $info.Cipher) { "$($info.Auth) / $($info.Cipher)" } else { '-' }
        Write-Host $ac -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'IPv4') -NoNewline
        Write-Host (Nz $info.IPv4 '-') -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'Gateway') -NoNewline
        Write-Host (Nz $info.Gateway '-') -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'Profile') -NoNewline
        Write-Host (Nz $info.Profile '-') -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'MAC') -NoNewline
        Write-Host (Nz $info.PhysicalAddress '-') -ForegroundColor White

        Write-Host ''

        # Link / Traffic section
        Write-Host "[ Link / Traffic ]" -ForegroundColor Cyan
        Write-Host $line

        $rxText = if ($null -ne $info.ReceiveRateMbps)  { '{0:0.0}' -f $info.ReceiveRateMbps } else { '-' }
        $txText = if ($null -ne $info.TransmitRateMbps) { '{0:0.0}' -f $info.TransmitRateMbps } else { '-' }

        Write-Host ("{0,-12}: " -f 'Link rate') -NoNewline
        Write-Host ("{0} Mbps (rx) | {1} Mbps (tx)" -f $rxText, $txText) -ForegroundColor White

        Write-Host ("{0,-12}: " -f 'Signal') -NoNewline
        if ($null -eq $info.SignalPct -and $null -eq $info.Rssi) {
          Write-Host '-'
        } else {
          Write-SignalBar -Percent $sigPct -BarWidth $barWidth -Color $sigColor `
            -Prefix (("{0}%" -f $sigPct).PadRight(6)) -Suffix ("  ({0})" -f $rssiText)
        }

        Write-Host ("{0,-12}: " -f 'Throughput') -NoNewline
        if ($null -ne $rxRate -and $null -ne $txRate) {
          Write-Host ("{0:N2} Mbit/s (down) | {1:N2} Mbit/s (up)" -f $rxRate, $txRate) -ForegroundColor White
        } else {
          Write-Host "(warming up... or unavailable)" -ForegroundColor Yellow
        }

        Write-Host ("{0,-12}: " -f 'Data total') -NoNewline
        Write-Host ("{0} / {1}" -f (Format-Bytes $info.RxBytes), (Format-Bytes $info.TxBytes)) -ForegroundColor White

        Write-Host ''

        # Nearby SSIDs (merged 2.4 / 5 / 6 GHz)
        Write-Host "[ Nearby SSIDs ]" -ForegroundColor Cyan -NoNewline
        $hdrParts = @()
        if ($ScanInterval -gt 0 -and $null -ne $lastReadSec -and -not $Script:LocationBlocked) {
          $hdrParts += ("updated {0}s ago" -f [int]($sw.Elapsed.TotalSeconds - $lastReadSec))
        }
        if (-not $Script:LocationBlocked -and $nets.Count -gt 0) { $hdrParts += "* = connected, shaded = band in use" }
        if ($hdrParts.Count -gt 0) {
          Write-Host (Limit-Text ("  (" + ($hdrParts -join '; ') + ")") ($width - 16)) -ForegroundColor DarkGray -NoNewline
        }
        Write-Host ""
        if ($scanStatus) { Write-Host (Limit-Text "  $scanStatus" $width) -ForegroundColor Yellow }
        Write-Host $line

        if ($Script:LocationBlocked) {
          Write-Host "  (unavailable: location services are off)" -ForegroundColor Yellow
        } elseif ($nets.Count -gt 0) {
          # Connected network first, then the strongest others; the connected one is always included
          $connRows  = @($nets | Where-Object { $info.SSID -and $_.SSID -eq $info.SSID })
          $otherRows = @($nets | Where-Object { -not ($info.SSID -and $_.SSID -eq $info.SSID) })
          $shown     = @($connRows) + @($otherRows | Select-Object -First ([Math]::Max(0, $NearbyCount - $connRows.Count)))

          # Band the adapter is on right now (shaded cell)
          $connBand = $null
          if     ($info.Band -like '2.4*') { $connBand = '2.4' }
          elseif ($info.Band -like '5*')   { $connBand = '5' }
          elseif ($info.Band -like '6*')   { $connBand = '6' }
          elseif ($info.Channel)           { $connBand = if ([int]$info.Channel -le 14) { '2.4' } else { '5' } }

          # Only show band columns that have data
          $cols = @()
          if ($shown | Where-Object { $_.Ch24 }) { $cols += [pscustomobject]@{ Key = '24'; Band = '2.4'; Title = '2.4 GHz' } }
          if ($shown | Where-Object { $_.Ch5  }) { $cols += [pscustomobject]@{ Key = '5';  Band = '5';   Title = '5 GHz'   } }
          if ($shown | Where-Object { $_.Ch6  }) { $cols += [pscustomobject]@{ Key = '6';  Band = '6';   Title = '6 GHz'   } }

          # Column widths: "  * " (4) + SSID + 12 per band ("  " + 10) + "  BSS" (5)
          $maxSsid = 4
          foreach ($n in $shown) { if ($n.SSID.Length -gt $maxSsid) { $maxSsid = $n.SSID.Length } }
          $fixedW = 4 + ($cols.Count * 12) + 5
          $ssidW  = [Math]::Max(6, [Math]::Min($maxSsid, $width - $fixedW))

          Write-Host ('    ' + 'SSID'.PadRight($ssidW)) -ForegroundColor DarkGray -NoNewline
          foreach ($c in $cols) { Write-Host ('  ' + $c.Title.PadRight(10)) -ForegroundColor DarkGray -NoNewline }
          Write-Host '  BSS' -ForegroundColor DarkGray

          foreach ($n in $shown) {
            $isConn  = [bool]($info.SSID -and $n.SSID -eq $info.SSID)
            $mark    = if ($isConn) { '*' } else { '-' }
            $nameClr = if ($isConn) { 'White' } else { 'Gray' }

            Write-Host ("  {0} {1}" -f $mark, (Limit-Text $n.SSID $ssidW).PadRight($ssidW)) -ForegroundColor $nameClr -NoNewline

            foreach ($c in $cols) {
              $ch  = $n.("Ch"  + $c.Key)
              $sig = $n.("Sig" + $c.Key)
              Write-Host '  ' -NoNewline
              if ($ch) {
                $cell = "ch{0,3} {1,3}%" -f $ch, $sig
                $clr  = Get-SignalColor -Percent $sig
                if ($isConn -and $c.Band -eq $connBand) {
                  Write-Host $cell -ForegroundColor $clr -BackgroundColor DarkGray -NoNewline
                } else {
                  Write-Host $cell -ForegroundColor $clr -NoNewline
                }
              } else {
                Write-Host ('-'.PadRight(10)) -ForegroundColor DarkGray -NoNewline
              }
            }

            Write-Host ("  {0,3}" -f $n.Bssids) -ForegroundColor DarkGray
          }
        } else {
          Write-Host "  (none reported)" -ForegroundColor Yellow
        }

        Write-Host ''
        Write-Host ("Press Ctrl-C to exit. Refresh: {0}s" -f $Interval) -ForegroundColor Cyan
        Stop-Frame
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
      $Script:InFrame = $false
      Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
      Start-Sleep -Seconds $Interval
    }
  }
}
finally {
  try { [Console]::CursorVisible = $true } catch {}
}
