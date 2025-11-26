<#
    Net-Diag-PingMTU v6.66
    ------------------------------------------------------------
    English output · Clear labels · VPN-aware · Optional logging
    Copyright (c) 2025 Benny Hult
    Licensed under the BSD 3-Clause License. See LICENSE file in
    the project root for details.

    Changes since v6.1d:
      - Added -Log switch:
          * Writes all console output (without colors) to a plain-text log file:
                C:\Temp\Net-Diag-PingMTU_log\
            Filename format:
                Net-Diag-PingMTU_YYYY-MM-DD-HH_mm.txt
      - Updated header to match all parameters and switches.

    Summary of functionality:
      • Network information:
          - Adapter: description, alias, IPv4, gateway, DNS, DNS suffix
          - Interface metric
          - DHCP server, lease start/end, estimated renew/rebind
      • Route information:
          - Active default route (0.0.0.0/0): IfAlias, IfIndex, NextHop, Metric
          - VPN/virtual adapter detection (PANGP, AnyConnect, TAP, /32 no-gateway)
      • Basic connectivity tests:
          - Loopback, local IPv4, default gateway
          - DNS servers #1 and #2
          - External IPs (default: 1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222)
          - DNS names (default: google.com, cloudflare.com)
          - For each target: loss %, min/avg/max ms
      • Load series tests (non-DF):
          - LAN: gateway
          - WAN: best external IP from basic tests
          - Sizes: 32, 128, 256, 512, 1024, 1300, 1400, 1472,
                   1536, 1800, 2000, 2048 bytes
      • MTU / DF binary search:
          - Finds max ICMP data size that succeeds with DF set
          - Performed for gateway + all external IPs
          - MTU estimate = (ICMP data + 28)
      • Large-packet behavior (DF vs non-DF):
          - Tests descending sizes above the estimated MTU
          - Detects: DF fragmentation needed, DF success, no-reply/blackhole
          - Compares DF and non-DF behavior
          - Ending summary: largest DF success or fallback to “base (no-frag)”
      • Final summary:
          - Path MTU estimate (gateway preferred)
          - Gateway reachability
          - External IP reachability
          - DNS name reachability
          - Clear highlighting of issues

    Parameters:
      -InterfaceAlias <string>
          Optional. Select a specific active IPv4 interface by alias
          (wildcards allowed). Default: use interface from default route,
          fallback to first active IPv4 interface.

      -ListInterfaces
          Switch. Lists all active IPv4 interfaces at startup:
          alias, description, IPv4, gateway, DNS, prefix length, LikelyVPN.

      -ExternalIps <string[]>
          External IPv4 addresses for ping + MTU/DF tests.
          Default: '1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222'

      -ExternalNames <string[]>
          DNS names to resolve and ping.
          Default: 'google.com','cloudflare.com'

      -LoadSizes <int[]>
          ICMP data sizes for non-DF load testing.
          Default: 32,128,256,512,1024,1300,1400,1472,1536,1800,2000,2048

      -PingCount <int>
          Number of echo requests per test. Default: 10.

      -TimeoutMs <int>
          Ping timeout in milliseconds. Default: 2000.

      -MtuHigh <int>
          Upper bound for DF binary search and large-packet tests.
          Default: 4096.

      -VerboseErrors
          Switch. Shows raw ping.exe output for diagnostics.

      -Log
          Switch. Writes timestamped .txt log to:
                C:\Temp\Net-Diag-PingMTU_log\

    Usage examples:
        powershell -ExecutionPolicy Bypass -File .\Net-Diag-PingMTU.ps1
        powershell -ExecutionPolicy Bypass -File .\Net-Diag-PingMTU.ps1 -ListInterfaces
        powershell -ExecutionPolicy Bypass -File .\Net-Diag-PingMTU.ps1 -InterfaceAlias "Ethernet*"
        powershell -ExecutionPolicy Bypass -File .\Net-Diag-PingMTU.ps1 -Log
#>


[CmdletBinding()]
param(
  [string]  $InterfaceAlias,                    # optional: pick a specific interface by alias (wildcards ok)
  [switch]  $ListInterfaces,                    # list all active IPv4 adapters at start
  [string[]]$ExternalIps   = @('1.1.1.1','8.8.8.8','9.9.9.9','208.67.222.222'),
  [string[]]$ExternalNames = @('google.com','cloudflare.com'),
  # Extended to 2048 for load series (non-DF):
  [int[]]   $LoadSizes     = @(32,128,256,512,1024,1300,1400,1472,1536,1800,2000,2048),
  [int]     $PingCount     = 10,
  [int]     $TimeoutMs     = 2000,
  [int]     $MtuHigh       = 4096,
  [switch]  $VerboseErrors,
  [switch]  $Log           # optional: write log file under C:\Temp\Net-Diag-PingMTU_log
)

# ===================== Logging setup =====================
$Global:LogFile = $null

if ($Log) {
    $logRoot = 'C:\Temp\Net-Diag-PingMTU_log'
    try {
        if (-not (Test-Path -LiteralPath $logRoot)) {
            New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
        }
        $now = Get-Date
        $ts  = $now.ToString('yyyy-MM-dd-HH_mm')
        $Global:LogFile = Join-Path $logRoot ("Net-Diag-PingMTU_{0}.txt" -f $ts)
        "Net-Diag-PingMTU v6.2 log started {0}" -f $now.ToString('u') | Out-File -FilePath $Global:LogFile -Encoding UTF8 -Force
    } catch {
        Write-Warning "Could not initialize log file in $logRoot : $($_.Exception.Message)"
        $Global:LogFile = $null
    }
}

function Write-Log {
    param([string]$Text)
    if ($Global:LogFile) {
        $Text | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    }
}

# ===================== Helpers (console + log) =====================
function Write-Section($title){
    $line = "`n=== $title ==="
    Write-Host $line -ForegroundColor Cyan
    Write-Log $line
}
function Write-Info($msg){
    $line = "[i] $msg"
    Write-Host $line -ForegroundColor DarkCyan
    Write-Log $line
}
function Write-Ok($msg){
    $line = "[OK] $msg"
    Write-Host $line -ForegroundColor Green
    Write-Log $line
}
function Write-Warn($msg){
    $line = "[!] $msg"
    Write-Host $line -ForegroundColor Yellow
    Write-Log $line
}
function Write-Err($msg){
    $line = "[x] $msg"
    Write-Host $line -ForegroundColor Red
    Write-Log $line
}

function Get-ActiveIPv4Interfaces {
  Get-NetIPConfiguration | Where-Object { $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up' }
}

function Pick-Interface {
  param([string]$Alias)
  if($Alias){
    $ifs = Get-ActiveIPv4Interfaces | Where-Object { $_.NetAdapter.InterfaceAlias -like $Alias }
    if($ifs){ return $ifs | Select-Object -First 1 }
  }
  $default = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
             Sort-Object RouteMetric | Select-Object -First 1
  if($default){ return Get-NetIPConfiguration -InterfaceIndex $default.ifIndex }
  return Get-ActiveIPv4Interfaces | Select-Object -First 1
}

function Describe-Adapters {
  Get-ActiveIPv4Interfaces | ForEach-Object {
    $idx = $_.InterfaceIndex
    $ip4 = $_.IPv4Address.IPAddress
    $gw4 = $_.IPv4DefaultGateway.NextHop
    $dns = ($_.DnsServer.ServerAddresses -join ', ')
    $desc = $_.NetAdapter.InterfaceDescription
    $alias = $_.NetAdapter.InterfaceAlias
    $maskLen = (Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.IPAddress } | Select-Object -First 1).PrefixLength
    $isVpn = ($desc -match 'VPN|PANGP|AnyConnect|TAP|TUN|WireGuard|Secure|Virtual' -or $maskLen -eq 32 -or -not $gw4)
    [pscustomobject]@{ Alias=$alias; Description=$desc; IPv4=$ip4; Gateway=$gw4; Dns=$dns; PrefixLen=$maskLen; LikelyVPN=$isVpn }
  }
}

function Resolve-RouteInfo {
  param([string]$Target)
  try {
    $r = Get-NetRoute -DestinationPrefix "$Target/32" -ErrorAction SilentlyContinue |
         Sort-Object RouteMetric | Select-Object -First 1
    if(-not $r){
      $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
          Sort-Object RouteMetric | Select-Object -First 1
    }
    if($r){
      $ifN = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue
      return [pscustomobject]@{
        IfAlias     = $(if($ifN){$ifN.Name}else{$r.ifIndex})
        IfIndex     = $r.ifIndex
        NextHop     = $r.NextHop
        RouteMetric = $r.RouteMetric
      }
    }
  } catch {}
  return $null
}

function Ping-Once {
  param(
    [Parameter(Mandatory)] [string]$Target,
    [int]$Count = 1,
    [int]$Timeout = 2000,
    [int]$BufferSize = 32,
    [switch]$SetDF,
    [string]$SourceIP
  )
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = 'ping.exe'
  $args = @($Target,'-n', $Count, '-w', $Timeout)
  if($SetDF){ $args += '-f' }
  if($BufferSize){ $args += ('-l', $BufferSize) }
  # IMPORTANT: don't force -S for loopback — Windows ping ignores/errs -> leads to false failures
  if($SourceIP -and $Target -ne '127.0.0.1'){ $args += ('-S', $SourceIP) }
  $psi.Arguments = ($args -join ' ')
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  # mirror raw ping output to log if verbose errors
  if($VerboseErrors -and $out){
    $out.Split("`n") | ForEach-Object { Write-Log $_.TrimEnd() }
  }

  [pscustomobject]@{ Target=$Target; ExitCode=$p.ExitCode; Output=$out; Error=$err }
}

function Parse-PingStats {
  param([string]$Text)
  $packets = [regex]::Match($Text, 'Packets: Sent = (\d+), Received = (\d+), Lost = (\d+) \((\d+)% loss\)')
  $times   = [regex]::Match($Text, 'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms')
  $sent=$recv=$lost=0; $lossPct=100; $min=$max=$avg=$null
  if($packets.Success){ $sent=[int]$packets.Groups[1].Value; $recv=[int]$packets.Groups[2].Value; $lost=[int]$packets.Groups[3].Value; $lossPct=[int]$packets.Groups[4].Value }
  if($times.Success){ $min=[int]$times.Groups[1].Value; $max=[int]$times.Groups[2].Value; $avg=[int]$times.Groups[3].Value }
  [pscustomobject]@{ Sent=$sent; Received=$recv; Lost=$lost; LossPercent=$lossPct; MinMs=$min; MaxMs=$max; AvgMs=$avg }
}

function Ping-DF {
  param([string]$Target,[int]$Size,[int]$Timeout = 2000,[string]$SourceIP)
  $r = Ping-Once -Target $Target -Count 1 -Timeout $Timeout -BufferSize $Size -SetDF -SourceIP $SourceIP
  $success = ($r.Output -match 'TTL=' -and $r.ExitCode -eq 0)
  $frag = ($r.Output -match 'Packet needs to be fragmented' -or $r.Output -match 'must be fragmented')
  [pscustomobject]@{ Size=$Size; Success=$success; FragmentNeeded=$frag; Raw=$r.Output; Target=$Target }
}

function Find-MaxICMPDataSize {
  param([string]$Target,[int]$Low = 0,[int]$High = 1472,[int]$Timeout = 2000,[string]$SourceIP)
  $maxOk = -1
  while($Low -le $High){
    $mid = [int](($Low + $High) / 2)
    $res = Ping-DF -Target $Target -Size $mid -Timeout $Timeout -SourceIP $SourceIP
    if($res.Success -and -not $res.FragmentNeeded){ $maxOk=$mid; $Low=$mid+1 } else { $High=$mid-1 }
  }
  return $maxOk
}

# ===================== 1) Network info =====================
Write-Section '1) Network information'
if($ListInterfaces){
  Write-Info 'Active IPv4 adapters:'
  $adapterTable = Describe-Adapters | Format-Table -AutoSize | Out-String
  $adapterTable.Split("`n") | ForEach-Object{
    $line = $_.TrimEnd()
    if($line){
      Write-Host $line
      Write-Log  $line
    }
  }
}

$iface = Pick-Interface -Alias $InterfaceAlias
if(-not $iface){ Write-Err 'No active IPv4 interface found.'; return }

$myIp  = $iface.IPv4Address.IPAddress
$gw    = $iface.IPv4DefaultGateway.NextHop
$dns   = $iface.DnsServer.ServerAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }
$alias = $iface.NetAdapter.InterfaceAlias
$metricRow = Get-NetIPInterface -AddressFamily IPv4 -InterfaceAlias $alias -ErrorAction SilentlyContinue | Select-Object -First 1
$metric = if($metricRow){ $metricRow.InterfaceMetric } else { $null }

# CIM DHCP + DNS suffix fallback
$dhcpServer=$null; $leaseObt=$null; $leaseEnd=$null; $renewTime=$null; $rebindTime=$null; $dhcpPresent=$false
try {
  $wmi = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object { $_.IPEnabled -and $_.InterfaceIndex -eq $iface.InterfaceIndex }
  if($wmi){
    $dhcpServer = $wmi.DHCPServer
    $leaseObt   = $wmi.DHCPLeaseObtained
    $leaseEnd   = $wmi.DHCPLeaseExpires
    if(-not $iface.DnsSuffix -and $wmi.DNSDomain){ $iface | Add-Member -NotePropertyName DnsSuffix -NotePropertyValue $wmi.DNSDomain -Force }
    if($leaseObt -and $leaseEnd){
      $dhcpPresent = $true
      $span = ($leaseEnd - $leaseObt)
      $renewTime  = $leaseObt + [timespan]::FromTicks([long]($span.Ticks * 0.5))
      $rebindTime = $leaseObt + [timespan]::FromTicks([long]($span.Ticks * 0.875))
    }
  }
} catch {}

Write-Info ("Adapter:        {0}" -f $iface.NetAdapter.InterfaceDescription)
Write-Info ("Alias:          {0}" -f $alias)
Write-Info ("IPv4 address:   {0}" -f $myIp)
Write-Info ("Default GW:     {0}" -f $gw)
Write-Info ("DNS servers:    {0}" -f ($dns -join ', '))
Write-Info ("DNS suffix:     {0}" -f ($iface.DnsSuffix))
if($metric -ne $null){ Write-Info ("Interface metric: {0}" -f $metric) }
if($dhcpPresent -or $dhcpServer -or $leaseObt -or $leaseEnd){
  if($dhcpServer){ Write-Info ("DHCP server:   {0}" -f $dhcpServer) }
  if($leaseObt){ Write-Info ("Lease start:   {0}" -f $leaseObt) }
  if($leaseEnd){ Write-Info ("Lease end:     {0}" -f $leaseEnd) }
  if($renewTime){ Write-Info ("DHCP renew:    {0} (estimated)" -f $renewTime) }
  if($rebindTime){ Write-Info ("DHCP rebind:   {0} (estimated)" -f $rebindTime) }
}

# Active default path
Write-Section 'Active default path'
$def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric
$active = $def | Select-Object -First 1
if($active){
  $ifN = Get-NetAdapter -InterfaceIndex $active.ifIndex -ErrorAction SilentlyContinue
  $ifAliasText = if ($ifN) { $ifN.Name } else { [string]$active.ifIndex }
  Write-Info ("IfAlias: {0}" -f $ifAliasText)
  Write-Info ("IfIndex: {0}" -f $active.ifIndex)
  Write-Info ("NextHop: {0}" -f $active.NextHop)
  Write-Info ("RouteMetric: {0}" -f $active.RouteMetric)
}

# VPN hint
$vpnAdapters = (Describe-Adapters | Where-Object { $_.Alias -ne $alias -and $_.LikelyVPN })
if($vpnAdapters){
  Write-Warn 'VPN/Virtual adapters detected (traffic to some prefixes may bypass default tests):'
  $vpnTable = $vpnAdapters | Format-Table Alias,Description,IPv4,Gateway,Dns,PrefixLen -AutoSize | Out-String
  $vpnTable.Split("`n") | ForEach-Object{
    $line = $_.TrimEnd()
    if($line){
      Write-Host $line
      Write-Log  $line
    }
  }
}

# ===================== 2) Basic connectivity =====================
Write-Section ("2) Basic connectivity (ping: {0} packets each)" -f $PingCount)
$basicResults = @()
$tests = @(
  @{ Name='Loopback';       Target='127.0.0.1'; Label='Loopback' },
  @{ Name='Local address';  Target=$myIp;       Label=("Local IPv4 ({0})" -f $myIp) },
  @{ Name='Default gateway';Target=$gw;         Label=("Default GW ({0})" -f $gw) },
  @{ Name='DNS server #1';  Target=($dns | Select-Object -First 1); Label=("DNS server #1 ({0})" -f ($dns | Select-Object -First 1)) },
  @{ Name='DNS server #2';  Target=($dns | Select-Object -Skip 1 | Select-Object -First 1); Label=("DNS server #2 ({0})" -f ($dns | Select-Object -Skip 1 | Select-Object -First 1)) }
)
$tests += ($ExternalIps | ForEach-Object { @{ Name='External IP'; Label=("External IP ({0})" -f $_); Target=$_ } })
foreach($hn in $ExternalNames){
  $ipText = 'N/A'
  try {
    $ips = [System.Net.Dns]::GetHostAddresses($hn) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | ForEach-Object { $_.ToString() }
    if($ips){ $ipText = ($ips -join ',') }
  } catch {}
  $tests += @{ Name='DNS name'; Target=$hn; Label=("DNS name ({0}) A {1}" -f $hn,$ipText) }
}

foreach($t in $tests){
  if([string]::IsNullOrWhiteSpace($t.Target)){ continue }
  $labelLine = ("- {0}" -f $t.Label)
  Write-Host $labelLine -ForegroundColor White
  Write-Log  $labelLine
  $srcForThis = if($t.Target -eq '127.0.0.1'){ $null } else { $myIp }  # NO -S for loopback
  $r = Ping-Once -Target $t.Target -Count $PingCount -Timeout $TimeoutMs -BufferSize 32 -SourceIP $srcForThis
  $stats = Parse-PingStats -Text $r.Output
  $ok = ($stats.Received -gt 0)
  if($ok){
    Write-Ok ("Reply | loss {0}% | min/avg/max {1}/{2}/{3} ms" -f $stats.LossPercent,$stats.MinMs,$stats.AvgMs,$stats.MaxMs)
  } else {
    Write-Warn ("No reply | loss {0}%" -f $stats.LossPercent)
  }
  if($VerboseErrors -and $r.Output){
    $r.Output.Split("`n") | ForEach-Object{
      $line = $_.TrimEnd()
      if($line){
        Write-Host $line
        Write-Log  $line
      }
    }
  }
  $basicResults += [pscustomobject]@{ Name=$t.Name; Target=$t.Target; Ok=$ok; Loss=$stats.LossPercent; Min=$stats.MinMs; Avg=$stats.AvgMs; Max=$stats.MaxMs }
}

# Helper: choose best WAN target from Basic connectivity (no random)
function Get-BestWanTarget {
  param([object[]]$Basic)
  $candidates = $Basic | Where-Object { $_.Name -eq 'External IP' -and $_.Ok } |
                Sort-Object Loss, Avg
  if($candidates -and $candidates.Count -gt 0){ return $candidates[0].Target }
  # fallback to first configured external if none succeeded
  return ($ExternalIps | Select-Object -First 1)
}

# ===================== 3) Load series (LAN & WAN, non-DF) =====================
Write-Section ("3) Load series (ICMP data sizes, {0} packets each)" -f $PingCount)

function Run-LoadSeries {
  param([string]$Label,[string]$Target,[int[]]$Sizes,[int]$Count,[int]$Timeout,[string]$SourceIP)
  $hdr = ("-- {0} -> {1}" -f $Label,$Target)
  Write-Host $hdr -ForegroundColor White
  Write-Log  $hdr
  foreach($size in $Sizes){
    $line = ("* Size = {0} bytes -> {1}" -f $size, $Target)
    Write-Host $line -ForegroundColor White
    Write-Log  $line
    $res = Ping-Once -Target $Target -Count $Count -Timeout $Timeout -BufferSize $size -SourceIP $SourceIP
    $stats = Parse-PingStats -Text $res.Output
    if($stats.Received -gt 0){
      Write-Ok ("OK | loss {0}% | min/avg/max {1}/{2}/{3} ms" -f $stats.LossPercent,$stats.MinMs,$stats.AvgMs,$stats.MaxMs)
    } else {
      Write-Warn ("Loss/timeout | loss {0}%" -f $stats.LossPercent)
    }
    if($VerboseErrors -and $res.Output){
      $res.Output.Split("`n") | ForEach-Object{
        $l = $_.TrimEnd()
        if($l){
          Write-Host $l
          Write-Log  $l
        }
      }
    }
  }
}

# LAN = Gateway
if($gw){
  Run-LoadSeries -Label 'LAN (Gateway)' -Target $gw -Sizes $LoadSizes -Count $PingCount -Timeout $TimeoutMs -SourceIP $myIp | Out-Null
} else {
  Write-Warn "LAN (Gateway): not available (no default gateway)."
}

# WAN = best external from Basic connectivity
$wanTarget = Get-BestWanTarget -Basic $basicResults
Run-LoadSeries -Label 'WAN (Best external)' -Target $wanTarget -Sizes $LoadSizes -Count $PingCount -Timeout $TimeoutMs -SourceIP $myIp | Out-Null

# ===================== 4) MTU / DF search =====================
Write-Section ("4) MTU / DF search (max ICMP data {0} bytes)" -f $MtuHigh)
$targets = @()
if($gw){ $targets += [pscustomobject]@{ Name='Gateway'; IP=$gw } }
$targets += ($ExternalIps | ForEach-Object { [pscustomobject]@{ Name=("External {0}" -f $_); IP=$_ } })

$mtuResults = @()
foreach($t in $targets){
  $route = Resolve-RouteInfo -Target $t.IP
  $src = $myIp
  if($route){
    Write-Info ("Target for DF test: {0} ({1}) via IfAlias={2} NextHop={3} Metric={4} [src {5}]" -f $t.Name,$t.IP,$route.IfAlias,$route.NextHop,$route.RouteMetric,$src)
  } else {
    Write-Info ("Target for DF test: {0} ({1}) [src {2}]" -f $t.Name,$t.IP,$src)
  }
  $m = Find-MaxICMPDataSize -Target $t.IP -Low 0 -High $MtuHigh -Timeout $TimeoutMs -SourceIP $src
  if($m -ge 0){
    $mtuEst = $m + 28
    Write-Ok ("{0}: largest non-fragmenting ICMP data = {1} (estimated MTU ~ {2})" -f $t.Name,$m,$mtuEst)
    $mtuResults += [pscustomobject]@{ Name=$t.Name; Target=$t.IP; MaxData=$m; EstimatedMTU=$mtuEst; RouteIfAlias=$route.IfAlias; RouteIfIndex=$route.IfIndex; RouteNextHop=$route.NextHop; RouteMetric=$route.RouteMetric; SourceIP=$src }
  } else {
    Write-Warn ("{0}: could not determine max size (fragmentation/timeouts)" -f $t.Name)
    $mtuResults += [pscustomobject]@{ Name=$t.Name; Target=$t.IP; MaxData=$null; EstimatedMTU=$null; RouteIfAlias=$route.IfAlias; RouteIfIndex=$route.IfIndex; RouteNextHop=$route.NextHop; RouteMetric=$route.RouteMetric; SourceIP=$src }
  }
}

# ===================== 5) Large packet behavior (DF vs non-DF, DESC & summary) =====================
Write-Section '5) Large packet behavior (DF vs non-DF)'
function Test-LargeBehaviorForTarget {
  param([string]$Target,[int]$Base,[int]$High,[int]$Timeout,[string]$SourceIP,[string]$Label)
  $candidates = @()
  if($Base -ge 0){ $candidates += ($Base+1) }
  $candidates += 1600,2000,3000,4000,6000,$High
  $sizes = ($candidates | Where-Object { $_ -is [int] -and $_ -gt 0 -and $_ -le $High } | Sort-Object -Unique -Descending)

  $largestDfSuccess = $null
  foreach($sz in $sizes){
    $df = Ping-Once -Target $Target -Count 1 -Timeout $Timeout -BufferSize $sz -SetDF -SourceIP $SourceIP
    $dfNeedsFrag = ($df.Output -match 'Packet needs to be fragmented' -or $df.Output -match 'must be fragmented')
    $dfSuccess   = ($df.Output -match 'TTL=' -and $df.ExitCode -eq 0)
    if($dfNeedsFrag){
      Write-Warn ("{0} bytes DF: 'needs fragmentation' -> path MTU smaller than {1}" -f $sz, ($sz+28))
      $noDf = Ping-Once -Target $Target -Count 1 -Timeout $Timeout -BufferSize $sz -SourceIP $SourceIP
      $noDfSuccess = ($noDf.Output -match 'TTL=' -and $noDf.ExitCode -eq 0)
      if($noDfSuccess){ Write-Ok ("{0} bytes non-DF: delivered via fragmentation" -f $sz) } else { Write-Err ("{0} bytes non-DF: not delivered (fragments likely blocked)" -f $sz) }
    } elseif($dfSuccess){
      Write-Ok ("{0} bytes DF: delivered without fragmentation -> STOP" -f $sz)
      $largestDfSuccess = $sz
      break
    } else {
      Write-Err ("{0} bytes DF: no reply -> possible PMTUD blackhole / ICMP Type 3 Code 4 filtered" -f $sz)
      $noDf = Ping-Once -Target $Target -Count 1 -Timeout $Timeout -BufferSize $sz -SourceIP $SourceIP
      $noDfSuccess = ($noDf.Output -match 'TTL=' -and $noDf.ExitCode -eq 0)
      if($noDfSuccess){ Write-Ok ("{0} bytes non-DF: delivered via fragmentation" -f $sz) } else { Write-Warn ("{0} bytes non-DF: not delivered" -f $sz) }
    }
  }

  if($largestDfSuccess -ne $null){
    Write-Info ("Largest DF-success size above base: {0} (MTU ~ {1})" -f $largestDfSuccess, ($largestDfSuccess+28))
  } elseif($Base -ge 0){
    Write-Info ("Reached all probe sizes above base without DF success; base (no-frag) = {0}, MTU ~ {1}" -f $Base, ($Base+28))
  } else {
    Write-Info ("No DF-success and no base known.")
  }
}

$behaviorTargets = @()
if($gw){ $behaviorTargets += [pscustomobject]@{ Name='Gateway'; IP=$gw } }
# Use the same selected best WAN target for consistency
$bestWanForBehavior = $wanTarget
if($bestWanForBehavior){ $behaviorTargets += [pscustomobject]@{ Name='External'; IP=$bestWanForBehavior } }

foreach($bt in $behaviorTargets){
  $base=-1
  if($mtuResults){
    $row = $mtuResults | Where-Object { $_.Target -eq $bt.IP } | Select-Object -First 1
    if($row -and $row.MaxData -ne $null){ $base=[int]$row.MaxData }
  }
  Write-Info ("Target: {0} ({1}) [src {2}]" -f $bt.Name,$bt.IP,$myIp)
  Test-LargeBehaviorForTarget -Target $bt.IP -Base $base -High $MtuHigh -Timeout $TimeoutMs -SourceIP $myIp -Label $bt.Name
}

# ===================== 6) MTU/DF summary by target =====================
Write-Section '6) MTU/DF summary by target'
$summary = @()
foreach($row in $mtuResults){
  $summary += [pscustomobject]@{
    Target        = $row.Target
    BasicOK       = $true
    MaxDFPayload  = $row.MaxData
    InferredMTU   = $row.EstimatedMTU
    RouteIfAlias  = $row.RouteIfAlias
    RouteNextHop  = $row.RouteNextHop
    RouteMetric   = $row.RouteMetric
    SourceIP      = $row.SourceIP
  }
}
$sumTable = $summary | Sort-Object Target | Format-Table -AutoSize | Out-String
$sumTable.Split("`n") | ForEach-Object{
  $line = $_.TrimEnd()
  if($line){
    Write-Host $line
    Write-Log  $line
  }
}

# ===================== 7) Recap =====================
Write-Section '7) Recap'
$dnsOk = ($basicResults | Where-Object { $_.Name -like 'DNS name*' -and $_.Ok }).Count -gt 0
$extOk = ($basicResults | Where-Object { $_.Name -like 'External IP*' -and $_.Ok }).Count -gt 0
$gwOk  = ($basicResults | Where-Object { $_.Name -eq 'Default gateway' }).Ok
$gwOk  = if($gwOk -ne $null){ $gwOk } else { $false }

# overall MTU from gateway (preferred) or first ext
$mtuFinal = $null
if($mtuResults){
  $gwRow = $mtuResults | Where-Object { $_.Name -eq 'Gateway' -and $_.MaxData -ne $null } | Select-Object -First 1
  if($gwRow){ $mtuFinal = $gwRow.MaxData + 28 }
  else {
    $anyRow = $mtuResults | Where-Object { $_.MaxData -ne $null } | Select-Object -First 1
    if($anyRow){ $mtuFinal = $anyRow.MaxData + 28 }
  }
}

Write-Info ("Adapter:        {0}" -f $iface.NetAdapter.InterfaceDescription)
Write-Info ("IP/GW/DNS:     {0} / {1} / {2}" -f $myIp,$gw, ($dns -join ', '))
if($iface.DnsSuffix){ Write-Info ("DNS suffix:    {0}" -f $iface.DnsSuffix) }
if($metric -ne $null){ Write-Info ("Interface metric: {0}" -f $metric) }
if($dhcpPresent -or $dhcpServer -or $leaseObt -or $leaseEnd){
  $dhcpLine = "DHCP:"; if($dhcpServer){ $dhcpLine += (" server {0}" -f $dhcpServer) }
  if($leaseObt -and $leaseEnd){ $dhcpLine += (", lease {0} -> {1}" -f $leaseObt,$leaseEnd) }
  Write-Info $dhcpLine
  if($renewTime){ Write-Info ("DHCP renew:  {0} (estimated)" -f $renewTime) }
  if($rebindTime){ Write-Info ("DHCP rebind: {0} (estimated)" -f $rebindTime) }
}
if($vpnAdapters){ Write-Warn 'Note: VPN/virtual adapters present; some destinations may route via VPN-specific policies.' }
if($mtuFinal){ Write-Info ("Path MTU:      {0} (ICMP data {1} without fragmentation)" -f $mtuFinal,($mtuFinal-28)) }

$gwText  = if($gwOk){'OK'} else {'FAIL'}
$extText = if($extOk){'OK'} else {'FAIL'}
$dnsText = if($dnsOk){'OK'} else {'FAIL'}
Write-Info ("Gateway reach: {0}" -f $gwText)
Write-Info ("Internet IPs:  {0}" -f $extText)
Write-Info ("DNS names:     {0}" -f $dnsText)

$issues = @()
if(-not $gwOk){ $issues += 'Gateway not reachable' }
if(-not $extOk){ $issues += 'External IP(s) not reachable' }
if(-not $dnsOk){ $issues += 'DNS resolution or reachability problem' }
if(-not $mtuFinal -or $mtuFinal -lt 1500){ $issues += 'Non-standard path MTU' }

if($issues.Count -eq 0){ Write-Ok 'Overall: OK. Connectivity normal; MTU OK; DNS OK.' }
else { Write-Warn ("Overall: WARN " + ($issues -join '; ')) }

if ($Log -and $Global:LogFile) {
    Write-Info ("Log file written to: {0}" -f $Global:LogFile)
}
