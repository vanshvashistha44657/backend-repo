param(
  [string]$ConfigPath = "$env:ProgramData\SentinelOps\sensor.json",
  [string]$ApiBaseUrl,
  [string]$SensorId,
  [string]$SensorSecret,
  [ValidateSet("arp", "subnet")][string]$DiscoveryMode = "arp",
  [string]$SubnetCidr,
  [int[]]$ServicePorts = @(),
  [ValidateRange(15, 3600)][int]$IntervalSeconds = 60,
  [ValidateRange(1, 1024)][int]$MaxHosts = 254,
  [string]$PidPath = "$env:ProgramData\SentinelOps\sensor.pid",
  [switch]$Once
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Add-CollectionError([System.Collections.Generic.List[object]]$Errors, [string]$Method, [string]$Message) {
  $Errors.Add(@{ method = $Method; message = $Message.Substring(0, [Math]::Min(256, $Message.Length)) })
}

function Get-Config {
  $file = if (Test-Path -LiteralPath $ConfigPath) { Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json } else { $null }
  $base = if ($ApiBaseUrl) { $ApiBaseUrl } elseif ($file.ApiBaseUrl) { [string]$file.ApiBaseUrl } else { "" }
  $id = if ($SensorId) { $SensorId } elseif ($file.SensorId) { [string]$file.SensorId } else { "" }
  $secret = if ($SensorSecret) { $SensorSecret } elseif ($file.SensorSecretProtected) {
    ([System.Management.Automation.PSCredential]::new("sensor", (ConvertTo-SecureString ([string]$file.SensorSecretProtected)))).GetNetworkCredential().Password
  } elseif ($file.SensorSecret) { [string]$file.SensorSecret } else { "" }
  if (!$base -or !$id -or !$secret) { throw "ApiBaseUrl, SensorId and SensorSecret are required. Create the protected config file using sensor/README.md." }
  if ($base -notmatch '^https://') { throw "The sensor requires an HTTPS ApiBaseUrl." }
  return @{ ApiBaseUrl = $base.TrimEnd('/'); SensorId = $id; SensorSecret = $secret }
}

function Get-WifiObservation([System.Collections.Generic.List[object]]$Errors) {
  $value = @{ state = "unavailable"; ssid = $null; bssid = $null; signal_percent = $null; rssi_dbm = $null; link_speed_mbps = $null; collection_method = "netsh wlan show interfaces" }
  try {
    $lines = @(netsh wlan show interfaces 2>$null)
    foreach ($line in $lines) {
      if ($line -match '^\s*SSID\s*:\s*(.*)$' -and $line -notmatch '^\s*BSSID') { $value.ssid = $matches[1].Trim() }
      elseif ($line -match '^\s*BSSID\s*:\s*(.*)$') { $value.bssid = $matches[1].Trim() }
      elseif ($line -match '^\s*State\s*:\s*(.*)$') { $value.state = $matches[1].Trim().ToLowerInvariant() }
      elseif ($line -match '^\s*Signal\s*:\s*(\d+)%') { $value.signal_percent = [int]$matches[1] }
      elseif ($line -match '^\s*Receive rate \(Mbps\)\s*:\s*([\d.]+)') { $value.link_speed_mbps = [double]$matches[1] }
    }
    if ($value.state -eq "unavailable" -and $value.ssid) { $value.state = "connected" }
  } catch { Add-CollectionError $Errors "wifi" $_.Exception.Message }
  return $value
}

function Get-NetworkObservation([System.Collections.Generic.List[object]]$Errors) {
  $wifi = Get-WifiObservation $Errors
  $configs = @()
  try { $configs = @(Get-NetIPConfiguration -ErrorAction Stop) } catch { Add-CollectionError $Errors "Get-NetIPConfiguration" $_.Exception.Message }
  $interfaces = New-Object System.Collections.Generic.List[object]
  $primary = $configs | Where-Object { $_.IPv4DefaultGateway -or $_.NetProfile.Name } | Select-Object -First 1
  if (!$primary) { $primary = $configs | Select-Object -First 1 }
  foreach ($config in $configs) {
    $adapter = $null
    try { $adapter = Get-NetAdapter -Name $config.InterfaceAlias -ErrorAction Stop } catch { Add-CollectionError $Errors "Get-NetAdapter" $_.Exception.Message }
    $ips = @($config.IPv4Address | ForEach-Object { $_.IPAddress })
    if (!$ips) { $ips = @($config.IPv6Address | ForEach-Object { $_.IPAddress }) }
    $interfaces.Add(@{
      name = [string]$config.InterfaceAlias; alias = [string]$config.InterfaceAlias
      state = if ($adapter) { [string]$adapter.Status } else { "unknown" }
      connection_type = if ($adapter) { [string]$adapter.MediaType } else { "unknown" }
      mac = if ($adapter) { [string]$adapter.MacAddress } else { "" }
      local_ips = @($ips); collection_method = "Get-NetIPConfiguration/Get-NetAdapter"
    })
  }
  $local = if ($primary) { @($primary.IPv4Address | Select-Object -First 1) } else { @() }
  $gateway = if ($primary -and $primary.IPv4DefaultGateway) { [string]$primary.IPv4DefaultGateway.NextHop } else { $null }
  $dns = if ($primary -and $primary.DNSServer) { @($primary.DNSServer.ServerAddresses) } else { @() }
  $ip = if ($local) { [string]$local[0].IPAddress } else { $null }
  $prefix = if ($local) { [int]$local[0].PrefixLength } else { $null }
  $subnet = if ($ip -and $null -ne $prefix) { "$ip/$prefix" } else { $null }
  return @{
    connection = @{ state = if ($wifi.state -eq "connected") { "connected" } elseif ($ip) { "connected" } else { "disconnected" }; ssid = $wifi.ssid; bssid = $wifi.bssid; local_ip = $ip; subnet = $subnet; gateway = $gateway; dns = @($dns); signal = @{ percent = $wifi.signal_percent; rssi_dbm = $wifi.rssi_dbm; link_speed_mbps = $wifi.link_speed_mbps } }
    interfaces = @($interfaces); wifi = $wifi; primary_ip = $ip; primary_prefix = $prefix
  }
}

function Get-Ipv4UInt([string]$Ip) {
  $bytes = [Net.IPAddress]::Parse($Ip).GetAddressBytes(); [Array]::Reverse($bytes); return [uint64][BitConverter]::ToUInt32($bytes, 0)
}
function Convert-UIntIpv4([uint64]$Value) {
  $bytes = [BitConverter]::GetBytes([uint32]($Value -band 0xffffffff)); [Array]::Reverse($bytes); return ([Net.IPAddress]::new($bytes)).ToString()
}
function Get-SubnetHosts([string]$Cidr, [int]$Limit) {
  if ($Cidr -notmatch '^((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})$') { throw "SubnetCidr must be IPv4 CIDR notation, for example 192.168.1.0/24." }
  $prefix = [int]$matches[2]; if ($prefix -lt 16 -or $prefix -gt 30) { throw "Subnet discovery allows only IPv4 prefixes /16 through /30." }
  $ipValue = Get-Ipv4UInt $matches[1]; $mask = [uint64]([uint32]::MaxValue -shl (32 - $prefix)); $network = $ipValue -band $mask; $broadcast = $network + ([uint64]1 -shl (32 - $prefix)) - 1
  $count = [Math]::Min([int]($broadcast - $network - 1), $Limit); $hosts = New-Object System.Collections.Generic.List[string]
  for ($i = 1; $i -le $count; $i++) { $hosts.Add((Convert-UIntIpv4 ($network + $i))) }
  return @($hosts)
}

function Get-NeighbourDevices([System.Collections.Generic.List[object]]$Errors, [string]$Mode, [string]$Cidr, [int]$Limit, [int[]]$Ports) {
  $devices = @{}
  try {
    foreach ($neighbor in @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop)) {
      $mac = [string]$neighbor.LinkLayerAddress
      if ($neighbor.IPAddress -and $mac -and $mac -notmatch '^00-00-00-00-00-00$|^FF-FF-FF-FF-FF-FF$') { $devices["$($mac.ToLowerInvariant())|$($neighbor.IPAddress)"] = @{ ip = [string]$neighbor.IPAddress; mac = $mac; state = [string]$neighbor.State; collection_methods = @("Get-NetNeighbor") } }
    }
  } catch { Add-CollectionError $Errors "Get-NetNeighbor" $_.Exception.Message }
  if ($Mode -eq "subnet") {
    if (!$Cidr) { Add-CollectionError $Errors "subnet-discovery" "SubnetCidr is required when DiscoveryMode is subnet." }
    else {
      foreach ($target in @(Get-SubnetHosts $Cidr $Limit)) {
        try {
          $null = ping.exe -n 1 -w 800 $target 2>$null
          if ($LASTEXITCODE -eq 0) {
            $key = "|$target"; if (!$devices.ContainsKey($key)) { $devices[$key] = @{ ip = $target; mac = ""; state = "responded_to_icmp"; collection_methods = @("Test-Connection") } }
          }
        } catch { Add-CollectionError $Errors "Test-Connection" $_.Exception.Message }
        Start-Sleep -Milliseconds 75
      }
    }
  }
  $result = New-Object System.Collections.Generic.List[object]
  foreach ($device in $devices.Values) {
    $hostname = $null
    try { $ptr = Resolve-DnsName -Name $device.ip -Type PTR -ErrorAction SilentlyContinue | Select-Object -First 1; if ($ptr) { $hostname = [string]$ptr.NameHost } } catch { }
    $services = New-Object System.Collections.Generic.List[object]
    foreach ($port in @($Ports | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Select-Object -First 16)) {
      $client = New-Object Net.Sockets.TcpClient; $available = $false
      try { $task = $client.ConnectAsync($device.ip, $port); $available = $task.Wait(400) -and $client.Connected } catch { } finally { $client.Dispose() }
      $services.Add(@{ port = $port; protocol = "tcp"; available = $available; method = "TcpClient.ConnectAsync" }); Start-Sleep -Milliseconds 75
    }
    $result.Add(@{ ip = $device.ip; mac = $device.mac; hostname = $hostname; vendor = $null; state = $device.state; services = @($services); collection_methods = @($device.collection_methods) + $(if ($hostname) { @("Resolve-DnsName PTR") } else { @() }) })
  }
  return @($result)
}

function Send-SensorJson([hashtable]$Config, [string]$Path, [object]$Payload, [hashtable]$Headers) {
  $json = $Payload | ConvertTo-Json -Depth 12 -Compress
  return Invoke-RestMethod -Method Post -Uri "$($Config.ApiBaseUrl)$Path" -Headers $Headers -ContentType "application/json" -Body $json -TimeoutSec 60
}

$config = Get-Config
$directory = Split-Path -Parent $ConfigPath
if (!(Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
Set-Content -LiteralPath $PidPath -Value $PID -Encoding ascii
$headers = @{ "X-Sensor-ID" = $config.SensorId; "X-Sensor-Secret" = $config.SensorSecret; "User-Agent" = "SentinelOps-Windows-Sensor/1.0" }
try {
  do {
    $errors = New-Object System.Collections.Generic.List[object]
    try {
      $network = Get-NetworkObservation $errors
      $devices = Get-NeighbourDevices $errors $DiscoveryMode $SubnetCidr $MaxHosts $ServicePorts
      $observedAt = (Get-Date).ToUniversalTime().ToString("o")
      $heartbeat = @{ observed_at = $observedAt; hostname = $env:COMPUTERNAME; platform = "windows"; sensor_version = "1.0"; heartbeat_interval_seconds = $IntervalSeconds; collection_errors = @($errors) }
      Send-SensorJson $config "/sensor/v1/heartbeat" $heartbeat $headers | Out-Null
      $snapshot = @{ client_observation_id = [guid]::NewGuid().ToString(); observed_at = $observedAt; hostname = $env:COMPUTERNAME; platform = "windows"; sensor_version = "1.0"; connection = $network.connection; interfaces = @($network.interfaces); devices = @($devices); collection_methods = @("Get-NetIPConfiguration", "Get-NetAdapter", "Get-NetNeighbor", "netsh wlan show interfaces"); collection_errors = @($errors) }
      $result = Send-SensorJson $config "/sensor/v1/snapshots" $snapshot $headers
      Write-Host ("{0} snapshot={1} devices={2} errors={3}" -f (Get-Date).ToUniversalTime().ToString("o"), $result.snapshotId, $result.devicesAccepted, $errors.Count)
    } catch { Write-Warning ("Sensor collection/ingestion failed: " + $_.Exception.Message) }
    if (!$Once) { Start-Sleep -Seconds $IntervalSeconds }
  } while (!$Once)
} finally {
  if (Test-Path -LiteralPath $PidPath) { Remove-Item -LiteralPath $PidPath -Force -ErrorAction SilentlyContinue }
}
