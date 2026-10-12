# SentinelOps Windows sensor

This read-only PowerShell sensor reports observations from a Windows laptop to the SentinelOps backend. Use it only on a network and devices you own or are explicitly authorized to monitor. It does not capture packet payloads, credentials, or Wi-Fi keys. ARP/neighbour collection is the default; subnet discovery and TCP checks are opt-in, bounded, and rate-limited.

## Enroll without exposing a secret in the website

Enrollment is a one-time API operation from an administrator's protected PowerShell session. The website does not list or fetch sensor secrets. Replace the placeholders with a short-lived access token obtained through the normal SentinelOps login flow:

```powershell
$api = "https://your-backend.example.com"
$token = "<administrator access token>"
$enrollment = Invoke-RestMethod -Method Post -Uri "$api/sensors/enroll" `
  -Headers @{ Authorization = "Bearer $token"; "X-SentinelOps-Enrollment" = "powershell" } `
  -ContentType "application/json" `
  -Body (@{ name = $env:COMPUTERNAME; hostname = $env:COMPUTERNAME; platform = "windows"; sensor_version = "1.0" } | ConvertTo-Json)

$dir = "$env:ProgramData\SentinelOps"
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$protectedSecret = ConvertTo-SecureString $enrollment.credentials.secret -AsPlainText -Force
@{ ApiBaseUrl = $api; SensorId = $enrollment.credentials.sensorId; SensorSecretProtected = (ConvertFrom-SecureString $protectedSecret) } |
  ConvertTo-Json | Set-Content -LiteralPath "$dir\sensor.json" -Encoding utf8
icacls "$dir\sensor.json" /inheritance:r /grant:r "$env:USERNAME:(R,W)" | Out-Null
```

The enrollment response contains the secret once. Store it in the protected file and do not paste it into tickets, browser storage, screenshots, or source control. If it is exposed, revoke the sensor from the API and enroll it again.

## Start, stop, and collect

From the checkout containing this file:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\sensor\sentinelops-sensor.ps1 -ConfigPath "$env:ProgramData\SentinelOps\sensor.json"
```

The process writes its PID to `C:\ProgramData\SentinelOps\sensor.pid`. To run in the background and stop it:

```powershell
Start-Process powershell.exe -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"$PWD\sensor\sentinelops-sensor.ps1",'-ConfigPath',"$env:ProgramData\SentinelOps\sensor.json" -WindowStyle Hidden
$pid = Get-Content "$env:ProgramData\SentinelOps\sensor.pid"
Stop-Process -Id ([int]$pid)
```

For a single report, add `-Once`. The default `-DiscoveryMode arp` reads only the local neighbour table. To explicitly probe an authorized subnet, provide a bounded CIDR; this sends one low-rate ICMP probe per address:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\sensor\sentinelops-sensor.ps1 `
  -ConfigPath "$env:ProgramData\SentinelOps\sensor.json" -DiscoveryMode subnet -SubnetCidr "192.168.1.0/24" -MaxHosts 254
```

Optional TCP availability checks are read-only connection attempts and must be explicitly selected, for example `-ServicePorts 53,80,443`. A successful check means only that a TCP connection was accepted at that time; it does not identify software or prove authorization.

The backend stores collection methods, timestamps, errors, and the distinction between observed values and unavailable values. A sensor is shown as active only after a recent successful heartbeat; it becomes stale after three heartbeat intervals.

For isolated local integration tests only, the backend may be run with `ALLOW_INSECURE_SENSOR_LOCAL=true` and the sensor may use `-AllowInsecureLocal -ApiBaseUrl http://127.0.0.1:...`. Never use that exception for a real laptop or production service.
