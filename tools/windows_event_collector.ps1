<#
.SYNOPSIS
Sends new Sysmon and Windows Security events to Mini-SIEM.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\windows_event_collector.ps1 -ServerUrl http://192.168.1.10:5000 -Secret "replace-me"

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\windows_event_collector.ps1 -ServerUrl http://localhost:5000 -Secret "replace-me" -Once

.NOTES
Run from an elevated shell when the current account cannot read the Security log.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [uri]$ServerUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Secret,

    [ValidateRange(1, 500)]
    [int]$BatchSize = 100,

    [ValidateRange(1, 3600)]
    [int]$PollSeconds = 10,

    [ValidateRange(1, 5)]
    [int]$MaxAttempts = 3,

    [string]$StateDirectory = "$env:ProgramData\Mini-SIEM",

    [switch]$Once
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Channels = [ordered]@{
    "Microsoft-Windows-Sysmon/Operational" = @(1, 3, 7, 10, 11, 13)
    "Security" = @(4624, 4625, 4688, 4698, 4720)
    "Microsoft-Windows-Windows Defender/Operational" = @(5007)
}
$Endpoint = ([uri]::new($ServerUrl, "/api/windows-events")).AbsoluteUri
$StateFile = Join-Path $StateDirectory "collector-state.json"
$BufferFile = Join-Path $StateDirectory "collector-buffer.json"
$CollectorIdFile = Join-Path $StateDirectory "collector-id.txt"
$CollectorVersion = "0.9.0"

function Get-StableCollectorId {
    if (Test-Path -LiteralPath $CollectorIdFile) {
        $saved = (Get-Content -Raw -LiteralPath $CollectorIdFile).Trim()
        if ($saved -notmatch '^win-[0-9a-f]{32}$') {
            throw "Collector ID file is invalid: $CollectorIdFile"
        }
        return $saved
    }
    $collectorId = "win-$([guid]::NewGuid().ToString('N'))"
    $temporary = "$CollectorIdFile.tmp"
    Set-Content -LiteralPath $temporary -Value $collectorId -Encoding UTF8
    Move-Item -Force -LiteralPath $temporary -Destination $CollectorIdFile
    return $collectorId
}

function Read-State {
    $state = @{}
    if (Test-Path -LiteralPath $StateFile) {
        $saved = Get-Content -Raw -LiteralPath $StateFile | ConvertFrom-Json
        foreach ($property in $saved.PSObject.Properties) {
            $state[$property.Name] = [long]$property.Value
        }
    }
    return $state
}

function Save-JsonAtomic([string]$Path, $Value) {
    $temporary = "$Path.tmp"
    $Value | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -Force -LiteralPath $temporary -Destination $Path
}

function Get-LatestRecordId([string]$Channel, [bool]$Quiet = $false) {
    try {
        $event = Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction Stop
        return [long]$event.RecordId
    }
    catch {
        if (-not $Quiet) {
            Write-Warning "Cannot read '$Channel'; the collector will retry it later."
        }
        return [long]-1
    }
}

function Initialize-Cursors([hashtable]$State) {
    $created = $false
    foreach ($channel in $Channels.Keys) {
        if (-not $State.ContainsKey($channel)) {
            $State[$channel] = Get-LatestRecordId $channel
            $created = $true
        }
    }
    if ($created) {
        Save-JsonAtomic $StateFile $State
        Write-Host "Initialized at the newest records; historical events were not sent."
    }
    return $created
}

function Refresh-UnavailableCursors([hashtable]$State) {
    $changed = $false
    foreach ($channel in $Channels.Keys) {
        if ([long]$State[$channel] -lt 0) {
            $latest = Get-LatestRecordId $channel $true
            if ($latest -ge 0) {
                $State[$channel] = $latest
                $changed = $true
            }
        }
    }
    if ($changed) {
        Save-JsonAtomic $StateFile $State
    }
}

function Read-Buffer {
    if (-not (Test-Path -LiteralPath $BufferFile)) {
        return @()
    }
    return @(Get-Content -Raw -LiteralPath $BufferFile | ConvertFrom-Json)
}

function Send-Batch([object[]]$Items, [bool]$EndpointAvailable) {
    $hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "windows-host" }
    $payload = @{
        collector_id = $CollectorId
        collector_version = $CollectorVersion
        hostname = $hostname
        source_type = "WINDOWS_EVENT"
        heartbeat = $true
        endpoint_available = $EndpointAvailable
        events = @($Items | ForEach-Object { $_.xml })
    } | ConvertTo-Json -Depth 4 -Compress
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $response = Invoke-RestMethod -Method Post -Uri $Endpoint `
                -Headers @{ "X-Mini-SIEM-Secret" = $Secret } `
                -ContentType "application/json; charset=utf-8" -Body $payload -TimeoutSec 15
            if (-not $response.ok) {
                throw "Mini-SIEM rejected the batch."
            }
            return $true
        }
        catch {
            if ($attempt -lt $MaxAttempts) {
                Start-Sleep -Seconds ([math]::Pow(2, $attempt - 1))
            }
        }
    }
    return $false
}

function Get-NewEvents([hashtable]$State) {
    $items = @()
    foreach ($channel in $Channels.Keys) {
        $lastRecordId = [long]$State[$channel]
        if ($lastRecordId -lt 0) {
            continue
        }
        $eventFilter = ($Channels[$channel] | ForEach-Object { "EventID=$_" }) -join " or "
        $xpath = "*[System[(($eventFilter)) and EventRecordID > $lastRecordId]]"
        try {
            $records = @(Get-WinEvent -LogName $channel -FilterXPath $xpath `
                -Oldest -MaxEvents $BatchSize -ErrorAction Stop)
        }
        catch {
            $records = @()
            $State[$channel] = [long]-1
        }
        foreach ($record in $records) {
            $items += [pscustomobject]@{
                channel = $channel
                record_id = [long]$record.RecordId
                xml = $record.ToXml()
            }
        }
    }
    return $items
}

function Save-Cursors([hashtable]$State, [object[]]$Items) {
    foreach ($item in $Items) {
        if ([long]$item.record_id -gt [long]$State[$item.channel]) {
            $State[$item.channel] = [long]$item.record_id
        }
    }
    Save-JsonAtomic $StateFile $State
}

New-Item -ItemType Directory -Force -Path $StateDirectory | Out-Null
$CollectorId = Get-StableCollectorId
$state = Read-State
$initialized = Initialize-Cursors $state

do {
    $buffered = @(Read-Buffer)
    if ($buffered.Count -gt 0) {
        $endpointAvailable = @($state.Values | Where-Object { [long]$_ -ge 0 }).Count -gt 0
        if (Send-Batch $buffered $endpointAvailable) {
            Remove-Item -Force -LiteralPath $BufferFile
        }
        else {
            Write-Warning "Mini-SIEM unavailable; retained $($buffered.Count) buffered events."
            if (-not $Once) { Start-Sleep -Seconds $PollSeconds }
            continue
        }
    }

    if (-not $initialized) {
        Refresh-UnavailableCursors $state
        $events = @(Get-NewEvents $state)
        $endpointAvailable = @($state.Values | Where-Object { [long]$_ -ge 0 }).Count -gt 0
        if (-not (Send-Batch $events $endpointAvailable)) {
            if ($events.Count -gt 0) {
                Save-JsonAtomic $BufferFile $events
                Write-Warning "Mini-SIEM unavailable; buffered $($events.Count) events locally."
            }
        }
        if ($events.Count -gt 0) {
            Save-Cursors $state $events
        }
    }
    else {
        $endpointAvailable = @($state.Values | Where-Object { [long]$_ -ge 0 }).Count -gt 0
        if (-not (Send-Batch -Items @() -EndpointAvailable $endpointAvailable)) {
            Write-Warning "Mini-SIEM unavailable; heartbeat failed."
        }
    }
    $initialized = $false
    if (-not $Once) { Start-Sleep -Seconds $PollSeconds }
} while (-not $Once)
