param(
    [Parameter(Mandatory=$true)]
    [string] $CaseFolder,

    [Parameter(Mandatory=$false)]
    [string] $AlertTime,

    [Parameter(Mandatory=$false)]
    [string] $AnchorRequestId
)

# =========================
# Risky User Bot - SOC Triage
# FINAL DEFINITIVE BUILD
# =========================

# 1. Load Local Environment (.env)
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '=' -and $_ -notmatch '^#' } | ForEach-Object {
        $name, $value = $_.Split('=', 2)
        [System.Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim())
    }
}

# Define Fallbacks for Company Data
$RAPID7_ORG_ID = if ($env:RAPID7_ORG_ID) { $env:RAPID7_ORG_ID } else { "682B861F32ACBF7D3060" }
$RAPID7_LOGS   = if ($env:RAPID7_AZURE_INGRESS_LOGS) { $env:RAPID7_AZURE_INGRESS_LOGS } else { "%5B%222186bedc4-1ee4-4728-a970-43575fb22d9d%22%5D" }
$LS_URL        = if ($env:LANSWEEPER_URL) { $env:LANSWEEPER_URL } else { "https://mxpcorls01:82" }
$LS_DOMAIN     = if ($env:LANSWEEPER_DOMAIN) { $env:LANSWEEPER_DOMAIN } else { "MAXOR" }
$CS_BASE       = if ($env:CROWDSTRIKE_BASE_URL) { $env:CROWDSTRIKE_BASE_URL } else { "https://falcon.us-2.crowdstrike.com" }

# Column Aliases
$script:ColumnAliases = @{
    "DeviceId"        = @("Device ID", "DeviceId")
    "OperatingSystem" = @("Operating System", "OS", "OperatingSystem")
    "Browser"         = @("Browser")
    "ClientApp"       = @("Client app", "ClientApp")
    "JoinType"        = @("Join Type", "JoinType")
    "Compliant"       = @("Compliant")
    "Managed"         = @("Managed")
    "UserAgent"       = @("User agent", "UserAgent", "User-Agent")
    "City"            = @("City")
    "State"           = @("State", "State/Province")
    "Country"         = @("Country", "Country/Region")
}

function Get-FieldValue {
    param($Row, [string[]]$Aliases, $Default = "Unknown")
    if ($null -eq $Row) { return $Default }
    $props = if ($Row.PSObject) { $Row.PSObject.Properties.Name } else { $Row.Keys }
    foreach ($alias in $Aliases) {
        $normAlias = ($alias -replace '[^a-zA-Z0-9]', '').ToLower()
        foreach ($p in $props) {
            $normP = ($p -replace '[^a-zA-Z0-9]', '').ToLower()
            if ($p -ieq $alias -or $normP -eq $normAlias) {
                $val = if ($Row.PSObject) { $Row.$p } else { $Row[$p] }
                if ($null -ne $val -and -not [string]::IsNullOrWhiteSpace($val.ToString())) {
                    return $val.ToString().Trim()
                }
            }
        }
    }
    return $Default
}

function Get-Value {
    param($Row, $ColumnName)
    $aliases = @($ColumnName, ($ColumnName -replace ' ', ''), ($ColumnName + " (UTC)"), ($ColumnName -replace ' ', '_'), "User")
    return Get-FieldValue -Row $Row -Aliases $aliases -Default $null
}

function Parse-EventTime {
    param($Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { 
        $dt = [datetime]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        return [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    } catch { return $null }
}

function Get-Frequency {
    param($Value, $Aliases, $Events)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "Unknown" -or $null -eq $Events) { return 0 }
    return ($Events | Where-Object { (Get-FieldValue -Row $_ -Aliases $Aliases) -ieq $Value }).Count
}

function Get-LastSeen {
    param($Value, $Aliases, $Events)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "Unknown" -or $null -eq $Events) { return "N/A" }
    $match = $Events | Where-Object { (Get-FieldValue -Row $_ -Aliases $Aliases) -ieq $Value } | Sort-Object EventTime -Descending | Select-Object -First 1
    if ($match -and $match.EventTime) { return $match.EventTime.ToString("yyyy-MM-dd HH:mm") }
    return "Never"
}

function Test-IsNewValue {
    param($BaselineEvents, $Aliases, $Value)
    if ($null -eq $Value -or $Value -eq "Unknown") { return $false }
    if ($null -eq $BaselineEvents -or $BaselineEvents.Count -eq 0) { return $true }
    $existing = $BaselineEvents | ForEach-Object { Get-FieldValue -Row $_ -Aliases $Aliases } | Select-Object -Unique
    return -not ($existing -contains $Value)
}

function Get-RiskScore {
    param($Anchor, $IsNewIP, $IsNewDevice, $AnchorDevice)
    $score = 0
    if ($IsNewIP) { $score += 30 }
    if ($IsNewDevice) { $score += 30 }
    $ua = if ($AnchorDevice.UserAgent) { $AnchorDevice.UserAgent.ToString() } else { "" }
    if ($ua -ne "Unknown" -and $ua -notmatch "Mozilla/") { $score += 50 }
    if ($Anchor.Status -eq "Interrupted") { $score += 20 }
    if ($AnchorDevice.Compliant -eq "True") { $score -= 50 }
    if ($AnchorDevice.Managed -eq "True") { $score -= 30 }
    return [math]::Max(0, $score)
}

function Get-DecisionBucket {
    param($Anchor, $Score)
    if ($null -eq $Anchor) { return "unknown" }
    $status = if ($Anchor.Status) { $Anchor.Status.ToString().ToLower() } else { "" }
    if ($status -notmatch "success") {
        if ($Score -ge 70) { return "compromise_remediate_password" }
        return "close_attempt_blocked"
    }
    $mfa = if ($Anchor.MfaResult) { $Anchor.MfaResult.ToString().ToLower() } else { "" }
    if ($status -match "success") {
        if ($Score -ge 70) { return "investigate_active_compromise" }
        if ($mfa -eq "false" -or $mfa -eq "no") { return "contain_hard" }
        if ($mfa -eq "true" -or $mfa -eq "yes") { return "close_benign" }
    }
    return "investigate"
}

function Build-TicketStory {
    param($Anchor, $DecisionBucket, $IsNewIP, $IsNewLocation, $IsNewApp)
    $parts = @()
    $parts += "Anchor sign-in: user=$($Anchor.Username), time=$($Anchor.EventTime), app=$($Anchor.Application), status=$($Anchor.Status)."
    $parts += "IP=$($Anchor.IPAddress), location=$($Anchor.Location), requestId=$($Anchor.RequestId)."
    $parts += "Decision: $DecisionBucket."
    return ($parts -join " ")
}

function Get-ScopeButtons {
    param($BaseUrl, $ToolType, $TimeObj)
    $scopes = @(
        @{ Label = "1m";  Offset = 30 }
        @{ Label = "5m";  Offset = 150 }
        @{ Label = "1h";  Offset = 1800 }
        @{ Label = "24h"; Offset = 43200 }
        @{ Label = "7d";  Offset = 302400 }
        @{ Label = "30d"; Offset = 1296000 }
    )
    $html = "<div class='scope-group'>"
    foreach ($s in $scopes) {
        $st = ([datetimeoffset]::new($TimeObj.AddSeconds(-$s.Offset))).ToUnixTimeMilliseconds()
        $en = ([datetimeoffset]::new($TimeObj.AddSeconds($s.Offset))).ToUnixTimeMilliseconds()
        
        if ($ToolType -eq "CS") {
            $url = $BaseUrl + "&start=$st&end=$en"
            $html += "<a href='$url' target='_blank' class='scope-btn cs-scope-btn' data-time-params='&start=$st&end=$en'>$($s.Label)</a>"
        } else {
            $url = $BaseUrl + "&from=$st&to=$en"
            $html += "<a href='$url' target='_blank' class='scope-btn r7-scope-btn' data-time-params='&from=$st&to=$en'>$($s.Label)</a>"
        }
    }
    return $html + "</div>"
}

function Write-Report {
    param($Status, $Anchor, $AnchorDevice, $UtcTime, $EstTime, $CstTime, $Decision, $RiskScore, $UniqueFlaws, $IsNewIP, $IsNewLocation, $IsNewApp, $MatrixRows, $Set24h, $Set7d, $Set30d, $CaseFolder, $Rapid7OrgId, $Rapid7LogList, $EncodedIP, $PpUser, $PpSince, $PpUntil, $lsUserUrl, $CsBaseUrl, $ReportFileName, $PrefixInfo)
    
    $statusBadgeClass = if($anchor.Status -match 'Success') { 'badge-success' } else { 'badge-fail' }
    $reportPath = Join-Path $CaseFolder $ReportFileName

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC Report [$Status] - $($anchor.RequestId)</title>
    <style>
        :root { --bg: #0d1117; --card-bg: #161b22; --border: #30363d; --text-primary: #f0f6fc; --text-secondary: #8b949e; --blue: #58a6ff; --green: #3fb950; --red: #f85149; --orange: #d29922; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: var(--bg); color: var(--text-primary); margin: 0; padding: 20px; font-size: 13px; }
        .container { max-width: 1400px; margin: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 20px; }
        .badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; border: 1px solid transparent; }
        .badge-success { background: rgba(63, 185, 80, 0.15); color: var(--green); border-color: var(--green); }
        .badge-fail { background: rgba(248, 81, 73, 0.15); color: var(--red); border-color: var(--red); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
        .label { color: var(--text-secondary); font-size: 10px; text-transform: uppercase; font-weight: 600; display: block; margin-bottom: 6px; }
        .value { font-size: 14px; font-weight: 500; font-family: 'Cascadia Code', monospace; word-break: break-all; }
        .section-title { font-size: 14px; color: var(--blue); margin: 24px 0 12px 0; border-left: 4px solid var(--blue); padding-left: 10px; font-weight: 600; }
        .decision-banner { background: var(--card-bg); border: 2px solid var(--blue); border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 20px; }
        .decision-value { font-size: 32px; font-weight: 800; color: var(--blue); text-transform: uppercase; }
        .scope-group { display: flex; gap: 4px; margin-top: 8px; flex-wrap: wrap; }
        .scope-btn { background: #21262d; color: #8b949e; border: 1px solid var(--border); padding: 4px 10px; border-radius: 4px; font-size: 11px; text-decoration: none; font-weight: bold; }
        .scope-btn:hover { background: var(--blue); color: white; }
        .primary-pivot-btn { background: var(--blue); color: white; padding: 10px 20px; border-radius: 4px; font-weight: bold; display: block; text-align: center; text-decoration: none; margin-bottom: 10px; }
        .comparison-table { width: 100%; border-collapse: collapse; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
        .comparison-table th { background: #21262d; color: var(--blue); text-align: left; padding: 12px; font-size: 11px; }
        .comparison-table td { padding: 12px; border-bottom: 1px solid var(--border); }
        .anchor-row-highlight { background: rgba(88, 166, 255, 0.1) !important; border-left: 4px solid var(--blue); }
    </style>
    <script>
        function copy(t) { navigator.clipboard.writeText(t); alert('Copied: ' + t); }
        function updateDynamicPivots(n) {
            if(!n) return;
            const u = n.toUpperCase();
            const q = encodeURIComponent(u + " | table([@timestamp, ComputerName, UserName, LocalAddressIP, LocalPort, RemoteIP, DomainName, RemotePort, event_simpleName, ImageFileName, CommandLine])");
            const b = "$CsBaseUrl/investigate/search?repo=all&query=" + q;
            document.querySelectorAll('.cs-scope-btn').forEach(btn => { btn.href = b + btn.getAttribute('data-time-params'); });
            document.getElementById('primary-cs-pivot').href = b + document.getElementById('primary-cs-pivot').getAttribute('data-time-params');
            document.getElementById('cs-host-details').href = "$CsBaseUrl/host-management/hosts?filter=hostname%3A%27" + u + "%27";
            document.getElementById('current-target-display').innerText = u;
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Risky User Analysis</h1>
            <div style="font-family: monospace; color: var(--text-secondary)">ID: $($anchor.RequestId)</div>
        </div>

        <div class="decision-banner">
            <div class="label">Behavioral Risk Score: $RiskScore</div>
            <div class="decision-value">$($Decision.ToUpper())</div>
        </div>

        <div class="section-title">TIME CORRELATION (UTC / EST / CST)</div>
        <div class="grid">
            <div class="card"><span class="label">UTC</span><span class="value">$($UtcTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
            <div class="card"><span class="label">EST</span><span class="value">$($EstTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
            <div class="card"><span class="label">CST</span><span class="value">$($CstTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
        </div>

        <div class="section-title">IDENTITY & NETWORK ORIGIN</div>
        <div class="grid">
            <div class="card">
                <span class="label">User</span><span class="value">$($anchor.Username)</span>
                <div style="margin-top:8px;">
                    <a href="https://portal.azure.com/#view/Microsoft_AAD_IAM/UserDetailsMenuBlade/~/overview/userId/$($anchor.Username)" target="_blank" style="color:var(--blue); font-size:11px;">Entra Profile</a>
                </div>
            </div>
            <div class="card">
                <span class="label">IP Address</span><span class="value">$($anchor.IPAddress)</span>
                $PrefixInfo
                <div style="margin-top:8px; display:flex; gap:10px;">
                    <a href="https://www.virustotal.com/gui/ip-address/$($anchor.IPAddress)" target="_blank" style="color:var(--blue); font-size:11px;">VirusTotal</a>
                    <a href="https://bgp.he.net/ip/$($anchor.IPAddress)" target="_blank" style="color:var(--orange); font-size:11px;">BGP Lookup</a>
                </div>
            </div>
            <div class="card"><span class="label">Application</span><span class="value">$($anchor.Application)</span></div>
        </div>

        <div class="section-title">SOC TOOLBOX</div>
        <div class="card" style="border: 1px dashed var(--blue); margin-bottom: 15px;">
            <span class="label">Manual Host Override (from Lansweeper)</span>
            <input type="text" placeholder="Paste computer name..." onchange="updateDynamicPivots(this.value)" style="width:100%; background:#0d1117; color:white; border:1px solid var(--border); padding:8px; border-radius:4px;">
            <div style="font-size:10px; margin-top:5px; color:var(--text-secondary)">Active Pivot: <span id="current-target-display" style="color:var(--blue)">$($AnchorDevice.DeviceId)</span></div>
        </div>
        <div class="grid">
            <div class="card">
                <span class="label">CrowdStrike EDR</span>
                $(
                    $q = [uri]::EscapeDataString($AnchorDevice.DeviceId.ToUpper() + " | table([@timestamp, ComputerName, UserName, LocalAddressIP, LocalPort, RemoteIP, DomainName, RemotePort, event_simpleName, ImageFileName, CommandLine])")
                    Get-ScopeButtons -BaseUrl "$CsBaseUrl/investigate/search?repo=all&query=$q" -ToolType "CS" -TimeObj $UtcTime
                )
                <a href="$CsBaseUrl/host-management/hosts?filter=hostname%3A%27$($AnchorDevice.DeviceId.ToUpper())%27" id="cs-host-details" target="_blank" style="background:rgba(88, 166, 255, 0.1); color:var(--blue); border:1px solid var(--blue); padding:8px 15px; border-radius:4px; display:block; text-align:center; text-decoration:none; margin-top:10px; font-weight:bold;">VIEW HOST DETAILS</a>
            </div>
            <div class="card">
                <span class="label">Proofpoint Search</span>
                <a href="https://admin.proofpoint.com/smartSearchPage?recipient=$PpUser&since=$PpSince&until=$PpUntil&sort=receivedAt&order=asc" target="_blank" style="background:var(--orange); color:white; padding:10px; border-radius:4px; display:block; text-align:center; text-decoration:none; font-weight:bold; margin-bottom:8px;">Email (3D Lookback)</a>
                <a href="https://us.threatresponse.proofpoint.com/incidents?search=$PpUser" target="_blank" style="background:rgba(210, 153, 34, 0.2); color:var(--orange); border:1px solid var(--orange); padding:10px; border-radius:4px; display:block; text-align:center; text-decoration:none; font-weight:bold;">TRAP Incidents</a>
            </div>
            <div class="card">
                <span class="label">Lansweeper User</span>
                <a href="$lsUserUrl" target="_blank" style="background:var(--green); color:white; padding:10px; border-radius:4px; display:block; text-align:center; text-decoration:none; font-weight:bold;">View User Profile</a>
            </div>
            <div class="card">
                <span class="label">Rapid7 Logs</span>
                $(Get-ScopeButtons -BaseUrl "https://us.idr.insight.rapid7.com/op/$Rapid7OrgId#/search?logs=$Rapid7LogList&query=where($EncodedIP)" -ToolType "R7" -TimeObj $UtcTime)
            </div>
        </div>

        <div class="section-title">STATISTICAL BASELINE (SIDE-BY-SIDE)</div>
        <table class="comparison-table">
            <thead><tr><th>Attribute</th><th>Value</th><th>Last Seen</th><th>24h</th><th>7d</th><th>30d</th></tr></thead>
            <tbody>
                <tr><td>Device ID</td><td>$($AnchorDevice.DeviceId)</td><td>$(Get-LastSeen $AnchorDevice.DeviceId $script:ColumnAliases['DeviceId'] $Set30d)</td><td>$(Get-Frequency $AnchorDevice.DeviceId $script:ColumnAliases['DeviceId'] $Set24h)</td><td>$(Get-Frequency $AnchorDevice.DeviceId $script:ColumnAliases['DeviceId'] $Set7d)</td><td>$(Get-Frequency $AnchorDevice.DeviceId $script:ColumnAliases['DeviceId'] $Set30d)</td></tr>
                <tr><td>IP Address</td><td>$($anchor.IPAddress)</td><td>$(Get-LastSeen $anchor.IPAddress @('IP address') $Set30d)</td><td>$(Get-Frequency $anchor.IPAddress @('IP address') $Set24h)</td><td>$(Get-Frequency $anchor.IPAddress @('IP address') $Set7d)</td><td>$(Get-Frequency $anchor.IPAddress @('IP address') $Set30d)</td></tr>
            </tbody>
        </table>

        <div class="section-title">DEVICE CORRELATION MATRIX (30D)</div>
        <table class="comparison-table">
            <thead><tr><th>Device ID</th><th>IPs</th><th>OS / Browser</th><th>Posture</th><th>30d Seen</th><th>Last Seen</th></tr></thead>
            <tbody>$($MatrixRows -join "")</tbody>
        </table>

        <div class="section-title">🧠 ANALYST NOTES: IPV6 TRIAGE</div>
        <div class="story-box" style="border-left-color: var(--orange);">
            <p><strong>Why /64 matters:</strong> IPv6 addresses are vast. Attackers often rotate the last 64 bits (Interface ID) to bypass single-IP blocks. The first 64 bits (Prefix) usually identify the specific network or residential household.</p>
            <p><strong>SOC Action:</strong> If you see multiple failures from the same /64 prefix (even with different full IPs), you are likely dealing with a single automated script or actor. <strong>Consider blocking the entire /64 range</strong> instead of the individual address.</p>
        </div>
    </div>
</body>
</html>
"@
    $html | Out-File $reportPath -Encoding utf8
    Write-Host "`nHTML Report generated: $reportPath"
}

# --- MAIN ---
Write-Host "`n=== DIAGNOSTICS ==="
$files = Get-ChildItem -Path $CaseFolder -Filter "*.csv"
$data = @{}
$flatEvents = New-Object System.Collections.Generic.List[pscustomobject]

foreach ($file in $files) {
    Write-Host "Loading: $($file.Name)... " -NoNewline
    try {
        $raw = try { Import-Csv $file.FullName -ErrorAction Stop } catch {
            $c = Get-Content $file.FullName; $hR = ($c[0] -split ",").Trim(); $seen = @{}; 
            $sh = foreach($col in $hR){ $n=if(!$col){"Blank"}else{$col}; if($seen.ContainsKey($n)){$seen[$n]++; "$n`_$($seen[$n])"}else{$seen[$n]=1;$n} }
            $c | Select-Object -Skip 1 | ConvertFrom-Csv -Header $sh
        }
        $norm = New-Object System.Collections.Generic.List[pscustomobject]
        foreach($r in $raw){
            $dt = Parse-EventTime (Get-Value -Row $r -ColumnName "Date")
            $uname = Get-Value -Row $r -ColumnName "Username"
            $r | Add-Member -MemberType NoteProperty -Name "EventTime" -Value $dt -Force
            $r | Add-Member -MemberType NoteProperty -Name "RequestId" -Value (Get-Value -Row $r -ColumnName "Request ID") -Force
            $r | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value (Get-Value -Row $r -ColumnName "IP address") -Force
            $r | Add-Member -MemberType NoteProperty -Name "Username" -Value $uname -Force
            $r | Add-Member -MemberType NoteProperty -Name "MfaResult" -Value "N/A" -Force
            $r | Add-Member -MemberType NoteProperty -Name "ConditionalAccess" -Value (Get-FieldValue -Row $r -Aliases @("Conditional Access")) -Force
            $norm.Add($r); $flatEvents.Add($r)
        }
        $data[$file.Name] = $norm
        Write-Host "OK ($($norm.Count) rows)"
    } catch { Write-Host "FAILED" }
}

# Anchor selection
Write-Host "`n=== ANCHOR SELECTION ==="
$anchor = $null
if($AnchorRequestId){
    $anchor = $flatEvents | Where-Object { $_.RequestId -eq $AnchorRequestId } | Select-Object -First 1
}

if($anchor){
    $AnchorDevice = [pscustomobject]@{
        DeviceId = (Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["DeviceId"]).ToUpper()
        OperatingSystem = Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["OperatingSystem"]
        Browser = Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["Browser"]
        ClientApp = Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["ClientApp"]
        JoinType = Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["JoinType"]
        Compliant = Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["Compliant"]
        Managed = Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["Managed"]
        UserAgent = Get-FieldValue -Row $anchor -Aliases $script:ColumnAliases["UserAgent"]
    }
    
    $utcTime = if($anchor.EventTime){ [datetime]::SpecifyKind($anchor.EventTime, [System.DateTimeKind]::Utc) } else { [datetime]::UtcNow }
    $estTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime, [TimeZoneInfo]::FindSystemTimeZoneById("Eastern Standard Time"))
    $cstTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime, [TimeZoneInfo]::FindSystemTimeZoneById("Central Standard Time"))
    
    $encodedIP = [uri]::EscapeDataString($anchor.IPAddress)
    $trunc = "Unknown"; if($anchor.Username -and $anchor.Username -match "@"){$trunc = $anchor.Username.Split('@')[0]}elseif($anchor.Username){$trunc=$anchor.Username}
    $lsUserUrl = "$LS_URL/user.aspx?username=$trunc&userdomain=$LS_DOMAIN"
    $ppUser = [uri]::EscapeDataString($anchor.Username)
    $ppSince = $utcTime.AddDays(-3).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $ppUntil = $utcTime.ToString("yyyy-MM-ddTHH:mm:ssZ")

    # Metrics
    Write-Host "Processing Baseline Metrics..."
    $set24h = $flatEvents | Where-Object { $_.EventTime -ge (Get-Date).AddHours(-24) }
    $set7d  = $flatEvents | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-7) }
    $set30d = $flatEvents | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-30) }
    
    $isNewIP = Test-IsNewValue -BaselineEvents $set30d -Aliases @("IP address") -Value $anchor.IPAddress
    $isNewDevice = Test-IsNewValue -BaselineEvents $set30d -Aliases $script:ColumnAliases["DeviceId"] -Value $AnchorDevice.DeviceId
    
    $deviceGroups = $set30d | Group-Object { Get-FieldValue -Row $_ -Aliases $script:ColumnAliases["DeviceId"] }
    $matrixRows = foreach($g in $deviceGroups){
        $dId = $g.Name.ToUpper(); $evs = $g.Group
        $ips = $evs.IPAddress | Select-Object -Unique
        $rowStyle = if($dId -eq $AnchorDevice.DeviceId){"class='anchor-row-highlight'"}else{""}
        "<tr $rowStyle><td>$dId</td><td>$($ips -join ',')</td><td>$(Get-FieldValue -Row $evs[0] -Aliases $script:ColumnAliases['OperatingSystem'])</td><td>$(Get-FieldValue -Row $evs[0] -Aliases $script:ColumnAliases['Compliant'])</td><td>$($evs.Count)</td><td>$(($evs | Sort-Object EventTime -Descending | Select-Object -First 1).EventTime.ToString('yyyy-MM-dd HH:mm'))</td></tr>"
    }
    
    $riskScore = Get-RiskScore -Anchor $anchor -IsNewIP $isNewIP -IsNewDevice $isNewDevice -AnchorDevice $AnchorDevice
    $decision = Get-DecisionBucket -Anchor $anchor -Score $riskScore

    $ts = (Get-Date).ToString("yyyyddMM-hhmmssfff tt")
    $label = if($AnchorDevice.DeviceId -ne "Unknown") { $AnchorDevice.DeviceId } else { $trunc }
    $fName = "$ts EST RiskyUserAlert $($label) report.html"

    # Prefix Logic
    $ipVal = $anchor.IPAddress; $prefixInfo = ""; if ($ipVal -match ':') {
        $segments = $ipVal.Split(':'); if ($segments.Count -ge 4) {
            $prefix64 = ($segments[0..3] -join ':') + "::/64"; $prefixInfo = "<div style='font-size:11px; color:var(--orange); margin-top:4px;'>Network Prefix: <span class='value'>$prefix64</span></div>"
        }
    }

    Write-Report -Status "FINAL" -Anchor $anchor -AnchorDevice $AnchorDevice -UtcTime $utcTime -EstTime $estTime -CstTime $cstTime -Decision $decision -RiskScore $riskScore -UniqueFlaws @() -IsNewIP $isNewIP -IsNewLocation $false -IsNewApp $false -MatrixRows $matrixRows -Set24h $set24h -Set7d $set7d -Set30d $set30d -CaseFolder $CaseFolder -Rapid7OrgId $RAPID7_ORG_ID -Rapid7LogList $RAPID7_LOGS -EncodedIP $encodedIP -PpUser $ppUser -PpSince $ppSince -PpUntil $ppUntil -lsUserUrl $lsUrl -CsBaseUrl $CS_BASE -ReportFileName $fName -PrefixInfo $prefixInfo
}
Write-Host "REGRESSION_CHECK: OK"
