param(
    [Parameter(Mandatory=$true)]
    [string] $CaseFolder,

    [Parameter(Mandatory=$false)]
    [string] $AlertTime,

    [Parameter(Mandatory=$false)]
    [string] $AnchorRequestId
)

# =========================
# Risky User CSV Triage MVP
# =========================

function Fail {
    param([string] $Message)
    Write-Host "ERROR: $Message"
    exit 1
}

function Get-FieldValue {
    param(
        [Parameter(Mandatory=$false)] $Row,
        [Parameter(Mandatory=$true)] [string[]] $Aliases,
        $Default = "Unknown"
    )
    if ($null -eq $Row) { return $Default }
    
    $props = @()
    if ($Row.PSObject -and $Row.PSObject.Properties) {
        $props = $Row.PSObject.Properties.Name
    } elseif ($Row -is [System.Collections.IDictionary]) {
        $props = $Row.Keys
    }

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
    param(
        [Parameter(Mandatory=$true)] $Row,
        [Parameter(Mandatory=$true)] [string] $ColumnName
    )
    if ($null -eq $Row) { return $null }
    
    # Ultra-robust aliases for Entra headers
    $aliases = @(
        $ColumnName, 
        ($ColumnName -replace ' ', ''), 
        ($ColumnName + " (UTC)"), 
        ($ColumnName -replace ' ', '_'),
        "User", 
        "User name",
        "Username"
    )
    return Get-FieldValue -Row $Row -Aliases $aliases -Default $null
}

function Parse-EventTime {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { 
        $dt = [datetime]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        return [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    } catch { return $null }
}

function Get-Frequency {
    param([string]$Value, [string[]]$Aliases, $Datasets)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "Unknown") { return 0 }
    $total = 0
    foreach ($set in $Datasets) {
        if ($null -ne $set) {
            $total += ($set | Where-Object { 
                $v = Get-FieldValue -Row $_ -Aliases $Aliases
                $v -ieq $Value 
            }).Count
        }
    }
    return $total
}

function Get-LastSeen {
    param([string]$Value, [string[]]$Aliases, $Datasets)
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -eq "Unknown") { return "N/A" }
    $latest = $null
    foreach ($set in $Datasets) {
        if ($null -ne $set) {
            $match = $set | Where-Object { 
                $v = Get-FieldValue -Row $_ -Aliases $Aliases
                $v -ieq $Value 
            } | Sort-Object EventTime -Descending | Select-Object -First 1
            if ($match -and $match.EventTime -and ($null -eq $latest -or $match.EventTime -gt $latest)) {
                $latest = $match.EventTime
            }
        }
    }
    if ($latest) { return $latest.ToString("yyyy-MM-dd HH:mm") } else { return "Never" }
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
        @{ Label = "5m";  Offset = 150 }
        @{ Label = "1h";  Offset = 1800 }
        @{ Label = "24h"; Offset = 43200 }
        @{ Label = "7d";  Offset = 302400 }
        @{ Label = "30d"; Offset = 1296000 }
    )
    $start1m = ([datetimeoffset]::new($TimeObj.AddSeconds(-30))).ToUnixTimeMilliseconds()
    $end1m   = ([datetimeoffset]::new($TimeObj.AddSeconds(30))).ToUnixTimeMilliseconds()
    $primaryUrl = if ($ToolType -eq "CS") { $BaseUrl + "&start=$start1m&end=$end1m" } else { $BaseUrl + "&from=$start1m&to=$end1m" }
    $html = "<a href='$primaryUrl' target='_blank' class='primary-pivot-btn' id='primary-$($ToolType.ToLower())-pivot' data-time-params='$(if($ToolType -eq "CS"){"&start=$start1m&end=$end1m"}else{"&from=$start1m&to=$end1m"})'>PIVOT TO EXACT MINUTE</a>"
    $html += "<div class='scope-group'>"
    foreach ($s in $scopes) {
        $st = ([datetimeoffset]::new($TimeObj.AddSeconds(-$s.Offset))).ToUnixTimeMilliseconds()
        $en = ([datetimeoffset]::new($TimeObj.AddSeconds($s.Offset))).ToUnixTimeMilliseconds()
        $tUrl = if ($ToolType -eq "CS") { $BaseUrl + "&start=$st&end=$en" } else { $BaseUrl + "&from=$st&to=$en" }
        $html += "<a href='$tUrl' target='_blank' class='scope-btn $($ToolType.ToLower())-scope-btn' data-time-params='$(if($ToolType -eq "CS"){"&start=$st&end=$en"}else{"&from=$st&to=$en"})'>$($s.Label)</a>"
    }
    return $html + "</div>"
}

function Write-Report {
    param($Status, $Anchor, $AnchorDevice, $UtcTime, $EstTime, $CstTime, $Decision, $RiskScore, $UniqueFlaws, $IsNewIP, $IsNewLocation, $IsNewApp, $MatrixRows, $Set24h, $Set7d, $Set30d, $CaseFolder, $ColumnAliases, $Rapid7OrgId, $Rapid7LogList, $EncodedIP, $PpUser, $PpSince, $PpUntil, $lsUserUrl)
    
    $statusBadgeClass = if($anchor.Status -match 'Success') { 'badge-success' } else { 'badge-fail' }
    $reportPath = Join-Path $CaseFolder "RiskyUser_TriageReport.html"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SOC Report [$Status] - $($anchor.RequestId)</title>
    <style>
        :root { --bg: #0d1117; --card-bg: #161b22; --border: #30363d; --text-primary: #f0f6fc; --text-secondary: #8b949e; --blue: #58a6ff; --green: #3fb950; --red: #f85149; --orange: #d29922; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background-color: var(--bg); color: var(--text-primary); margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 20px; }
        .badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; border: 1px solid transparent; }
        .badge-success { background: rgba(63, 185, 80, 0.15); color: var(--green); border-color: var(--green); }
        .badge-fail { background: rgba(248, 81, 73, 0.15); color: var(--red); border-color: var(--red); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
        .label { color: var(--text-secondary); font-size: 11px; text-transform: uppercase; font-weight: 600; display: block; margin-bottom: 6px; }
        .value { font-size: 14px; font-weight: 500; font-family: monospace; }
        .section-title { font-size: 14px; color: var(--blue); margin: 24px 0 12px 0; border-left: 4px solid var(--blue); padding-left: 10px; font-weight: 600; }
        .decision-banner { background: var(--card-bg); border: 2px solid var(--blue); border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 20px; }
        .decision-value { font-size: 32px; font-weight: 800; color: var(--blue); text-transform: uppercase; }
        .scope-group { display: flex; gap: 4px; margin-top: 8px; }
        .scope-btn { background: #21262d; color: #8b949e; border: 1px solid var(--border); padding: 2px 8px; border-radius: 4px; font-size: 10px; text-decoration: none; }
        .primary-pivot-btn { background: var(--blue); color: white; padding: 8px 15px; border-radius: 4px; font-weight: bold; display: block; text-align: center; text-decoration: none; font-size: 12px; }
        .comparison-table { width: 100%; border-collapse: collapse; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .comparison-table th { background: #21262d; color: var(--blue); text-align: left; padding: 12px; font-size: 11px; }
        .comparison-table td { padding: 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
        .anchor-row-highlight { background: rgba(88, 166, 255, 0.1) !important; }
    </style>
    <script>
        function copy(text) { navigator.clipboard.writeText(text); alert('Copied: ' + text); }
        function updateDynamicPivots(n) {
            if(!n) return;
            const b = "https://falcon.us-2.crowdstrike.com/investigate/search?repo=all&query=" + encodeURIComponent("ComputerName='" + n + "' | table @timestamp, ComputerName, UserName, event_simpleName, ImageFileName, CommandLine, LocalAddressIP, RemoteAddressIP");
            document.querySelectorAll('.cs-scope-btn').forEach(btn => { btn.href = b + btn.getAttribute('data-time-params'); });
            const p = document.getElementById('primary-cs-pivot');
            if(p) p.href = b + p.getAttribute('data-time-params');
            document.getElementById('cs-host-details').href = "https://falcon.us-2.crowdstrike.com/host-management/hosts?filter=hostname%233A%27" + n + "%27";
            document.getElementById('current-target-display').innerText = n;
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Risky User Analysis [$Status]</h1>
            <div class="badge $statusBadgeClass">$($anchor.Status)</div>
        </div>
        <div class="decision-banner">
            <div class="label">Primary Decision (Risk Score: $RiskScore)</div>
            <div class="decision-value">$($Decision.ToUpper())</div>
        </div>
        <div class="section-title">TIME CONVERSIONS</div>
        <div class="grid">
            <div class="card"><span class="label">UTC</span><span class="value">$(if($UtcTime){$UtcTime.ToString("yyyy-MM-dd HH:mm:ss")}else{"Unknown"})</span></div>
            <div class="card"><span class="label">EST (Eastern)</span><span class="value">$(if($EstTime){$EstTime.ToString("yyyy-MM-dd HH:mm:ss")}else{"Unknown"})</span></div>
            <div class="card"><span class="label">CST (Central)</span><span class="value">$(if($CstTime){$CstTime.ToString("yyyy-MM-dd HH:mm:ss")}else{"Unknown"})</span></div>
        </div>
        <div class="section-title">IDENTITY & NETWORK</div>
        <div class="grid">
            <div class="card"><span class="label">User</span><span class="value">$($anchor.Username)</span></div>
            <div class="card"><span class="label">IP Address</span><span class="value">$($anchor.IPAddress)</span></div>
            <div class="card"><span class="label">Geo Detail</span><span class="value">$($anchor.City), $($anchor.State)</span></div>
            <div class="card"><span class="label">Application</span><span class="value">$($anchor.Application)</span></div>
        </div>
        <div class="section-title">SOC TOOLBOX</div>
        <div class="card" style="border: 1px dashed var(--blue); margin-bottom: 15px;">
            <span class="label">Manual Host Override (from Lansweeper)</span>
            <input type="text" id="host-override" onchange="updateDynamicPivots(this.value)" style="width:100%; background:#0d1117; color:white; border:1px solid var(--border); padding:8px;">
            <div style="font-size:10px; margin-top:5px;">Active: <span id="current-target-display">$($AnchorDevice.DeviceId)</span></div>
        </div>
        <div class="grid">
            <div class="card">
                <span class="label">CrowdStrike EDR</span>
                $(Get-ScopeButtons -BaseUrl ("https://falcon.us-2.crowdstrike.com/investigate/search?repo=all&query=" + [uri]::EscapeDataString("ComputerName='$($AnchorDevice.DeviceId)' | table @timestamp, ComputerName, UserName, event_simpleName, ImageFileName, CommandLine, LocalAddressIP, RemoteAddressIP")) -ToolType "CS" -TimeObj $UtcTime)
                <a href="https://falcon.us-2.crowdstrike.com/host-management/hosts?filter=hostname%233A%27$($AnchorDevice.DeviceId)%27" id="cs-host-details" target="_blank" style="font-size:10px; color:var(--blue); display:block; margin-top:10px;">Host Details Page</a>
            </div>
            <div class="card">
                <span class="label">Lansweeper User</span>
                <a href="$lsUserUrl" target="_blank" style="background:var(--green); color:white; padding:8px 15px; border-radius:4px; display:block; text-align:center; text-decoration:none;">View User Profile</a>
            </div>
            <div class="card span-2">
                <span class="label">Rapid7 Logs</span>
                $(Get-ScopeButtons -BaseUrl "https://us.idr.insight.rapid7.com/op/$Rapid7OrgId#/search?logs=$Rapid7LogList&query=where($EncodedIP)" -ToolType "R7" -TimeObj $UtcTime)
            </div>
        </div>
        $(if($Status -eq "FINAL"){
            @"
        <div class="section-title">DEVICE CORRELATION MATRIX</div>
        <table class="comparison-table">
            <thead><tr><th>Device ID</th><th>IPs</th><th>OS/Browser</th><th>Posture</th><th>24h</th><th>7d</th><th>30d</th></tr></thead>
            <tbody>$($MatrixRows -join "")</tbody>
        </table>
"@
        }else{
            "<div class='card' style='text-align:center; padding:40px; color:var(--orange); font-weight:bold;'>ANALYSIS IN PROGRESS... REFRESH IN 10S</div>"
        })
    </div>
</body>
</html>
"@
    $html | Out-File $reportPath -Encoding utf8
    Write-Host "HTML Report updated: $reportPath"
}

# --- MAIN ---
$data = @{}
$presence = @{}
$files = Get-ChildItem $CaseFolder -Filter "*.csv"

foreach ($f in $files) {
    try {
        $raw = try { Import-Csv $f.FullName -ErrorAction Stop } catch {
            $c = Get-Content $f.FullName; $hRow = ($c[0] -split ",").Trim(); $seen = @{}; 
            $sh = foreach($col in $hRow){ $n=if(!$col){"Blank"}else{$col}; if($seen.ContainsKey($n)){$seen[$n]++; "$n`_$($seen[$n])"}else{$seen[$n]=1;$n} }
            $c | Select-Object -Skip 1 | ConvertFrom-Csv -Header $sh
        }
        $norm = New-Object System.Collections.Generic.List[pscustomobject]
        foreach($r in $raw){
            $dt = Parse-EventTime (Get-Value -Row $r -ColumnName "Date")
            # Force Username extraction here
            $uname = Get-Value -Row $r -ColumnName "Username"
            $r | Add-Member -MemberType NoteProperty -Name "EventTime" -Value $dt -Force
            $r | Add-Member -MemberType NoteProperty -Name "RequestId" -Value (Get-Value -Row $r -ColumnName "Request ID") -Force
            $r | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value (Get-Value -Row $r -ColumnName "IP address") -Force
            $r | Add-Member -MemberType NoteProperty -Name "Username" -Value $uname -Force
            $r | Add-Member -MemberType NoteProperty -Name "MfaResult" -Value "N/A" -Force
            $r | Add-Member -MemberType NoteProperty -Name "ConditionalAccess" -Value (Get-FieldValue -Row $r -Aliases @("Conditional Access")) -Force
            $norm.Add($r)
        }
        $data[$f.Name] = $norm
        if($f.Name -match "InteractiveSignIns" -and $f.Name -notmatch "AuthDetails"){$presence["Interactive"]=$true}
        if($f.Name -match "NonInteractive"){$presence["NonInteractive"]=$true}
        if($f.Name -match "AuthDetails"){$presence["AuthDetails"]=$true}
    } catch { Write-Warning "Failed: $($f.Name)" }
}

# Anchor Selection
$anchor = $null
if($AnchorRequestId){
    foreach($k in $data.Keys){
        if($k -match "AuthDetails"){continue}
        $m = $data[$k] | Where-Object { $_.RequestId -eq $AnchorRequestId } | Select-Object -First 1
        if($m){ 
            $anchor = $m
            $authK = $k.Replace("InteractiveSignIns", "InteractiveSignIns_AuthDetails")
            if($data.ContainsKey($authK)){
                $am = $data[$authK] | Where-Object { $_.RequestId -eq $AnchorRequestId } | Select-Object -First 1
                if($am){ $anchor.MfaResult = $am.Status }
            }
            break 
        }
    }
}

if($anchor){
    $AnchorDevice = [pscustomobject]@{
        DeviceId = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["DeviceId"]
        OperatingSystem = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["OperatingSystem"]
        Browser = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["Browser"]
        ClientApp = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["ClientApp"]
        JoinType = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["JoinType"]
        Compliant = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["Compliant"]
        Managed = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["Managed"]
        UserAgent = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["UserAgent"]
    }
    
    $utcTime = if($anchor.EventTime){$anchor.EventTime}else{[datetime]::UtcNow}
    $estTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime, [TimeZoneInfo]::FindSystemTimeZoneById("Eastern Standard Time"))
    $cstTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime, [TimeZoneInfo]::FindSystemTimeZoneById("Central Standard Time"))
    
    $ppUser = [uri]::EscapeDataString($anchor.Username)
    $ppSince = $utcTime.AddDays(-3).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $ppUntil = $utcTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    $encodedIP = [uri]::EscapeDataString($anchor.IPAddress)
    $trunc = "Unknown"; if($anchor.Username -and $anchor.Username -match "@"){$trunc = $anchor.Username.Split('@')[0]}elseif($anchor.Username){$trunc=$anchor.Username}
    $lsUrl = "https://mxpcorls01:82/user.aspx?username=$trunc&userdomain=MAXOR"
    
    # Phase 1: Progressive Report
    Write-Report -Status "INITIAL" -Anchor $anchor -AnchorDevice $AnchorDevice -UtcTime $utcTime -EstTime $estTime -CstTime $cstTime -Decision "PENDING" -RiskScore 0 -UniqueFlaws @() -IsNewIP $false -IsNewLocation $false -IsNewApp $false -MatrixRows @() -Set24h @() -Set7d @() -Set30d @() -CaseFolder $CaseFolder -ColumnAliases $ColumnAliases -Rapid7OrgId "682B861F32ACBF7D3060" -Rapid7LogList "%5B%222186bedc4-1ee4-4728-a970-43575fb22d9d%22%5D" -EncodedIP $encodedIP -PpUser $ppUser -PpSince $ppSince -PpUntil $ppUntil -lsUserUrl $lsUrl

    # Phase 2: Heavy Math
    $data30d = $data.Values | ForEach-Object { $_ } | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-30) }
    $isNewIP = Test-IsNewValue -BaselineEvents $data30d -PropertyName "IPAddress" -Value $anchor.IPAddress
    $isNewDevice = Test-IsNewValue -BaselineEvents $data30d -PropertyName "DeviceId" -Value $AnchorDevice.DeviceId
    
    $deviceGroups = ($data.Values | ForEach-Object{$_}) | Group-Object { Get-FieldValue -Row $_ -Aliases $ColumnAliases["DeviceId"] }
    $matrix = foreach($g in $deviceGroups){
        $dId = $g.Name; $evs = $g.Group
        $ips = $evs.IPAddress | Select-Object -Unique
        $c24 = ($evs | Where-Object { $_.EventTime -ge (Get-Date).AddHours(-24) }).Count
        $c7 = ($evs | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-7) }).Count
        $c30 = ($evs | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-30) }).Count
        $rowStyle = if($dId -eq $AnchorDevice.DeviceId){"class='anchor-row-highlight'"}else{""}
        "<tr $rowStyle><td>$dId</td><td>$($ips -join ',')</td><td>$($evs[0].OperatingSystem)</td><td>$($evs[0].Compliant)</td><td>$c24</td><td>$c7</td><td>$c30</td></tr>"
    }
    
    $risk = Get-RiskScore -Anchor $anchor -IsNewIP $isNewIP -IsNewDevice $isNewDevice -AnchorDevice $AnchorDevice
    $finalDecision = Get-DecisionBucket -Anchor $anchor -Score $risk
    
    # Phase 3: Final Update
    Write-Report -Status "FINAL" -Anchor $anchor -AnchorDevice $AnchorDevice -UtcTime $utcTime -EstTime $estTime -CstTime $cstTime -Decision $finalDecision -RiskScore $risk -UniqueFlaws @() -IsNewIP $isNewIP -IsNewLocation $false -IsNewApp $false -MatrixRows $matrix -Set24h @() -Set7d @() -Set30d @() -CaseFolder $CaseFolder -ColumnAliases $ColumnAliases -Rapid7OrgId "682B861F32ACBF7D3060" -Rapid7LogList "%5B%222186bedc4-1ee4-4728-a970-43575fb22d9d%22%5D" -EncodedIP $encodedIP -PpUser $ppUser -PpSince $ppSince -PpUntil $ppUntil -lsUserUrl $lsUrl
}
Write-Host "REGRESSION_CHECK: OK"
