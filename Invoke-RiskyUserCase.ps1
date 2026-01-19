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
# Phase 1: CSV-only
# Inputs:
# InteractiveSignIns.csv
# InteractiveSignIns_AuthDetails.csv
# Join Key:
# Request ID
# Output:
# Console output only (report file later)
# =========================

function Fail {
    param([string] $Message)
    Write-Host "ERROR: $Message"
    exit 1
}

function Get-Value {
    param(
        [Parameter(Mandatory=$true)] $Row,
        [Parameter(Mandatory=$true)] [string] $ColumnName
    )
    if ($null -eq $Row) { return $null }
    $props = $Row.PSObject.Properties.Name
    if ($props -contains $ColumnName) { return $Row.$ColumnName }
    return $null
}

function Parse-EventTime {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return [datetime]::Parse($Value) } catch { return $null }
}

function Normalize-InteractiveSignInRow {
    param($Row)

    $dt = Parse-EventTime (Get-Value -Row $Row -ColumnName "Date")

    $statusRaw = Get-Value -Row $Row -ColumnName "Status"
    $statusNorm = "Unknown"
    if ($statusRaw) {
        $s = $statusRaw.ToString().Trim().ToLower()
        if ($s -match "success") { $statusNorm = "Success" }
        elseif ($s -match "fail") { $statusNorm = "Failure" }
        elseif ($s -match "interrupt") { $statusNorm = "Interrupted" }
    }

    [pscustomobject]@{
        Username = Get-Value -Row $Row -ColumnName "Username"
        EventTime = $dt
        Application = Get-Value -Row $Row -ColumnName "Application"
        StatusRaw = $statusRaw
        Status = $statusNorm
        IPAddress = Get-Value -Row $Row -ColumnName "IP address"
        Location = Get-Value -Row $Row -ColumnName "Location"
        RequestId = Get-Value -Row $Row -ColumnName "Request ID"
        SignInId = Get-Value -Row $Row -ColumnName "Sign-in ID"
    }
}

function Normalize-AuthDetailRow {
    param($Row)

    $succeededRaw = Get-Value -Row $Row -ColumnName "Succeeded"
    $mfaSucceeded = $null

    if ($succeededRaw -ne $null) {
        $t = $succeededRaw.ToString().Trim().ToLower()
        if ($t -in @("true","1","yes")) { $mfaSucceeded = $true }
        if ($t -in @("false","0","no")) { $mfaSucceeded = $false }
    }

    [pscustomobject]@{
        RequestId = Get-Value -Row $Row -ColumnName "Request ID"
        AuthDetailTime = Parse-EventTime (Get-Value -Row $Row -ColumnName "Date")
        AuthenticationMethod = Get-Value -Row $Row -ColumnName "Authentication method"
        AuthenticationMethodDetail = Get-Value -Row $Row -ColumnName "Authentication method detail"
        MfaSucceeded = $mfaSucceeded
        ResultDetail = Get-Value -Row $Row -ColumnName "Result detail"
        Requirement = Get-Value -Row $Row -ColumnName "Requirement"
    }
}

function Join-SignInsWithAuthDetails {
    param(
        [Parameter(Mandatory=$true)] $InteractiveEvents,
        [Parameter(Mandatory=$true)] $AuthDetails
    )

    # GitHub trick: hashtable join
    $authByRequestId = @{}
    foreach ($a in $AuthDetails) {
        if (-not [string]::IsNullOrWhiteSpace($a.RequestId)) {
            if (-not $authByRequestId.ContainsKey($a.RequestId)) {
                $authByRequestId[$a.RequestId] = $a
            }
        }
    }

    $joined = foreach ($e in $InteractiveEvents) {
        $auth = $null
        if ($e.RequestId -and $authByRequestId.ContainsKey($e.RequestId)) {
            $auth = $authByRequestId[$e.RequestId]
        }

        [pscustomobject]@{
            Username = $e.Username
            EventTime = $e.EventTime
            Application = $e.Application
            Status = $e.Status
            IPAddress = $e.IPAddress
            Location = $e.Location
            RequestId = $e.RequestId

            MfaSucceeded = $auth.MfaSucceeded
            AuthenticationMethod = $auth.AuthenticationMethod
            Requirement = $auth.Requirement
            ResultDetail = $auth.ResultDetail
        }
    }

    return $joined
}

function Get-TopCounts {
    param(
        [Parameter(Mandatory=$true)] $Events,
        [Parameter(Mandatory=$true)] [string] $PropertyName,
        [int] $Top = 5
    )

    $Events |
        Where-Object { $_.$PropertyName -and $_.$PropertyName.ToString().Trim() -ne "" } |
        Group-Object -Property $PropertyName |
        Sort-Object Count -Descending |
        Select-Object -First $Top |
        ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } }
}

function Select-AnchorEvent {
    param(
        [Parameter(Mandatory=$true)] $Events,
        $AlertTimeValue
    )

    $valid = $Events | Where-Object { $_.EventTime -ne $null }

    if ($AlertTimeValue) {
        return $valid |
            Sort-Object @{Expression={ [math]::Abs(($_.EventTime - $AlertTimeValue).TotalSeconds) }} |
            Select-Object -First 1
    }

    $recentSuccess = $valid |
        Where-Object { $_.Status -eq "Success" } |
        Sort-Object EventTime |
        Select-Object -Last 1

    if ($recentSuccess) { return $recentSuccess }

    return $valid | Sort-Object EventTime | Select-Object -Last 1
}

function Test-IsNewValue {
    param(
        [Parameter(Mandatory=$true)] $BaselineEvents,
        [Parameter(Mandatory=$true)] [string] $PropertyName,
        [Parameter(Mandatory=$true)] $Value
    )

    if ($null -eq $Value -or $Value.ToString().Trim() -eq "") { return $false }

    $existing = $BaselineEvents |
        Where-Object { $_.$PropertyName -and $_.$PropertyName.ToString().Trim() -ne "" } |
        Select-Object -ExpandProperty $PropertyName -Unique

    return -not ($existing -contains $Value)
}

function Get-DecisionBucket {
    param([Parameter(Mandatory=$true)] $Anchor)

    if ($Anchor.Status -ne "Success") {
        return "close_attempt_blocked"
    }

    if ($Anchor.Status -eq "Success" -and $Anchor.MfaSucceeded -eq $false) {
        return "contain_hard"
    }

    if ($Anchor.Status -eq "Success" -and $Anchor.MfaSucceeded -eq $true) {
        return "close_benign"
    }

    return "investigate"
}

function Build-TicketStory {
    param(
        [Parameter(Mandatory=$true)] $Anchor,
        [Parameter(Mandatory=$true)] [string] $DecisionBucket,
        [bool] $IsNewIP,
        [bool] $IsNewLocation,
        [bool] $IsNewApp
    )

    $parts = @()
    $parts += "Anchor sign-in: user=$($Anchor.Username), time=$($Anchor.EventTime), app=$($Anchor.Application), status=$($Anchor.Status)."
    $parts += "IP=$($Anchor.IPAddress), location=$($Anchor.Location), requestId=$($Anchor.RequestId)."
    $parts += "MFA: succeeded=$($Anchor.MfaSucceeded), method=$($Anchor.AuthenticationMethod), requirement=$($Anchor.Requirement)."
    $parts += "Novelty: newIP=$IsNewIP, newLocation=$IsNewLocation, newApp=$IsNewApp."
    $parts += "Decision: $DecisionBucket."
    return ($parts -join " ")
}

# -------------------------
# Main
# -------------------------

if (-not (Test-Path $CaseFolder)) {
    Fail "CaseFolder not found: $CaseFolder"
}

# 1. Load Interactive (Optional)
$interactivePath = Join-Path $CaseFolder "InteractiveSignIns.csv"
$authDetailsPath = Join-Path $CaseFolder "InteractiveSignIns_AuthDetails.csv"
$joined = @()

if ((Test-Path $interactivePath) -and (Test-Path $authDetailsPath)) {
    $interactiveRaw = Import-Csv $interactivePath
    $authRaw = Import-Csv $authDetailsPath
    Write-Host "Loaded InteractiveSignIns rows: $($interactiveRaw.Count)"
    Write-Host "Loaded AuthDetails rows: $($authRaw.Count)"
    $interactiveEvents = $interactiveRaw | ForEach-Object { Normalize-InteractiveSignInRow $_ }
    $authDetails = $authRaw | ForEach-Object { Normalize-AuthDetailRow $_ }
    $joined = Join-SignInsWithAuthDetails -InteractiveEvents $interactiveEvents -AuthDetails $authDetails
    Write-Host "Joined Interactive rows: $($joined.Count)"
} else {
    Write-Host "Interactive files missing or incomplete; skipping."
}

# 2. Load Non-Interactive (Optional)
$niEvents = @()
$niFiles = "NonInteractiveSignIns_24h.csv", "NonInteractiveSignIns_7d.csv", "NonInteractiveSignIns_30d.csv"
foreach ($f in $niFiles) {
    $p = Join-Path $CaseFolder $f
    if (Test-Path $p) {
        $raw = Import-Csv $p
        if ($raw) {
            Write-Host "Loaded $f rows: $($raw.Count)"
            $niEvents += $raw | ForEach-Object { Normalize-InteractiveSignInRow $_ }
        }
    }
}

if ($joined.Count -eq 0 -and $niEvents.Count -eq 0) {
    Fail "No sign-in data loaded. Check CaseFolder for CSV files."
}

# 3. Anchor selection
$anchor = $null
$foundIn = ""

if ($AnchorRequestId) {
    $anchor = $joined | Where-Object { $_.RequestId -eq $AnchorRequestId } | Select-Object -First 1
    if ($anchor) { $foundIn = "Interactive" }
    else {
        $anchor = $niEvents | Where-Object { $_.RequestId -eq $AnchorRequestId } | Select-Object -First 1
        if ($anchor) { $foundIn = "Non-interactive" }
    }
} else {
    $alertTimeValue = $null
    if ($AlertTime) { $alertTimeValue = Parse-EventTime $AlertTime }
    $anchor = Select-AnchorEvent -Events $joined -AlertTimeValue $alertTimeValue
    if ($anchor) { $foundIn = "Interactive (Default Selection)" }
}

if (-not $anchor) {
    if ($AnchorRequestId) {
        Write-Host ""
        Write-Host "AnchorRequestId not found: $AnchorRequestId"
        
        Write-Host "`nTop 10 Newest Interactive Request IDs:"
        $joined | Sort-Object EventTime -Descending | Select-Object -First 10 | Format-Table EventTime, RequestId, Application -AutoSize
        
        if ($niEvents.Count -gt 0) {
            Write-Host "`nTop 10 Newest Non-interactive Request IDs:"
            $niEvents | Sort-Object EventTime -Descending | Select-Object -First 10 | Format-Table EventTime, RequestId, Application -AutoSize
        }
        exit 0
    }
    Fail "No anchor event found."
}

Write-Host ""
Write-Host "ANCHOR (Found in: $foundIn)"
$anchor | Format-List Username,EventTime,Application,Status,IPAddress,Location,RequestId,MfaSucceeded,AuthenticationMethod,Requirement

# 4. Baseline summaries
if ($joined.Count -gt 0) {
    Write-Host ""
    Write-Host "--- INTERACTIVE BASELINE (Top 5) ---"
    Write-Host "Top IPAddress:"
    Get-TopCounts -Events $joined -PropertyName "IPAddress" -Top 5 | Format-Table -AutoSize
    Write-Host "Top Location:"
    Get-TopCounts -Events $joined -PropertyName "Location" -Top 5 | Format-Table -AutoSize
    Write-Host "Top Application:"
    Get-TopCounts -Events $joined -PropertyName "Application" -Top 5 | Format-Table -AutoSize
}

if ($niEvents.Count -gt 0) {
    Write-Host ""
    Write-Host "--- NON-INTERACTIVE BASELINE (Top 5) ---"
    Write-Host "Top IPAddress:"
    Get-TopCounts -Events $niEvents -PropertyName "IPAddress" -Top 5 | Format-Table -AutoSize
    Write-Host "Top Location:"
    Get-TopCounts -Events $niEvents -PropertyName "Location" -Top 5 | Format-Table -AutoSize
    Write-Host "Top Application:"
    Get-TopCounts -Events $niEvents -PropertyName "Application" -Top 5 | Format-Table -AutoSize
}

# 5. Novelty vs baseline (simple)
# Use interactive as baseline if available; otherwise use non-interactive
$baseline = if ($joined.Count -gt 0) { $joined } else { $niEvents }

$isNewIP = Test-IsNewValue -BaselineEvents $baseline -PropertyName "IPAddress" -Value $anchor.IPAddress
$isNewLocation = Test-IsNewValue -BaselineEvents $baseline -PropertyName "Location" -Value $anchor.Location
$isNewApp = Test-IsNewValue -BaselineEvents $baseline -PropertyName "Application" -Value $anchor.Application

Write-Host ""
Write-Host "NOVELTY"
Write-Host "New IP: $isNewIP"
Write-Host "New Location: $isNewLocation"
Write-Host "New App: $isNewApp"

# Decision + story
$decision = Get-DecisionBucket -Anchor $anchor

Write-Host ""
Write-Host "DECISION"
Write-Host $decision

Write-Host ""
Write-Host "STORY"
Write-Host (Build-TicketStory -Anchor $anchor -DecisionBucket $decision -IsNewIP $isNewIP -IsNewLocation $isNewLocation -IsNewApp $isNewApp)

Write-Host ""
Write-Host "DONE"
Write-Host "Run command:"
Write-Host ".\Invoke-RiskyUserCase.ps1 -CaseFolder `"$CaseFolder`""
