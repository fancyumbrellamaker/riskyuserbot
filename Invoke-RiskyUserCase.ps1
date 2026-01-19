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
# Phase 1: DIAGNOSTICS
# Phase 2: ANCHOR
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
    
    # Robust fallback for common Entra CSV variations
    if ($ColumnName -eq "Date" -and ($props -contains "Date (UTC)")) { return $Row."Date (UTC)" }
    if ($ColumnName -eq "IP address" -and ($props -contains "IPAddress")) { return $Row.IPAddress }
    if ($ColumnName -eq "Request ID" -and ($props -contains "RequestId")) { return $Row.RequestId }
    if ($ColumnName -eq "Conditional Access" -and ($props -contains "ConditionalAccess")) { return $Row.ConditionalAccess }
    
    return $null
}

function Parse-EventTime {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return [datetime]::Parse($Value) } catch { return $null }
}

function Normalize-Row {
    param($Row)
    [pscustomobject]@{
        Username          = Get-Value -Row $Row -ColumnName "Username"
        EventTime         = Parse-EventTime (Get-Value -Row $Row -ColumnName "Date")
        Application       = Get-Value -Row $Row -ColumnName "Application"
        Status            = Get-Value -Row $Row -ColumnName "Status"
        IPAddress         = Get-Value -Row $Row -ColumnName "IP address"
        Location          = Get-Value -Row $Row -ColumnName "Location"
        RequestId         = Get-Value -Row $Row -ColumnName "Request ID"
        ConditionalAccess = Get-Value -Row $Row -ColumnName "Conditional Access"
        MfaResult         = "N/A"
    }
}

function Get-TopCounts {
    param(
        [Parameter(Mandatory=$true)] $Events,
        [Parameter(Mandatory=$true)] [string] $PropertyName,
        [int] $Top = 5
    )
    if ($null -eq $Events -or $Events.Count -eq 0) { return @() }
    $Events |
        Where-Object { $_.$PropertyName -and $_.$PropertyName.ToString().Trim() -ne "" } |
        Group-Object -Property $PropertyName |
        Sort-Object Count -Descending |
        Select-Object -First $Top |
        ForEach-Object { [pscustomobject]@{ Name = $_.Name; Count = $_.Count } }
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
    if ($null -eq $Anchor) { return "unknown" }
    $status = if ($Anchor.Status) { $Anchor.Status.ToString().ToLower() } else { "" }
    if ($status -notmatch "success") { return "close_attempt_blocked" }
    
    $mfa = if ($Anchor.MfaResult) { $Anchor.MfaResult.ToString().ToLower() } else { "" }
    if ($status -match "success") {
        if ($mfa -eq "false" -or $mfa -eq "no") { return "contain_hard" }
        if ($mfa -eq "true" -or $mfa -eq "yes") { return "close_benign" }
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
    $parts += "MFA: result=$($Anchor.MfaResult), ca=$($Anchor.ConditionalAccess)."
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

$designFlaws = @()
$foundFiles = Get-ChildItem -Path $CaseFolder -Filter "*.csv"
$data = @{}
$presence = @{
    "Interactive"    = $false
    "NonInteractive" = $false
    "AuthDetails"    = $false
    "AppSignIns"     = $false
    "MSISignIns"     = $false
}

# --- DIAGNOSTICS ---
Write-Host "`n=== DIAGNOSTICS ==="

if ($foundFiles.Count -eq 0) {
    Write-Host "No CSV files found in $CaseFolder"
    $designFlaws += "DF01 MissingFiles"
} else {
    foreach ($file in $foundFiles) {
        try {
            $raw = Import-Csv $file.FullName -ErrorAction Stop
            # Store normalized data for datasets
            $normalized = $raw | ForEach-Object { Normalize-Row $_ }
            $data[$file.Name] = $normalized
            Write-Host "Loaded: $($file.Name) ($($raw.Count) rows)"
            
            if ($file.Name -match "AuthDetails") { $presence["AuthDetails"] = $true }
            elseif ($file.Name -match "NonInteractive") { $presence["NonInteractive"] = $true }
            elseif ($file.Name -match "InteractiveSignIns") { $presence["Interactive"] = $true }
            elseif ($file.Name -match "AppSignIns") { $presence["AppSignIns"] = $true }
            elseif ($file.Name -match "MSISignIns") { $presence["MSISignIns"] = $true }
        } catch {
            Write-Warning "Failed to load $($file.Name): $($_.Exception.Message)"
            $designFlaws += "DF04 DateParseFailure ($($file.Name))"
        }
    }
}

Write-Host "`nDataset Types Present:"
foreach ($type in $presence.Keys | Sort-Object) {
    $status = if ($presence[$type]) { "[PRESENT]" } else { "[MISSING]" }
    Write-Host "  $type`: $status"
}

# --- ANCHOR ---
Write-Host "`n=== ANCHOR ==="
$anchor = $null

if ([string]::IsNullOrWhiteSpace($AnchorRequestId)) {
    Write-Host "No -AnchorRequestId provided. Skipping anchor selection."
} else {
    # Search Order: Interactive then Non-Interactive
    $searchOrder = $data.Keys | Sort-Object { if ($_ -match "InteractiveSignIns" -and $_ -notmatch "AuthDetails") { 0 } else { 1 } }
    foreach ($key in $searchOrder) {
        if ($key -match "AuthDetails") { continue }
        $match = $data[$key] | Where-Object { $_.RequestId -eq $AnchorRequestId } | Select-Object -First 1
        if ($match) {
            $anchor = $match
            Write-Host "Found anchor in: $key"
            
            # Link AuthDetails if Interactive
            if ($key -match "InteractiveSignIns") {
                $authKey = $key.Replace("InteractiveSignIns", "InteractiveSignIns_AuthDetails")
                if ($data.ContainsKey($authKey)) {
                    $authMatch = $data[$authKey] | Where-Object { $_.RequestId -eq $AnchorRequestId } | Select-Object -First 1
                    if ($authMatch) { $anchor.MfaResult = $authMatch.Status }
                }
            }
            break
        }
    }
}

if ($anchor) {
    $anchor | Format-List EventTime, Username, IPAddress, Location, Application, Status, ConditionalAccess, MfaResult, RequestId
} else {
    if (-not [string]::IsNullOrWhiteSpace($AnchorRequestId)) {
        $designFlaws += "DF05 AnchorNotFound"
        Write-Host "Anchor Request ID '$AnchorRequestId' not found."
    }
}

# --- BASELINE_7D ---
Write-Host "`n=== BASELINE_7D ==="
$data7d = $data.Values | ForEach-Object { $_ } | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-7) }
if ($data7d) {
    Write-Host "Top IPAddress:"
    Get-TopCounts -Events $data7d -PropertyName "IPAddress" | Format-Table -AutoSize
}

# --- BASELINE_30D ---
Write-Host "`n=== BASELINE_30D ==="
$data30d = $data.Values | ForEach-Object { $_ } | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-30) }
if ($data30d) {
    Write-Host "Top IPAddress:"
    Get-TopCounts -Events $data30d -PropertyName "IPAddress" | Format-Table -AutoSize
}

# --- NOVELTY ---
Write-Host "`n=== NOVELTY ==="
$isNewIP = $false; $isNewLoc = $false; $isNewApp = $false
if ($anchor) {
    $isNewIP = Test-IsNewValue -BaselineEvents $data30d -PropertyName "IPAddress" -Value $anchor.IPAddress
    Write-Host "New IP: $isNewIP"
}

# --- DESIGN_FLAWS ---
Write-Host "`n=== DESIGN_FLAWS ==="
if ($designFlaws.Count -gt 0) {
    $designFlaws | Select-Object -Unique | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "None"
}

# --- DECISION ---
Write-Host "`n=== DECISION ==="
$decision = Get-DecisionBucket -Anchor $anchor
Write-Host $decision

# --- STORY ---
Write-Host "`n=== STORY ==="
if ($anchor) {
    Write-Host (Build-TicketStory -Anchor $anchor -DecisionBucket $decision -IsNewIP $isNewIP -IsNewLocation $isNewLoc -IsNewApp $isNewApp)
}

Write-Host "`nDONE"
