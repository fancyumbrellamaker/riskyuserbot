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

function Test-Columns {
    param($RawData, $RequiredCols, $DatasetName)
    if ($null -eq $RawData -or $RawData.Count -eq 0) { return }
    
    # Get headers and strip BOM/special chars from the first header if present
    $headers = $RawData[0].PSObject.Properties.Name | ForEach-Object { 
        $h = $_.Trim()
        # Remove common BOM patterns from the start of the first header
        $h = $h -replace "^[^\w]*Date", "Date"
        $h
    }
    
    $missing = @()
    foreach ($req in $RequiredCols) {
        $found = $false
        foreach ($h in $headers) {
            if ($h -match [regex]::Escape($req) -or $h -ieq $req) {
                $found = $true
                break
            }
        }
        if (-not $found) { $missing += $req }
    }

    if ($missing) {
        $script:designFlaws += "DF03 MissingColumns ($DatasetName)"
        Write-Host "ERROR: Dataset '$DatasetName' missing columns: $($missing -join ', ')"
        Write-Host "Available headers (first 30): $($($headers | Select-Object -First 30) -join ', ')"
    }
}

# -------------------------
# Main
# -------------------------

if (-not (Test-Path $CaseFolder)) {
    $designFlaws += "DF01 MissingFiles"
}

$foundFiles = Get-ChildItem -Path $CaseFolder -Filter "*.csv" -ErrorAction SilentlyContinue
if ($null -eq $foundFiles -or $foundFiles.Count -eq 0) {
    if ("DF01 MissingFiles" -notin $designFlaws) { $designFlaws += "DF01 MissingFiles" }
}

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
            
            # DF03 Column Validation
            if ($file.Name -match "InteractiveSignIns" -and $file.Name -notmatch "AuthDetails") {
                Test-Columns -RawData $raw -DatasetName $file.Name -RequiredCols @("Date", "Request ID", "User", "Username", "IP address", "Location", "Application", "Status")
            }
            elseif ($file.Name -match "NonInteractive") {
                Test-Columns -RawData $raw -DatasetName $file.Name -RequiredCols @("Date (UTC)", "Request ID", "User", "Username", "IP address", "Location", "Application", "Status")
            }

            # DF04 Date Parse Tracking
            $dateCol = if ($file.Name -match "NonInteractive") { "Date (UTC)" } else { "Date" }
            $failCount = 0; $samples = @()
            foreach ($r in $raw) {
                $v = Get-Value -Row $r -ColumnName $dateCol
                if ($null -eq (Parse-EventTime $v) -and -not [string]::IsNullOrWhiteSpace($v)) {
                    $failCount++
                    if ($samples.Count -lt 3) { $samples += $v }
                }
            }
            if ($raw.Count -gt 0 -and ($failCount / $raw.Count) -gt 0.3) {
                $designFlaws += "DF04 DateParseFailure ($($file.Name))"
                Write-Host "ERROR: Dataset '$($file.Name)' date parse failure rate: $([math]::Round(($failCount/$raw.Count)*100))%. Samples: $($samples -join ', ')"
            }

            if ($null -eq $raw -or $raw.Count -eq 0) {
                $designFlaws += "DF02 EmptyDataset ($($file.Name))"
            }
            # Store normalized data for datasets
            $normalized = $raw | ForEach-Object { Normalize-Row $_ }
            $data[$file.Name] = $normalized
            Write-Host "Loaded: $($file.Name) ($($raw.Count) rows)"
            
            if ($file.Name -match "AuthDetails") { $presence["AuthDetails"] = $true }
            elseif ($file.Name -match "NonInteractive") { $presence["NonInteractive"] = $true }
            elseif ($file.Name -match "InteractiveSignIns") { 
                $presence["Interactive"] = $true
                # DF06 Join Rate Check
                $authKey = $file.Name.Replace("InteractiveSignIns", "InteractiveSignIns_AuthDetails")
                if (Test-Path (Join-Path $CaseFolder $authKey)) {
                    $authRaw = Import-Csv (Join-Path $CaseFolder $authKey)
                    $ids = $raw | Select-Object -ExpandProperty "Request ID" -Unique
                    $authIds = $authRaw | Select-Object -ExpandProperty "Request ID" -Unique
                    $matches = $ids | Where-Object { $_ -in $authIds }
                    $rate = if ($ids.Count -gt 0) { ($matches.Count / $ids.Count) * 100 } else { 100 }
                    if ($ids.Count -gt 0 -and $rate -lt 20) {
                        $designFlaws += "DF06 JoinRateLow ($($file.Name): $([math]::Round($rate))%)"
                    }
                }
            }
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
    
    # Dataset Time Windows
    Write-Host "`nDataset Time Windows:"
    foreach ($key in $minMax.Keys | Sort-Object) {
        Write-Host "  $key`: $($minMax[$key].Min.ToString('yyyy-MM-dd')) to $($minMax[$key].Max.ToString('yyyy-MM-dd'))"
    }
    
    # DF07 UserMismatch
    $baselineUsers = @()
    if ($data.ContainsKey("InteractiveSignIns_7d.csv")) { 
        $list = $data["InteractiveSignIns_7d.csv"] | ForEach-Object { $_.Username }
        if ($list) { $baselineUsers += $list }
    }
    if ($data.ContainsKey("InteractiveSignIns_30d.csv")) { 
        $list = $data["InteractiveSignIns_30d.csv"] | ForEach-Object { $_.Username }
        if ($list) { $baselineUsers += $list }
    }
    
    if ($baselineUsers) {
        $uniqueBaselineUsers = $baselineUsers | Select-Object -Unique
        if ($anchor.Username -and $anchor.Username -notin $uniqueBaselineUsers) {
            $designFlaws += "DF07 UserMismatch ($($anchor.Username) not in baseline)"
        }
    }

    # DF09 LocationMissing
    if ([string]::IsNullOrWhiteSpace($anchor.Location) -or $anchor.Location -ieq "Unknown") {
        $designFlaws += "DF09 LocationMissing (IP: $($anchor.IPAddress))"
    }

    # DF10 IPMissing
    if ([string]::IsNullOrWhiteSpace($anchor.IPAddress)) {
        $designFlaws += "DF10 IPMissing"
    }

    # DF08 TimeWindowMismatch
    $minMax = @{}
    foreach ($key in $data.Keys) {
        $dates = $data[$key].EventTime | Where-Object { $_ -ne $null }
        if ($dates) {
            $sorted = $dates | Sort-Object
            $minMax[$key] = @{ Min = $sorted[0]; Max = $sorted[-1] }
        }
    }
    
    if ($anchor.EventTime) {
        $threshold = $anchor.EventTime.AddDays(-45)
        $outOfRange = @()
        foreach ($key in $minMax.Keys) {
            if ($key -match "7d|30d" -and $minMax[$key].Max -lt $threshold) {
                $outOfRange += "$key (max: $($minMax[$key].Max.ToShortDateString()))"
            }
        }
        if ($outOfRange) {
            $designFlaws += "DF08 TimeWindowMismatch"
            Write-Host "WARNING: Baseline data is outside 45-day window: $($outOfRange -join ', ')"
        }
    }
} else {
    if (-not [string]::IsNullOrWhiteSpace($AnchorRequestId)) {
        $designFlaws += "DF05 AnchorNotFound"
        Write-Host "Anchor Request ID '$AnchorRequestId' not found in any loaded dataset."
        
        foreach ($key in $data.Keys) {
            if ($key -match "AuthDetails") { continue }
            Write-Host "`nTop 10 Newest Request IDs in $key`:"
            $data[$key] | Sort-Object EventTime -Descending | Select-Object -First 10 | Format-Table EventTime, Username, RequestId, Application -AutoSize
        }
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
    # Ensure distinct codes and explicit line breaks
    $uniqueFlaws = @($designFlaws) | Select-Object -Unique
    foreach ($flaw in $uniqueFlaws) {
        if (-not [string]::IsNullOrWhiteSpace($flaw)) {
            Write-Host " - $flaw"
        }
    }
    if ($uniqueFlaws -match "DF01") {
        Write-Host "HINT: Export sign-in logs CSVs and place them in the CaseFolder."
    }
    if ($uniqueFlaws -match "DF06") {
        Write-Host "HINT: Join rate is low. Re-export both CSVs ensuring the same Time Range and Filters (e.g. User or Request ID) are applied to both Sign-ins and AuthDetails."
    }
    if ($uniqueFlaws -match "DF08") {
        Write-Host "HINT: Baseline files appear to contain data from a different time period than the anchor."
    }
    if ($uniqueFlaws -match "DF09") {
        Write-Host "HINT: Anchor event is missing location data. Check if IP address is from a known VPN or datacenter."
    }
    if ($uniqueFlaws -match "DF10") {
        Write-Host "HINT: Anchor event is missing an IP address. This can happen with certain managed service identity or app-only sign-ins."
    }
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
