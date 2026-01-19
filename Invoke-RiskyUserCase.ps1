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
    
    # Performance: Direct access first
    try { 
        $val = $Row.$ColumnName
        if ($null -ne $val) { return $val }
    } catch { }
    
    # Fallbacks for common Entra variations
    $props = $Row.PSObject.Properties.Name
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

$designFlaws = @() # Correctly initialize as an array

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
            # DF14 DuplicateHeaders Check (Before Import-Csv)
            $rawHeaders = Get-Content $file.FullName -TotalCount 1
            if ($rawHeaders -match ",,") {
                $designFlaws += "DF14 DuplicateHeaders ($($file.Name): Blank header detected)"
            }
            $headerList = ($rawHeaders -split ",").Trim()
            $duplicates = $headerList | Group-Object | Where-Object { $_.Count -gt 1 }
            if ($duplicates) {
                $designFlaws += "DF14 DuplicateHeaders ($($file.Name): $($duplicates.Name -join ', '))"
            }

            # DF18 ExportTypeMismatch
            $isInteractiveName = $file.Name -match "^InteractiveSignIns" -and $file.Name -notmatch "AuthDetails"
            $isNonInteractiveName = $file.Name -match "^NonInteractive"
            $hasDate = $headerList -contains "Date"
            $hasDateUtc = $headerList -contains "Date (UTC)"

            if ($isInteractiveName -and $hasDateUtc -and -not $hasDate) {
                $designFlaws += "DF18 ExportTypeMismatch ($($file.Name): Found Date (UTC) in Interactive file)"
            }
            if ($isNonInteractiveName -and $hasDate -and -not $hasDateUtc) {
                $designFlaws += "DF18 ExportTypeMismatch ($($file.Name): Found Date in Non-Interactive file)"
            }

            $raw = Import-Csv $file.FullName -ErrorAction Stop
            
            # DF03 Column Validation
            if ($file.Name -match "InteractiveSignIns" -and $file.Name -notmatch "AuthDetails") {
                Test-Columns -RawData $raw -DatasetName $file.Name -RequiredCols @("Date", "Request ID", "User", "Username", "IP address", "Location", "Application", "Status")
            }
            elseif ($file.Name -match "NonInteractive") {
                Test-Columns -RawData $raw -DatasetName $file.Name -RequiredCols @("Date (UTC)", "Request ID", "User", "Username", "IP address", "Location", "Application", "Status")
            }

            # DF04 Date Parse Tracking + Normalization (Single Pass)
            $dateCol = if ($file.Name -match "NonInteractive") { "Date (UTC)" } else { "Date" }
            $failCount = 0; $samples = @()
            $normalized = New-Object System.Collections.Generic.List[pscustomobject]
            
            foreach ($r in $raw) {
                $dtValue = Get-Value -Row $r -ColumnName $dateCol
                $dt = Parse-EventTime $dtValue
                
                if ($null -eq $dt -and -not [string]::IsNullOrWhiteSpace($dtValue)) {
                    $failCount++
                    if ($samples.Count -lt 3) { $samples += $dtValue }
                }
                
                $normalized.Add([pscustomobject]@{
                    Username          = Get-Value -Row $r -ColumnName "Username"
                    EventTime         = $dt
                    Application       = Get-Value -Row $r -ColumnName "Application"
                    Status            = Get-Value -Row $r -ColumnName "Status"
                    IPAddress         = Get-Value -Row $r -ColumnName "IP address"
                    Location          = Get-Value -Row $r -ColumnName "Location"
                    RequestId         = Get-Value -Row $r -ColumnName "Request ID"
                    ConditionalAccess = Get-Value -Row $r -ColumnName "Conditional Access"
                    MfaResult         = "N/A"
                })
            }

            if ($raw.Count -gt 0 -and ($failCount / $raw.Count) -gt 0.3) {
                $designFlaws += "DF04 DateParseFailure ($($file.Name))"
                Write-Host "ERROR: Dataset '$($file.Name)' date parse failure rate: $([math]::Round(($failCount/$raw.Count)*100))%. Samples: $($samples -join ', ')"
            }

            if ($null -eq $raw -or $raw.Count -eq 0) {
                $designFlaws += "DF02 EmptyDataset ($($file.Name))"
            }
            if ($raw.Count -gt 50000) {
                $designFlaws += "DF13 TooManyEventsTruncated ($($file.Name): $($raw.Count) rows)"
            }

            # DF15 MixedTenantNoise
            $tenantIds = $raw | ForEach-Object { Get-Value -Row $_ -ColumnName "Home tenant ID" } | Where-Object { $_ }
            if ($tenantIds) {
                $tenantGroups = $tenantIds | Group-Object
                if ($tenantGroups.Count -gt 1) {
                    $topTenants = $tenantGroups | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) ($($_.Count))" }
                    $designFlaws += "DF15 MixedTenantNoise ($($file.Name): $($topTenants -join ', '))"
                }
            }

            # Store normalized data for datasets
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

    # DF19 NonInteractiveOnlyCase
    $hasInt = $presence["Interactive"]
    $hasNi = $presence["NonInteractive"]
    if (-not $hasInt -and $hasNi) {
        $designFlaws += "DF19 NonInteractiveOnlyCase"
        Write-Host "Case appears to be Non-Interactive only."
    }

    # DF20 InteractiveOnlyCase
    if ($hasInt -and -not $hasNi) {
        $designFlaws += "DF20 InteractiveOnlyCase"
        Write-Host "Case appears to be Interactive only."
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

    # DF11 AppMissing
    if ([string]::IsNullOrWhiteSpace($anchor.Application)) {
        $designFlaws += "DF11 AppMissing"
    }

    # DF16 ConditionalAccessUnknown
    if ([string]::IsNullOrWhiteSpace($anchor.ConditionalAccess) -or $anchor.ConditionalAccess -in @("Unknown", "Not Available", "None")) {
        $designFlaws += "DF16 ConditionalAccessUnknown"
    }

    # DF17 MFAUnknown
    $isMfaBlank = [string]::IsNullOrWhiteSpace($anchor.MfaResult) -or $anchor.MfaResult -in @("Unknown", "N/A")
    $isAuthMissingOrLow = (-not $presence["AuthDetails"]) -or ($designFlaws -match "DF06")
    if ($isMfaBlank -and $isAuthMissingOrLow) {
        $designFlaws += "DF17 MFAUnknown"
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

# DF12 TooFewEventsForBaseline
$count7d = if ($data7d) { @($data7d).Count } else { 0 }
$count30d = if ($data30d) { @($data30d).Count } else { 0 }
if ($count7d -lt 25 -or $count30d -lt 100) {
    $designFlaws += "DF12 TooFewEventsForBaseline (7d: $count7d, 30d: $count30d)"
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
    # Force each flaw onto a new line with explicit Write-Host calls
    $uniqueFlaws = @($designFlaws) | Select-Object -Unique
    foreach ($flaw in $uniqueFlaws) {
        if (-not [string]::IsNullOrWhiteSpace($flaw)) {
            Write-Host " - $flaw"
        }
    }
    if ($uniqueFlaws -match "DF01") {
        Write-Host "DF01 MissingFiles: HINT: Export sign-in logs CSVs and place them in the CaseFolder."
    }
    if ($uniqueFlaws -match "DF06") {
        Write-Host "DF06 JoinRateLow: HINT: Join rate is low. Re-export both CSVs ensuring the same Time Range and Filters (e.g. User or Request ID) are applied to both Sign-ins and AuthDetails."
    }
    if ($uniqueFlaws -match "DF08") {
        Write-Host "DF08 TimeWindowMismatch: HINT: Baseline files appear to contain data from a different time period than the anchor."
    }
    if ($uniqueFlaws -match "DF09") {
        Write-Host "DF09 LocationMissing: HINT: Anchor event is missing location data. Check if IP address is from a known VPN or datacenter."
    }
    if ($uniqueFlaws -match "DF10") {
        Write-Host "DF10 IPMissing: HINT: Anchor event is missing an IP address. This can happen with certain managed service identity or app-only sign-ins."
    }
    if ($uniqueFlaws -match "DF11") {
        Write-Host "DF11 AppMissing: HINT: Anchor event is missing Application name. Verify if the sign-in was to a legacy or custom internal resource."
    }
    if ($uniqueFlaws -match "DF12") {
        Write-Host "DF12 TooFewEventsForBaseline: HINT: Baseline event counts are low. Novelty detection may be less reliable until more historical data is provided."
    }
    if ($uniqueFlaws -match "DF13") {
        Write-Host "DF13 TooManyEventsTruncated: HINT: Dataset is very large. Consider exporting a smaller time window or filtering to a specific user to improve performance."
    }
    if ($uniqueFlaws -match "DF14") {
        Write-Host "DF14 DuplicateHeaders: HINT: Duplicate or blank headers detected. Check the first row of the CSV file for errors."
    }
    if ($uniqueFlaws -match "DF15") {
        Write-Host "DF15 MixedTenantNoise: HINT: Multiple tenant IDs detected. This investigation may contain data from different environments or guest accounts."
    }
    if ($uniqueFlaws -match "DF16") {
        Write-Host "DF16 ConditionalAccessUnknown: HINT: Conditional Access status is not available. Review the Azure AD sign-in logs for policy details."
    }
    if ($uniqueFlaws -match "DF17") {
        Write-Host "DF17 MFAUnknown: HINT: MFA result is unknown. This typically means the AuthDetails CSV was missing or didn't contain matching Request IDs for the anchor event."
    }
    if ($uniqueFlaws -match "DF18") {
        Write-Host "DF18 ExportTypeMismatch: HINT: Export type mismatch detected. Entra CSV headers don't match the filename. Verify you didn't rename the files incorrectly."
    }
    if ($uniqueFlaws -match "DF19") {
        Write-Host "DF19 NonInteractiveOnlyCase: HINT: Investigation is limited to non-interactive sign-ins. Manual correlation with user activity in other logs may be required."
    }
    if ($uniqueFlaws -match "DF20") {
        Write-Host "DF20 InteractiveOnlyCase: HINT: Investigation is limited to interactive sign-ins. Review if the user has non-interactive activity that might be missed."
    }
} else {
    Write-Host "None"
}

# --- DECISION ---
Write-Host "`n=== DECISION ==="
$decision = "N/A (No Anchor)"
if ($anchor) {
    $decision = Get-DecisionBucket -Anchor $anchor
}
Write-Host $decision

# --- STORY ---
Write-Host "`n=== STORY ==="
if ($anchor) {
    Write-Host (Build-TicketStory -Anchor $anchor -DecisionBucket $decision -IsNewIP $isNewIP -IsNewLocation $isNewLoc -IsNewApp $isNewApp)
}

Write-Host "`nDONE"
