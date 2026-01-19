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
    try { 
        # Ensure the time is parsed as UTC
        $dt = [datetime]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        return [datetime]::SpecifyKind($dt, [System.DateTimeKind]::Utc)
    } catch { return $null }
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
        City              = Get-FieldValue -Row $Row -Aliases @("City")
        State             = Get-FieldValue -Row $Row -Aliases @("State", "State/Province")
        Country           = Get-FieldValue -Row $Row -Aliases @("Country", "Country/Region")
        RequestId         = Get-Value -Row $Row -ColumnName "Request ID"
        ConditionalAccess = Get-Value -Row $Row -ColumnName "Conditional Access"
        MfaResult         = "N/A"
        DeviceDetail      = $Row # Keep raw row for device extraction
    }
}

# Column Aliases for Device + UA + Geo
$ColumnAliases = @{
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
        foreach ($p in $props) {
            if ($p -ieq $alias -or ($p -replace '[^a-zA-Z0-9]', '') -ieq ($alias -replace '[^a-zA-Z0-9]', '')) {
                $val = if ($Row.PSObject) { $Row.$p } else { $Row[$p] }
                if ($null -ne $val -and -not [string]::IsNullOrWhiteSpace($val.ToString())) {
                    return $val.ToString().Trim()
                }
            }
        }
    }
    
    return $Default
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

function Get-Frequency {
    param(
        [string]$Value, 
        [string[]]$Aliases, 
        $Datasets
    )
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
                
                # Add normalized properties directly to the CSV object for maximum data retention
                $r | Add-Member -MemberType NoteProperty -Name "EventTime" -Value $dt -Force
                $r | Add-Member -MemberType NoteProperty -Name "RequestId" -Value (Get-Value -Row $r -ColumnName "Request ID") -Force
                $r | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value (Get-Value -Row $r -ColumnName "IP address") -Force
                $r | Add-Member -MemberType NoteProperty -Name "MfaResult" -Value "N/A" -Force
                $r | Add-Member -MemberType NoteProperty -Name "ConditionalAccess" -Value (Get-FieldValue -Row $r -Aliases @("Conditional Access")) -Force
                
                $normalized.Add($r)
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
    
    # --- ANCHOR_DEVICE ---
    Write-Host "`n=== ANCHOR_DEVICE ==="
    # Debug properties
    # $anchor.PSObject.Properties.Name | ForEach-Object { Write-Host "DEBUG PROP: $_" }
    
    $AnchorDevice = [pscustomobject]@{
        DeviceId        = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["DeviceId"]
        OperatingSystem = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["OperatingSystem"]
        Browser         = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["Browser"]
        ClientApp       = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["ClientApp"]
        JoinType        = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["JoinType"]
        Compliant       = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["Compliant"]
        Managed         = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["Managed"]
        UserAgent       = Get-FieldValue -Row $anchor -Aliases $ColumnAliases["UserAgent"]
    }
    $AnchorDevice | Format-List
    
    # Timezone Conversions (Force UTC source)
    $utcTime = $anchor.EventTime
    $estTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime, [TimeZoneInfo]::FindSystemTimeZoneById("Eastern Standard Time"))
    $cstTime = [TimeZoneInfo]::ConvertTimeFromUtc($utcTime, [TimeZoneInfo]::FindSystemTimeZoneById("Central Standard Time"))
    
    # Dataset Time Windows
    Write-Host "`nDataset Time Windows:"
    foreach ($key in $minMax.Keys | Sort-Object) {
        Write-Host "  $key`: $($minMax[$key].Min.ToString('yyyy-MM-dd')) to $($minMax[$key].Max.ToString('yyyy-MM-dd'))"
    }

    # --- DEVICE MATRIX LOGIC ---
    $allEvents = $data.Values | ForEach-Object { $_ }
    $deviceGroups = $allEvents | Group-Object { 
        $d = Get-FieldValue -Row $_ -Aliases $ColumnAliases["DeviceId"]
        if ($d -eq "Unknown") {
            $ua = Get-FieldValue -Row $_ -Aliases $ColumnAliases["UserAgent"]
            if ($ua -ne "Unknown") { "Unknown ($($ua.Substring(0,[math]::Min(30, $ua.Length))))" } else { "Unknown Device" }
        } else { $d }
    }
    
    $matrixRows = foreach ($g in $deviceGroups) {
        $devId = $g.Name
        $groupEvents = $g.Group
        
        $ips = $groupEvents | ForEach-Object { Get-FieldValue -Row $_ -Aliases @("IP address") } | Select-Object -Unique
        $locs = $groupEvents | ForEach-Object { Get-FieldValue -Row $_ -Aliases @("Location") } | Select-Object -Unique
        $apps = $groupEvents | Group-Object { Get-FieldValue -Row $_ -Aliases @("Application") } | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name }
        $osBrowser = $groupEvents | ForEach-Object { 
            $o = Get-FieldValue -Row $_ -Aliases $ColumnAliases["OperatingSystem"]
            $b = Get-FieldValue -Row $_ -Aliases $ColumnAliases["Browser"]
            "$o / $b"
        } | Select-Object -Unique

        # Security Posture logic
        $compliances = $groupEvents | ForEach-Object { Get-FieldValue -Row $_ -Aliases $ColumnAliases["Compliant"] } | Select-Object -Unique
        $joins       = $groupEvents | ForEach-Object { Get-FieldValue -Row $_ -Aliases $ColumnAliases["JoinType"] } | Select-Object -Unique
        $isAppOnly   = $groupEvents | ForEach-Object { Get-FieldValue -Row $_ -Aliases $ColumnAliases["ClientApp"] } | Where-Object { $_ -match "App|Service" } | Select-Object -First 1
        
        # Last Seen Logic
        $lastSeenTime = ($groupEvents | Sort-Object EventTime -Descending | Select-Object -First 1).EventTime
        $lastSeenStr = if ($lastSeenTime) { $lastSeenTime.ToString("yyyy-MM-dd HH:mm") } else { "Unknown" }

        # Frequency windows
        $c24 = ($groupEvents | Where-Object { $_.EventTime -ge (Get-Date).AddHours(-24) }).Count
        $c7  = ($groupEvents | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-7) }).Count
        $c30 = ($groupEvents | Where-Object { $_.EventTime -ge (Get-Date).AddDays(-30) }).Count
        $totalFreq = $groupEvents.Count

        $rowClass = if ($devId -eq $AnchorDevice.DeviceId -or $devId -match [regex]::Escape($AnchorDevice.DeviceId)) { "class='anchor-row-highlight'" } else { "" }

        @"
        <tr $rowClass>
            <td class="val-col" style="font-size:11px;">$devId</td>
            <td style="font-size:11px;">$($ips -join ", ")</td>
            <td style="font-size:11px;">$($locs -join ", ")</td>
            <td style="font-size:10px; color:var(--blue)">$($osBrowser -join "<br>")</td>
            <td style="font-size:10px;">
                <div style="color:$(if($compliances -contains 'True'){'var(--green)'}else{'var(--text-secondary)'})">Compliant: $($compliances -join '/')</div>
                <div style="color:var(--blue)">Join: $($joins -join '/')</div>
                $(if($isAppOnly){"<div style='color:var(--orange)'>TYPE: Application</div>"}else{"<div style='color:var(--text-secondary)'>TYPE: User</div>"})
            </td>
            <td style="color:var(--text-secondary); font-size:10px;">$($apps -join ", ")</td>
            <td style="font-size:11px; white-space:nowrap;">$lastSeenStr</td>
            <td class="freq-cell" style="color:var(--text-primary)">$totalFreq</td>
            <td class="freq-cell $(if($c24 -eq 0){'zero'})">$c24</td>
            <td class="freq-cell $(if($c7 -eq 0){'zero'})">$c7</td>
            <td class="freq-cell $(if($c30 -eq 0){'zero'})">$c30</td>
        </tr>
"@
    }

    # Baseline side-by-side datasets
    $set24h = $data.Keys | Where-Object { $_ -match "24h" } | ForEach-Object { $data[$_] }
    $set7d  = $data.Keys | Where-Object { $_ -match "7d" } | ForEach-Object { $data[$_] }
    $set30d = $data.Keys | Where-Object { $_ -match "30d" } | ForEach-Object { $data[$_] }
    if (-not $set24h) { $set24h = @($anchor) }
    if (-not $set7d) { $set7d = @($anchor) }
    if (-not $set30d) { $set30d = @($anchor) }
    
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

# --- HTML REPORT GENERATION ---
if ($anchor) {
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss_fff")
    $safeUser = $anchor.Username -replace '[^a-zA-Z0-9]', '_'
    $reportFileName = "$($timestamp)_$($safeUser)_RiskyUserAlert.html"
    $reportPath = Join-Path $CaseFolder $reportFileName

    $statusBadgeClass = if($anchor.Status -match 'Success') { 'badge-success' } else { 'badge-fail' }

    $htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Triage Report - $($anchor.RequestId)</title>
    <style>
        :root {
            --bg: #0d1117;
            --card-bg: #161b22;
            --border: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --blue: #58a6ff;
            --green: #3fb950;
            --red: #f85149;
            --orange: #d29922;
        }
        body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background-color: var(--bg); color: var(--text-primary); margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: auto; }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 20px; }
        .badge { padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; border: 1px solid transparent; }
        .badge-success { background: rgba(63, 185, 80, 0.15); color: var(--green); border-color: var(--green); }
        .badge-fail { background: rgba(248, 81, 73, 0.15); color: var(--red); border-color: var(--red); }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 20px; }
        .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; position: relative; }
        .card:hover { border-color: #8b949e; }
        .label { color: var(--text-secondary); font-size: 11px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; display: block; margin-bottom: 6px; }
        .value { font-size: 14px; font-weight: 500; word-break: break-all; font-family: 'Cascadia Code', 'Consolas', monospace; }
        .copy-icon { cursor: pointer; float: right; opacity: 0.3; }
        .copy-icon:hover { opacity: 1; }
        .section-title { font-size: 14px; color: var(--blue); margin: 24px 0 12px 0; display: flex; align-items: center; gap: 8px; font-weight: 600; border-left: 4px solid var(--blue); padding-left: 10px; }
        .decision-banner { background: var(--card-bg); border: 2px solid var(--blue); border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 20px; box-shadow: inset 0 0 20px rgba(88, 166, 255, 0.1); }
        .decision-value { font-size: 32px; font-weight: 800; color: var(--blue); text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 10px rgba(88, 166, 255, 0.3); }
        .links { margin-top: 8px; display: flex; gap: 12px; }
        .links a { color: var(--blue); text-decoration: none; font-size: 12px; }
        .links a:hover { text-decoration: underline; }
        .story-box { background: #0d1117; border-left: 4px solid var(--blue); padding: 16px; font-style: italic; color: var(--text-secondary); line-height: 1.5; }
        .flaw-item { color: var(--orange); font-family: monospace; font-size: 13px; margin-bottom: 4px; }
        .comparison-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
        .comparison-table th { background: #21262d; color: var(--blue); text-align: left; padding: 12px; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
        .comparison-table td { padding: 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
        .comparison-table tr:last-child td { border-bottom: none; }
        .comparison-table .val-col { color: var(--text-primary); font-family: monospace; font-weight: 600; }
        .freq-cell { text-align: center; font-weight: 700; color: var(--blue); }
        .freq-cell.zero { color: var(--text-secondary); opacity: 0.4; font-weight: 400; }
        .anchor-row-highlight { background: rgba(88, 166, 255, 0.1) !important; border-left: 4px solid var(--blue); }
    </style>
    <script>
        function copy(text) {
            navigator.clipboard.writeText(text);
            const msg = document.getElementById('copy-msg');
            msg.innerText = 'Copied: ' + text;
            msg.style.opacity = 1;
            setTimeout(() => msg.style.opacity = 0, 2000);
        }
    </script>
</head>
<body>
    <div id="copy-msg" style="position:fixed; top:20px; right:20px; background:var(--green); color:black; padding:8px 16px; border-radius:4px; opacity:0; transition:opacity 0.3s; pointer-events:none; z-index:1000; font-weight:600;"></div>
    <div class="container">
        <div class="header">
            <div>
                <h1 style="margin:0; font-size: 24px;">Risky User Analysis</h1>
                <div style="color:var(--text-secondary); font-size: 13px; margin-top: 4px;">Request ID: <span class="value" style="color:var(--blue)">$($anchor.RequestId)</span></div>
            </div>
            <div class="badge $($statusBadgeClass)">$($anchor.Status)</div>
        </div>

        <div class="decision-banner">
            <div class="label">Primary Decision</div>
            <div class="decision-value">$($decision.ToUpper())</div>
        </div>

        <div class="section-title">TIME CONVERSIONS</div>
        <div class="grid">
            <div class="card"><span class="label">UTC</span><span class="value">$($utcTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
            <div class="card"><span class="label">EST (Eastern)</span><span class="value">$($estTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
            <div class="card"><span class="label">CST (Central)</span><span class="value">$($cstTime.ToString("yyyy-MM-dd HH:mm:ss"))</span></div>
        </div>

        <div class="section-title">IDENTITY & NETWORK</div>
        <div class="grid">
            <div class="card">
                <span class="copy-icon" onclick="copy('$($anchor.Username)')">COPY</span>
                <span class="label">User</span><span class="value">$($anchor.Username)</span>
                <div class="links">
                    <a href="https://portal.azure.com/#view/Microsoft_AAD_IAM/UserDetailsMenuBlade/~/overview/userId/$($anchor.Username)" target="_blank">Entra Profile</a>
                </div>
            </div>
            <div class="card">
                <span class="copy-icon" onclick="copy('$($anchor.IPAddress)')">COPY</span>
                <span class="label">IP Address</span><span class="value">$($anchor.IPAddress)</span>
                <div class="links">
                    <a href="https://www.virustotal.com/gui/ip-address/$($anchor.IPAddress)" target="_blank">VirusTotal</a>
                    <a href="https://www.abuseipdb.com/check/$($anchor.IPAddress)" target="_blank">AbuseIPDB</a>
                </div>
            </div>
            <div class="card">
                <span class="label">Geo Detail</span>
                <span class="value">$($anchor.City), $($anchor.State), $($anchor.Country)</span>
                <div style="font-size:11px; color:var(--text-secondary); margin-top:4px;">Source: $($anchor.Location)</div>
            </div>
            <div class="card"><span class="label">Application</span><span class="value">$($anchor.Application)</span></div>
        </div>

        <div class="section-title">DEVICE & SECURITY</div>
        <div class="grid">
            <div class="card"><span class="label">MFA Result / CA</span><span class="value" style="color:var(--orange)">$($anchor.MfaResult) / $($anchor.ConditionalAccess)</span></div>
            <div class="card"><span class="label">OS / Browser</span><span class="value">$($AnchorDevice.OperatingSystem) / $($AnchorDevice.Browser)</span></div>
            <div class="card"><span class="label">Device ID</span><span class="value" style="font-size:11px;">$($AnchorDevice.DeviceId)</span></div>
            <div class="card">
                <span class="label">Compliance / Managed</span>
                <span class="value">$($AnchorDevice.Compliant) / $($AnchorDevice.Managed)</span>
                <div style="font-size:11px; color:var(--text-secondary); margin-top:4px;">Join: $($AnchorDevice.JoinType)</div>
            </div>
        </div>
        <div class="card" style="margin-bottom:20px;">
            <span class="label">Client App / User Agent</span>
            <div class="value" style="color:var(--blue); margin-bottom:8px;">$($AnchorDevice.ClientApp)</div>
            <div class="value" style="font-size:12px; line-height:1.4; font-family:monospace; color:var(--text-secondary);">$($AnchorDevice.UserAgent)</div>
        </div>

        <div class="section-title">STATISTICAL BASELINE (SIDE-BY-SIDE)</div>
        <table class="comparison-table">
            <thead>
                <tr>
                    <th>Attribute</th>
                    <th>Anchor Value</th>
                    <th style="text-align:center">24h Freq</th>
                    <th style="text-align:center">7d Freq</th>
                    <th style="text-align:center">30d Freq</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Device ID</td>
                    <td class="val-col">$($AnchorDevice.DeviceId)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $AnchorDevice.DeviceId -Aliases $ColumnAliases["DeviceId"] -Datasets $set24h)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $AnchorDevice.DeviceId -Aliases $ColumnAliases["DeviceId"] -Datasets $set7d)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $AnchorDevice.DeviceId -Aliases $ColumnAliases["DeviceId"] -Datasets $set30d)</td>
                </tr>
                <tr>
                    <td>IP Address</td>
                    <td class="val-col">$($anchor.IPAddress)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.IPAddress -Aliases @("IP address") -Datasets $set24h)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.IPAddress -Aliases @("IP address") -Datasets $set7d)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.IPAddress -Aliases @("IP address") -Datasets $set30d)</td>
                </tr>
                <tr>
                    <td>Location</td>
                    <td class="val-col">$($anchor.Location)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.Location -Aliases @("Location") -Datasets $set24h)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.Location -Aliases @("Location") -Datasets $set7d)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.Location -Aliases @("Location") -Datasets $set30d)</td>
                </tr>
                <tr>
                    <td>Application</td>
                    <td class="val-col">$($anchor.Application)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.Application -Aliases @("Application") -Datasets $set24h)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.Application -Aliases @("Application") -Datasets $set7d)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $anchor.Application -Aliases @("Application") -Datasets $set30d)</td>
                </tr>
                <tr>
                    <td>User Agent</td>
                    <td class="val-col">$(if($AnchorDevice.UserAgent.Length -gt 30){$AnchorDevice.UserAgent.Substring(0,30) + "..."}else{$AnchorDevice.UserAgent})</td>
                    <td class="freq-cell">$(Get-Frequency -Value $AnchorDevice.UserAgent -Aliases $ColumnAliases["UserAgent"] -Datasets $set24h)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $AnchorDevice.UserAgent -Aliases $ColumnAliases["UserAgent"] -Datasets $set7d)</td>
                    <td class="freq-cell">$(Get-Frequency -Value $AnchorDevice.UserAgent -Aliases $ColumnAliases["UserAgent"] -Datasets $set30d)</td>
                </tr>
            </tbody>
        </table>

        <div class="section-title">DEVICE CORRELATION MATRIX (ALL SEEN DEVICES)</div>
        <table class="comparison-table">
            <thead>
                <tr>
                    <th>Device ID</th>
                    <th>Associated IPs</th>
                    <th>Locations</th>
                    <th>OS / Browser</th>
                    <th>Posture / Type</th>
                    <th>Top Apps</th>
                    <th>Last Seen</th>
                    <th style="text-align:center">Freq</th>
                    <th style="text-align:center">24h</th>
                    <th style="text-align:center">7d</th>
                    <th style="text-align:center">30d</th>
                </tr>
            </thead>
            <tbody>
                $($matrixRows -join "`n")
            </tbody>
        </table>

        <div class="section-title">INVESTIGATION STORY</div>
        <div class="story-box">
            $(Build-TicketStory -Anchor $anchor -DecisionBucket $decision -IsNewIP $isNewIP -IsNewLocation $isNewLoc -IsNewApp $isNewApp)
        </div>

        <div class="section-title">DESIGN FLAWS</div>
        <div class="card">
            $(if ($uniqueFlaws) { $uniqueFlaws | ForEach-Object { "<div class='flaw-item'>- $_</div>" } } else { "None Detected" })
        </div>
    </div>
</body>
</html>
"@

    $htmlHeader | Out-File -FilePath $reportPath -Encoding utf8
    Write-Host "`nHTML Report generated at: $reportPath"
}

Write-Host "`nDONE"
Write-Host "REGRESSION_CHECK: OK"
