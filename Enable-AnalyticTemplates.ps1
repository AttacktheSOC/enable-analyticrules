
<# 
.SYNOPSIS
    Enable Microsoft Sentinel Analytic Rules from Content Templates with flexible command-line filtering (Title, TTPs, DataType) and confirmation prompt.
.DESCRIPTION
    Combines robust authentication and baseline packaging with command-line filtering options, including a third filter on required data types (tables) found in requiredDataConnectors[*].dataTypes.
    -Title <string>           : Partial match against rule Display Name (case-insensitive)
    -TTPs  <comma-separated>  : Exact match against MITRE ATT&CK techniques/subTechniques (e.g., T1059, T1562.001), uses or logic on lists of ttps
    -DataType <string>        : Exact match against normalized dataTypes (e.g., DeviceProcessEvents, SecurityAlert, AzureDiagnostics)
    -or                       : If provided AND multiple filters are specified, selection uses OR logic; default is AND.
    If no filters are provided, ALL templates are enabled (subject to existing rule check).
.NOTES
    Requires Az.Accounts module. Run Connect-AzAccount before use if you don't have a current context.
#>

[CmdletBinding()] 
param(
    [Parameter(Mandatory = $true)]
    [string]$subscriptionId,
    [Parameter(Mandatory = $true)]
    [string]$resourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]$workspaceName,
    [Parameter(Mandatory = $false)]
    [string]$Title,
    [Parameter(Mandatory = $false)]
    [string]$TTPs,
    [Parameter(Mandatory = $false)]
    [string]$DataType,
    [Parameter(Mandatory = $false)]
    [switch]$or
)

# ---------------------------------------------
# AUTH
# ---------------------------------------------
$apiVersion = "2023-04-01-preview"
Write-Host "Getting Azure access token..." -ForegroundColor Cyan
try {
    $token = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
    if ($token -is [System.Security.SecureString]) {
        $token = [System.Net.NetworkCredential]::new("", $token).Password
    }
} catch {
    Write-Warning "Failed to get Azure access token. Please run 'Connect-AzAccount' first. Error: $_"
    return
}
$headers = @{ 
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

# ---------------------------------------------
# Helper: extract techniques/subTechniques from template
# ---------------------------------------------
function Get-TemplateTechniques {
    param([Parameter(Mandatory)] $Template)
    function _ToArray([object] $Value) {
        if ($null -eq $Value) { return @() }
        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return @($Value) }
        return @($Value)
    }
    if ($null -eq $Template -or $null -eq $Template.properties) { return @() }
    $main = $Template.properties.mainTemplate
    if ($null -eq $main -or $null -eq $main.resources) { return @() }
    $resources = $main.resources
    if ($resources -isnot [System.Collections.IEnumerable] -or $resources -is [string]) { $resources = @($resources) }
    $parents = @{}; $subs = @{}
    foreach ($res in $resources) {
        $props = $res.properties
        if ($null -eq $props) { continue }
        foreach ($t in (_ToArray $props.techniques)) {
            if ($null -ne $t -and -not [string]::IsNullOrWhiteSpace([string]$t)) {
                $key = ([string]$t).ToUpperInvariant()
                if (-not $parents.ContainsKey($key)) { $parents[$key] = $true }
            }
        }
        foreach ($st in (_ToArray $props.subTechniques)) {
            if ($null -ne $st -and -not [string]::IsNullOrWhiteSpace([string]$st)) {
                $key = ([string]$st).ToUpperInvariant()
                if (-not $subs.ContainsKey($key)) { $subs[$key] = $true }
            }
        }
    }
    if ($subs.Count -gt 0 -and $parents.Count -gt 0) {
        $parentsToDrop = @{}
        foreach ($p in $parents.Keys) {
            foreach ($st in $subs.Keys) {
                if ($st.StartsWith("$p")) { $parentsToDrop[$p] = $true; break }
            }
        }
        foreach ($drop in $parentsToDrop.Keys) { $parents.Remove($drop) }
    }
    $final = @{}
    foreach ($p in $parents.Keys) { $final[$p] = $true }
    foreach ($s in $subs.Keys)    { $final[$s] = $true }
    return [string[]]$final.Keys
}

# ---------------------------------------------
# Helper: normalize dataTypes and extract from template
# ---------------------------------------------
function Normalize-DataType([string]$dt) {
    if ([string]::IsNullOrWhiteSpace($dt)) { return $null }
    $n = $dt.Trim()
    $n = $n -replace '\s*\(.*\)$',''
    return $n.ToUpperInvariant()
}

function Get-TemplateDataTypes($tpl) {
    $dataTypes = @()
    if ($null -eq $tpl -or $null -eq $tpl.properties) { return @() }
    $main = $tpl.properties.mainTemplate
    if ($null -eq $main -or $null -eq $main.resources) { return @() }
    $resources = $main.resources
    if ($resources -isnot [System.Collections.IEnumerable] -or $resources -is [string]) { $resources = @($resources) }
    foreach ($res in $resources) {
        $props = $res.properties
        if ($null -eq $props -or -not $props.requiredDataConnectors) { continue }
        foreach ($rdc in $props.requiredDataConnectors) {
            if ($null -eq $rdc) { continue }
            $types = $rdc.dataTypes
            if ($null -eq $types) { continue }
            if ($types -isnot [System.Collections.IEnumerable] -or $types -is [string]) { $types = @($types) }
            foreach ($dt in $types) {
                $norm = Normalize-DataType ([string]$dt)
                if ($norm) { $dataTypes += $norm }
            }
        }
    }
    return $dataTypes | Select-Object -Unique
}

# ---------------------------------------------
# GET EXISTING ALERT RULES
# ---------------------------------------------
Write-Host "Fetching existing alert rules..." -ForegroundColor Cyan
$alertRulesUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules`?api-version=$apiVersion"
try {
    $existingRulesResp = Invoke-RestMethod -Uri $alertRulesUrl -Headers $headers -Method GET
    $existingRules = @{}
    foreach ($rule in $existingRulesResp.value) { $existingRules[$rule.name] = $rule.properties.displayName }
    Write-Host "Found $($existingRules.Count) existing alert rules." -ForegroundColor Green
} catch {
    Write-Warning "Failed to retrieve existing alert rules: $_"
    return
}

# ---------------------------------------------
# GET CONTENT TEMPLATES (AnalyticsRule)
# ---------------------------------------------
Write-Host "Fetching analytic rule templates..." -ForegroundColor Cyan
$templatesUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contenttemplates`?api-version=$apiVersion&`$filter=(properties/contentKind eq 'AnalyticsRule')"
try {
    $templatesJson = Invoke-RestMethod -Uri $templatesUrl -Headers $headers -Method GET
    Write-Host "Found $($templatesJson.value.Count) analytic rule templates." -ForegroundColor Green
} catch {
    Write-Warning "Failed to retrieve content templates: $_"
    return
}
$allTemplates = @($templatesJson.value)

# ---------------------------------------------
# FILTERING (command-line options)
# ---------------------------------------------
$targetTTPs = @()
if (-not [string]::IsNullOrWhiteSpace($TTPs)) {
    $targetTTPs = $TTPs.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                  ForEach-Object { $_.ToUpperInvariant() } | Where-Object { $_ -match '^T\d{4}(\.\d{3})?$' } | Select-Object -Unique
}

function Get-DisplayNameFromTemplate($tpl) {
    $main = $tpl.properties.mainTemplate
    if ($null -ne $main -and $null -ne $main.resources) {
        $inner = $main.resources | Where-Object { $_.type -eq "Microsoft.SecurityInsights/AlertRuleTemplates" } | Select-Object -First 1
        if ($inner -and $inner.properties -and $inner.properties.displayName) { return [string]$inner.properties.displayName }
    }
    if ($tpl.properties.displayName) { return [string]$tpl.properties.displayName }
    return "(no displayName)"
}

$selectedTemplates = @()
foreach ($tpl in $allTemplates) {
    $ruleTitle = Get-DisplayNameFromTemplate $tpl

    # Title match (contains, case-insensitive)
    $titleMatch = $false
    $hasTitleFilter = -not [string]::IsNullOrWhiteSpace($Title)
    if ($hasTitleFilter) { $titleMatch = ($ruleTitle -like "*${Title}*") }

    # TTP match (exact any)
    $ttpMatch = $false
    $hasTtpFilter = ($targetTTPs.Count -gt 0)
    if ($hasTtpFilter) {
        $tmplIds = Get-TemplateTechniques -Template $tpl
        if ($tmplIds -and $tmplIds.Count -gt 0) {
            $lookup = @{}
            foreach ($id in $tmplIds) { if (-not $lookup.ContainsKey($id)) { $lookup[$id] = $true } }
            foreach ($u in $targetTTPs) { if ($lookup.ContainsKey($u)) { $ttpMatch = $true; break } }
        }
    }

    # DataType match (exact after normalization, across all connectors)
    $dataTypeMatch = $false
    $hasDataTypeFilter = -not [string]::IsNullOrWhiteSpace($DataType)
    if ($hasDataTypeFilter) {
        $normUserDT = Normalize-DataType $DataType
        $tplDTs = Get-TemplateDataTypes $tpl
        if ($tplDTs -and $tplDTs.Count -gt 0 -and $normUserDT) {
            $dataTypeMatch = ($tplDTs -contains $normUserDT)
        }
    }

    # Decide selection based on provided filters and -or
    $bools = @()
    if ($hasTitleFilter)    { $bools += $titleMatch }
    if ($hasTtpFilter)      { $bools += $ttpMatch }
    if ($hasDataTypeFilter) { $bools += $dataTypeMatch }

    $shouldSelect = $false
    if ($bools.Count -eq 0) {
        # No filters provided: select all
        $shouldSelect = $true
    } elseif ($or) {
        $shouldSelect = ($bools -contains $true)
    } else {
        # AND across provided filters
        $shouldSelect = (-not ($bools -contains $false))
    }

    if ($shouldSelect) { $selectedTemplates += $tpl }
}

Write-Host "Selected $($selectedTemplates.Count) template(s) to enable." -ForegroundColor Cyan
if (-not $selectedTemplates -or $selectedTemplates.Count -eq 0) {
    Write-Warning "No templates matched the chosen criteria. Nothing to enable."
    return
}

# ---------------------------------------------
# Confirmation prompt (what-if with count)
# ---------------------------------------------
Write-Host ""; Write-Host "The following rules will be enabled:" -ForegroundColor Yellow
foreach ($tpl in $selectedTemplates) {
    $ruleTitle  = Get-DisplayNameFromTemplate $tpl
    $templateId = $tpl.properties.contentId
    $dataTypes  = (Get-TemplateDataTypes $tpl) -join ", "
    Write-Host " - $ruleTitle (TemplateId: $templateId) [DataTypes: $dataTypes]"
}
Write-Host ""
$ruleCount = $selectedTemplates.Count
$confirm = Read-Host "Proceed to enable these $ruleCount rule(s)? (Y/N)"
if ($confirm -notin @('Y','y','Yes','YES')) {
    Write-Host "Cancelled. No rules were enabled." -ForegroundColor Cyan
    return
}

# ---------------------------------------------
# CREATE ALERT RULES (baseline packaging preserved)
# ---------------------------------------------
$createdCount = 0
$skippedCount = 0
$failedCount  = 0

foreach ($tpl in $selectedTemplates) {
    $ruleTitle = Get-DisplayNameFromTemplate $tpl
    Write-Host "`nProcessing template: $ruleTitle" -ForegroundColor Gray

    $mainTemplate = $tpl.properties.mainTemplate
    if ($null -eq $mainTemplate -or $null -eq $mainTemplate.resources) {
        Write-Warning "Template '$ruleTitle' does not have 'mainTemplate.resources'. Skipping."
        $skippedCount++
        continue
    }

    $alertRuleResource = $mainTemplate.resources | Where-Object { $_.type -eq "Microsoft.SecurityInsights/AlertRuleTemplates" } | Select-Object -First 1
    if ($null -eq $alertRuleResource) {
        Write-Warning "Template '$ruleTitle' does not contain 'AlertRuleTemplates' resource. Skipping."
        $skippedCount++
        continue
    }

    $ruleId = $alertRuleResource.name
    if ($existingRules.ContainsKey($ruleId)) {
        Write-Host "Rule '$ruleTitle' already exists in workspace. Skipping." -ForegroundColor Yellow
        $skippedCount++
        continue
    }

    Write-Host "Creating new rule: '$ruleTitle'" -ForegroundColor Green

    # Copy properties from template resource (baseline behavior)
    $bodyProperties = @{}
    $alertRuleResource.properties.psobject.Properties | ForEach-Object { $bodyProperties[$_.Name] = $_.Value }

    # Force enable + tie to original template
    $bodyProperties.enabled = $true
    $bodyProperties.alertRuleTemplateName = $tpl.properties.contentId

    $body = @{
        name       = $ruleId
        type       = "Microsoft.SecurityInsights/alertRules"
        kind       = $alertRuleResource.kind
        properties = $bodyProperties
    }

    $bodyJson = $body | ConvertTo-Json -Depth 10
    $putUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertrules/$ruleId`?api-version=$apiVersion"

    try {
        Invoke-RestMethod -Uri $putUrl -Method PUT -Headers $headers -Body $bodyJson
        Write-Host "Success: Created alert rule '$ruleTitle'." -ForegroundColor Green
        $createdCount++
    } catch {
        Write-Warning "Failed to create rule '$ruleTitle': $_"
        $failedCount++
    }
}

# ---------------------------------------------
# SUMMARY
# ---------------------------------------------
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "  - Created new rules: $createdCount"
Write-Host "  - Skipped (already enabled or invalid): $skippedCount"
Write-Host "  - Failed: $failedCount"
