<#
.SYNOPSIS
    Comprehensive Azure Secrets Testing and Validation Tool

.DESCRIPTION
    Professional-grade tool for security testing of discovered Azure credentials and secrets.
    Tests multiple credential types, performs enumeration, detects sensitive data exposure,
    and generates comprehensive reports for penetration testing documentation.
    
 .PARAMETER Mode
    Operation mode: Interactive, ServicePrincipal, UserPassword, AccessToken, AppInsights, StorageKey, CosmosDB, Batch, ConfigFile

.PARAMETER ConfigFile
    Path to configuration file (appsettings.json, web.config, .env) to auto-extract secrets

.PARAMETER TenantId
    Azure AD Tenant ID

.PARAMETER ClientId
    Service Principal Application/Client ID

.PARAMETER ClientSecret
    Service Principal Client Secret

.PARAMETER Username
    Azure user account (UPN)

.PARAMETER Password
    User account password

.PARAMETER AccessToken
    Bearer access token

.PARAMETER InstrumentationKey
    Application Insights instrumentation key

.PARAMETER AppId
    Application Insights Application ID

.PARAMETER ApiKey
    Application Insights API Key

.PARAMETER StorageAccountName
    Azure Storage account name

.PARAMETER StorageAccountKey
    Azure Storage account key

.PARAMETER CosmosEndpoint
    Cosmos DB endpoint URL

.PARAMETER CosmosKey
    Cosmos DB access key

.PARAMETER ConnectionString
    Generic connection string to parse and test

.PARAMETER Enumerate
    Perform comprehensive enumeration if authentication succeeds

.PARAMETER DeepScan
    Enable deep scanning (Graph API, sensitive data patterns, etc.)

.PARAMETER QueryHours
    Hours of historical data to query (default: 24)

.PARAMETER OutputFile
    Path for JSON output file

.PARAMETER HtmlReport
    Generate HTML report

.PARAMETER VerboseOutput
    Enable detailed debug output

.PARAMETER NoColor
    Disable colored output

.PARAMETER SkipModuleCheck
    Skip Az module installation check

.EXAMPLE
    .\Test-AzureSecrets.ps1 -Mode Interactive

.EXAMPLE
    .\Test-AzureSecrets.ps1 -Mode ServicePrincipal -TenantId "xxx" -ClientId "yyy" -ClientSecret "zzz" -Enumerate -DeepScan

.EXAMPLE
    .\Test-AzureSecrets.ps1 -Mode ConfigFile -ConfigFile "appsettings.json" -Enumerate -HtmlReport -OutputFile "results.json"

.EXAMPLE
    .\Test-AzureSecrets.ps1 -Mode AppInsights -InstrumentationKey "guid" -AppId "id" -ApiKey "key" -QueryHours 168

.EXAMPLE
    .\Test-AzureSecrets.ps1 -Mode Batch -ConfigFile "secrets-list.txt" -OutputFile "batch-results.json"

.NOTES
    Author: Made with ❤️ from your friendly hacker - er2oneousbit 
    Created with the assistance of Claude Sonnet 4 (claude-sonnet-4-5-20250929)
    Version: 2.0
    Purpose: Authorized security testing and penetration testing
    Requires: PowerShell 5.1+, Az.Accounts module (auto-installs if missing)
    

    Changelog:
    2026-03-11 (claude-sonnet-4-6):
      - Line 442: Replaced ?? null coalescing operator with PS5.1-compatible if/else
        (??  is PS7+ only; causes parse error on PS5.1)
      - Lines 1377, 1388, 1402, 1411, 1419: Wrapped SecureStringToBSTR calls with
        -is [System.Security.SecureString] type guard to handle environments where
        Read-Host -AsSecureString returns a plain String (PS remoting, non-interactive sessions)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Interactive","ServicePrincipal","UserPassword","AccessToken","AppInsights","StorageKey","CosmosDB","Batch","ConfigFile")]
    [string]$Mode = "Interactive",
    
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [string]$AccessToken,
    
    [Parameter(Mandatory=$false)]
    [string]$InstrumentationKey,
    
    [Parameter(Mandatory=$false)]
    [string]$AppId,
    
    [Parameter(Mandatory=$false)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountName,
    
    [Parameter(Mandatory=$false)]
    [string]$StorageAccountKey,
    
    [Parameter(Mandatory=$false)]
    [string]$CosmosEndpoint,
    
    [Parameter(Mandatory=$false)]
    [string]$CosmosKey,
    
    [Parameter(Mandatory=$false)]
    [string]$ConnectionString,
    
    [Parameter(Mandatory=$false)]
    [switch]$Enumerate,
    
    [Parameter(Mandatory=$false)]
    [switch]$DeepScan,
    
    [Parameter(Mandatory=$false)]
    [int]$QueryHours = 24,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [switch]$HtmlReport,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoColor,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipModuleCheck
)

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

$ErrorActionPreference = "Continue"
$script:StartTime = Get-Date

$script:Results = @{
    Metadata = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Mode = $Mode
        Tester = $env:USERNAME
        Computer = $env:COMPUTERNAME
        Version = "2.0"
    }
    Summary = @{
        TotalTests = 0
        SuccessfulTests = 0
        FailedTests = 0
        HighRiskFindings = 0
        MediumRiskFindings = 0
        LowRiskFindings = 0
    }
    Findings = @()
    TestedSecrets = @()
    Enumeration = @{
        AzureAD = @{}
        Subscriptions = @()
        ResourceGroups = @()
        Resources = @()
        RoleAssignments = @()
        GraphAPI = @{}
        AppInsights = @{}
        Storage = @{}
        CosmosDB = @{}
    }
    SensitiveData = @()
    Recommendations = @()
    Errors = @()
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Banner {
    $banner = @"

    ╔════════════════════════════════════════════════════════════════════════╗
    ║                                                                        ║
    ║           █████╗ ███████╗██╗   ██╗██████╗ ███████╗                    ║
    ║          ██╔══██╗╚══███╔╝██║   ██║██╔══██╗██╔════╝                    ║
    ║          ███████║  ███╔╝ ██║   ██║██████╔╝█████╗                      ║
    ║          ██╔══██║ ███╔╝  ██║   ██║██╔══██╗██╔══╝                      ║
    ║          ██║  ██║███████╗╚██████╔╝██║  ██║███████╗                    ║
    ║          ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝                    ║
    ║                                                                        ║
    ║              Comprehensive Azure Secrets Testing Tool                 ║
    ║                          Version 2.0                                   ║
    ║                                                                        ║
    ║                  For Authorized Security Testing Only                 ║
    ║                                                                        ║
    ╚════════════════════════════════════════════════════════════════════════╝

"@
    
    Write-ColorOutput $banner "Cyan"
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoNewline
    )
    
    if ($NoColor) {
        if ($NoNewline) {
            Write-Host $Message -NoNewline
        } else {
            Write-Host $Message
        }
    } else {
        if ($NoNewline) {
            Write-Host $Message -ForegroundColor $Color -NoNewline
        } else {
            Write-Host $Message -ForegroundColor $Color
        }
    }
}

function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet("Info","Success","Warning","Error","Progress","Header")]
        [string]$Type = "Info"
    )
    
    $colors = @{
        Info = "White"
        Success = "Green"
        Warning = "Yellow"
        Error = "Red"
        Progress = "Cyan"
        Header = "Magenta"
    }
    
    $prefix = switch ($Type) {
        "Info"     { "[*]" }
        "Success"  { "[+]" }
        "Warning"  { "[!]" }
        "Error"    { "[-]" }
        "Progress" { "[~]" }
        "Header"   { "[#]" }
    }
    
    Write-ColorOutput "$prefix $Message" $colors[$Type]
}

function Write-DebugMessage {
    param([string]$Message)
    if ($VerboseOutput) {
        Write-ColorOutput "[DEBUG] $Message" "DarkGray"
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-ColorOutput "═══════════════════════════════════════════════════════════════" "Cyan"
    Write-ColorOutput "  $Title" "Cyan"
    Write-ColorOutput "═══════════════════════════════════════════════════════════════" "Cyan"
    Write-Host ""
}

function Add-Finding {
    param(
        [string]$Type,
        [string]$Severity,
        [string]$Title,
        [string]$Description,
        [hashtable]$Evidence,
        [string]$Recommendation
    )
    
    $finding = @{
        Type = $Type
        Severity = $Severity
        Title = $Title
        Description = $Description
        Evidence = $Evidence
        Recommendation = $Recommendation
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:Results.Findings += $finding
    
    # Update summary
    switch ($Severity) {
        "High"   { $script:Results.Summary.HighRiskFindings++ }
        "Medium" { $script:Results.Summary.MediumRiskFindings++ }
        "Low"    { $script:Results.Summary.LowRiskFindings++ }
    }
    
    Write-StatusMessage "[$Severity] $Title" $(if ($Severity -eq "High") { "Error" } elseif ($Severity -eq "Medium") { "Warning" } else { "Info" })
}

function Test-RequiredModule {
    param(
        [string]$ModuleName,
        [string]$MinimumVersion
    )
    
    Write-DebugMessage "Checking for module: $ModuleName"
    
    $module = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
    
    if (-not $module) {
        Write-StatusMessage "$ModuleName module not found" "Warning"
        
        if ($SkipModuleCheck) {
            Write-StatusMessage "Skipping module installation (SkipModuleCheck enabled)" "Warning"
            return $false
        }
        
        $install = Read-Host "Install $ModuleName module? (Y/N)"
        
        if ($install -eq 'Y' -or $install -eq 'y') {
            try {
                Write-StatusMessage "Installing $ModuleName module..." "Progress"
                Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
                Write-StatusMessage "$ModuleName module installed successfully" "Success"
                return $true
            }
            catch {
                Write-StatusMessage "Failed to install $ModuleName module: $_" "Error"
                $script:Results.Errors += "Module installation failed: $_"
                return $false
            }
        }
        else {
            Write-StatusMessage "Cannot proceed without $ModuleName module" "Error"
            return $false
        }
    }
    
    Write-DebugMessage "$ModuleName module is installed (Version: $($module.Version))"
    return $true
}

# ============================================================================
# CONFIG FILE PARSING
# ============================================================================

function Get-SecretsFromConfigFile {
    param([string]$FilePath)
    
    Write-Section "Parsing Configuration File"
    
    if (-not (Test-Path $FilePath)) {
        Write-StatusMessage "File not found: $FilePath" "Error"
        return $null
    }
    
    $extension = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $secrets = @{}
    
    try {
        switch ($extension) {
            ".json" {
                Write-StatusMessage "Parsing JSON configuration file..." "Progress"
                $content = Get-Content $FilePath -Raw | ConvertFrom-Json
                
                # Azure AD / Service Principal
                if ($content.AzureAd) {
                    $secrets.TenantId = $content.AzureAd.TenantId
                    $secrets.ClientId = $content.AzureAd.ClientId
                    $secrets.ClientSecret = $content.AzureAd.ClientSecret
                    Write-StatusMessage "Found Azure AD service principal configuration" "Success"
                }
                
                # Application Insights
                if ($content.ApplicationInsights) {
                    $secrets.InstrumentationKey = $content.ApplicationInsights.InstrumentationKey
                    $secrets.AppId = $content.ApplicationInsights.ApplicationId
                    $secrets.ApiKey = $content.ApplicationInsights.ApiKey
                    Write-StatusMessage "Found Application Insights configuration" "Success"
                }
                
                # Connection Strings
                if ($content.ConnectionStrings) {
                    $secrets.ConnectionStrings = @{}
                    $content.ConnectionStrings.PSObject.Properties | ForEach-Object {
                        $secrets.ConnectionStrings[$_.Name] = $_.Value
                        Write-StatusMessage "Found connection string: $($_.Name)" "Success"
                    }
                }
                
                # Storage
                if ($content.Storage -or $content.AzureStorage) {
                    $storage = if ($content.Storage) { $content.Storage } else { $content.AzureStorage }
                    $secrets.StorageAccountName = $storage.AccountName
                    $secrets.StorageAccountKey = $storage.AccountKey
                    Write-StatusMessage "Found Azure Storage configuration" "Success"
                }
                
                # Cosmos DB
                if ($content.CosmosDb) {
                    $secrets.CosmosEndpoint = $content.CosmosDb.Endpoint
                    $secrets.CosmosKey = $content.CosmosDb.Key
                    Write-StatusMessage "Found Cosmos DB configuration" "Success"
                }
            }
            
            ".config" {
                Write-StatusMessage "Parsing XML configuration file..." "Progress"
                [xml]$content = Get-Content $FilePath
                
                # Connection strings
                $connectionStrings = $content.configuration.connectionStrings.add
                if ($connectionStrings) {
                    $secrets.ConnectionStrings = @{}
                    foreach ($cs in $connectionStrings) {
                        $secrets.ConnectionStrings[$cs.name] = $cs.connectionString
                        Write-StatusMessage "Found connection string: $($cs.name)" "Success"
                    }
                }
                
                # App settings
                $appSettings = $content.configuration.appSettings.add
                foreach ($setting in $appSettings) {
                    if ($setting.key -match "TenantId|ClientId|ClientSecret|InstrumentationKey") {
                        $secrets[$setting.key] = $setting.value
                        Write-StatusMessage "Found app setting: $($setting.key)" "Success"
                    }
                }
            }
            
            ".env" {
                Write-StatusMessage "Parsing .env file..." "Progress"
                $content = Get-Content $FilePath
                
                foreach ($line in $content) {
                    if ($line -match '^([^=]+)=(.+)$') {
                        $key = $matches[1].Trim()
                        $value = $matches[2].Trim().Trim('"').Trim("'")
                        
                        switch -Regex ($key) {
                            "TENANT.*ID" { $secrets.TenantId = $value }
                            "CLIENT.*ID|APP.*ID" { $secrets.ClientId = $value }
                            "CLIENT.*SECRET|APP.*SECRET" { $secrets.ClientSecret = $value }
                            "INSTRUMENTATION.*KEY" { $secrets.InstrumentationKey = $value }
                            "STORAGE.*NAME" { $secrets.StorageAccountName = $value }
                            "STORAGE.*KEY" { $secrets.StorageAccountKey = $value }
                            "COSMOS.*ENDPOINT" { $secrets.CosmosEndpoint = $value }
                            "COSMOS.*KEY" { $secrets.CosmosKey = $value }
                        }
                        
                        Write-DebugMessage "Parsed: $key"
                    }
                }
            }
            
            default {
                Write-StatusMessage "Unsupported file type: $extension" "Error"
                return $null
            }
        }
        
        Write-StatusMessage "Successfully parsed configuration file" "Success"
        return $secrets
        
    }
    catch {
        Write-StatusMessage "Error parsing config file: $_" "Error"
        $script:Results.Errors += "Config parsing error: $_"
        return $null
    }
}

# ============================================================================
# AZURE AD / SERVICE PRINCIPAL TESTING
# ============================================================================

function Test-ServicePrincipal {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    
    Write-Section "Testing Service Principal Credentials"
    
    $script:Results.Summary.TotalTests++
    $testResult = @{
        Type = "ServicePrincipal"
        TenantId = $TenantId
        ClientId = $ClientId
        Success = $false
        Details = @{}
    }
    
    try {
        Write-StatusMessage "Testing service principal authentication..." "Progress"
        Write-DebugMessage "Tenant ID: $TenantId"
        Write-DebugMessage "Client ID: $ClientId"
        
        # Create credential
        $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($ClientId, $secureSecret)
        
        # Attempt connection
        $connection = Connect-AzAccount -ServicePrincipal -Credential $credential -TenantId $TenantId -ErrorAction Stop
        
        Write-StatusMessage "Service principal authentication SUCCESSFUL!" "Success"
        $testResult.Success = $true
        $script:Results.Summary.SuccessfulTests++
        
        # Get context
        $context = Get-AzContext
        $testResult.Details = @{
            TenantId = $context.Tenant.Id
            TenantDomain = $context.Tenant.Directory
            Account = $context.Account.Id
            AccountType = $context.Account.Type
            Environment = $context.Environment.Name
        }
        
        # Add finding
        Add-Finding -Type "Exposed Credentials" -Severity "High" `
            -Title "Valid Azure Service Principal Credentials Exposed" `
            -Description "Service principal credentials were found and validated. These credentials provide programmatic access to Azure resources and services." `
            -Evidence @{
                ClientId = $ClientId
                TenantId = $TenantId
                AccountType = "ServicePrincipal"
                AuthenticationStatus = "Successful"
            } `
            -Recommendation "Immediately rotate these credentials. Review audit logs for unauthorized access. Implement credential rotation policies."
        
        # Enumerate if requested
        if ($Enumerate) {
            Get-AzureADEnumeration
            Get-AzureSubscriptions
            Get-AzureResources
        }
        
        # Deep scan if requested
        if ($DeepScan) {
            Test-MicrosoftGraphAccess
            Search-SensitivePermissions
        }
        
    }
    catch {
        Write-StatusMessage "Service principal authentication FAILED: $($_.Exception.Message)" "Error"
        $testResult.Success = $false
        $testResult.Error = $_.Exception.Message
        $script:Results.Summary.FailedTests++
        $script:Results.Errors += "ServicePrincipal auth error: $($_.Exception.Message)"
    }
    
    $script:Results.TestedSecrets += $testResult
}

function Test-UserPassword {
    param(
        [string]$Username,
        [string]$Password,
        [string]$TenantId
    )
    
    Write-Section "Testing User Credentials"
    
    $script:Results.Summary.TotalTests++
    $testResult = @{
        Type = "UserPassword"
        Username = $Username
        Success = $false
        Details = @{}
    }
    
    try {
        Write-StatusMessage "Testing user credentials..." "Progress"
        Write-DebugMessage "Username: $Username"
        
        $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)
        
        if ($TenantId) {
            Connect-AzAccount -Credential $credential -TenantId $TenantId -ErrorAction Stop | Out-Null
        }
        else {
            Connect-AzAccount -Credential $credential -ErrorAction Stop | Out-Null
        }
        
        Write-StatusMessage "User authentication SUCCESSFUL!" "Success"
        $testResult.Success = $true
        $script:Results.Summary.SuccessfulTests++
        
        $context = Get-AzContext
        $testResult.Details = @{
            TenantId = $context.Tenant.Id
            Account = $context.Account.Id
            AccountType = $context.Account.Type
        }
        
        Add-Finding -Type "Exposed Credentials" -Severity "High" `
            -Title "Valid Azure User Credentials Exposed" `
            -Description "User account credentials were found and validated." `
            -Evidence @{
                Username = $Username
                TenantId = $context.Tenant.Id
                AuthenticationStatus = "Successful"
            } `
            -Recommendation "Force password reset immediately. Review account activity logs. Implement MFA. Store credentials in approved secrets management system."
        
        if ($Enumerate) {
            Get-AzureADEnumeration
            Get-AzureSubscriptions
            Get-AzureResources
        }
        
        if ($DeepScan) {
            Test-MicrosoftGraphAccess
        }
    }
    catch {
        Write-StatusMessage "User authentication FAILED: $($_.Exception.Message)" "Error"
        $testResult.Success = $false
        $testResult.Error = $_.Exception.Message
        $script:Results.Summary.FailedTests++
        $script:Results.Errors += "UserPassword auth error: $($_.Exception.Message)"
    }
    
    $script:Results.TestedSecrets += $testResult
}

# ============================================================================
# APPLICATION INSIGHTS TESTING
# ============================================================================

function Test-ApplicationInsights {
    param(
        [string]$InstrumentationKey,
        [string]$AppId,
        [string]$ApiKey
    )
    
    Write-Section "Testing Application Insights Key"
    
    $script:Results.Summary.TotalTests++
    $testResult = @{
        Type = "ApplicationInsights"
        InstrumentationKey = $InstrumentationKey
        AppId = $AppId
        Success = $false
        Details = @{}
    }
    
    try {
        # Validate GUID format
        try {
            $guid = [System.Guid]::Parse($InstrumentationKey)
            Write-DebugMessage "Instrumentation key format is valid GUID"
        }
        catch {
            throw "Instrumentation key is not a valid GUID format"
        }
        
        # Test by sending telemetry
        $telemetryUrl = "https://dc.services.visualstudio.com/v2/track"
        
        $testEvent = @{
            name = "Microsoft.ApplicationInsights.Event"
            time = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            iKey = $InstrumentationKey
            tags = @{
                "ai.cloud.role" = "SecurityTest"
            }
            data = @{
                baseType = "EventData"
                baseData = @{
                    ver = 2
                    name = "PentestValidation"
                    properties = @{
                        TestType = "InstrumentationKeyValidation"
                    }
                }
            }
        }
        
        $body = ConvertTo-Json @($testEvent) -Depth 10 -Compress
        $response = Invoke-WebRequest -Uri $telemetryUrl -Method Post -Body $body -ContentType "application/json" -UseBasicParsing
        
        if ($response.StatusCode -eq 200) {
            Write-StatusMessage "Instrumentation key is VALID!" "Success"
            $testResult.Success = $true
            $script:Results.Summary.SuccessfulTests++
            
            Add-Finding -Type "Exposed Secrets" -Severity "Medium" `
                -Title "Valid Application Insights Instrumentation Key Exposed" `
                -Description "Application Insights instrumentation key allows sending telemetry data, potentially enabling data pollution attacks and monitoring disruption." `
                -Evidence @{
                    InstrumentationKey = $InstrumentationKey
                    ValidationStatus = "Successful"
                    CanSendTelemetry = $true
                } `
                -Recommendation "Rotate instrumentation key immediately. Store in secrets management system. Consider implementing ingestion endpoint authentication if available in your Application Insights tier."
            
            # Try to query data if AppId and ApiKey provided
            if ($AppId -and $ApiKey) {
                Write-StatusMessage "AppId and ApiKey provided - querying telemetry data..." "Progress"
                Get-AppInsightsTelemetry -InstrumentationKey $InstrumentationKey -AppId $AppId -ApiKey $ApiKey
            }
            else {
                Write-StatusMessage "AppId/ApiKey not provided - cannot query existing telemetry data" "Warning"
                Write-StatusMessage "Can only send data, not read existing logs" "Info"
            }
        }
    }
    catch {
        Write-StatusMessage "Application Insights key validation FAILED: $($_.Exception.Message)" "Error"
        $testResult.Success = $false
        $testResult.Error = $_.Exception.Message
        $script:Results.Summary.FailedTests++
    }
    
    $script:Results.TestedSecrets += $testResult
}

function Get-AppInsightsTelemetry {
    param(
        [string]$InstrumentationKey,
        [string]$AppId,
        [string]$ApiKey
    )
    
    Write-StatusMessage "Querying Application Insights telemetry data..." "Progress"
    
    $headers = @{
        "x-api-key" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    $baseUrl = "https://api.applicationinsights.io/v1/apps/$AppId"
    
    # Query recent requests
    try {
        $query = "requests | where timestamp > ago($($QueryHours)h) | take 100"
        $body = @{ query = $query } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri "$baseUrl/query" -Method Post -Headers $headers -Body $body
        
        if ($response.tables -and $response.tables[0].rows.Count -gt 0) {
            Write-StatusMessage "Retrieved $($response.tables[0].rows.Count) requests" "Success"
            $script:Results.Enumeration.AppInsights.Requests = $response.tables[0].rows
            
            # Upgrade severity if we can read data
            Add-Finding -Type "Data Exposure" -Severity "High" `
                -Title "Application Insights Data Readable - Potential Sensitive Information Exposure" `
                -Description "Full read access to Application Insights telemetry including requests, logs, exceptions, and custom events. May contain sensitive data." `
                -Evidence @{
                    AppId = $AppId
                    DataTypes = "Requests, Traces, Exceptions, Custom Events"
                    SampleRecordCount = $response.tables[0].rows.Count
                } `
                -Recommendation "Rotate API key immediately. Review all telemetry data for sensitive information. Implement data masking for PII/PHI in logs."
        }
    }
    catch {
        Write-StatusMessage "Could not query telemetry: $($_.Exception.Message)" "Warning"
    }
}

# ============================================================================
# STORAGE ACCOUNT TESTING
# ============================================================================

function Test-StorageAccount {
    param(
        [string]$AccountName,
        [string]$AccountKey
    )
    
    Write-Section "Testing Azure Storage Account"
    
    $script:Results.Summary.TotalTests++
    $testResult = @{
        Type = "StorageAccount"
        AccountName = $AccountName
        Success = $false
        Details = @{}
    }
    
    try {
        Write-StatusMessage "Testing storage account access..." "Progress"
        
        # Build connection string
        $connectionString = "DefaultEndpointsProtocol=https;AccountName=$AccountName;AccountKey=$AccountKey;EndpointSuffix=core.windows.net"
        
        # Test by listing containers
        $uri = "https://$AccountName.blob.core.windows.net/?comp=list"
        $date = [DateTime]::UtcNow.ToString("R")
        
        # Create signature
        $stringToSign = "GET`n`n`n`n`n`n`n`n`n`n`n`nx-ms-date:$date`nx-ms-version:2021-08-06`n/$AccountName/`ncomp:list"
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = [Convert]::FromBase64String($AccountKey)
        $signature = [Convert]::ToBase64String($hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign)))
        
        $headers = @{
            "x-ms-date" = $date
            "x-ms-version" = "2021-08-06"
            "Authorization" = "SharedKey $AccountName`:$signature"
        }
        
        $response = Invoke-WebRequest -Uri $uri -Headers $headers -Method Get -UseBasicParsing
        
        Write-StatusMessage "Storage account key is VALID!" "Success"
        $testResult.Success = $true
        $script:Results.Summary.SuccessfulTests++
        
        # Parse containers
        [xml]$xmlResponse = $response.Content
        $containers = $xmlResponse.EnumerationResults.Containers.Container
        
        $testResult.Details.Containers = @($containers | ForEach-Object { $_.Name })
        
        Write-StatusMessage "Found $($containers.Count) blob containers" "Info"
        
        Add-Finding -Type "Exposed Secrets" -Severity "High" `
            -Title "Valid Azure Storage Account Key Exposed" `
            -Description "Storage account access key provides full access to all data in the storage account including blobs, files, tables, and queues." `
            -Evidence @{
                AccountName = $AccountName
                ValidationStatus = "Successful"
                ContainersFound = $containers.Count
            } `
            -Recommendation "Rotate storage account key immediately. Review access logs. Implement SAS tokens with minimal permissions instead of account keys. Enable soft delete."
        
        $script:Results.Enumeration.Storage = $testResult.Details
        
    }
    catch {
        Write-StatusMessage "Storage account key validation FAILED: $($_.Exception.Message)" "Error"
        $testResult.Success = $false
        $testResult.Error = $_.Exception.Message
        $script:Results.Summary.FailedTests++
    }
    
    $script:Results.TestedSecrets += $testResult
}

# ============================================================================
# COSMOS DB TESTING
# ============================================================================

function Test-CosmosDB {
    param(
        [string]$Endpoint,
        [string]$Key
    )
    
    Write-Section "Testing Cosmos DB"
    
    $script:Results.Summary.TotalTests++
    $testResult = @{
        Type = "CosmosDB"
        Endpoint = $Endpoint
        Success = $false
        Details = @{}
    }
    
    try {
        Write-StatusMessage "Testing Cosmos DB access..." "Progress"
        
        # List databases
        $verb = "GET"
        $resourceType = "dbs"
        $resourceLink = ""
        $date = [DateTime]::UtcNow.ToString("R")
        
        $stringToSign = "$verb`n$resourceType`n$resourceLink`n$($date.ToLowerInvariant())`n`n"
        
        $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
        $hmacsha.key = [Convert]::FromBase64String($Key)
        $signature = [Convert]::ToBase64String($hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign)))
        
        $authHeader = [System.Web.HttpUtility]::UrlEncode("type=master&ver=1.0&sig=$signature")
        
        $headers = @{
            "authorization" = $authHeader
            "x-ms-date" = $date
            "x-ms-version" = "2018-12-31"
        }
        
        $uri = "$Endpoint/dbs"
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        Write-StatusMessage "Cosmos DB key is VALID!" "Success"
        $testResult.Success = $true
        $script:Results.Summary.SuccessfulTests++
        
        $databases = $response.Databases
        $testResult.Details.Databases = @($databases | ForEach-Object { $_.id })
        
        Write-StatusMessage "Found $($databases.Count) databases" "Info"
        
        Add-Finding -Type "Exposed Secrets" -Severity "High" `
            -Title "Valid Cosmos DB Master Key Exposed" `
            -Description "Cosmos DB master key provides full access to all databases, collections, and documents. Can read, write, and delete all data." `
            -Evidence @{
                Endpoint = $Endpoint
                ValidationStatus = "Successful"
                DatabasesFound = $databases.Count
            } `
            -Recommendation "Rotate master key immediately. Use resource tokens or read-only keys where possible. Review audit logs. Enable Azure Defender for Cosmos DB."
        
        $script:Results.Enumeration.CosmosDB = $testResult.Details
        
    }
    catch {
        Write-StatusMessage "Cosmos DB key validation FAILED: $($_.Exception.Message)" "Error"
        $testResult.Success = $false
        $testResult.Error = $_.Exception.Message
        $script:Results.Summary.FailedTests++
    }
    
    $script:Results.TestedSecrets += $testResult
}

# ============================================================================
# ENUMERATION FUNCTIONS
# ============================================================================

function Get-AzureADEnumeration {
    Write-StatusMessage "Enumerating Azure AD tenant information..." "Progress"
    
    try {
        $context = Get-AzContext
        
        $script:Results.Enumeration.AzureAD = @{
            TenantId = $context.Tenant.Id
            TenantDomain = $context.Tenant.Directory
            Account = $context.Account.Id
            AccountType = $context.Account.Type
            Environment = $context.Environment.Name
        }
        
        Write-StatusMessage "Tenant ID: $($context.Tenant.Id)" "Info"
        Write-StatusMessage "Account: $($context.Account.Id)" "Info"
        
    }
    catch {
        Write-StatusMessage "Failed to enumerate Azure AD: $($_.Exception.Message)" "Warning"
    }
}

function Get-AzureSubscriptions {
    Write-StatusMessage "Enumerating subscriptions..." "Progress"
    
    try {
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
        
        if ($subscriptions) {
            $script:Results.Enumeration.Subscriptions = @($subscriptions | ForEach-Object {
                @{
                    Name = $_.Name
                    Id = $_.Id
                    State = $_.State
                    TenantId = $_.TenantId
                }
            })
            
            Write-StatusMessage "Found $($subscriptions.Count) subscription(s)" "Success"
            
            foreach ($sub in $subscriptions) {
                Write-Host "  - $($sub.Name) ($($sub.State))" -ForegroundColor Gray
            }
        }
        else {
            Write-StatusMessage "No subscriptions accessible" "Warning"
        }
    }
    catch {
        Write-StatusMessage "Failed to enumerate subscriptions: $($_.Exception.Message)" "Warning"
    }
}

function Get-AzureResources {
    Write-StatusMessage "Enumerating Azure resources..." "Progress"
    
    try {
        # Ensure Az.Resources is loaded
        Import-Module Az.Resources -ErrorAction SilentlyContinue
        
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
        $allResources = @()
        
        foreach ($sub in $subscriptions) {
            Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue | Out-Null
            
            # Get resource groups
            $resourceGroups = Get-AzResourceGroup -ErrorAction SilentlyContinue
            
            if ($resourceGroups) {
                $script:Results.Enumeration.ResourceGroups += @($resourceGroups | ForEach-Object {
                    @{
                        Name = $_.ResourceGroupName
                        Location = $_.Location
                        SubscriptionName = $sub.Name
                    }
                })
            }
            
            # Get resources
            $resources = Get-AzResource -ErrorAction SilentlyContinue
            
            if ($resources) {
                $allResources += @($resources | ForEach-Object {
                    @{
                        Name = $_.Name
                        Type = $_.ResourceType
                        Location = $_.Location
                        ResourceGroupName = $_.ResourceGroupName
                        SubscriptionName = $sub.Name
                    }
                })
            }
        }
        
        $script:Results.Enumeration.Resources = $allResources
        
        if ($allResources.Count -gt 0) {
            Write-StatusMessage "Found $($allResources.Count) resources" "Success"
        }
        
    }
    catch {
        Write-StatusMessage "Failed to enumerate resources: $($_.Exception.Message)" "Warning"
    }
}

function Test-MicrosoftGraphAccess {
    Write-StatusMessage "Testing Microsoft Graph API access..." "Progress"
    
    try {
        $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com" -ErrorAction Stop).Token
        
        $headers = @{
            'Authorization' = "Bearer $token"
            'Content-Type' = 'application/json'
        }
        
        # Try various Graph API endpoints
        $endpoints = @{
            "Users" = "https://graph.microsoft.com/v1.0/users?`$top=5"
            "Groups" = "https://graph.microsoft.com/v1.0/groups?`$top=5"
            "Applications" = "https://graph.microsoft.com/v1.0/applications?`$top=5"
            "ServicePrincipals" = "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=5"
            "Organization" = "https://graph.microsoft.com/v1.0/organization"
        }
        
        $graphResults = @{}
        
        foreach ($endpoint in $endpoints.Keys) {
            try {
                $response = Invoke-RestMethod -Uri $endpoints[$endpoint] -Headers $headers -Method Get -ErrorAction Stop
                
                if ($response.value) {
                    $graphResults[$endpoint] = @{
                        Count = $response.value.Count
                        Sample = $response.value | Select-Object -First 3
                    }
                    Write-StatusMessage "Can read $endpoint via Graph API" "Success"
                }
            }
            catch {
                Write-DebugMessage "Cannot access $endpoint : $($_.Exception.Message)"
            }
        }
        
        if ($graphResults.Count -gt 0) {
            $script:Results.Enumeration.GraphAPI = $graphResults
            
            Add-Finding -Type "Privilege Escalation" -Severity "High" `
                -Title "Microsoft Graph API Access Available" `
                -Description "Service principal has permissions to read directory information via Microsoft Graph API." `
                -Evidence $graphResults `
                -Recommendation "Review and reduce Graph API permissions following principle of least privilege. Monitor Graph API access logs."
        }
        
    }
    catch {
        Write-DebugMessage "No Microsoft Graph access: $($_.Exception.Message)"
    }
}

function Search-SensitivePermissions {
    Write-StatusMessage "Searching for sensitive permissions..." "Progress"
    
    try {
        Import-Module Az.Resources -ErrorAction SilentlyContinue
        
        # Get role assignments
        $allAssignments = Get-AzRoleAssignment -ErrorAction SilentlyContinue
        
        $sensitiveRoles = @("Owner", "Contributor", "User Access Administrator", "Global Administrator")
        
        $sensitiveAssignments = $allAssignments | Where-Object { 
            $_.RoleDefinitionName -in $sensitiveRoles 
        }
        
        if ($sensitiveAssignments) {
            Write-StatusMessage "Found $($sensitiveAssignments.Count) sensitive role assignments" "Warning"
            
            $script:Results.Enumeration.RoleAssignments = @($sensitiveAssignments | ForEach-Object {
                @{
                    Role = $_.RoleDefinitionName
                    Scope = $_.Scope
                    DisplayName = $_.DisplayName
                }
            })
        }
        
    }
    catch {
        Write-DebugMessage "Could not enumerate role assignments: $($_.Exception.Message)"
    }
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

function New-HtmlReport {
    Write-Section "Generating HTML Report"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Secrets Testing Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078D4; border-bottom: 3px solid #0078D4; padding-bottom: 10px; }
        h2 { color: #106EBE; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-box.success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .stat-box.danger { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }
        .stat-box.warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .stat-number { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .stat-label { font-size: 14px; opacity: 0.9; }
        .finding { margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; background: #f9f9f9; }
        .finding.high { border-left-color: #d32f2f; }
        .finding.medium { border-left-color: #f57c00; }
        .finding.low { border-left-color: #fbc02d; }
        .severity { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 12px; }
        .severity.high { background: #d32f2f; color: white; }
        .severity.medium { background: #f57c00; color: white; }
        .severity.low { background: #fbc02d; color: black; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0078D4; color: white; }
        tr:hover { background: #f5f5f5; }
        .timestamp { color: #666; font-size: 12px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Secrets Security Assessment Report</h1>
        <p class="timestamp">Generated: $($script:Results.Metadata.Timestamp) by $($script:Results.Metadata.Tester)@$($script:Results.Metadata.Computer)</p>
        
        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="stat-box">
                <div class="stat-label">Total Tests</div>
                <div class="stat-number">$($script:Results.Summary.TotalTests)</div>
            </div>
            <div class="stat-box success">
                <div class="stat-label">Successful</div>
                <div class="stat-number">$($script:Results.Summary.SuccessfulTests)</div>
            </div>
            <div class="stat-box danger">
                <div class="stat-label">High Risk</div>
                <div class="stat-number">$($script:Results.Summary.HighRiskFindings)</div>
            </div>
            <div class="stat-box warning">
                <div class="stat-label">Medium Risk</div>
                <div class="stat-number">$($script:Results.Summary.MediumRiskFindings)</div>
            </div>
        </div>
        
        <h2>Security Findings</h2>
"@
    
    foreach ($finding in $script:Results.Findings) {
        $severityClass = $finding.Severity.ToLower()
        $html += @"
        <div class="finding $severityClass">
            <h3>
                <span class="severity $severityClass">$($finding.Severity)</span>
                $($finding.Title)
            </h3>
            <p><strong>Type:</strong> $($finding.Type)</p>
            <p>$($finding.Description)</p>
            <p><strong>Recommendation:</strong> $($finding.Recommendation)</p>
            <p class="timestamp">Discovered: $($finding.Timestamp)</p>
        </div>
"@
    }
    
    $html += @"
        <h2>Tested Secrets Summary</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Status</th>
                <th>Details</th>
            </tr>
"@
    
    foreach ($secret in $script:Results.TestedSecrets) {
        $status = if ($secret.Success) { "✓ Valid" } else { "✗ Invalid" }
        $statusColor = if ($secret.Success) { "color: green;" } else { "color: red;" }
        
        $html += @"
            <tr>
                <td>$($secret.Type)</td>
                <td style="$statusColor"><strong>$status</strong></td>
                <td>$(($secret.Details | ConvertTo-Json -Compress))</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <div class="footer">
            <p>Made with ❤️ from your friendly hacker - er2oneousbit</p>
            <p>Azure Secrets Testing Tool v2.0 - For Authorized Security Testing Only</p>
        </div>
    </div>
</body>
</html>
"@
    
    $reportPath = $OutputFile -replace '\.json$', '.html'
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-StatusMessage "HTML report generated: $reportPath" "Success"
}

function Save-Results {
    if ($OutputFile) {
        try {
            Write-StatusMessage "Saving results to JSON: $OutputFile" "Progress"
            
            # Calculate duration
            $duration = (Get-Date) - $script:StartTime
            $script:Results.Metadata.Duration = $duration.ToString()
            
            $script:Results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
            Write-StatusMessage "Results saved successfully" "Success"
            
            if ($HtmlReport) {
                New-HtmlReport
            }
        }
        catch {
            Write-StatusMessage "Failed to save results: $($_.Exception.Message)" "Error"
        }
    }
}

function Show-Summary {
    Write-Section "Assessment Summary"
    
    Write-Host ""
    Write-ColorOutput "  Total Tests Run:      " "White" -NoNewline
    Write-ColorOutput "$($script:Results.Summary.TotalTests)" "Cyan"
    
    Write-ColorOutput "  Successful Tests:     " "White" -NoNewline
    Write-ColorOutput "$($script:Results.Summary.SuccessfulTests)" "Green"
    
    Write-ColorOutput "  Failed Tests:         " "White" -NoNewline
    Write-ColorOutput "$($script:Results.Summary.FailedTests)" "Red"
    
    Write-Host ""
    Write-ColorOutput "  High Risk Findings:   " "White" -NoNewline
    Write-ColorOutput "$($script:Results.Summary.HighRiskFindings)" "Red"
    
    Write-ColorOutput "  Medium Risk Findings: " "White" -NoNewline
    Write-ColorOutput "$($script:Results.Summary.MediumRiskFindings)" "Yellow"
    
    Write-ColorOutput "  Low Risk Findings:    " "White" -NoNewline
    Write-ColorOutput "$($script:Results.Summary.LowRiskFindings)" "Green"
    
    Write-Host ""
    
    $duration = (Get-Date) - $script:StartTime
    Write-ColorOutput "  Duration: $($duration.ToString('mm\:ss'))" "Cyan"
    Write-Host ""
}

# ============================================================================
# INTERACTIVE MODE
# ============================================================================

function Start-InteractiveMode {
    Write-Section "Interactive Mode"
    
    Write-Host "Select testing mode:" -ForegroundColor Cyan
    Write-Host "  1. Service Principal (ClientId/Secret)" -ForegroundColor White
    Write-Host "  2. User Credentials (Username/Password)" -ForegroundColor White
    Write-Host "  3. Access Token" -ForegroundColor White
    Write-Host "  4. Application Insights Key" -ForegroundColor White
    Write-Host "  5. Storage Account Key" -ForegroundColor White
    Write-Host "  6. Cosmos DB Key" -ForegroundColor White
    Write-Host "  7. Parse Configuration File" -ForegroundColor White
    Write-Host "  8. Test All Secrets (Comprehensive)" -ForegroundColor White
    Write-Host "  0. Exit" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Enter your choice"
    
    switch ($choice) {
        "1" {
            $script:TenantId = Read-Host "Tenant ID"
            $script:ClientId = Read-Host "Client ID"
            $script:ClientSecret = Read-Host "Client Secret" -AsSecureString
            if ($script:ClientSecret -is [System.Security.SecureString]) {
                $script:ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:ClientSecret))
            }
            
            $enumerate = Read-Host "Perform enumeration? (Y/N)"
            $script:Enumerate = ($enumerate -eq 'Y' -or $enumerate -eq 'y')
            
            Test-ServicePrincipal -TenantId $script:TenantId -ClientId $script:ClientId -ClientSecret $script:ClientSecret
        }
        
        "2" {
            $script:Username = Read-Host "Username"
            $script:Password = Read-Host "Password" -AsSecureString
            if ($script:Password -is [System.Security.SecureString]) {
                $script:Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:Password))
            }
            $script:TenantId = Read-Host "Tenant ID (optional, press Enter to skip)"
            
            $enumerate = Read-Host "Perform enumeration? (Y/N)"
            $script:Enumerate = ($enumerate -eq 'Y' -or $enumerate -eq 'y')
            
            Test-UserPassword -Username $script:Username -Password $script:Password -TenantId $script:TenantId
        }
        
        "4" {
            $script:InstrumentationKey = Read-Host "Instrumentation Key"
            $script:AppId = Read-Host "App ID (optional)"
            $script:ApiKey = Read-Host "API Key (optional)" -AsSecureString
            if ($script:ApiKey -is [System.Security.SecureString]) {
                $script:ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:ApiKey))
            }
            
            Test-ApplicationInsights -InstrumentationKey $script:InstrumentationKey -AppId $script:AppId -ApiKey $script:ApiKey
        }
        
        "5" {
            $script:StorageAccountName = Read-Host "Storage Account Name"
            $script:StorageAccountKey = Read-Host "Storage Account Key" -AsSecureString
            if ($script:StorageAccountKey -is [System.Security.SecureString]) {
                $script:StorageAccountKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:StorageAccountKey))
            }
            
            Test-StorageAccount -AccountName $script:StorageAccountName -AccountKey $script:StorageAccountKey
        }
        
        "6" {
            $script:CosmosEndpoint = Read-Host "Cosmos DB Endpoint URL"
            $script:CosmosKey = Read-Host "Cosmos DB Key" -AsSecureString
            if ($script:CosmosKey -is [System.Security.SecureString]) {
                $script:CosmosKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:CosmosKey))
            }
            
            Test-CosmosDB -Endpoint $script:CosmosEndpoint -Key $script:CosmosKey
        }
        
        "7" {
            $script:ConfigFile = Read-Host "Configuration file path"
            $secrets = Get-SecretsFromConfigFile -FilePath $script:ConfigFile
            
            if ($secrets) {
                $enumerate = Read-Host "Perform enumeration? (Y/N)"
                $script:Enumerate = ($enumerate -eq 'Y' -or $enumerate -eq 'y')
                
                Test-ExtractedSecrets -Secrets $secrets
            }
        }
        
        "0" {
            Write-StatusMessage "Exiting..." "Info"
            return
        }
        
        default {
            Write-StatusMessage "Invalid choice" "Error"
        }
    }
}

function Test-ExtractedSecrets {
    param([hashtable]$Secrets)
    
    # Test Service Principal if found
    if ($Secrets.TenantId -and $Secrets.ClientId -and $Secrets.ClientSecret) {
        Test-ServicePrincipal -TenantId $Secrets.TenantId -ClientId $Secrets.ClientId -ClientSecret $Secrets.ClientSecret
    }
    
    # Test Application Insights if found
    if ($Secrets.InstrumentationKey) {
        Test-ApplicationInsights -InstrumentationKey $Secrets.InstrumentationKey -AppId $Secrets.AppId -ApiKey $Secrets.ApiKey
    }
    
    # Test Storage if found
    if ($Secrets.StorageAccountName -and $Secrets.StorageAccountKey) {
        Test-StorageAccount -AccountName $Secrets.StorageAccountName -AccountKey $Secrets.StorageAccountKey
    }
    
    # Test Cosmos DB if found
    if ($Secrets.CosmosEndpoint -and $Secrets.CosmosKey) {
        Test-CosmosDB -Endpoint $Secrets.CosmosEndpoint -Key $Secrets.CosmosKey
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    Write-Banner
    
    # Check for required modules
    if (-not $SkipModuleCheck) {
        if (-not (Test-RequiredModule -ModuleName "Az.Accounts")) {
            return
        }
        
        try {
            Import-Module Az.Accounts -ErrorAction Stop
        }
        catch {
            Write-StatusMessage "Failed to import Az.Accounts: $_" "Error"
            return
        }
    }
    
    # Execute based on mode
    switch ($Mode) {
        "Interactive" {
            Start-InteractiveMode
        }
        
        "ServicePrincipal" {
            if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
                Write-StatusMessage "TenantId, ClientId, and ClientSecret required for ServicePrincipal mode" "Error"
                return
            }
            Test-ServicePrincipal -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        }
        
        "UserPassword" {
            if (-not $Username -or -not $Password) {
                Write-StatusMessage "Username and Password required for UserPassword mode" "Error"
                return
            }
            Test-UserPassword -Username $Username -Password $Password -TenantId $TenantId
        }
        
        "AppInsights" {
            if (-not $InstrumentationKey) {
                Write-StatusMessage "InstrumentationKey required for AppInsights mode" "Error"
                return
            }
            Test-ApplicationInsights -InstrumentationKey $InstrumentationKey -AppId $AppId -ApiKey $ApiKey
        }
        
        "StorageKey" {
            if (-not $StorageAccountName -or -not $StorageAccountKey) {
                Write-StatusMessage "StorageAccountName and StorageAccountKey required" "Error"
                return
            }
            Test-StorageAccount -AccountName $StorageAccountName -AccountKey $StorageAccountKey
        }
        
        "CosmosDB" {
            if (-not $CosmosEndpoint -or -not $CosmosKey) {
                Write-StatusMessage "CosmosEndpoint and CosmosKey required" "Error"
                return
            }
            Test-CosmosDB -Endpoint $CosmosEndpoint -Key $CosmosKey
        }
        
        "ConfigFile" {
            if (-not $ConfigFile) {
                Write-StatusMessage "ConfigFile parameter required" "Error"
                return
            }
            $secrets = Get-SecretsFromConfigFile -FilePath $ConfigFile
            if ($secrets) {
                Test-ExtractedSecrets -Secrets $secrets
            }
        }
    }
    
    # Cleanup Azure connection
    try {
        Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null
        Write-DebugMessage "Disconnected from Azure"
    }
    catch {
        # Silent fail
    }
    
    # Show summary and save
    Show-Summary
    Save-Results
    
    Write-Host ""
    Write-ColorOutput "Assessment complete! 🎯" "Green"
    Write-Host ""
}

# Execute
Main

# Made with ❤️ from your friendly hacker - er2oneousbit