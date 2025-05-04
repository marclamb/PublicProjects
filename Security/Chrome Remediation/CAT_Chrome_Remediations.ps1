# Function to ensure the registry path exists
function Ensure-RegistryPath {
    param (
        [string]$path
    )
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
        Write-Host "Created registry path: $path" -ForegroundColor Green
    }
}

# Function to apply and verify a registry setting
function Apply-RegistrySetting {
    param (
        [string]$vID,
        [string]$description,
        [string]$regPath,
        [string]$regName,
        [Parameter(Mandatory = $true)]
        [Alias('value')]
        $desiredValue
    )

    Write-Host "`nFinding: $vID"
    Write-Host "Description: $description"

    Ensure-RegistryPath -path $regPath

    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

    if ($currentValue -ne $desiredValue) {
        if ($desiredValue -is [string]) {
            Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type String
        } elseif ($desiredValue -is [int]) {
            Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
        } elseif ($desiredValue -is [array]) {
            Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type MultiString
        } else {
            Write-Host "Unsupported value type for $vID" -ForegroundColor Red
            return
        }

        Write-Host "$vID remediation applied. $regName set to $desiredValue."
    } else {
        Write-Host "$vID is already correctly configured."
    }

    # Verification
    $currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    if ($currentValue -eq $desiredValue) {
        Write-Host "$vID setting verified successfully." -ForegroundColor Green
    } else {
        Write-Host "$vID setting verification failed!" -ForegroundColor Red
    }
}

# Remediation for each finding
$findings = @(
    @{
        vID = "V-221558"
        description = "Firewall traversal from remote host must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "RemoteAccessHostFirewallTraversal"
        desiredValue = 0
    },
    @{
        vID = "V-221559"
        description = "Site tracking users location must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DefaultGeolocationSetting"
        desiredValue = 2
    },
    @{
        vID = "V-221561"
        description = "Sites ability to show pop-ups must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DefaultPopupsSetting"
        desiredValue = 2
    },
    @{
        vID = "V-221562"
        description = "Extensions installation must be blocklisted by default."
        regPath = "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlacklist"
        regName = "1"
        desiredValue = "*"
    },
    @{
        vID = "V-221563"
        description = "Extensions that are approved for use must be allowlisted."
        regPath = "HKLM:\Software\Policies\Google\Chrome\ExtensionInstallWhitelist"
        regName = "1"
        desiredValue = "whitelisted_extension_id"
    },
    @{
        vID = "V-221564"
        description = "The default search providers name must be set."
        regPath = "HKLM:\Software\Policies\Google\Chrome\DefaultSearchProvider"
        regName = "Name"
        desiredValue = "YourSearchProviderName"
    },
    @{
        vID = "V-221565"
        description = "The default search provider URL must be set to perform encrypted searches."
        regPath = "HKLM:\Software\Policies\Google\Chrome\DefaultSearchProvider"
        regName = "SearchURL"
        desiredValue = "https://encrypted.search.provider.com/?q={searchTerms}"
    },
    @{
        vID = "V-221566"
        description = "Default search provider must be enabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome\DefaultSearchProvider"
        regName = "Enabled"
        desiredValue = 1
    },
    @{
        vID = "V-221567"
        description = "The Password Manager must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "PasswordManagerEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221570"
        description = "Background processing must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "BackgroundModeEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221571"
        description = "Google Data Synchronization must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "SyncDisabled"
        desiredValue = 1
    },
    @{
        vID = "V-221572"
        description = "The URL protocol schema javascript must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DisableJavaScript"
        desiredValue = 1
    },
    @{
        vID = "V-221573"
        description = "Cloud print sharing must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "CloudPrintProxyEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221574"
        description = "Network prediction must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "NetworkPredictionOptions"
        desiredValue = 2
    },
    @{
        vID = "V-221575"
        description = "Metrics reporting to Google must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "MetricsReportingEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221576"
        description = "Search suggestions must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "SearchSuggestEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221577"
        description = "Importing of saved passwords must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "PasswordImportEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221578"
        description = "Incognito mode must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "IncognitoModeAvailability"
        desiredValue = 1
    },
    @{
        vID = "V-221579"
        description = "Online revocation checks must be performed."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "EnableOnlineRevocationChecks"
        desiredValue = 1
    },
    @{
        vID = "V-221580"
        description = "Safe Browsing must be enabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "SafeBrowsingEnabled"
        desiredValue = 1
    },
    @{
        vID = "V-221581"
        description = "Browser history must be saved."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "SavingBrowserHistoryDisabled"
        desiredValue = 0
    },
    @{
        vID = "V-221586"
        description = "Deletion of browser history must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "AllowDeletingBrowserHistory"
        desiredValue = 0
    },
    @{
        vID = "V-221587"
        description = "Prompt for download location must be enabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "PromptForDownloadLocation"
        desiredValue = 1
    },
    @{
        vID = "V-221588"
        description = "Download restrictions must be configured."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DownloadRestrictions"
        desiredValue = 3
    },
    @{
        vID = "V-221590"
        description = "Safe Browsing Extended Reporting must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "SafeBrowsingExtendedReportingEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221591"
        description = "WebUSB must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DefaultWebUsbGuardSetting"
        desiredValue = 1
    },
    @{
        vID = "V-221592"
        description = "Chrome Cleanup must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "ChromeCleanupEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221593"
        description = "Chrome Cleanup reporting must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "ChromeCleanupReportingEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-221594"
        description = "Google Cast must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "EnableMediaRouter"
        desiredValue = 0
    },
    @{
        vID = "V-221595"
        description = "Autoplay must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "AutoplayAllowed"
        desiredValue = 0
    },
    @{
        vID = "V-221597"
        description = "Anonymized data collection must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "EnableTelemetry"
        desiredValue = 0
    },
    @{
        vID = "V-221598"
        description = "Collection of WebRTC event logs must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "WebRtcEventLogCollectionAllowed"
        desiredValue = 0
    },
    @{
        vID = "V-226401"
        description = "Guest Mode must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "BrowserGuestModeEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-226402"
        description = "AutoFill for credit cards must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "AutoFillCreditCardEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-226403"
        description = "AutoFill for addresses must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "AutoFillAddressEnabled"
        desiredValue = 0
    },
    @{
        vID = "V-226404"
        description = "Import AutoFill form data must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "ImportAutoFillFormData"
        desiredValue = 0
    },
    @{
        vID = "V-241787"
        description = "Web Bluetooth API must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DefaultWebBluetoothGuardSetting"
        desiredValue = 1
    },
    @{
        vID = "V-245538"
        description = "Use of the QUIC protocol must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "QuicAllowed"
        desiredValue = 0
    },
    @{
        vID = "V-245539"
        description = "Session only based cookies must be enabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DefaultCookiesSetting"
        desiredValue = 2
    },
    @{
        vID = "V-221599"
        description = "Chrome development tools must be disabled."
        regPath = "HKLM:\Software\Policies\Google\Chrome"
        regName = "DeveloperToolsAvailability"
        desiredValue = 2
    }
)

# Apply each finding's remediation
foreach ($finding in $findings) {
    Apply-RegistrySetting -vID $finding.vID -description $finding.description -regPath $finding.regPath -regName $finding.regName -desiredValue $finding.desiredValue
}

Write-Host "`nAll findings have been processed."
