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

# Function to verify the registry setting
function Verify-RegistrySetting {
    param (
        [string]$regPath,
        [string]$regName,
        [string]$expectedValue
    )
    $actualValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    if ($actualValue -eq $expectedValue) {
        Write-Host "Verified: $regName is set to $expectedValue in $regPath" -ForegroundColor Green
    } else {
        Write-Host "Verification failed: $regName in $regPath is $actualValue, expected $expectedValue" -ForegroundColor Red
    }
}

# Existing Remediations
# V-235720 - Bypassing Microsoft Defender SmartScreen prompts for sites must be disabled.
$remediation_V235720 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SmartScreenPromptOverride"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235721 - Bypassing of Microsoft Defender SmartScreen warnings about downloads must be disabled.
$remediation_V235721 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SmartScreenPromptOverrideForFiles"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235723 - InPrivate mode must be disabled.
$remediation_V235723 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "InPrivateModeAvailability"
    $desiredValue = 1
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235724 - Background processing must be disabled.
$remediation_V235724 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "BackgroundModeEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235725 - The ability of sites to show pop-ups must be disabled.
$remediation_V235725 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "DefaultPopupsSetting"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235726 - The default search provider must be set to use an encrypted connection.
$remediation_V235726 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\SearchScopes"
    $regName = "DefaultScope"
    $desiredValue = "https://www.bing.com/search?q={searchTerms}"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type String
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235728 - Network prediction must be disabled.
$remediation_V235728 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "NetworkPredictionOptions"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235729 - Search suggestions must be disabled.
$remediation_V235729 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SearchSuggestEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235730 - Importing of autofill form data must be disabled.
$remediation_V235730 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "AutofillFormDataImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235732 - Importing of cookies must be disabled.
$remediation_V235732 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "ImportCookies"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# New Remediations
# V-235759 - Edge must be configured to allow only TLS.
$remediation_V235759 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SSLVersionMin"
    $desiredValue = "tls1.2"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type String
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235733 - Importing of extensions must be disabled.
$remediation_V235733 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "ExtensionsImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235734 - Importing of browsing history must be disabled.
$remediation_V235734 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "BrowsingHistoryImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235735 - Importing of home page settings must be disabled.
$remediation_V235735 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "HomePageImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235736 - Importing of open tabs must be disabled.
$remediation_V235736 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "OpenTabsImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235737 - Importing of payment info must be disabled.
$remediation_V235737 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "PaymentInfoImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235738 - Importing of saved passwords must be disabled.
$remediation_V235738 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "PasswordManagerImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235739 - Importing of search engine settings must be disabled.
$remediation_V235739 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SearchEngineImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235740 - Importing of shortcuts must be disabled.
$remediation_V235740 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "ShortcutsImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235741 - Autoplay must be disabled.
$remediation_V235741 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "AutoplayAllowed"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235742 - WebUSB must be disabled.
$remediation_V235742 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "WebUsbAskForUrls"
    $desiredValue = "*"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type String
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235743 - Google Cast must be disabled.
$remediation_V235743 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "EnableMediaRouter"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235744 - Web Bluetooth API must be disabled.
$remediation_V235744 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "DefaultWebBluetoothGuardSetting"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235745 - Autofill for Credit Cards must be disabled.
$remediation_V235745 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "AutofillCreditCardEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235746 - Autofill for addresses must be disabled.
$remediation_V235746 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "AutofillAddressEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235747 - Online revocation checks must be performed.
$remediation_V235747 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "EnableOnlineRevocationChecks"
    $desiredValue = 1
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235748 - Personalization of ads, search, and news by sending browsing history to Microsoft must be disabled.
$remediation_V235748 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "PersonalizationReportingEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235749 - Site tracking of a user’s location must be disabled.
$remediation_V235749 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "DefaultGeolocationSetting"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235750 - Browser history must be saved.
$remediation_V235750 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SavingBrowserHistoryDisabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235754 - Extensions installation must be blocklisted by default.
$remediation_V235754 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"
    Ensure-RegistryPath -path $regPath
    New-ItemProperty -Path $regPath -Name "1" -Value "*" -PropertyType String -Force | Out-Null
    Verify-RegistrySetting -regPath $regPath -regName "1" -expectedValue "*"
}

# V-235756 - The Password Manager must be disabled.
$remediation_V235756 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "PasswordManagerEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235760 - Site isolation for every site must be enabled.
$remediation_V235760 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "IsolateOrigins"
    $desiredValue = "*"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type String
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235761 - Supported authentication schemes must be configured.
$remediation_V235761 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "AuthSchemes"
    $desiredValue = "basic,digest,ntlm,negotiate"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type String
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235763 - Microsoft Defender SmartScreen must be enabled.
$remediation_V235763 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SmartScreenEnabled"
    $desiredValue = 1
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235764 - Microsoft Defender SmartScreen must be configured to block potentially unwanted apps.
$remediation_V235764 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "PreventSmartScreenPromptOverrideForFiles"
    $desiredValue = 1
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235766 - Tracking of browsing activity must be disabled.
$remediation_V235766 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "DoNotTrackEnabled"
    $desiredValue = 1
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235767 - A website's ability to query for payment methods must be disabled.
$remediation_V235767 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "DefaultPaymentMethodGuardSetting"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235768 - Suggestions of similar web pages in the event of a navigation error must be disabled.
$remediation_V235768 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "AlternateErrorPagesEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235769 - User feedback must be disabled.
$remediation_V235769 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "UserFeedbackAllowed"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235770 - The collections feature must be disabled.
$remediation_V235770 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "CollectionsEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235771 - The Share Experience feature must be disabled.
$remediation_V235771 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "ShareEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235772 - Guest mode must be disabled.
$remediation_V235772 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "BrowserGuestModeEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235773 - Relaunch notification must be required.
$remediation_V235773 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "RelaunchNotification"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235774 - The built-in DNS client must be disabled.
$remediation_V235774 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "BuiltInDnsClientEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-246736 - Use of the QUIC protocol must be disabled.
$remediation_V246736 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "QuicAllowed"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235727 - Data Synchronization must be disabled.
$remediation_V235727 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "SyncDisabled"
    $desiredValue = 1
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235731 - Importing of browser settings must be disabled.
$remediation_V235731 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "BrowserSettingsImportEnabled"
    $desiredValue = 0
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235751 - Edge development tools must be disabled.
$remediation_V235751 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "DeveloperToolsAvailability"
    $desiredValue = 2
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235752 - Download restrictions must be configured.
$remediation_V235752 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "DownloadRestrictions"
    $desiredValue = 3
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# V-235765 - The download location prompt must be configured.
$remediation_V235765 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $regName = "PromptForDownloadLocation"
    $desiredValue = 1
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord
    Verify-RegistrySetting -regPath $regPath -regName $regName -expectedValue $desiredValue
}

# Array of all findings to remediate
$findings = @(
    @{ severity = "medium"; vID = "V-235720"; description = "Bypassing Microsoft Defender SmartScreen prompts for sites must be disabled."; remediationScript = $remediation_V235720 },
    @{ severity = "medium"; vID = "V-235721"; description = "Bypassing of Microsoft Defender SmartScreen warnings about downloads must be disabled."; remediationScript = $remediation_V235721 },
    @{ severity = "medium"; vID = "V-235723"; description = "InPrivate mode must be disabled."; remediationScript = $remediation_V235723 },
    @{ severity = "medium"; vID = "V-235724"; description = "Background processing must be disabled."; remediationScript = $remediation_V235724 },
    @{ severity = "medium"; vID = "V-235725"; description = "The ability of sites to show pop-ups must be disabled."; remediationScript = $remediation_V235725 },
    @{ severity = "medium"; vID = "V-235726"; description = "The default search provider must be set to use an encrypted connection."; remediationScript = $remediation_V235726 },
    @{ severity = "medium"; vID = "V-235728"; description = "Network prediction must be disabled."; remediationScript = $remediation_V235728 },
    @{ severity = "medium"; vID = "V-235729"; description = "Search suggestions must be disabled."; remediationScript = $remediation_V235729 },
    @{ severity = "medium"; vID = "V-235730"; description = "Importing of autofill form data must be disabled."; remediationScript = $remediation_V235730 },
    @{ severity = "medium"; vID = "V-235732"; description = "Importing of cookies must be disabled."; remediationScript = $remediation_V235732 },
    @{ severity = "medium"; vID = "V-235759"; description = "Edge must be configured to allow only TLS."; remediationScript = $remediation_V235759 },
    @{ severity = "medium"; vID = "V-235733"; description = "Importing of extensions must be disabled."; remediationScript = $remediation_V235733 },
    @{ severity = "medium"; vID = "V-235734"; description = "Importing of browsing history must be disabled."; remediationScript = $remediation_V235734 },
    @{ severity = "medium"; vID = "V-235735"; description = "Importing of home page settings must be disabled."; remediationScript = $remediation_V235735 },
    @{ severity = "medium"; vID = "V-235736"; description = "Importing of open tabs must be disabled."; remediationScript = $remediation_V235736 },
    @{ severity = "medium"; vID = "V-235737"; description = "Importing of payment info must be disabled."; remediationScript = $remediation_V235737 },
    @{ severity = "medium"; vID = "V-235738"; description = "Importing of saved passwords must be disabled."; remediationScript = $remediation_V235738 },
    @{ severity = "medium"; vID = "V-235739"; description = "Importing of search engine settings must be disabled."; remediationScript = $remediation_V235739 },
    @{ severity = "medium"; vID = "V-235740"; description = "Importing of shortcuts must be disabled."; remediationScript = $remediation_V235740 },
    @{ severity = "medium"; vID = "V-235741"; description = "Autoplay must be disabled."; remediationScript = $remediation_V235741 },
    @{ severity = "medium"; vID = "V-235742"; description = "WebUSB must be disabled."; remediationScript = $remediation_V235742 },
    @{ severity = "medium"; vID = "V-235743"; description = "Google Cast must be disabled."; remediationScript = $remediation_V235743 },
    @{ severity = "medium"; vID = "V-235744"; description = "Web Bluetooth API must be disabled."; remediationScript = $remediation_V235744 },
    @{ severity = "medium"; vID = "V-235745"; description = "Autofill for Credit Cards must be disabled."; remediationScript = $remediation_V235745 },
    @{ severity = "medium"; vID = "V-235746"; description = "Autofill for addresses must be disabled."; remediationScript = $remediation_V235746 },
    @{ severity = "medium"; vID = "V-235747"; description = "Online revocation checks must be performed."; remediationScript = $remediation_V235747 },
    @{ severity = "medium"; vID = "V-235748"; description = "Personalization of ads, search, and news by sending browsing history to Microsoft must be disabled."; remediationScript = $remediation_V235748 },
    @{ severity = "medium"; vID = "V-235749"; description = "Site tracking of a user’s location must be disabled."; remediationScript = $remediation_V235749 },
    @{ severity = "medium"; vID = "V-235750"; description = "Browser history must be saved."; remediationScript = $remediation_V235750 },
    @{ severity = "medium"; vID = "V-235754"; description = "Extensions installation must be blocklisted by default."; remediationScript = $remediation_V235754 },
    @{ severity = "medium"; vID = "V-235756"; description = "The Password Manager must be disabled."; remediationScript = $remediation_V235756 },
    @{ severity = "medium"; vID = "V-235760"; description = "Site isolation for every site must be enabled."; remediationScript = $remediation_V235760 },
    @{ severity = "medium"; vID = "V-235761"; description = "Supported authentication schemes must be configured."; remediationScript = $remediation_V235761 },
    @{ severity = "medium"; vID = "V-235763"; description = "Microsoft Defender SmartScreen must be enabled."; remediationScript = $remediation_V235763 },
    @{ severity = "medium"; vID = "V-235764"; description = "Microsoft Defender SmartScreen must be configured to block potentially unwanted apps."; remediationScript = $remediation_V235764 },
    @{ severity = "medium"; vID = "V-235766"; description = "Tracking of browsing activity must be disabled."; remediationScript = $remediation_V235766 },
    @{ severity = "medium"; vID = "V-235767"; description = "A website's ability to query for payment methods must be disabled."; remediationScript = $remediation_V235767 },
    @{ severity = "medium"; vID = "V-235768"; description = "Suggestions of similar web pages in the event of a navigation error must be disabled."; remediationScript = $remediation_V235768 },
    @{ severity = "medium"; vID = "V-235769"; description = "User feedback must be disabled."; remediationScript = $remediation_V235769 },
    @{ severity = "medium"; vID = "V-235770"; description = "The collections feature must be disabled."; remediationScript = $remediation_V235770 },
    @{ severity = "medium"; vID = "V-235771"; description = "The Share Experience feature must be disabled."; remediationScript = $remediation_V235771 },
    @{ severity = "medium"; vID = "V-235772"; description = "Guest mode must be disabled."; remediationScript = $remediation_V235772 },
    @{ severity = "medium"; vID = "V-235773"; description = "Relaunch notification must be required."; remediationScript = $remediation_V235773 },
    @{ severity = "medium"; vID = "V-235774"; description = "The built-in DNS client must be disabled."; remediationScript = $remediation_V235774 },
    @{ severity = "medium"; vID = "V-246736"; description = "Use of the QUIC protocol must be disabled."; remediationScript = $remediation_V246736 },
    @{ severity = "medium"; vID = "V-235727"; description = "Data Synchronization must be disabled."; remediationScript = $remediation_V235727 },
    @{ severity = "medium"; vID = "V-235731"; description = "Importing of browser settings must be disabled."; remediationScript = $remediation_V235731 },
    @{ severity = "medium"; vID = "V-235751"; description = "Edge development tools must be disabled."; remediationScript = $remediation_V235751 },
    @{ severity = "medium"; vID = "V-235752"; description = "Download restrictions must be configured."; remediationScript = $remediation_V235752 },
    @{ severity = "medium"; vID = "V-235765"; description = "The download location prompt must be configured."; remediationScript = $remediation_V235765 }
)

# Iterate over each finding and execute the remediation
foreach ($finding in $findings) {
    Write-Host "`nFinding: $($finding.vID)"
    Write-Host "Description: $($finding.description)"
    $action = Read-Host "Do you want to (C)ontinue remediation (default), (S)kip, or (E)xit the script? [Press Enter for Continue]" -Default "C"

    switch ($action.ToUpper()) {
        "S" {
            Write-Host "Skipping remediation for $($finding.vID)..."
            continue
        }
        "E" {
            Write-Host "Exiting script..."
            exit
        }
        default {
            Write-Host "Executing remediation for $($finding.vID)..."
            & $finding.remediationScript
        }
    }
}

Write-Host "`nAll selected findings have been processed." -ForegroundColor Green
