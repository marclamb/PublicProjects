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

# Function to display finding information
function Display-Finding {
    param (
        [string]$severity,
        [string]$vID,
        [string]$description,
        [string]$fixText
    )

    Write-Host "Severity: $severity" -ForegroundColor Yellow
    Write-Host "Finding: $vID" -ForegroundColor Cyan
    Write-Host "Description: $description" -ForegroundColor White
    Write-Host "Fix: $fixText" -ForegroundColor Green
}

# Function to remediate a specific finding
function Remediate-Finding {
    param (
        [string]$severity,
        [string]$vID,
        [string]$description,
        [string]$fixText,
        [scriptblock]$remediationScript
    )

    Display-Finding -severity $severity -vID $vID -description $description -fixText $fixText

    # Prompt user for action
    $action = Read-Host "Do you want to (C)ontinue remediation, (S)kip, or (E)xit the script?"

    switch ($action.ToUpper()) {
        "C" {
            # Execute remediation script
            Write-Host "Executing remediation for $vID..." -ForegroundColor Green
            & $remediationScript
        }
        "S" {
            Write-Host "Skipping remediation for $vID..." -ForegroundColor Yellow
        }
        "E" {
            Write-Host "Exiting script." -ForegroundColor Red
            exit
        }
        default {
            Write-Host "Invalid selection. Skipping remediation for $vID..." -ForegroundColor Yellow
        }
    }
}

# Remediation Scripts for CAT II Findings

# V-254283 - UEFI firmware and configuration to run in UEFI mode
$remediation_V254283 = {
    # This requires manual verification and configuration in BIOS/UEFI settings. 
    # No direct PowerShell remediation available.
    Write-Host "V-254283 requires manual verification. Ensure UEFI mode is configured in BIOS settings." -ForegroundColor Yellow
}

# V-254285 - Account lockout duration
$remediation_V254285 = {
    $lockoutDuration = 15
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"

    secedit /export /cfg $seceditCfgPath
    (Get-Content $seceditCfgPath) -replace 'LockoutDuration = \d+', "LockoutDuration = $lockoutDuration" | Set-Content $seceditCfgPath
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas SECURITYPOLICY /quiet
    Remove-Item $seceditCfgPath
    Write-Host "V-254285 remediation applied. Lockout duration set to $lockoutDuration minutes."
}

# V-254286 - Bad logon attempts
$remediation_V254286 = {
    $lockoutThreshold = 3
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"

    secedit /export /cfg $seceditCfgPath
    (Get-Content $seceditCfgPath) -replace 'LockoutBadCount = \d+', "LockoutBadCount = $lockoutThreshold" | Set-Content $seceditCfgPath
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas SECURITYPOLICY /quiet
    Remove-Item $seceditCfgPath
    Write-Host "V-254286 remediation applied. Lockout threshold set to $lockoutThreshold bad logon attempts."
}

# V-254287 - Reset time before bad logon counter
$remediation_V254287 = {
    $resetTime = 15
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"

    secedit /export /cfg $seceditCfgPath
    (Get-Content $seceditCfgPath) -replace 'ResetLockoutCount = \d+', "ResetLockoutCount = $resetTime" | Set-Content $seceditCfgPath
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas SECURITYPOLICY /quiet
    Remove-Item $seceditCfgPath
    Write-Host "V-254287 remediation applied. Reset time set to $resetTime minutes."
}

# V-254288 - Password history
$remediation_V254288 = {
    $passwordHistory = 24
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"

    secedit /export /cfg $seceditCfgPath
    (Get-Content $seceditCfgPath) -replace 'PasswordHistorySize = \d+', "PasswordHistorySize = $passwordHistory" | Set-Content $seceditCfgPath
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas SECURITYPOLICY /quiet
    Remove-Item $seceditCfgPath
    Write-Host "V-254288 remediation applied. Password history set to $passwordHistory passwords."
}

# V-254290 - Minimum password age
$remediation_V254290 = {
    $minPasswordAge = 1
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"

    secedit /export /cfg $seceditCfgPath
    (Get-Content $seceditCfgPath) -replace 'MinimumPasswordAge = \d+', "MinimumPasswordAge = $minPasswordAge" | Set-Content $seceditCfgPath
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas SECURITYPOLICY /quiet
    Remove-Item $seceditCfgPath
    Write-Host "V-254290 remediation applied. Minimum password age set to $minPasswordAge day."
}

# V-254291 - Minimum password length
$remediation_V254291 = {
    $minPasswordLength = 14
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"

    secedit /export /cfg $seceditCfgPath
    (Get-Content $seceditCfgPath) -replace 'MinimumPasswordLength = \d+', "MinimumPasswordLength = $minPasswordLength" | Set-Content $seceditCfgPath
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas SECURITYPOLICY /quiet
    Remove-Item $seceditCfgPath
    Write-Host "V-254291 remediation applied. Minimum password length set to $minPasswordLength characters."
}

# V-254306 - Audit Detailed Tracking - Plug and Play Events successes.
$remediation_V254306 = {
    auditpol /set /subcategory:"Plug and Play Events" /success:enable
    Write-Host "V-254306 remediation applied. Audit success for Plug and Play Events enabled."
}

# V-254310 - Audit Logon/Logoff - Group Membership successes.
$remediation_V254310 = {
    auditpol /set /subcategory:"Group Membership" /success:enable
    Write-Host "V-254310 remediation applied. Audit success for Group Membership enabled."
}

# V-254320 - Audit Policy Change - Audit Policy Change failures.
$remediation_V254320 = {
    auditpol /set /subcategory:"Audit Policy Change" /failure:enable
    Write-Host "V-254320 remediation applied. Audit failure for Audit Policy Change enabled."
}

# V-254322 - Audit Policy Change - Authorization Policy Change successes.
$remediation_V254322 = {
    auditpol /set /subcategory:"Authorization Policy Change" /success:enable
    Write-Host "V-254322 remediation applied. Audit success for Authorization Policy Change enabled."
}

# V-254325 - Audit System - IPsec Driver successes.
$remediation_V254325 = {
    auditpol /set /subcategory:"IPsec Driver" /success:enable
    Write-Host "V-254325 remediation applied. Audit success for IPsec Driver enabled."
}

# V-254326 - Audit System - IPsec Driver failures.
$remediation_V254326 = {
    auditpol /set /subcategory:"IPsec Driver" /failure:enable
    Write-Host "V-254326 remediation applied. Audit failure for IPsec Driver enabled."
}

# V-254333 - Prevent the display of slide shows on the lock screen.
$remediation_V254333 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "NoLockScreenSlideshow" -Value 1 -Type DWord
    Write-Host "V-254333 remediation applied. Lock screen slide shows disabled."
}

# V-254334 - Disable WDigest Authentication.
$remediation_V254334 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0 -Type DWord
    Write-Host "V-254334 remediation applied. WDigest Authentication disabled."
}

# V-254339 - Disable insecure logons to an SMB server.
$remediation_V254339 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord
    Write-Host "V-254339 remediation applied. Insecure logons to SMB server disabled."
}

# V-254341 - Include command line data in process creation events.
$remediation_V254341 = {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    Write-Host "V-254341 remediation applied. Command line data included in process creation events."
}

# V-254342 - Enable Remote host allows delegation of nonexportable credentials.
$remediation_V254342 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
    Ensure-RegistryPath -path $regPath
    New-ItemProperty -Path $regPath -Name "AllowProtectedCreds" -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host "V-254342 remediation applied. Remote host delegation of nonexportable credentials enabled."
}

# V-254345 - Reprocess group policy objects even if they have not changed.
$remediation_V254345 = {
    $regPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "GroupPolicyMinTransferRate" -Value 0 -Type DWord
    Write-Host "V-254345 remediation applied. Group policy objects will be reprocessed even if they have not changed."
}

# V-254346 - Turn off downloading print driver packages over HTTP.
$remediation_V254346 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisableWebPnPDownload" -Value 1 -Type DWord
    Write-Host "V-254346 remediation applied. Downloading print driver packages over HTTP turned off."
}

# V-254347 - Windows Server 2022 printing over HTTP must be turned off.
$remediation_V254347 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisableHTTPPrinting" -Value 1 -Type DWord
    Write-Host "V-254347 remediation applied. Printing over HTTP is turned off."
}

# V-254348 - Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen.
$remediation_V254348 = {
    $regPath = "HKLM:\Software\Policies\Microsoft\Windows\System"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DontDisplayNetworkSelectionUI" -Value 1 -Type DWord
    Write-Host "V-254348 remediation applied. Network selection UI is hidden on the logon screen."
}

# V-254349 - Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery).
$remediation_V254349 = {
    powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
    Write-Host "V-254349 remediation applied. Users must authenticate when waking from sleep (on battery)."
}

# V-254350 - Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in).
$remediation_V254350 = {
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONSOLELOCK 1
    Write-Host "V-254350 remediation applied. Users must authenticate when waking from sleep (plugged in)."
}

# V-254355 - Windows Server 2022 administrator accounts must not be enumerated during elevation.
$remediation_V254355 = {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "EnumerateAdministrators" -Value 0 -Type DWord
    Write-Host "V-254355 remediation applied. Administrator accounts are not enumerated during elevation."
}

# V-254358 - Windows Server 2022 Application event log size must be configured to 32768 KB or greater.
$remediation_V254358 = {
    wevtutil sl Application /ms:32768
    Write-Host "V-254358 remediation applied. Application event log size set to 32768 KB."
}

# V-254359 - Windows Server 2022 Security event log size must be configured to 196608 KB or greater.
$remediation_V254359 = {
    wevtutil sl Security /ms:196608
    Write-Host "V-254359 remediation applied. Security event log size set to 196608 KB."
}

# V-254360 - Windows Server 2022 System event log size must be configured to 32768 KB or greater.
$remediation_V254360 = {
    wevtutil sl System /ms:32768
    Write-Host "V-254360 remediation applied. System event log size set to 32768 KB."
}

# V-254361 - Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled.
$remediation_V254361 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "EnableSmartScreen" -Value 1 -Type DWord
    Write-Host "V-254361 remediation applied. Microsoft Defender SmartScreen is enabled."
}

# V-254365 - Windows Server 2022 must not save passwords in the Remote Desktop Client.
$remediation_V254365 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisablePasswordSaving" -Value 1 -Type DWord
    Write-Host "V-254365 remediation applied. Saving passwords in the Remote Desktop Client is disabled."
}

# V-254366 - Windows Server 2022 Remote Desktop Services must prevent drive redirection.
$remediation_V254366 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "fDisableCdm" -Value 1 -Type DWord
    Write-Host "V-254366 remediation applied. Drive redirection is disabled."
}

# V-254367 - Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection.
$remediation_V254367 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "fPromptForPassword" -Value 1 -Type DWord
    Write-Host "V-254367 remediation applied. Prompt for passwords upon connection is enabled."
}

# V-254368 - Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications.
$remediation_V254368 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "fEncryptRPCTraffic" -Value 1 -Type DWord
    Write-Host "V-254368 remediation applied. Secure RPC communications are required."
}

# V-254369 - Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level.
$remediation_V254369 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "MinEncryptionLevel" -Value 3 -Type DWord
    Write-Host "V-254369 remediation applied. Client connection encryption set to High Level."
}

# V-254370 - Windows Server 2022 must prevent attachments from being downloaded from RSS feeds.
$remediation_V254370 = {
    $regPath = "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisableEnclosureDownload" -Value 1 -Type DWord
    Write-Host "V-254370 remediation applied. Attachments from RSS feeds are prevented from being downloaded."
}

# V-254372 - Windows Server 2022 must prevent Indexing of encrypted files.
$remediation_V254372 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord
    Write-Host "V-254372 remediation applied. Indexing of encrypted files is prevented."
}

# V-254373 - Windows Server 2022 must prevent users from changing installation options.
$remediation_V254373 = {
    $regPath = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "EnableUserControl" -Value 0 -Type DWord
    Write-Host "V-254373 remediation applied. Users are prevented from changing installation options."
}

# V-254377 - Windows Server 2022 PowerShell script block logging must be enabled.
$remediation_V254377 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Write-Host "V-254377 remediation applied. PowerShell script block logging is enabled."
}

# V-254379 - Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic.
$remediation_V254379 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord
    Write-Host "V-254379 remediation applied. Unencrypted traffic is not allowed for WinRM client."
}

# V-254380 - Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication.
$remediation_V254380 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowDigest" -Value 0 -Type DWord
    Write-Host "V-254380 remediation applied. Digest authentication is not allowed for WinRM client."
}

# V-254382 - Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic.
$remediation_V254382 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowUnencryptedTraffic" -Value 0 -Type DWord
    Write-Host "V-254382 remediation applied. Unencrypted traffic is disabled for WinRM service."
}

# V-254383 - Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials.
$remediation_V254383 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisableRunAs" -Value 1 -Type DWord
    Write-Host "V-254383 remediation applied. Storing RunAs credentials is disabled for WinRM service."
}

# V-254384 - Windows Server 2022 must have PowerShell Transcription enabled.
$remediation_V254384 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1 -Type DWord
    Write-Host "V-254384 remediation applied. PowerShell Transcription is enabled."
}

# V-254431 - Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server.
$remediation_V254431 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "RestrictRemoteClients" -Value 1 -Type DWord
    Write-Host "V-254431 remediation applied. Unauthenticated RPC clients are restricted."
}

# V-254433 - Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators.
$remediation_V254433 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "RestrictRemoteSAM" -Value 1 -Type DWord
    Write-Host "V-254433 remediation applied. Remote calls to SAM are restricted to Administrators."
}

# V-254434 - Access this computer from the network user right must only be assigned to Administrators and Authenticated Users.
$remediation_V254434 = {
    $privilege = "SeNetworkLogonRight"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with Administrators and Authenticated Users SIDs
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-544,*S-1-5-11" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254434 remediation applied. Only Administrators and Authenticated Users are allowed to access the computer from the network."
}

# V-254435 - Deny access to this computer from the network user right must be configured to prevent access from highly privileged domain accounts and local accounts, and from unauthenticated access.
$remediation_V254435 = {
    $privilege = "SeDenyNetworkLogonRight"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with the appropriate SIDs
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-544,*S-1-5-32-500,*S-1-5-32-501,*S-1-5-32-502" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254435 remediation applied. Access denied to computer from the network for specified accounts."
}

# V-254436 - Deny log on as a batch job user right must be configured
$remediation_V254436 = {
    $privilege = "SeDenyBatchLogonRight"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with the necessary accounts
    # This assumes SIDs for highly privileged domain accounts and unauthenticated access are well-defined
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-544,*S-1-5-32-500,*S-1-5-32-501" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254436 remediation applied. Denied log on as a batch job for specified accounts."
}

# V-254438 - Deny log on locally user right must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems.
$remediation_V254438 = {
    $privilege = "SeDenyInteractiveLogonRight"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with the required SID values (e.g., for Admin and unauthenticated users)
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-544,*S-1-5-7" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254438 remediation applied. Denied log on locally for specified accounts."
}

# V-254439 - Deny log on through Remote Desktop Services user right must be configured
$remediation_V254439 = {
    $privilege = "SeDenyRemoteInteractiveLogonRight"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with appropriate SIDs
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-500,*S-1-5-32-501,*S-1-5-32-502,*S-1-5-6" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254439 remediation applied. Denied log on through Remote Desktop Services for specified accounts."
}

# V-254448 - Windows Server 2022 built-in guest account must be renamed.
$remediation_V254448 = {
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

    if ($null -ne $guestAccount) {
        Rename-LocalUser -Name "Guest" -NewName "RenamedGuestAccount"
        Write-Host "V-254448 remediation applied. Built-in guest account renamed."
    } else {
        Write-Host "Guest account not found. Skipping rename operation." -ForegroundColor Yellow
    }
}

# V-254449 - Windows Server 2022 must force audit policy subcategory settings to override audit policy category settings.
$remediation_V254449 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1 -Type DWord
    Write-Host "V-254449 remediation applied. Audit policy subcategory settings forced to override category settings."
}

# V-254456 - Windows Server 2022 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver.
$remediation_V254456 = {
    $regPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "ScreenSaveTimeOut" -Value 900 -Type String
    Set-ItemProperty -Path $regPath -Name "ScreenSaverIsSecure" -Value 1 -Type String
    Set-ItemProperty -Path $regPath -Name "ScreenSaveActive" -Value 1 -Type String
    Write-Host "V-254456 remediation applied. Machine inactivity limit set to 15 minutes with screen saver lock."
}

# V-254457 - Windows Server 2022 required legal notice must be configured to display before console logon.
$remediation_V254457 = {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "legalnoticecaption" -Value "Warning" -Type String
    Set-ItemProperty -Path $regPath -Name "legalnoticetext" -Value "Unauthorized use of this system is prohibited. All activities are subject to monitoring." -Type String
    Write-Host "V-254457 remediation applied. Legal notice configured."
}

# V-254459 - Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation.
$remediation_V254459 = {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "ScRemoveOption" -Value 1 -Type DWord  # 1 = Lock Workstation, 2 = Force Logoff
    Write-Host "V-254459 remediation applied. Smart Card removal option configured to Lock Workstation."
}

# V-254460 - Windows Server 2022 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled.
$remediation_V254460 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "RequireSecuritySignature" -Value 1 -Type DWord
    Write-Host "V-254460 remediation applied. Microsoft network client digitally sign communications (always) enabled."
}

# V-254463 - Windows Server 2022 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled.
$remediation_V254463 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "RequireSecuritySignature" -Value 1 -Type DWord
    Write-Host "V-254463 remediation applied. Microsoft network server digitally sign communications (always) enabled."
}

# V-254464 - Windows Server 2022 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled.
$remediation_V254464 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "EnableSecuritySignature" -Value 1 -Type DWord
    Write-Host "V-254464 remediation applied. Microsoft network server digitally sign communications (if client agrees) enabled."
}

# V-254470 - Windows Server 2022 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously.
$remediation_V254470 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "UseMachineId" -Value 1 -Type DWord
    Write-Host "V-254470 remediation applied. Services using Local System with Negotiate and NTLM must use the computer identity."
}

# V-254471 - Windows Server 2022 must prevent NTLM from falling back to a Null session.
$remediation_V254471 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "RestrictNullSessAccess" -Value 1 -Type DWord
    Write-Host "V-254471 remediation applied. NTLM fallback to Null session prevented."
}

# V-254472 - Prevent PKU2U authentication using online identities
$remediation_V254472 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowOnlineID" -Value 0 -Type DWord
    Write-Host "V-254472 remediation applied. PKU2U authentication using online identities disabled."
}

# V-254473 - Configure Kerberos encryption types to prevent DES and RC4 encryption suites
$remediation_V254473 = {
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -Value 0x7fffffff -Type DWord
    Write-Host "V-254473 remediation applied. DES and RC4 encryption suites disabled."
}

# V-254477 - Configure session security for NTLM SSP-based clients to require NTLMv2 session security and 128-bit encryption
$remediation_V254477 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "NTLMMinClientSec" -Value 0x20080000 -Type DWord
    Write-Host "V-254477 remediation applied. NTLMv2 session security and 128-bit encryption required for clients."
}

# V-254478 - Configure session security for NTLM SSP-based servers to require NTLMv2 session security and 128-bit encryption
$remediation_V254478 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "NTLMMinServerSec" -Value 0x20080000 -Type DWord
    Write-Host "V-254478 remediation applied. NTLMv2 session security and 128-bit encryption required for servers."
}

# V-254479 - Require users to enter a password to access private keys stored on the computer
$remediation_V254479 = {
    $regPath = "HKLM:\Software\Policies\Microsoft\Cryptography"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "ForceKeyProtection" -Value 2 -Type DWord
    Write-Host "V-254479 remediation applied. Password required to access private keys."
}

# V-254480 - Configure the system to use FIPS-compliant algorithms for encryption, hashing, and signing
$remediation_V254480 = {
    $regPath = "HKLM:\System\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "Enabled" -Value 1 -Type DWord
    Write-Host "V-254480 remediation applied. FIPS-compliant algorithms enabled."
}

# V-254482 - Enable UAC approval mode for the built-in Administrator account
$remediation_V254482 = {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "FilterAdministratorToken" -Value 1 -Type DWord
    Write-Host "V-254482 remediation applied. UAC approval mode enabled for built-in Administrator."
}

# V-254484 - UAC must prompt administrators for consent on the secure desktop
$remediation_V254484 = {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
    Set-ItemProperty -Path $regPath -Name "PromptOnSecureDesktop" -Value 1 -Type DWord
    Write-Host "V-254484 remediation applied. UAC prompts for consent on secure desktop."
}

# V-254485 - UAC must automatically deny standard user requests for elevation
$remediation_V254485 = {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord
    Write-Host "V-254485 remediation applied. UAC automatically denies standard user requests for elevation."
}

# V-254493 - Allow log on locally user right must only be assigned to the Administrators group.
$remediation_V254493 = {
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"

    secedit /export /cfg $seceditCfgPath /log $env:windir\security\logs\scesrv.log
    (Get-Content $seceditCfgPath) -replace 'SeInteractiveLogonRight = .*', 'SeInteractiveLogonRight = *S-1-5-32-544' | Set-Content $seceditCfgPath
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /quiet
    Remove-Item $seceditCfgPath
    Write-Host "V-254493 remediation applied. 'Allow log on locally' set to Administrators group only." -ForegroundColor Green
}

# V-254494 - Back up files and directories user right must only be assigned to the Administrators group.
$remediation_V254494 = {
    $privilege = "SeBackupPrivilege"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with Administrators group SID
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-544" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254494 remediation applied. Only Administrators group has the 'Back up files and directories' user right."
}

# V-254504 - Increase scheduling priority user right must only be assigned to the Administrators group.
$remediation_V254504 = {
    $privilege = "SeIncreaseBasePriorityPrivilege"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with Administrators group SID
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-544" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254504 remediation applied. Only Administrators group has the 'Increase scheduling priority' user right."
}

# V-254511 - Restore files and directories user right must only be assigned to the Administrators group.
$remediation_V254511 = {
    $privilege = "SeRestorePrivilege"
    $seceditCfgPath = "c:\secpol.cfg"
    $seceditDbPath = "$env:windir\security\database\secedit.sdb"
    $seceditLogPath = "$env:windir\security\logs\scesrv.log"

    # Export the current security configuration
    secedit /export /cfg $seceditCfgPath

    # Replace the privilege assignment with Administrators group SID
    (Get-Content $seceditCfgPath) -replace "$privilege = .*", "$privilege = *S-1-5-32-544" | Set-Content $seceditCfgPath

    # Apply the configuration with the USER_RIGHTS area specified
    secedit /configure /db $seceditDbPath /cfg $seceditCfgPath /overwrite /areas USER_RIGHTS /log $seceditLogPath /quiet

    # Clean up the temporary configuration file
    Remove-Item $seceditCfgPath

    Write-Host "V-254511 remediation applied. Only Administrators group has the 'Restore files and directories' user right."
}

# Array of CAT II findings
$findings = @(
    @{
        severity = "medium"
        vID = "V-254283"
        description = "Windows Server 2022 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS."
        fixText = "Ensure the system is configured to run in UEFI mode via BIOS/UEFI settings."
        remediationScript = $remediation_V254283
    },
    @{
        severity = "medium"
        vID = "V-254285"
        description = "Windows Server 2022 account lockout duration must be configured to 15 minutes or greater."
        fixText = "Configure the account lockout duration to 15 minutes or greater."
        remediationScript = $remediation_V254285
    },
    @{
        severity = "medium"
        vID = "V-254286"
        description = "Windows Server 2022 must have the number of allowed bad logon attempts configured to three or less."
        fixText = "Configure the number of bad logon attempts allowed before lockout to three or less."
        remediationScript = $remediation_V254286
    },
    @{
        severity = "medium"
        vID = "V-254287"
        description = "Windows Server 2022 must have the period of time before the bad logon counter is reset configured to 15 minutes or greater."
        fixText = "Configure the reset time for bad logon attempts to 15 minutes or greater."
        remediationScript = $remediation_V254287
    },
    @{
        severity = "medium"
        vID = "V-254288"
        description = "Windows Server 2022 password history must be configured to 24 passwords remembered."
        fixText = "Configure the password history to 24 passwords remembered."
        remediationScript = $remediation_V254288
    },
    @{
        severity = "medium"
        vID = "V-254290"
        description = "Windows Server 2022 minimum password age must be configured to at least one day."
        fixText = "Configure the minimum password age to at least one day."
        remediationScript = $remediation_V254290
    },
    @{
        severity = "medium"
        vID = "V-254291"
        description = "Windows Server 2022 minimum password length must be configured to 14 characters."
        fixText = "Configure the minimum password length to 14 characters."
        remediationScript = $remediation_V254291
    },
    @{
        severity = "medium"
        vID = "V-254322"
        description = "Windows Server 2022 must be configured to audit Policy Change - Authorization Policy Change successes."
        fixText = "Configure the system to audit Authorization Policy Change successes."
        remediationScript = $remediation_V254322
    },
    @{
        severity = "medium"
        vID = "V-254325"
        description = "Windows Server 2022 must be configured to audit System - IPsec Driver successes."
        fixText = "Configure the system to audit IPsec Driver successes."
        remediationScript = $remediation_V254325
    },
    @{
        severity = "medium"
        vID = "V-254326"
        description = "Windows Server 2022 must be configured to audit System - IPsec Driver failures."
        fixText = "Configure the system to audit IPsec Driver failures."
        remediationScript = $remediation_V254326
    },
    @{
        severity = "medium"
        vID = "V-254333"
        description = "Windows Server 2022 must prevent the display of slide shows on the lock screen."
        fixText = "Configure the system to prevent the display of slide shows on the lock screen."
        remediationScript = $remediation_V254333
    },
    @{
        severity = "medium"
        vID = "V-254334"
        description = "Windows Server 2022 must have WDigest Authentication disabled."
        fixText = "Configure the system to disable WDigest Authentication."
        remediationScript = $remediation_V254334
    },
    @{
        severity = "medium"
        vID = "V-254339"
        description = "Windows Server 2022 insecure logons to an SMB server must be disabled."
        fixText = "Configure the system to disable insecure logons to an SMB server."
        remediationScript = $remediation_V254339
    },
    @{
        severity = "medium"
        vID = "V-254341"
        description = "Windows Server 2022 command line data must be included in process creation events."
        fixText = "Configure the system to include command line data in process creation events."
        remediationScript = $remediation_V254341
    },
    @{
        severity = "medium"
        vID = "V-254342"
        description = "Windows Server 2022 must be configured to enable Remote host allows delegation of nonexportable credentials."
        fixText = "Configure the system to enable Remote host allows delegation of nonexportable credentials."
        remediationScript = $remediation_V254342
    },
    @{
        severity = "medium"
        vID = "V-254345"
        description = "Windows Server 2022 group policy objects must be reprocessed even if they have not changed."
        fixText = "Configure the system to reprocess group policy objects even if they have not changed."
        remediationScript = $remediation_V254345
    },
    @{
        severity = "medium"
        vID = "V-254346"
        description = "Windows Server 2022 downloading print driver packages over HTTP must be turned off."
        fixText = "Configure the system to turn off downloading print driver packages over HTTP."
        remediationScript = $remediation_V254346
    },
    @{
        severity = "medium"
        vID = "V-254347"
        description = "Windows Server 2022 printing over HTTP must be turned off."
        fixText = "Disable the ability to print over HTTP by configuring the policy value in the registry."
        remediationScript = $remediation_V254347
    },
    @{
        severity = "medium"
        vID = "V-254348"
        description = "Windows Server 2022 network selection user interface (UI) must not be displayed on the logon screen."
        fixText = "Configure the registry to prevent the network selection UI from being displayed on the logon screen."
        remediationScript = $remediation_V254348
    },
    @{
        severity = "medium"
        vID = "V-254349"
        description = "Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (on battery)."
        fixText = "Configure power settings to require authentication when the system wakes from sleep while on battery."
        remediationScript = $remediation_V254349
    },
    @{
        severity = "medium"
        vID = "V-254350"
        description = "Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in)."
        fixText = "Configure power settings to require authentication when the system wakes from sleep while plugged in."
        remediationScript = $remediation_V254350
    },
    @{
        severity = "medium"
        vID = "V-254355"
        description = "Windows Server 2022 administrator accounts must not be enumerated during elevation."
        fixText = "Configure the registry to prevent enumeration of administrator accounts during elevation."
        remediationScript = $remediation_V254355
    },
    @{
        severity = "medium"
        vID = "V-254358"
        description = "Windows Server 2022 Application event log size must be configured to 32768 KB or greater."
        fixText = "Set the Application event log size to 32768 KB or greater using the wevtutil command."
        remediationScript = $remediation_V254358
    },
    @{
        severity = "medium"
        vID = "V-254359"
        description = "Windows Server 2022 Security event log size must be configured to 196608 KB or greater."
        fixText = "Set the Security event log size to 196608 KB or greater using the wevtutil command."
        remediationScript = $remediation_V254359
    },
    @{
        severity = "medium"
        vID = "V-254360"
        description = "Windows Server 2022 System event log size must be configured to 32768 KB or greater."
        fixText = "Set the System event log size to 32768 KB or greater using the wevtutil command."
        remediationScript = $remediation_V254360
    },
    @{
        severity = "medium"
        vID = "V-254361"
        description = "Windows Server 2022 Microsoft Defender antivirus SmartScreen must be enabled."
        fixText = "Enable Microsoft Defender SmartScreen by configuring the appropriate registry setting."
        remediationScript = $remediation_V254361
    },
    @{
        severity = "medium"
        vID = "V-254365"
        description = "Windows Server 2022 must not save passwords in the Remote Desktop Client."
        fixText = "Configure the registry to disable password saving in the Remote Desktop Client."
        remediationScript = $remediation_V254365
    },
    @{
        severity = "medium"
        vID = "V-254366"
        description = "Windows Server 2022 Remote Desktop Services must prevent drive redirection."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection >> Do not allow drive redirection to 'Enabled'."
        remediationScript = $remediation_V254366
    },
    @{
        severity = "medium"
        vID = "V-254367"
        description = "Windows Server 2022 Remote Desktop Services must always prompt a client for passwords upon connection."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> Always prompt for password upon connection to 'Enabled'."
        remediationScript = $remediation_V254367
    },
    @{
        severity = "medium"
        vID = "V-254368"
        description = "Windows Server 2022 Remote Desktop Services must require secure Remote Procedure Call (RPC) communications."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> Require use of specific security layer for remote (RDP) connections to 'Enabled' with 'SSL (TLS 1.0)' or 'Negotiate'."
        remediationScript = $remediation_V254368
    },
    @{
        severity = "medium"
        vID = "V-254369"
        description = "Windows Server 2022 Remote Desktop Services must be configured with the client connection encryption set to High Level."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> Set client connection encryption level to 'Enabled' and 'High Level'."
        remediationScript = $remediation_V254369
    },
    @{
        severity = "medium"
        vID = "V-254370"
        description = "Windows Server 2022 must prevent attachments from being downloaded from RSS feeds."
        fixText = "Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> RSS Feeds >> Disable downloading of enclosures to 'Enabled'."
        remediationScript = $remediation_V254370
    },
    @{
        severity = "medium"
        vID = "V-254372"
        description = "Windows Server 2022 must prevent Indexing of encrypted files."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Search >> Prevent indexing of encrypted files to 'Enabled'."
        remediationScript = $remediation_V254372
    },
    @{
        severity = "medium"
        vID = "V-254373"
        description = "Windows Server 2022 must prevent users from changing installation options."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> Enable user control over installs to 'Disabled'."
        remediationScript = $remediation_V254373
    },
    @{
        severity = "medium"
        vID = "V-254377"
        description = "Windows Server 2022 PowerShell script block logging must be enabled."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows PowerShell >> Turn on PowerShell Script Block Logging to 'Enabled'."
        remediationScript = $remediation_V254377
    },
    @{
        severity = "medium"
        vID = "V-254379"
        description = "Windows Server 2022 Windows Remote Management (WinRM) client must not allow unencrypted traffic."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> Allow unencrypted traffic to 'Disabled'."
        remediationScript = $remediation_V254379
    },
    @{
        severity = "medium"
        vID = "V-254380"
        description = "Windows Server 2022 Windows Remote Management (WinRM) client must not use Digest authentication."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> Allow Digest authentication to 'Disabled'."
        remediationScript = $remediation_V254380
    },
    @{
        severity = "medium"
        vID = "V-254382"
        description = "Windows Server 2022 Windows Remote Management (WinRM) service must not allow unencrypted traffic."
        fixText = "Configure the registry value for HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service >> AllowUnencryptedTraffic to '0'."
        remediationScript = $remediation_V254382
    },
    @{
        severity = "medium"
        vID = "V-254383"
        description = "Windows Server 2022 Windows Remote Management (WinRM) service must not store RunAs credentials."
        fixText = "Configure the registry value for HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service >> DisableRunAs to '1'."
        remediationScript = $remediation_V254383
    },
    @{
        severity = "medium"
        vID = "V-254384"
        description = "Windows Server 2022 must have PowerShell Transcription enabled."
        fixText = "Configure the registry value for HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription >> EnableTranscripting to '1'."
        remediationScript = $remediation_V254384
    },
    @{
        severity = "medium"
        vID = "V-254431"
        description = "Windows Server 2022 must restrict unauthenticated Remote Procedure Call (RPC) clients from connecting to the RPC server."
        fixText = "Configure the registry value for HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc >> RestrictRemoteClients to '1'."
        remediationScript = $remediation_V254431
    },
    @{
        severity = "medium"
        vID = "V-254433"
        description = "Windows Server 2022 must restrict remote calls to the Security Account Manager (SAM) to Administrators."
        fixText = "Configure the registry value for HKLM:\SYSTEM\CurrentControlSet\Control\Lsa >> RestrictRemoteSAM to '1'."
        remediationScript = $remediation_V254433
    },
    @{
        severity = "medium"
        vID = "V-254434"
        description = "Windows Server 2022 Access this computer from the network user right must only be assigned to Administrators and Authenticated Users."
        fixText = "Configure the security policy value for Access this computer from the network user right to include only Administrators and Authenticated Users."
        remediationScript = $remediation_V254434
    },
    @{
        severity = "medium"
        vID = "V-254435"
        description = "Windows Server 2022 Deny access to this computer from the network user right must be configured to prevent access from highly privileged domain accounts and local accounts and from unauthenticated access on all systems."
        fixText = "Configure the security policy value for Deny access to this computer from the network user right to prevent access from highly privileged domain accounts and local accounts, and from unauthenticated access."
        remediationScript = $remediation_V254435
    },
    @{
        severity = "medium"
        vID = "V-254436"
        description = "Windows Server 2022 Deny log on as a batch job user right must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."
        fixText = "Configure the security policy value for Deny log on as a batch job user right to prevent access from highly privileged domain accounts and from unauthenticated access."
        remediationScript = $remediation_V254436
    },
    @{
        severity = "medium"
        vID = "V-254438"
        description = "Windows Server 2022 Deny log on locally user right must be configured to prevent access from highly privileged domain accounts and from unauthenticated access on all systems."
        fixText = "Configure the security policy value for Deny log on locally user right to prevent access from highly privileged domain accounts and from unauthenticated access."
        remediationScript = $remediation_V254438
    },
    @{
        severity = "medium"
        vID = "V-254439"
        description = "Windows Server 2022 Deny log on through Remote Desktop Services user right must be configured to prevent access from highly privileged domain accounts and all local accounts and from unauthenticated access on all systems."
        fixText = "Configure the security policy value for Deny log on through Remote Desktop Services user right to prevent access from highly privileged domain accounts, all local accounts, and unauthenticated access."
        remediationScript = $remediation_V254439
    },
    @{
        severity = "medium"
        vID = "V-254448"
        description = "Windows Server 2022 built-in guest account must be renamed."
        fixText = "Rename the built-in guest account to something other than 'Guest'."
        remediationScript = $remediation_V254448
    },
    @{
        severity = "medium"
        vID = "V-254449"
        description = "Windows Server 2022 must force audit policy subcategory settings to override audit policy category settings."
        fixText = "Set the registry key 'SCENoApplyLegacyAuditPolicy' to 1 to force subcategory settings to override category settings."
        remediationScript = $remediation_V254449
    },
    @{
        severity = "medium"
        vID = "V-254456"
        description = "Windows Server 2022 machine inactivity limit must be set to 15 minutes or less, locking the system with the screen saver."
        fixText = "Configure the machine inactivity limit to lock the system with a screen saver after 15 minutes of inactivity."
        remediationScript = $remediation_V254456
    },
    @{
        severity = "medium"
        vID = "V-254457"
        description = "Windows Server 2022 required legal notice must be configured to display before console logon."
        fixText = "Set the registry keys 'legalnoticecaption' and 'legalnoticetext' to display the required legal notice before logon."
        remediationScript = $remediation_V254457
    },
    @{
        severity = "medium"
        vID = "V-254459"
        description = "Windows Server 2022 Smart Card removal option must be configured to Force Logoff or Lock Workstation."
        fixText = "Configure the Smart Card removal option to either Force Logoff or Lock Workstation."
        remediationScript = $remediation_V254459
    },
    @{
        severity = "medium"
        vID = "V-254460"
        description = "Windows Server 2022 setting Microsoft network client: Digitally sign communications (always) must be configured to Enabled."
        fixText = "Enable the setting to digitally sign communications (always) for Microsoft network client."
        remediationScript = $remediation_V254460
    },
    @{
        severity = "medium"
        vID = "V-254463"
        description = "Windows Server 2022 setting Microsoft network server: Digitally sign communications (always) must be configured to Enabled."
        fixText = "Enable the setting to digitally sign communications (always) for Microsoft network server."
        remediationScript = $remediation_V254463
    },
    @{
        severity = "medium"
        vID = "V-254464"
        description = "Windows Server 2022 setting Microsoft network server: Digitally sign communications (if client agrees) must be configured to Enabled."
        fixText = "Enable the setting to digitally sign communications (if client agrees) for Microsoft network server."
        remediationScript = $remediation_V254464
    },
    @{
        severity = "medium"
        vID = "V-254470"
        description = "Windows Server 2022 services using Local System that use Negotiate when reverting to NTLM authentication must use the computer identity instead of authenticating anonymously."
        fixText = "Set the registry key 'UseMachineId' to 1 to ensure the computer identity is used instead of authenticating anonymously."
        remediationScript = $remediation_V254470
    },
    @{
        severity = "medium"
        vID = "V-254471"
        description = "Windows Server 2022 must prevent NTLM from falling back to a Null session."
        fixText = "Set the registry key 'RestrictNullSessAccess' to 1 to prevent NTLM from falling back to a Null session."
        remediationScript = $remediation_V254471
    },
    @{
        severity = "medium"
        vID = "V-254472"
        description = "Windows Server 2022 must prevent PKU2U authentication using online identities."
        fixText = "Configure the registry to prevent PKU2U authentication using online identities."
        remediationScript = $remediation_V254472
    },
    @{
        severity = "medium"
        vID = "V-254473"
        description = "Windows Server 2022 Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites."
        fixText = "Configure the registry to prevent the use of DES and RC4 encryption suites in Kerberos."
        remediationScript = $remediation_V254473
    },
    @{
        severity = "medium"
        vID = "V-254477"
        description = "Windows Server 2022 session security for NTLM SSP-based clients must be configured to require NTLMv2 session security and 128-bit encryption."
        fixText = "Configure the registry to require NTLMv2 session security and 128-bit encryption for NTLM SSP-based clients."
        remediationScript = $remediation_V254477
    },
    @{
        severity = "medium"
        vID = "V-254478"
        description = "Windows Server 2022 session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption."
        fixText = "Configure the registry to require NTLMv2 session security and 128-bit encryption for NTLM SSP-based servers."
        remediationScript = $remediation_V254478
    },
    @{
        severity = "medium"
        vID = "V-254479"
        description = "Windows Server 2022 users must be required to enter a password to access private keys stored on the computer."
        fixText = "Configure the registry to require a password for accessing private keys."
        remediationScript = $remediation_V254479
    },
    @{
        severity = "medium"
        vID = "V-254480"
        description = "Windows Server 2022 must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing."
        fixText = "Configure the system to use FIPS-compliant algorithms."
        remediationScript = $remediation_V254480
    },
    @{
        severity = "medium"
        vID = "V-254482"
        description = "Windows Server 2022 User Account Control (UAC) approval mode for the built-in Administrator must be enabled."
        fixText = "Enable UAC approval mode for the built-in Administrator account."
        remediationScript = $remediation_V254482
    },
    @{
        severity = "medium"
        vID = "V-254484"
        description = "Windows Server 2022 User Account Control (UAC) must, at a minimum, prompt administrators for consent on the secure desktop."
        fixText = "Configure UAC to prompt administrators for consent on the secure desktop."
        remediationScript = $remediation_V254484
    },
    @{
        severity = "medium"
        vID = "V-254485"
        description = "Windows Server 2022 User Account Control (UAC) must automatically deny standard user requests for elevation."
        fixText = "Configure UAC to automatically deny standard user requests for elevation."
        remediationScript = $remediation_V254485
    },
    @{
        severity = "medium"
        vID = "V-254493"
        description = "Windows Server 2022 Allow log on locally user right must only be assigned to the Administrators group."
        fixText = "Restrict the 'Allow log on locally' user right to the Administrators group."
        remediationScript = $remediation_V254493
    },
    @{
        severity = "medium"
        vID = "V-254494"
        description = "Windows Server 2022 back up files and directories user right must only be assigned to the Administrators group."
        fixText = "Configure the user right 'Back up files and directories' to only be assigned to the Administrators group."
        remediationScript = $remediation_V254494
    },
    @{
        severity = "medium"
        vID = "V-254504"
        description = "Windows Server 2022 increase scheduling priority: user right must only be assigned to the Administrators group."
        fixText = "Configure the user right 'Increase scheduling priority' to only be assigned to the Administrators group."
        remediationScript = $remediation_V254504
    },
    @{
        severity = "medium"
        vID = "V-254511"
        description = "Windows Server 2022 restore files and directories user right must only be assigned to the Administrators group."
        fixText = "Configure the user right 'Restore files and directories' to only be assigned to the Administrators group."
        remediationScript = $remediation_V254511
    }
)

# Iterate over each finding
foreach ($finding in $findings) {
    # Check if the remediation has already been applied and skip if true
    $alreadyApplied = $false

    # Check specific conditions for each finding if needed
    switch ($finding.vID) {
        "V-254511" {
            # Example: Check if a specific registry setting or security setting is already applied
            # $alreadyApplied = <insert logic to check if already applied>
            $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
            if ((Get-ItemProperty -Path $regPath).SomeRegistryValue -eq 'ExpectedValue') {
                $alreadyApplied = $true
            }
        }
        # Add more cases as needed for other findings
    }

    if ($alreadyApplied) {
        Write-Host "$($finding.vID) has already been applied. Skipping..." -ForegroundColor Yellow
        continue
    }

    # Display finding details
    Display-Finding -severity $finding.severity -vID $finding.vID -description $finding.description -fixText $finding.fixText
    
    # Prompt the user with a default action of "Continue"
    $action = Read-Host "Do you want to (C)ontinue remediation (default), (S)kip, or (E)xit the script? [Press Enter for Continue]"
    
    # Treat empty input (pressing Enter) as "C" for Continue
    if ([string]::IsNullOrEmpty($action)) {
        $action = "C"
    }

    switch ($action.ToUpper()) {
        "S" {
            Write-Host "Skipping remediation for $($finding.vID)..." -ForegroundColor Yellow
            continue
        }
        "E" {
            Write-Host "Exiting script." -ForegroundColor Red
            exit
        }
        "C" {
            # Execute remediation script
            Write-Host "Executing remediation for $($finding.vID)..." -ForegroundColor Green
            & $finding.remediationScript
        }
        default {
            Write-Host "Invalid selection. Skipping remediation for $($finding.vID)..." -ForegroundColor Yellow
        }
    }

    # Add a new line space between remediations
    Write-Host "`n"
}

Write-Host "All CAT II findings have been processed." -ForegroundColor Green
