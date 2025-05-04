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

# Remediation Scripts for CAT I Findings

# V-254352 - Windows Server 2022 Autoplay must be turned off for nonvolume devices.
$remediation_V254352 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "NoAutoplayfornonVolume" -Value 1 -Type DWord
    Write-Host "V-254352 remediation applied."
}

# V-254353 - Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands.
$remediation_V254353 = {
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "NoAutorun" -Value 1 -Type DWord
    Write-Host "V-254353 remediation applied."
}

# V-254354 - Windows Server 2022 AutoPlay must be disabled for all drives.
$remediation_V254354 = {
    $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    Write-Host "V-254354 remediation applied."
}

# V-254374 - Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option.
$remediation_V254374 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AlwaysInstallElevated" -Value 0 -Type DWord
    Write-Host "V-254374 remediation applied."
}

# V-254378 - Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication.
$remediation_V254378 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowBasic" -Value 0 -Type DWord
    Write-Host "V-254378 remediation applied."
}

# V-254381 - Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication.
$remediation_V254381 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "AllowBasic" -Value 0 -Type DWord
    Write-Host "V-254381 remediation applied."
}

# V-254467 - Windows Server 2022 must not allow anonymous enumeration of SAM accounts and shares.
$remediation_V254467 = {
    $regPath1 = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $regPath2 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    Ensure-RegistryPath -path $regPath1
    Ensure-RegistryPath -path $regPath2

    Set-ItemProperty -Path $regPath1 -Name "RestrictNullSessAccess" -Value 1 -Type DWord
    Set-ItemProperty -Path $regPath2 -Name "RestrictAnonymous" -Value 1 -Type DWord

    Write-Host "V-254467 remediation applied."
}


# V-254475 - Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM.
$remediation_V254475 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord
    Write-Host "V-254475 remediation applied."
}

# Array of CAT I findings
$findings = @(
    @{
        severity = "high"
        vID = "V-254352"
        description = "Windows Server 2022 Autoplay must be turned off for nonvolume devices."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> Disallow Autoplay for nonvolume devices to 'Enabled'."
        remediationScript = $remediation_V254352
    },
    @{
        severity = "high"
        vID = "V-254353"
        description = "Windows Server 2022 default AutoRun behavior must be configured to prevent AutoRun commands."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> Set the default behavior for AutoRun to 'Enabled' with 'Do not execute any autorun commands' selected."
        remediationScript = $remediation_V254353
    },
    @{
        severity = "high"
        vID = "V-254354"
        description = "Windows Server 2022 AutoPlay must be disabled for all drives."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> Turn off AutoPlay to 'Enabled' with 'All Drives' selected."
        remediationScript = $remediation_V254354
    },
    @{
        severity = "high"
        vID = "V-254374"
        description = "Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> Always install with elevated privileges to 'Disabled'."
        remediationScript = $remediation_V254374
    },
    @{
        severity = "high"
        vID = "V-254378"
        description = "Windows Server 2022 Windows Remote Management (WinRM) client must not use Basic authentication."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> Client >> Allow Basic authentication to 'Disabled'."
        remediationScript = $remediation_V254378
    },
    @{
        severity = "high"
        vID = "V-254381"
        description = "Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> Service >> Allow Basic authentication to 'Disabled'."
        remediationScript = $remediation_V254381
    },
    @{
        severity = "high"
        vID = "V-254467"
        description = "Windows Server 2022 must not allow anonymous enumeration of SAM accounts and shares."
        fixText = "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: Do not allow anonymous enumeration of SAM accounts and shares."
        remediationScript = $remediation_V254467
    },
    @{
        severity = "high"
        vID = "V-254475"
        description = "Windows Server 2022 LAN Manager authentication level must be configured to send NTLMv2 response only and to refuse LM and NTLM."
        fixText = "Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> Network security: LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'."
        remediationScript = $remediation_V254475
    }
)

# Iterate over each finding
foreach ($finding in $findings) {
    Remediate-Finding -severity $finding.severity -vID $finding.vID -description $finding.description -fixText $finding.fixText -remediationScript $finding.remediationScript
}

Write-Host "All CAT I findings have been processed." -ForegroundColor Green
