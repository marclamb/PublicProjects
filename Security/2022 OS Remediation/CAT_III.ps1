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

# Remediation Scripts for CAT III Findings

# V-254335 - Windows Server 2022 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing.
$remediation_V254335 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisableIpSourceRouting" -Value 2 -Type DWord
    Write-Host "V-254335 remediation applied."
}

# V-254336 - Windows Server 2022 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing.
$remediation_V254336 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisableIpSourceRouting" -Value 2 -Type DWord
    Write-Host "V-254336 remediation applied."
}

# V-254337 - Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes.
$remediation_V254337 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "EnableICMPRedirect" -Value 0 -Type DWord
    Write-Host "V-254337 remediation applied."
}

# V-254338 - Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers.
$remediation_V254338 = {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "NoNameReleaseOnDemand" -Value 1 -Type DWord
    Write-Host "V-254338 remediation applied."
}

# V-254351 - Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.
$remediation_V254351 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat"
    Ensure-RegistryPath -path $regPath
    Set-ItemProperty -Path $regPath -Name "DisableInventory" -Value 1 -Type DWord
    Write-Host "V-254351 remediation applied."
}

# V-254357 - Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet.
$remediation_V254357 = {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    $regName = "DODownloadMode"
    $desiredValue = 1  # Change this value based on your preference (0, 1, or 2 - but not 3)

    # Ensure the registry path exists
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    # Apply the setting
    Set-ItemProperty -Path $regPath -Name $regName -Value $desiredValue -Type DWord

    Write-Host "V-254357 remediation applied. Windows Update is configured not to obtain updates from other PCs on the internet."
}

# Array of CAT III findings
$findings = @(
    @{
        severity = "low"
        vID = "V-254335"
        description = "Windows Server 2022 Internet Protocol version 6 (IPv6) source routing must be configured to the highest protection level to prevent IP source routing."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> TCPIP Settings >> IPv6 Configuration Parameters >> Disable IPv6 source routing to 'Enabled'."
        remediationScript = $remediation_V254335
    },
    @{
        severity = "low"
        vID = "V-254336"
        description = "Windows Server 2022 source routing must be configured to the highest protection level to prevent Internet Protocol (IP) source routing."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> TCPIP Settings >> IPv4 Configuration Parameters >> Disable IP source routing to 'Enabled'."
        remediationScript = $remediation_V254336
    },
    @{
        severity = "low"
        vID = "V-254337"
        description = "Windows Server 2022 must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)-generated routes."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> TCPIP Settings >> Disable ICMP redirects to 'Enabled'."
        remediationScript = $remediation_V254337
    },
    @{
        severity = "low"
        vID = "V-254338"
        description = "Windows Server 2022 must be configured to ignore NetBIOS name release requests except from WINS servers."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> NetBT Parameters >> No name release on demand to 'Enabled'."
        remediationScript = $remediation_V254338
    },
    @{
        severity = "low"
        vID = "V-254351"
        description = "Windows Server 2022 Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Application Compatibility >> Turn off Application Compatibility Inventory to 'Enabled'."
        remediationScript = $remediation_V254351
    },
    @{
        severity = "low"
        vID = "V-254357"
        description = "Windows Server 2022 Windows Update must not obtain updates from other PCs on the internet."
        fixText = "Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Delivery Optimization >> Download Mode to 'Enabled' with any option except 'Internet' selected."
        remediationScript = $remediation_V254357
    }
)

# Iterate over each finding in CAT III
foreach ($finding in $findings) {
    # Check if the remediation has already been applied and skip if true
    $alreadyApplied = $false

    # Implement logic to check if the specific remediation is already applied
    # Example: For registry-based settings, you might check if the relevant key or value is already set
    # switch ($finding.vID) {
    #    "V-xxxxxx" {
    #        # Check if a specific registry setting or security setting is already applied
    #        $regPath = "HKLM:\Some\Path"
    #        if ((Get-ItemProperty -Path $regPath).SomeValue -eq 'ExpectedValue') {
    #            $alreadyApplied = $true
    #        }
    #    }
    #    # Add more cases as needed for other findings
    # }

    if ($alreadyApplied) {
        Write-Host "$($finding.vID) has already been applied. Skipping..." -ForegroundColor Yellow
        continue
    }

    # Remediation prompt with default action to Continue
    Display-Finding -severity $finding.severity -vID $finding.vID -description $finding.description -fixText $finding.fixText
    $action = Read-Host "Do you want to (C)ontinue remediation (default), (S)kip, or (E)xit the script? [Press Enter for Continue]" -Default "C"

    switch ($action.ToUpper()) {
        "S" {
            Write-Host "Skipping remediation for $($finding.vID)..." -ForegroundColor Yellow
            continue
        }
        "E" {
            Write-Host "Exiting script." -ForegroundColor Red
            exit
        }
        default {
            # Execute remediation script
            Write-Host "Executing remediation for $($finding.vID)..." -ForegroundColor Green
            & $finding.remediationScript
        }
    }

    # Add a new line space between remediations
    Write-Host "`n"
}

Write-Host "All CAT III findings have been processed." -ForegroundColor Green
