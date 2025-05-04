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

# Set the account lockout duration to 15 minutes
net accounts /lockoutduration:15

Write-Host "Account lockout duration set to 15 minutes."
# Set the account lockout duration to 15 minutes
net accounts /lockoutduration:15

Write-Host "Account lockout duration set to 15 minutes."
