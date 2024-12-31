<#
.SYNOPSIS
    Enables Windows Insider Preview on a host machine without linking a Microsoft account.

.DESCRIPTION
    This script configures a Windows host to receive Insider Preview builds without requiring a linked Microsoft account.
    It supports selecting the Dev, Beta, or Release Preview channels, and the
    Active development of Windows (Mainline) or Skip ahead content types.
    The script handles different settings for Windows 10 (v1809+) and Windows 11.

.PARAMETER Channel
    Specifies the Insider Preview channel: Dev, Beta, or ReleasePreview.

.PARAMETER ContentType
    Specifies the content type: Mainline or SkipAhead.

.PARAMETER Ring
    Specifies the ring: External or Internal.

.PARAMETER Restore
    Specifies the restore option: Registry or a backup file path.

.EXAMPLE
    Enable-OfflineInsiderPreview -Channel Dev -ContentType Mainline

.EXAMPLE
    Enable-OfflineInsiderPreview -Channel Beta -ContentType SkipAhead
#>

param(
    [ValidateSet("Dev", "Beta", "ReleasePreview")]
    [string]$Channel,

    [ValidateSet("Mainline", "SkipAhead")]
    [string]$ContentType,

    [Parameter(Mandatory = $false)]
    [string]$Ring = "External",

    [Parameter(Mandatory = $false)]
    [string]$Restore
)

#region Constants
# Script version
$script:VERSION = "3.0"

# Paths
$script:SCRIPT_PATH = $PSScriptRoot
if (!$script:SCRIPT_PATH) {
    $script:SCRIPT_PATH = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$script:CONFIG_FILE = Join-Path $script:SCRIPT_PATH "Enable-Insider.json"
$script:BACKUP_FILE = Join-Path $script:SCRIPT_PATH "Enable-Insider-backup.json"

# Minimum supported build number
$script:MIN_BUILD_NUMBER = 17763  # Windows 10 1809

# Windows 11 build number
$script:WIN11_BUILD_NUMBER = 22000

# Logging
$script:LOG_INDENT = "  "
$script:LOG_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss"

# Global backup state
$Global:BackupInProgress = $false
$Global:CurrentBackup = $null
$Global:BackupFile = $null

#endregion

# Add this function to handle registry restoration
function Remove-InsiderSettings {
    $jsonContent = Get-Content -Path "$PSScriptRoot\Enable-Insider.json" | ConvertFrom-Json

    # Function to recursively remove registry values
    function Remove-RegistrySettings {
        param($settings)

        foreach ($path in $settings.PSObject.Properties.Name) {
            $values = $settings.$path

            if (Test-Path $path) {
                foreach ($key in $values.PSObject.Properties.Name) {
                    Write-Host "Removing registry value: $path\$key"
                    Remove-ItemProperty -Path $path -Name $key -ErrorAction SilentlyContinue
                }
            }
        }
    }

    # Remove common settings
    Remove-RegistrySettings $jsonContent.common.insider_settings
    Remove-RegistrySettings $jsonContent.common.telemetry

    # Remove Windows 10/11 specific settings
    $windowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
    if ($windowsVersion -like "*Windows 10*") {
        Remove-RegistrySettings $jsonContent.windows10.base
        # Check if LTSC and remove those settings if applicable
        if ((Get-WindowsEdition -Online).Edition -like "*LTSC*") {
            Remove-RegistrySettings $jsonContent.windows10.ltsc
        }
    }
    elseif ($windowsVersion -like "*Windows 11*") {
        Remove-RegistrySettings $jsonContent.windows11.base
    }

    Write-Host "Registry settings have been restored to default values."
}

# Add this near the beginning of the main script
if ($Restore -eq "Registry") {
    Remove-InsiderSettings
    return
}

#region Functions
function Write-Log {
    param(
        [string]$Message,
        [switch]$NoTimestamp
    )
    $indent = "  "
    if ($NoTimestamp) {
        Write-Host "$indent$Message"
    } else {
        Write-Host "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") - $indent$Message"
    }
}

function Show-Usage {
    $scriptName = Split-Path -Leaf $MyInvocation.ScriptName
    Write-Log "[$scriptName] Easy Enable Insider Preview for Windows 10/11" -NoTimestamp
    Write-Log "====================================================================" -NoTimestamp
    Write-Log "" -NoTimestamp
    Write-Log "Usage:" -NoTimestamp
    Write-Log "  Test current system:   $scriptName -Test" -NoTimestamp
    Write-Log "  Enable Insider:        $scriptName -Channel <Dev|Beta|ReleasePreview>" -NoTimestamp
    Write-Log "  Restore settings:      $scriptName -Restore <path_to_backup.json>" -NoTimestamp
    Write-Log "" -NoTimestamp
    Write-Log "Parameters:" -NoTimestamp
    Write-Log "  -Channel:              Required. Insider Preview channel (Dev, Beta, ReleasePreview)" -NoTimestamp
    Write-Log "  -Test:                 Verify system configuration without making changes" -NoTimestamp
    Write-Log "  -Restore:              Restore settings from a backup file" -NoTimestamp
    Write-Log "" -NoTimestamp
    Write-Log "Examples:" -NoTimestamp
    Write-Log "  $scriptName -Test" -NoTimestamp
    Write-Log "  $scriptName -Channel Dev" -NoTimestamp
    Write-Log "  $scriptName -Restore backup.json" -NoTimestamp
    Write-Log "" -NoTimestamp
    Write-Log "Note: -Channel is required when not using -Test or -Restore" -NoTimestamp
    Write-Log "" -NoTimestamp
    exit 1
}

function Get-InsiderConfig {
    param([string]$ConfigPath = $script:CONFIG_FILE)

    # Check if file exists using the constant path
    if (!(Test-Path $ConfigPath)) {
        Write-Error "Configuration file not found: $ConfigPath" -ErrorAction Stop
    }

    # PowerShell 5.1 compatible JSON conversion
    $jsonContent = Get-Content $ConfigPath -Raw
    $config = ConvertFrom-Json $jsonContent

    # Convert PSCustomObject to Hashtable
    function ConvertTo-Hashtable {
        param([Parameter(ValueFromPipeline)]$InputObject)

        process {
            if ($null -eq $InputObject) { return $null }
            if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
                $collection = @()
                foreach ($object in $InputObject) { $collection += ConvertTo-Hashtable $object }
                return $collection
            }
            if ($InputObject -is [PSCustomObject]) {
                $hash = @{}
                foreach ($property in $InputObject.PSObject.Properties) {
                    $hash[$property.Name] = ConvertTo-Hashtable $property.Value
                }
                return $hash
            }
            return $InputObject
        }
    }

    return ConvertTo-Hashtable $config
}

function Test-Prerequisites {
    param(
        [string]$Channel
    )
    # Only require Channel if not in Test mode
    if (-not $Test -and -not $Channel) {
        Show-Usage
    }

    $winInfo = Get-WindowsInfo
    Write-Log "System Information:"
    Write-Log "  OS Version:   $($winInfo.Version)"
    Write-Log "  Edition:      $($winInfo.Edition)"
    Write-Log "  Build Number: $($winInfo.BuildNumber)"
    Write-Log ""

    if ($winInfo.BuildNumber -lt 17763) {
        Write-Error "This script requires Windows 10 version 1809 (build 17763) or later." -ErrorAction Stop
    }

    Test-AdminPrivileges

    # Load configuration using the constant
    $config = Get-InsiderConfig -ConfigPath $script:CONFIG_FILE

    $missingItems = @()

    # Check features
    $features = Get-RequiredFeatures -Config $config -EditionType $winInfo.EditionType
    foreach ($feature in $features) {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if (-not $state -or $state.State -ne "Enabled") {
            $missingItems += "    - Windows Feature: $feature"
        }
    }

    # Check registry settings
    $winVer = if ($winInfo.IsWin11) { "windows11" } else { "windows10" }
    $baseSettings = $config[$winVer].base
    $missingItems += Set-InsiderRegistry -Settings $baseSettings -Channel "Dev" -TestOnly -Config $config -EditionType $winInfo.EditionType

    $editionSettings = Get-EditionSettings -Config $config -WinVer $winVer -EditionType $winInfo.EditionType
    if ($editionSettings) {
        $missingItems += Set-InsiderRegistry -Settings $editionSettings -Channel "Dev" -TestOnly -Config $config -EditionType $winInfo.EditionType
    }

    # Report findings
    if ($missingItems.Count -gt 0) {
        Write-Log "Missing Prerequisites:"
        foreach ($item in $missingItems) {
            # Ensure consistent padding for all items
            $paddedItem = $item -replace '^(\s+)-', '  -'
            Write-Log $paddedItem
        }
        Write-Log ""
        if (-not $Test) {
            Write-Log "Run this script without -Test to automatically configure these items."
        }
    } else {
        Write-Log "All prerequisites are met."
    }

    # Return both winInfo and config
    return @{
        WinInfo = $winInfo
        Config = $config
    }
}

function Test-AdminPrivileges {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Error: This script must be run with administrator privileges."
        Write-Log "Please restart PowerShell as Administrator and try again."
        exit 1
    }
    return $true
}

function Get-WindowsInfo {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $buildNumber = [System.Environment]::OSVersion.Version.Build
    $isWin11 = $buildNumber -ge 22000

    @{
        Version = if ($isWin11) {"Windows 11"} else {"Windows 10"}
        Edition = $osInfo.Caption
        BuildNumber = $buildNumber
        IsWin11 = $isWin11
        IsLTSC = $osInfo.Caption -match "LTSC|LTSB"
        IsIoT = $osInfo.Caption -match "IoT"
        EditionType = switch -Regex ($osInfo.Caption) {
            "IoT.*Enterprise" { "iot_enterprise" }
            "IoT.*Core" { "iot_core" }
            "Enterprise" { "enterprise" }
            "Education" { "education" }
            "Home" { "home" }
            "LTSC|LTSB" { "ltsc" }
            default { "other" }
        }
    }
}

# Add trap to handle the backup state
trap {
    if ($Global:BackupInProgress) {
        Write-Log "Script interrupted. Saving backup..."
        $Global:CurrentBackup | ConvertTo-Json -Depth 10 | Set-Content $Global:BackupFile
    }
    throw $_
}

# Initialize global backup variables
$Global:BackupInProgress = $false
$Global:CurrentBackup = $null
$Global:BackupFile = $null

function Initialize-Backup {
    param([string]$BackupFile = $script:BACKUP_FILE)

    $Global:BackupFile = $BackupFile
    $Global:BackupInProgress = $true
    $Global:CurrentBackup = @{
        Registry = @()
        Features = @()
        BCD = @{
            FlightSigning = $false
        }
    }

    # Get initial BCD state
    $bcdOutput = bcdedit /enum "{current}" | Select-String "flightsigning\s+Yes"
    $Global:CurrentBackup.BCD.FlightSigning = ($null -ne $bcdOutput)

    # Get initial features state
    $features = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" }
    $Global:CurrentBackup.Features = $features | Select-Object -ExpandProperty FeatureName
}

function Backup-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$BackupFile = $script:BACKUP_FILE
    )

    if (-not $Global:BackupInProgress) {
        Write-Log "Backup not initialized"
        return $false
    }

    try {
        # Only backup if we don't already have this key saved
        if (-not ($Global:CurrentBackup.Registry | Where-Object { $_.Path -eq $Path -and $_.Name -eq $Name })) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            $type = (Get-Item "Registry::$Path").GetValueKind($Name)

            # Create and add backup entry
            $registryBackup = @{
                "Path" = $Path
                "Name" = $Name
                "Value" = $value.$Name
                "Type" = $type.ToString()
            }

            $Global:CurrentBackup.Registry += $registryBackup

            # Save current state to file
            $Global:CurrentBackup | ConvertTo-Json -Depth 10 | Set-Content $BackupFile
        }
        return $true
    }
    catch {
        return $false
    }
}

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type,
        [switch]$TestOnly,
        [switch]$CreatePath,
        [switch]$Backup
    )

    try {
        # Create path if needed
        if ($CreatePath -and !(Test-Path $Path)) {
            if ($TestOnly) {
                return "  Missing registry path: $Path"
            }
            New-Item -Path $Path -Force | Out-Null
        }

        if ($TestOnly) {
            try {
                $actual = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
                if ($actual.${Name} -ne $Value) {
                    return "  Mismatch in $Path\${Name}: Expected '$Value', got '$($actual.${Name})'"
                }
            } catch {
                return "  Missing registry value: $Path\${Name}"
            }
        } else {
            # Check if value exists
            $currentValue = $null
            try {
                $currentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            } catch { }

            if ($currentValue -ne $Value) {
                if ($Backup) {
                    # Backup even if value doesn't exist (will store null)
                    Backup-RegistryValue -Path $Path -Name $Name -BackupFile $script:BACKUP_FILE
                }

                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
                Write-Log "Set $Name = $Value"
            }
        }
    } catch {
        $action = if ($TestOnly) { 'read' } else { 'set' }
        return "  Failed to $action $Path\${Name}: $($_.Exception.Message)"
    }
    return $null
}

function Merge-Hashtables {
    param([array]$HashTables)

    $output = @{}
    foreach ($ht in $HashTables) {
        if ($null -ne $ht) {  # Add null check
            foreach ($key in $ht.Keys) {
                $output[$key] = $ht[$key]
            }
        }
    }
    return $output
}

function Get-EditionSettings {
    param (
        [hashtable]$Config,
        [string]$WinVer,
        [string]$EditionType
    )

    # Add null checks
    if ($null -eq $Config -or $null -eq $Config[$WinVer]) {
        Write-Log "Warning: Configuration for $WinVer not found"
        return $null
    }

    $settings = $null
    if ($Config[$WinVer].ContainsKey($EditionType)) {
        $settings = $Config[$WinVer][$EditionType]
    }

    if ($null -eq $settings -and $WinVer -eq "windows11") {
        # Fall back to Windows 10 settings if Windows 11 specific settings not found
        if ($Config['windows10'] -and $Config['windows10'].ContainsKey($EditionType)) {
            $settings = $Config['windows10'][$EditionType]
        }
    }

    # Convert array to hashtable if needed
    if ($settings -is [array]) {
        $settingsHash = @{}
        foreach ($setting in $settings) {
            if ($setting -is [hashtable]) {
                foreach ($key in $setting.Keys) {
                    $settingsHash[$key] = $setting[$key]
                }
            }
        }
        $settings = $settingsHash
    }

    return $settings
}

function Get-RequiredFeatures {
    param (
        [hashtable]$Config,
        [string]$EditionType
    )

    $features = $Config.common.required_features.$EditionType
    if (-not $features) {
        $features = $Config.common.required_features.base
    }
    return $features
}

function Set-InsiderRegistry {
    param (
        [hashtable]$Settings,
        [string]$Channel,
        [switch]$TestOnly,
        [hashtable]$Config,
        [string]$EditionType
    )

    # Use the constant for backup file
    if (-not $TestOnly -and -not (Test-Path $script:BACKUP_FILE)) {
        "[]" | Set-Content $script:BACKUP_FILE
    }

    # Merge settings
    $Settings = Merge-Hashtables @($Settings, $Config.common.insider_settings)

    # Apply settings with hardcoded Mainline
    return New-InsiderSettingsHelper -Settings $Settings -Channel $Channel -TestOnly:$TestOnly -Backup:(-not $TestOnly)
}

function New-InsiderSettingsHelper {
    param (
        [hashtable]$Settings,
        [string]$Channel,
        [switch]$TestOnly,
        [switch]$Backup
    )

    $errors = @()
    foreach ($path in $Settings.Keys) {
        foreach ($item in $Settings[$path].GetEnumerator()) {
            $value = $item.Value.Value
            # Only perform string replacements if the value is actually a string
            if ($value -is [string]) {
                $value = $value.Replace("%CHANNEL%", $Channel).Replace("%CONTENTTYPE%", "Mainline").Replace("%scriptver%", "3.0").Replace("%Fancy%", "$Channel Channel").Replace("%Content%", "Mainline")
            }

            $registryError = Set-RegistryValue -Path $path -Name $item.Key -Value $value -Type $item.Value.Type `
                -TestOnly:$TestOnly -CreatePath -Backup:$Backup
            if ($registryError) {
                if ($TestOnly) {
                    $errors += $registryError
                } else {
                    Write-Log $registryError
                }
            }
        }
    }
    return $errors
}

function Set-HardwareBypass {
    param([hashtable]$Config)

    # Skip if no hardware settings exist
    if (-not ($Config.ContainsKey("windows11") -and $Config.windows11.ContainsKey("base"))) {
        return
    }

    $hwSettings = $Config.windows11.base
    foreach ($path in $hwSettings.Keys) {
        New-RegistryPathIfMissing -Path $path
        foreach ($item in $hwSettings[$path].GetEnumerator()) {
            Set-RegistryItem -Path $path -Name $item.Key -Value $item.Value.Value -Type $item.Value.Type
        }
    }
}

function Set-InsiderPreview {
    param(
        [hashtable]$Config,
        [hashtable]$WinInfo,
        [string]$Channel,
        [switch]$Test
    )

    if (-not $Test) {
        Write-Log "Configuring Insider Preview settings..."
        Enable-FlightSigning
    }

    $winVer = if ($WinInfo.IsWin11) { "windows11" } else { "windows10" }
    $errors = @()

    # Apply base settings for Windows version with hardcoded Mainline
    $errors += Set-InsiderRegistry -Settings $Config[$winVer].base -Channel $Channel -TestOnly:$Test -Config $Config -EditionType $WinInfo.EditionType

    # Apply edition-specific settings
    $editionSettings = Get-EditionSettings -Config $Config -WinVer $winVer -EditionType $WinInfo.EditionType

    if ($editionSettings) {
        $errors += Set-InsiderRegistry -Settings $editionSettings -Channel $Channel -TestOnly:$Test -Config $Config -EditionType $WinInfo.EditionType
    }

    if (-not $Test) {
        Write-Log "Setting hardware requirement bypasses..."
        Set-HardwareBypass -Config $Config
        Write-Log "Configuration completed. Please restart your computer for changes to take effect."
    }
}

function Start-InsiderEnrollment {
    param(
        [ValidateSet("Dev", "Beta", "ReleasePreview")]
        [string]$Channel,
        [switch]$Test,
        [string]$Restore
    )

    if ($Restore) {
        if (Test-Path $Restore) {
            Restore-InsiderSettings -BackupFile $Restore
            return
        } else {
            Write-Log "Error: Backup file not found: $Restore"
            exit 1
        }
    }

    if ($Test) {
        Write-Log "Testing system configuration..."
        Test-Prerequisites | Out-Null
        Write-Log "Test completed. Run with -Channel <Dev|Beta|ReleasePreview> to apply changes."
        return
    }

    if (-not (Test-Path $script:BACKUP_FILE)) {
        Initialize-Backup
    }

    try {
        $result = Test-Prerequisites -Channel $Channel
        Enable-RequiredFeatures -Config $result.Config -EditionType $result.WinInfo.EditionType
        Set-InsiderPreview -Config $result.Config -WinInfo $result.WinInfo -Channel $Channel -Test:$Test

        Write-Log ""
        Write-Log "Configuration completed successfully!"
        Write-Log "A backup of your original settings has been saved to:"
        Write-Log "  $script:BACKUP_FILE"
        Write-Log ""
        Write-Log "To restore your original settings, run:"
        Write-Log "  $($MyInvocation.MyCommand.Name) -Restore $script:BACKUP_FILE"
        Write-Log ""
        Write-Log "Please restart your computer for changes to take effect."
    }
    catch {
        Write-Log "Error occurred during enrollment: $($_.Exception.Message)"
        Write-Log "You can restore the system to its original state using:"
        Write-Log "  $($MyInvocation.MyCommand.Name) -Restore $script:BACKUP_FILE"
        exit 1
    }
    finally {
        if ($Global:BackupInProgress) {
            $Global:BackupInProgress = $false
            $Global:CurrentBackup | ConvertTo-Json -Depth 10 | Set-Content $Global:BackupFile
        }
    }
}

function Enable-RequiredFeatures {
    param([hashtable]$Config, [string]$EditionType)

    $features = $Config.common.required_features.$EditionType
    if (-not $features) {
        $features = $Config.common.required_features.base
    }

    foreach ($feature in $features) {
        $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($state) {
            if ($state.State -ne "Enabled") {
                Write-Log "  Enabling feature: $feature"
                try {
                    # Suppress the default output from Enable-WindowsOptionalFeature
                    Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart | Out-Null
                    Write-Log "    Successfully enabled $feature"
                } catch {
                    Write-Log "    Warning: Failed to enable $feature - $($_.Exception.Message)"
                }
            }
        } else {
            Write-Log "  Warning: Feature not found: $feature"
        }
    }
}

function Enable-FlightSigning {
    $output = bcdedit /set "{current}" flightsigning yes 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Log "Enabled flight signing in BCD"
        return $true
    } else {
        Write-Log "Failed to enable flight signing: $output"
        return $false
    }
}

function Backup-SystemState {
    param([string]$BackupFile)

    $backup = @{
        Registry = @()
        Features = @()
        BCD = @{
            FlightSigning = $false
        }
    }

    try {
        # Get BCD flightsigning state
        $bcdOutput = bcdedit /enum "{current}" | Select-String "flightsigning\s+Yes"
        $backup.BCD.FlightSigning = ($null -ne $bcdOutput)

        # Get enabled features
        $features = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" }
        $backup.Features = $features | Select-Object -ExpandProperty FeatureName

        # Convert to JSON and save
        $backup | ConvertTo-Json -Depth 10 | Set-Content $BackupFile
        return $true
    }
    catch {
        Write-Log "Failed to create backup: $($_.Exception.Message)"
        return $false
    }
}

function Restore-InsiderSettings {
    param([string]$BackupFile)

    Write-Log "Restoring settings from $BackupFile..."

    try {
        $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json

        # Restore registry values
        if ($backup.Registry) {
            foreach ($item in $backup.Registry) {
                try {
                    if (!(Test-Path $item.Path)) {
                        New-Item -Path $item.Path -Force | Out-Null
                    }
                    Set-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -Type $item.Type -Force
                    Write-Log "  Restored registry: $($item.Path)\$($item.Name)"
                }
                catch {
                    Write-Log "  Failed to restore registry: $($item.Path)\$($item.Name): $($_.Exception.Message)"
                }
            }
        }

        # Restore BCD settings
        if ($backup.BCD.FlightSigning -eq $false) {
            $output = bcdedit /deletevalue "{current}" flightsigning 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "  Restored BCD flightsigning setting"
            }
        }

        # Restore features
        if ($backup.Features) {
            $currentFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | Select-Object -ExpandProperty FeatureName
            $featuresToDisable = $currentFeatures | Where-Object { $_ -notin $backup.Features }

            foreach ($feature in $featuresToDisable) {
                try {
                    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart | Out-Null
                    Write-Log "  Restored feature state: Disabled $feature"
                }
                catch {
                    Write-Log "  Failed to restore feature: $feature : $($_.Exception.Message)"
                }
            }
        }

        Write-Log "Restore completed. Please restart your computer for changes to take effect."
    }
    catch {
        Write-Log "Error reading backup file: $($_.Exception.Message)"
        exit 1
    }
}
#endregion

# Main script execution
Start-InsiderEnrollment @PSBoundParameters
