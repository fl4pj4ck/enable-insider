# Windows Insider Enroller

A PowerShell tool to enable Windows Insider Preview without requiring a Microsoft account.

## Features
- Enroll in Windows Insider Preview (Dev, Beta, Release Preview channels)
- Support for Windows 10 (v1809+) and Windows 11
- Hardware requirement bypass for Windows 11
- System state backup and restore

## Requirements
- Windows 10 (v1809+) or Windows 11
- PowerShell 5.1 or later
- Administrator privileges

## Usage
1. Run the script as Administrator
2. Select desired Insider channel
3. Wait for enrollment to complete

## Configuration
The script uses a settings.json file for configuration. You can customize:

- Channel: "Dev", "Beta", or "ReleasePreview"
- FlightSigningEnabled: true/false (enable/disable Insider builds)
- Ring: "WIF", "WIS" (Windows Insider Fast/Slow)
- TestFlags: Used for specific testing scenarios

Example settings.json:
{
    "Channel": "Dev",
    "FlightSigningEnabled": true,
    "Ring": "WIF"
}

## Backup and Restore
The script creates backups of:
1. Registry keys specified in the settings.json template
2. BCD (Boot Configuration Data) settings when bypassing hardware requirements
3. Original system state values for any other modified settings

Each backup includes:
- A timestamp of when the backup was created
- All modified values and their original states
- Location of the modified settings (registry path, BCD, etc.)

Backups are stored in the "backup" folder with timestamp and can be restored using the -Restore parameter.

## Examples

Basic usage:
.\Enable-Insider.ps1

With specific channel:
.\Enable-Insider.ps1 -Channel Dev

With custom settings file:
.\Enable-Insider.ps1 -SettingsFile "mysettings.json"

Restore from backup:
.\Enable-Insider.ps1 -Restore "backup_20240315_123456"

Skip hardware checks (Windows 11):
.\Enable-Insider.ps1 -IgnoreHardwareRequirements

## Notes
- Settings changes require system restart
- Some settings may not apply to all Windows versions
- Use with caution - Insider builds can be unstable