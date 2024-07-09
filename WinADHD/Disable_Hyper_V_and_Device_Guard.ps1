<#
 Script for Disabling Hyper-V, Device Guard, WSL, and Virtual Machine Platform.
 This script aims to help students prepare their host machine for WINADHD VM Lab.
 Caution/Disclaimer: Under no circumstances does this script provide guarantees or warranties. Full responsibility lies with you to test the script for your Lab Environment.
 Note: It's recommended to set up the lab on your personal lab environment and to avoid using a work machine, as the script turns off some security settings.
#>

# Banner
$banner = @"
 __      _____ _  _   _   ___  _  _ ___    ___ ___ ___ ___     __  ___ _____   _____ ___  ___ ___ 
 \ \    / /_ _| \| | /_\ |   \| || |   \  | _ \ _ \ __| _ \   / / | _ \ __\ \ / / __| _ \/ __| __|
  \ \/\/ / | || .` |/ _ \| |) | __ | |) | |  _/   / _||  _/  / /  |   / _| \ V /| _||   /\__ \ _| 
   \_/\_/ |___|_|\_/_/ \_\___/|_||_|___/  |_| |_|_\___|_|   /_/   |_|_\___| \_/ |___|_|_\|___/___|
"@

Write-Host $banner -ForegroundColor Cyan
Write-Host "`n`n`n"

# Config file path
$configFile = "$env:USERPROFILE\winadhd_config.json"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated privileges
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Function to save the current configuration
function save_config {
    $config = @{
        HyperV = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All).State
        WSL = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State
        VirtualMachinePlatform = (Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State
        HypervisorLaunchType = (bcdedit /enum {current} | Select-String "hypervisorlaunchtype").Line
        VsmLaunchType = (bcdedit /enum {current} | Select-String "vsmlaunchtype").Line
        HypervisorEnforcedCodeIntegrity = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity").Enabled
        # SystemGuard = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard").Enabled
        EnableVirtualizationBasedSecurity = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard").EnableVirtualizationBasedSecurity
    }
    $config | ConvertTo-Json | Set-Content -Path $configFile
}

# Function to load the configuration
function load_config {
    if (Test-Path $configFile) {
        return Get-Content -Path $configFile | ConvertFrom-Json
    } else {
        Write-Host "Configuration file not found. Cannot revert settings."
        Exit
    }
}

# Function that disables settings and features to prep host for WINADHD Lab VM
function winadhd_prep {
    try {
        save_config

        # Disabling Hyper-V, WSL, and Virtual Machine Platform
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        bcdedit /set hypervisorlaunchtype off
        bcdedit /set vsmlaunchtype off 
    
        # Set Device Guard Off
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value "0"
        # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name "Enabled" -Value "0"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "0"

        Write-Host "Settings and features have been disabled. Computer needs to restart to take effect, would you like to restart now?"
        restart_status = $(Write-Host "(Y) to restart now, press any key to restart later" -ForegroundColor Yellow; Read-Host)
        restart_status = restart_status.ToUpper()
        if (restart_status -eq 'Y') { Restart-Computer }
    }
    catch {
        Write-Host $_.Exception.Message
        Write-Host "The script didn't run as expected, please run it again."
    }
}

# Function that reverses the disabled settings and features to prep host for WINADHD Lab VM
function reverse_settings {
    try {
        $config = load_config

        # Restoring Hyper-V
        if ($config.HyperV -eq "Enabled") {
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
        }
        
        # Restoring WSL
        if ($config.WSL -eq "Enabled") {
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        }

        # Restoring Virtual Machine Platform
        if ($config.VirtualMachinePlatform -eq "Enabled") {
            Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
        }

        # Restoring boot configuration
        bcdedit /set hypervisorlaunchtype $($config.HypervisorLaunchType -split " ")[-1]
        bcdedit /set vsmlaunchtype $($config.VsmLaunchType -split " ")[-1]
    
        # Restoring Device Guard settings
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value $config.HypervisorEnforcedCodeIntegrity
        # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name "Enabled" -Value $config.SystemGuard
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value $config.EnableVirtualizationBasedSecurity

        Write-Host "Settings and features have been restored. Please restart your computer for changes to take effect."
    }
    catch {
        Write-Host $_.Exception.Message
        Write-Host "The script didn't run as expected, please run it again."
    }
}

# Main logic
$choice = $(Write-Host "Do you want to disable features/settings or reverse the settings? (Y) to disable (R) to reverse the process: " -ForegroundColor Yellow; Read-Host)
$choice = $choice.ToUpper()

if ($choice -eq "Y") {
    winadhd_prep
} elseif ($choice -eq "R") {
    if (Test-Path $configFile) {
        reverse_settings
    } else {
        Write-Host "Sorry, no saved configuration found to revert the settings."
    }
} else {
    Write-Host "Invalid Choice. Exiting!"
    return
}
