<#
 Script for Disabling Hyper-V and Device Guar.
 This script aims to help students prepare their host machine for WINADHD VM Lab.
 Caution/Disclaimer: Under no circustances does this script provide garantees or warranties, Full responsibility relies on you to test the script for your Lab Environment.
 Note: It's recommended to setup the lab on your personal lab environment and to avoid using work machine, as the script turns of some security settings.
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



if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated privileges
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}


# Function that disables settings and features to prep host for WINADHD Lab VM (Disables settings)
function winadhd_prep {
    
    try {
        # Disabling Hyper-V
        Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
        bcdedit /set hypervisorlaunchtype off
        bcdedit /set vsmlaunchtype off 
    
        # Set Device Guard Off
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value "0"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name "Enabled" -Value "0"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "0"

        Write-Host "Disable Settings and Features."
    }
    catch {
        Write-Host $_.Exception.Message
        Write-Host "The script didn't run as expected, please run it again."
    }
}

# Function that reverses the disabled settings and features to prep host for WINADHD Lab VM (Enables settings)
function reverse_settings {
    try {
        # Enabling Hyper-V
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
        bcdedit /set hypervisorlaunchtype auto
        bcdedit /set vsmlaunchtype auto 
    
        # Set Device Guard Off
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value "1"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name "Enabled" -Value "1"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "1"

        Write-Host "Enable Settings and Features, successful reversing."
    }
    catch {
        Write-Host $_.Exception.Message
        Write-Host "The script didn't run as expected, please run it again"
    }
    
}

$choice = $(Write-Host "Do you want to disable features/settings or reverse the settings? (Y) to disable (R) to reverse the process: " -ForegroundColor yellow; Read-Host)
$choice = $choice.ToUpper()

if ($choice -eq "Y") {
    winadhd_prep
} elseif ($choice -eq "R") {
    reverse_settings
} else {
    Write-Host "Invalid Choice. Exiting!"
    return
}