<#
 Script for Disabling Hyper-V and Device Guar.
 This script aims to help students prepare their host machine for WINADHD VM Lab.
 Caution/Disclaimer: Under no circustances does this script provide garantees or warranties, Full responsibility relies on you to test the script for your Lab Environment.
 Note: It's recommended to setup the lab on your personal lab environment and to avoid using work environment to maintatin

#>

# Disabling Hyper-V
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor
bcdedit /set hypervisorlaunchtype off
bcdedit /set vsmlaunchtype off


# Set Device Guard Off
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value "0"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name "Enabled" -Value "0"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "0"


