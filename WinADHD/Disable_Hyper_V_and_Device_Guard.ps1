<#
 Script for disabling features and setting for John Strand Class Lab VM, WINADHD.
 This script aims to help students easily setup their host machine to be compatible to Lab VM preferences and revert back to previous mode when necessary
 Caution: Under no circustances does this script provide garantees or warranties, Full responsibility relies on you to test the script for your Environment.
 Caution: Not recommended to run in production machines, user on your personal computers
#>


#optional Debug Param
##    -LokiHakanin
param (
    [bool] $Debug,
    [bool] $DryRun = 0
)

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

#Making our config hash global to the script so it can be referenced across functions for logical checks etc.  
##    -LokiHakanin
$config = @{ 
        HyperV="";
        WSL="";
        VirtualMachinePlatform="";
        HypervisorPlatform="";
        HypervisorLaunchType="";
        VsmLaunchType="";
        HypervisorEnforcedCodeIntegrity="";
        SystemGuard="";
        EnableVirtualizationBasedSecurity="";
    }

<# Commonly referenced paths for registry keys
        Pulled these out here to ensure consistency across function calls and make it 
            "one place to update" in the event the registry keys need to change, 
            or if logic needs to be added to determine them. - LokiHakanin
        #>
$hypervisorEnforcedCodeIntegrityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
$hypervisorEnforcedCodeIntegrityKey = "Enabled"
$SystemGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard"    
$SystemGuardKey = "Enabled"
$DeviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$DeviceGuardKey = "EnableVirtualizationBasedSecurity"


if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with elevated privileges
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

<# Code to maximize the powershell windows #>
$Window = Get-Process -Id $PID | Select-Object -ExpandProperty MainWindowHandle
Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class WinAPI {
        [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    }
"@
[WinAPI]::ShowWindowAsync($Window, 3)

<# Simple function to test if a specific path / value combination exists in the registry.  
        -LokiHakanin
#>
function Test-RegistryValue {
    param 
    (
    [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Path,
    [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()]$Value
    )
    try 
        {
        Get-ItemProperty -Path $Path -ErrorAction Stop | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
        }  
    catch 
        {
        return $false
        }
}

<# Simple function to encapsulate null handling logic around registry lookups.
    Uses Test-RegistryValue function to confirm a specific Path / Key combination exists, if so, returns current value. 
    If Path / Key combo doesn't exist, confirms if the PATH at least exists.  
        If the path does exist but the key doesn't, returns -1
        If the path doesn't exist at all, returns -2
    -LokiHakanin #>

function Get-RegVal-IncludingExistence { 
    param (
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $Path,
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $Key
        )

    #If Key exists, return its value
    if (Test-RegistryValue -Path $Path -Value $key)
        {
        return (Get-ItemProperty -Path $Path ).$key
        } 
    #If the key doesn't exist, see if the PATH at least exists - if it does, return -1, if not, return -2
    elseif (Test-Path $Path)
        {
        return -1
        }
    else 
        {
        return -2
        } 
}

<# Basic function to perform repetitive checks for installed features and return a string of installation status
        Looks up the state of a windows feature with name $FeatureName.  
           If defined, it returns the "ToString()" of the retrieved state 
                (as the Type of these returns is FeatureState, which does 
                not de-serialize properly without explicit typing).
            If status is null / undefined, returns "" (the empty string)

  - LokiHakanin
    #>

function GetFeatureStatusAsString {
    param (
        [parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] $FeatureName
        )
    $temp = (Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).State
    if (($null -eq $Temp) -or ("" -eq $Temp)) 
        { 
        return "" 
        } 
    else 
        { 
        return $temp.ToString() 
        } 
}

# Function to save the current configuration
function save_config {
    

        <# Windows Features - 
        Null string means undefined / not configured (DOES NOT MEAN DISABLED)  
        "Enabled" means exists, is enabled
        "Disabled" means exists, but is disabled 
        #>
        $config.HyperV = GetFeatureStatusAsString("Microsoft-Hyper-V-All")
        $config.WSL = GetFeatureStatusAsString("Microsoft-Windows-Subsystem-Linux")
        $config.VirtualMachinePlatform = GetFeatureStatusAsString("VirtualMachinePlatform")
        $config.HypervisorPlatform = GetFeatureStatusAsString("HypervisorPlatform")

        <# Boot Configuration Data - 
           null string means undefined / not configured (DOES NOT MEAN DISABLED) 
           #>
        $config.HypervisorLaunchType = (bcdedit /enum {current} | Select-String "hypervisorlaunchtype").Line       
        $config.VsmLaunchType = (bcdedit /enum {current} | Select-String "vsmlaunchtype").Line

        <# Registry Settings 
        -2 = Reg path disn't exist
        -1 = Reg path existed, key did not
        0, 1, or other value = reg path and key existed, variable reflects value of key    
        #>
        $config.HypervisorEnforcedCodeIntegrity = Get-RegVal-IncludingExistence -Path $hypervisorEnforcedCodeIntegrityPath -Key $hypervisorEnforcedCodeIntegrityKey
        $config.SystemGuard = Get-RegVal-IncludingExistence -Path $SystemGuardPath -Key $SystemGuardKey
        $config.EnableVirtualizationBasedSecurity = Get-RegVal-IncludingExistence -Path $DeviceGuardPath -Key $DeviceGuardKey 
    
    if ($debug) 
        {
        Write-Host "Debug - Saved Configuration values:`r`n"
        }
    if ($debug) {$config}
    
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

        # debug info 
        if ($debug) 
            {
            Write-Host "`r`nDebug - in winadhd_prep, post save_config.`r`n"
            }
        if ($debug) 
            {
            Write-Host "Individual Actions:`r`n--------------`r`n"
            }
        

        # Disabling Hyper-V, WSL, and Virtual Machine Platform
        ## If these settings were not found in the first place, do nothing.               
        if (($null -ne $config.HyperV) -and ("" -ne $config.HyperV))
            {
            if ($debug) {Write-Host "Debug - Disable HyperV"}
            if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart }
            }
        if (($null -ne $config.WSL) -and ("" -ne $config.WSL))
            {
            if ($debug) {Write-Host "Debug - Disable WSL"}
            if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart}
            }
        if (($null -ne $config.VirtualMachinePlatform) -and ("" -ne $config.VirtualMachinePlatform))
            {
            if ($debug) {Write-Host "Debug - Disable VirtualMachinePlatform"}
            if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart}
            }
        if (($null -ne $config.HypervisorPlatform) -and ("" -ne $config.HypervisorPlatform))
            {
            if ($debug) {Write-Host "Debug - Disable HyperVisorPlatform"}
            if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart}
            }
        
        
        if ($debug) {Write-Host "`r`n" }

         # Boot Configuration Settings - Hypervisor etc. # 
         ## If these settings were not found in the first place, do nothing.  
         if (($null -ne $config.HypervisorLaunchType) -and ("" -ne $config.HypervisorLaunchType))
            {
            if ($debug) {Write-Host "Debug - Set Hypervisor LaunchType Off"}
            if (!$dryRun) { bcdedit /set hypervisorlaunchtype off }
            }
         if (($null -ne $config.VsmLaunchType) -and ("" -ne $config.VsmLaunchType))         
            {
            if ($debug) {Write-Host "Debug - Set VSm LaunchType Off"}
            if (!$dryRun) { bcdedit /set vsmlaunchtype off }
            } 
    
        # Set Device Guard Off
        <# Registry Settings 
        -2 = Reg path disn't exist - in this case, we'll do nothing (too invasive)
        -1 = Reg path existed, key did not - in this case, we'll add and set the key
        0, 1, or other value = reg path and key existed, variable reflects value of key - in this case, set the key   #>
        if ($config.HypervisorEnforcedCodeIntegrity -gt -2)
            {
            if ($debug) {Write-Host "Debug - EnforcedCodeIntegrity Path Exists"}
            if ($config.HypervisorEnforcedCodeIntegrity -eq -1)
                {
                if ($debug) {Write-Host "Debug - EnforcedCodeIntegrity Key Doesn't Exist, Creating"}
                if ($debug) {Write-Host ($hypervisorEnforcedCodeIntegrityPath + '\' + $hypervisorEnforcedCodeIntegrityKey)}
                if (!$dryRun) { New-ItemProperty -Path $hypervisorEnforcedCodeIntegrityPath -Name $hypervisorEnforcedCodeIntegrityKey -PropertyType Dword }
                }
            if ($debug) {Write-Host "Debug - Disabling EnforcedCodeIntegrity: PATH $hypervisorEnforcedCodeIntegrityPath KEY $hypervisorEnforcedCodeIntegrityKey`r`n"}
            if (!$dryRun) { Set-ItemProperty -Path $hypervisorEnforcedCodeIntegrityPath -Name $hypervisorEnforcedCodeIntegrityKey -Value "0" }
            }
        if ($config.SystemGuard -gt -2)
            {
            if ($debug) {Write-Host "Debug - SystemGuard Path Exists"}
            if ($config.SystemGuard -eq -1)
                {
                if ($debug) {Write-Host "Debug - SystemGuard Key Doesn't Exist, Creating"}
                if ($debug) {Write-Host ($SystemGuardPath + '\' + $SystemGuardKey)}
                if (!$dryRun) { New-ItemProperty -Path $SystemGuardPath -Name $SystemGuardKey -PropertyType Dword }
                }
            if ($debug) {Write-Host "Debug - Disabling SystemGuard PATH $SystemGuardPath KEY $SystemGuardKey`r`n"}
            if (!$dryRun) { Set-ItemProperty -Path $SystemGuardPath -Name $SystemGuardKey -Value "0" }
            }
        if ($config.EnableVirtualizationBasedSecurity -gt -2)
            {
            if ($debug) {Write-Host "Debug - DeviceGuard Path Exists"}
            if ($config.EnableVirtualizationBasedSecurity -eq -1)
                {
                if ($debug) {Write-Host "Debug - DeviceGuard Key Doesn't Exist, Creating"}
                if ($debug) {Write-Host ($DeviceGuardPath + '\' + $DeviceGuardKey)}
                if (!$dryRun) { New-ItemProperty -Path $DeviceGuardPath -Name $DeviceGuardKey -PropertyType Dword }
                }
            if ($debug) {Write-Host "Debug - Disabling DeviceGuard PATH $DeviceGuardPath KEY $DeviceGuardKey`r`n"}
            if (!$dryRun) { Set-ItemProperty -Path $DeviceGuardPath -Name $DeviceGuardKey -Value "0" }
            }           

        Write-Host "Settings and features have been disabled."
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

        if ($debug) 
            {
            Write-Host "Config settings to revert to"
            $config
            }
        
        # Restoring Hyper-V
        ## If it was not set in the first place (i.e. null / empty), do nothing.  
        if (($null -ne $config.HyperV) -and ("" -ne $config.HyperV))
        {
            if (($config.HyperV -eq "Enabled") -or ($config.HyperV -eq 1)) {
                if ($debug) { Write-host "Re-enabling HyperV Feature" }
                if (!$dryRun) { Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart }
            } else {
                if ($debug) { Write-host "Re-disabling HyperV Feature" }
                if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart}
            }
        }
        
        # Restoring WSL
        ## If it was not set in the first place (i.e. null / empty), do nothing.  
        if (($null -ne $config.WSL) -and ("" -ne $config.WSL))
        {
            if (($config.WSL -eq 1) -or ($config.WSL -eq "Enabled")) {
                if ($debug) { Write-host "Re-enabling WSL Feature" }
                if (!$dryRun) { Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart }
            } else {
                if ($debug) { Write-host "Re-disabling WSL Feature" }
                if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart }
            }
        }

        # Restoring Virtual Machine Platform
        ## If it was not set in the first place (i.e. null / empty), do nothing.  
        if (($null -ne $config.VirtualMachinePlatform) -and ("" -ne $config.VirtualMachinePlatform))
        {
            if (($config.VirtualMachinePlatform -eq 1) -or ($config.VirtualMachinePlatform -eq "Enabled")) {
                if ($debug) { Write-host "Re-enabling VirtualMachinePlatform Feature" }
                if (!$dryRun) { Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart }
            } else {
                if ($debug) { Write-host "Re-disabling VirtualMachinePlatform Feature" }
                if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart }
            }
        }

         # Restoring Hypervisor Platform
        ## If it was not set in the first place (i.e. null / empty), do nothing.  
        if (($null -ne $config.HypervisorPlatform) -and ("" -ne $config.HypervisorPlatform))
        {
            if (($config.HypervisorPlatform -eq 1) -or ($config.HypervisorPlatform -eq "Enabled")) {
                if ($debug) { Write-host "Re-enabling HypervisorPlatform Feature" }
                if (!$dryRun) { Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart }
            } else {
                if ($debug) { Write-host "Re-disabling HypervisorPlatform Feature" }
                if (!$dryRun) { Disable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -NoRestart }
            }
        }

        if ($debug) { Write-Host "`r`n" }

        # Restoring boot configuration
        ## Don't do anything if it wasn't set previously
         # Boot Configuration Settings - Hypervisor etc. # 
         if (($null -ne $config.HypervisorLaunchType) -and ($config.HypervisorLaunchType -ne ""))
            {
            if ($debug) { Write-Host "Debug - Restore Hypervisor LaunchType" }
            if (!$dryRun) { bcdedit /set hypervisorlaunchtype $($config.HypervisorLaunchType -split " ")[-1] }
            }
         if (($null -ne $config.VsmLaunchType) -and ($config.VsmLaunchType -ne ""))
            {
            if ($debug) { Write-Host "Debug - Restore VSm LaunchType" }
            if (!$dryRun) { bcdedit /set vsmlaunchtype $($config.VsmLaunchType -split " ")[-1] }
            }
        
        if ($debug) { Write-Host "`r`n" }
             
        # Restoring Device Guard settings
        <# Restoring Device Guard settings
           Generally -  
                If the path and key previously existed, we set it to its previous value
                If the path existed, but the key did not, since we previously created the Key, we delete the key.  
                If the path did not exist, we previously did nothing, and have nothing to restore
        #>
        if ($config.HypervisorEnforcedCodeIntegrity -gt -2)
            {
            if ($debug) { Write-Host "Debug - EnforcedCodeIntegrity Path Existed" }
            if ($config.HypervisorEnforcedCodeIntegrity -eq -1)
                {
                if ($debug) { Write-Host "Debug - EnforcedCodeIntegrity Key didn't exist, was created, deleting" }
                if ($debug) { Write-Host ($hypervisorEnforcedCodeIntegrityPath + '\' + $hypervisorEnforcedCodeIntegrityKey) }
                if (!$dryRun) { Remove-ItemProperty -Path $hypervisorEnforcedCodeIntegrityPath -Name $hypervisorEnforcedCodeIntegrityKey }
                }            
            else 
                {
                if ($debug) { Write-Host "Debug - Resetting EnforcedCodeIntegrity to previous value: PATH $hypervisorEnforcedCodeIntegrityPath KEY $hypervisorEnforcedCodeIntegrityKey PREVIOUS_VALUE =" $config.HypervisorEnforcedCodeIntegrity }
                if (!$dryRun) { Set-ItemProperty -Path $hypervisorEnforcedCodeIntegrityPath -Name $hypervisorEnforcedCodeIntegrityKey -Value $config.HypervisorEnforcedCodeIntegrity }
                }
            if ($debug) { Write-Host "`r`n" }
            }
            elseif ($debug)
                {
                Write-Host "EnforcedCodeIntegrity path did not exist, nothing to do`r`n"
                }
        if ($config.SystemGuard -gt -2)
            {
            if ($debug) { Write-Host "Debug - SystemGuard Path existed" }
            if ($config.SystemGuard -eq -1)
                {
                if ($debug) { Write-Host "Debug - SystemGuard Key didn't Exist, was created, deleting" }
                if ($debug) { Write-Host ($SystemGuardPath + '\' + $SystemGuardKey) }
                if (!$dryRun) { Remove-ItemProperty  -Path $SystemGuardPath -Name $SystemGuardKey }
                }            
            else 
                {
                if ($debug) { Write-Host "Debug - Resetting SystemGuard to previous value PATH $SystemGuardPath KEY $SystemGuardKey PREVIOUS_VALUE = " $config.SystemGuard }
                if (!$dryRun) { Set-ItemProperty -Path $SystemGuardPath -Name $SystemGuardKey -Value $config.SystemGuard }
                }
            if ($debug) { Write-Host "`r`n" }
            }
            elseif ($debug)
                {
                Write-Host "SystemGuard path did not exist, nothing to do`r`n"
                }
        if ($config.EnableVirtualizationBasedSecurity -gt -2)
            {
            if ($debug) { Write-Host "Debug - DeviceGuard Path Existed" }
            if ($config.EnableVirtualizationBasedSecurity -eq -1)
                {
                if ($debug) { Write-Host "Debug - DeviceGuard Key didn't Exist, was Created, deleting" }
                if ($debug) { Write-Host ($DeviceGuardPath + '\' + $DeviceGuardKey) }
                if (!$dryRun) { Remove-ItemProperty  -Path $DeviceGuardPath -Name $DeviceGuardKey }
                }            
            else 
                {
                if ($debug) { Write-Host "Debug - Resetting DeviceGuard to previous value PATH $DeviceGuardPath KEY $DeviceGuardKey PREVIOUS_VALUE = " $config.EnableVirtualizationBasedSecurity }
                if (!$dryRun) { Set-ItemProperty -Path $DeviceGuardPath -Name $DeviceGuardKey -Value $config.EnableVirtualizationBasedSecurity }
                }
            if ($debug) { Write-Host "`r`n" }            
            }
            elseif ($debug)
                {
                Write-Host "DeviceGuard path did not exist, nothing to do`r`n"
                }         

        Write-Host "Settings and features have been restored. Please restart your computer for changes to take effect."
    }
    catch {
        Write-Host $_.Exception.Message
        Write-Host "The script didn't run as expected, please run it again."
    }
}

#Flag debug mode
if ($Debug) { Write-Host "Running in Debug Mode, providing additional diagnostics." }
if (!$dryRun) 
    { 
    Write-Host "`r`nRunning in full command mode.  Run with '-DryRun 1' to preview changes without altering system settings" 
    }
else 
    {
    Write-Host "`r`nRunning in dry run mode.  No changes will be made.  Run without '-DryRun 1' to save changes." 
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

$restart_status = $(Write-Host "Computer needs to restart to take effect, would you like to restart now? (Y) to restart now, press any key to restart later" -ForegroundColor Yellow; Read-Host)
$restart_status = $restart_status.ToUpper()
if ($restart_status -eq 'Y') { if (!$dryRun) { Restart-Computer -Force } }
