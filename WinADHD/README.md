# Windows WINADHD LAB HOST Prep Script #

This is a simple quick script to disable all the features that we need to disable in order to get John Strands classes Lab VM to work as intended, mainly nested virtualization.

To get that to work, we need to disable:
>[!Note]
> Administrative privilege is required to successfully run the commands below.


 - Hyper-V
``` PowerShell
	Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
	bcdedit /set hypervisorlaunchtype off
	
```
 
 - Virtualization Security
```PowerShell
	 bcdedit /set vsmlaunchtype off
```
 
 - Device Guard
	 - Memory Integrity

```PowerShell
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value "0"

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\SystemGuard" -Name "Enabled" -Value "0"

	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value "0"
```

- You can also run [this](https://github.com/krooth/Antisyphon_lab_scripts/blob/main/WinADHD/Disable_Hyper_V_and_Device_Guard.ps1) script and be set.
