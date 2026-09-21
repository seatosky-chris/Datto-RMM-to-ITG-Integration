###
# File: \Find All Configurations by Model.ps1
# Project: RMM Integration
# Created Date: Monday, September 21st 2026, 9:42:23 am
# Author: Chris Jantzen
# -----
# Last Modified: Mon Sep 21 2026
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2026 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
###

Write-Host "This script will find all configurations in ITG that match the model ID(s) you provide. You can get the ID from the address bar when editing the model in ITG."
$ModelID = Read-Host "Enter Model ID(s) (comma separated for multiple IDs)"

. "$PSScriptRoot\Config.ps1" # Config

# Fixed SSL if necessary
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
	Write-Output "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
	Write-PSFMessage -Level Warning -Message "Temporarily changed TLS to TLS v1.2."
}

# Import/Install any required modules
If (Get-Module -ListAvailable -Name "ITGlueAPI") {Import-module ITGlueAPI -Force} Else { install-module ITGlueAPI -Force; import-module ITGlueAPI -Force}

# Connect to IT Glue
if ($ITGAPIKey.Key) {
	Add-ITGlueBaseURI -base_uri $ITGAPIKey.Url
	Add-ITGlueAPIKey $ITGAPIKey.Key
}

$ITG_OrgDevices = Get-ITGlueConfigurations -page_size "1000" -filter_archived $true
$i = 1
while ($ITG_OrgDevices.links.next) {
	$i++
	$Devices_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -filter_archived $true
	if (!$Devices_Next -or $Devices_Next.Error) {
		# We got an error querying configurations, wait and try again
		Start-Sleep -Seconds 2
		$Devices_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -filter_archived $true

		if (!$Devices_Next -or $Devices_Next.Error) {
			Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing configurations from ITG. Exiting..."
			Write-PSFMessage -Level Error -Message $Devices_Next.Error
			exit 1
		}
	}
	$ITG_OrgDevices.data += $Devices_Next.data
	$ITG_OrgDevices.links = $Devices_Next.links
	Start-Sleep -Seconds 1
}
$ITG_OrgDevices = $ITG_OrgDevices.data

# Filter the configurations by the model ID(s) provided
$ModelIDs = ($ModelID -split ",") | Foreach-Object { $_.Trim() }
Write-Output "Filtering configurations for the following model ID(s): $($ModelIDs -join ', ')"
$FilteredConfigurations = $ITG_OrgDevices | Where-Object { $ModelIDs -contains $_.attributes.'model-id' }

# Display the filtered configurations
if ($FilteredConfigurations) {
	Write-Output "Found the following configurations for the specified model ID(s):"
	$FilteredConfigurations | Select-Object @{Name="Configuration Name";Expression={$_.attributes.name}}, @{Name="Organization";Expression={$_.attributes.'organization-name'}}, @{Name="Model ID";Expression={$_.attributes.'model-id'}}, @{Name="Model Name";Expression={$_.attributes.'model-name'}}, @{Name="Configuration ID";Expression={$_.id}}, @{Name="Link";Expression={$_.'resource-url'}} | Out-GridView -Title "Filtered Configurations by Model ID"	
} else {
	Write-Output "No configurations found for the specified model ID(s)."
}

Write-Output "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")