###
# File: \ITG_Manufacturer_and_Model_Cleanup.ps1
# Project: RMM Integration
# Created Date: Tuesday, November 15th 2022, 10:13:02 am
# Author: Chris Jantzen
# -----
# Last Modified: Tue May 28 2024
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2023 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
# 2023-10-31	CJ	Implemented logging
###


. "$PSScriptRoot\Config.ps1" # Config

# Fixed SSL if necessary
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
	Write-Output "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
	Write-PSFMessage -Level Warning -Message "Temporarily changed TLS to TLS v1.2."
}

# Setup logging
If (Get-Module -ListAvailable -Name "PSFramework") {Import-module PSFramework} Else { install-module PSFramework -Force; import-module PSFramework}
$logFile = Join-Path -path "$PSScriptRoot\Logs" -ChildPath "log-itg_man_mod_cleanup-$(Get-date -f 'yyyyMMddHHmmss').txt";
Set-PSFLoggingProvider -Name logfile -FilePath $logFile -Enabled $true;
Write-PSFMessage -Level Verbose -Message "Starting the ITG Manufacturer and Model cleanup."

# Import/Install any required modules
If (Get-Module -ListAvailable -Name "ITGlueAPI") {Import-module ITGlueAPI -Force} Else { install-module ITGlueAPI -Force; import-module ITGlueAPI -Force}

# Connect to IT Glue
if ($ITGAPIKey.Key) {
	Add-ITGlueBaseURI -base_uri $ITGAPIKey.Url
	Add-ITGlueAPIKey $ITGAPIKey.Key
}

# Get ITG data
$ITGManufacturers = Get-ITGlueManufacturers -page_size 1000
if (!$ITGManufacturers -or $ITGManufacturers.Error) {
	Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing manufacturers from ITG. Exiting..."
	Write-PSFMessage -Level Error -Message $ITGManufacturers.Error
	exit 1
}
$ITGManufacturers = ($ITGManufacturers).data

$ITGModels = Get-ITGlueModels -page_size "1000"
$i = 1
while ($ITGModels.links.next) {
	$i++
	$Models_Next = Get-ITGlueModels -page_size "1000" -page_number $i
	if (!$Models_Next -or $Models_Next.Error) {
		# We got an error querying models, wait and try again
		Start-Sleep -Seconds 2
		$Models_Next = Get-ITGlueModels -page_size "1000" -page_number $i

		if (!$Models_Next -or $Models_Next.Error) {
			Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing models from ITG. Exiting..."
			Write-PSFMessage -Level Error -Message $Models_Next.Error
			exit 1
		}
	}
	$ITGModels.data += $Models_Next.data
	$ITGModels.links = $Models_Next.links
	Start-Sleep -Seconds 1
}
$ITGModels = $ITGModels.data

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
Write-PSFMessage -Level Verbose -Message "Grabbed $($ITGManufacturers.count) manufacturers, $($ITGModels.count) models, and $($ITG_OrgDevices.count) configurations from ITG."

if (!$ITGModels -or !$ITGManufacturers -or !$ITG_OrgDevices) {
	Write-PSFMessage -Level Error -Message "There were issues getting the Models, Manufacturers, and Configurations from ITG. Exiting..."
	exit 1
}

# Find all Manufacturers that need to be cleaned up (move models from old to new) and any that need to be re-added (with a cleaned up name)
$ManufacturersToFix = @()
$ManufacturersToAdd = @()
foreach ($Manufacturer in $ITGManufacturers) {
	$CleanedManufacturer = $Manufacturer.attributes.name;

	if ($CleanedManufacturer) {
		if ($CleanedManufacturer -like "*/*") {
			$CleanedManufacturer = ($CleanedManufacturer -split '/')[0]
		}
		$CleanedManufacturer = $CleanedManufacturer.Trim()
		$CleanedManufacturer = $CleanedManufacturer -replace ",? ?(Inc\.?$|Corporation$|Corp\.?$|Co\.$|Ltd\.?$)", ""
		$CleanedManufacturer = $CleanedManufacturer.Trim()
		$CleanedManufacturer = $CleanedManufacturer -replace ",? ?(Inc\.?$|Corporation$|Corp\.?$|Co\.$|Ltd\.?$)", ""
		$CleanedManufacturer = $CleanedManufacturer.Trim()
	}

	if ($Manufacturer.attributes.name -ne $CleanedManufacturer) {
		$ManufacturersToFix += [pscustomobject]@{
			Old = $Manufacturer.attributes.name
			New = $CleanedManufacturer
			OldID = $Manufacturer.id
		}

		if ($CleanedManufacturer -notin $ITGManufacturers.attributes.name) {
			$ManufacturersToAdd += [pscustomobject]@{
				Old = $Manufacturer.attributes.name
				New = $CleanedManufacturer
			}
		}
	}
}
Write-PSFMessage -Level Verbose -Message "Found $($ManufacturersToFix.count) manufacturers to fix and $($ManufacturersToAdd.count) to add."

foreach ($Manufacturer in ($ManufacturersToAdd.New | Sort-Object -Unique)) {
	New-ITGlueManufacturers -data @{
		type = "manufacturers"
		attributes = @{
			name = $Manufacturer
		}
	}
	Write-PSFMessage -Level Verbose -Message "Added new Manufacturer: $($Manufacturer)"
}

if (($ManufacturersToAdd | Measure-Object).Count -gt 0) {
	# If we added manufacturers, refresh the manufacturers list
	$ITGManufacturers = (Get-ITGlueManufacturers -page_size 1000).data
}

# Loop through each Manufacturer to fix and move all Models from the old to the new manufacturer
foreach ($FixManufacturer in $ManufacturersToFix) {
	$OldITGManufacturer = $ITGManufacturers | Where-Object {$_.id -eq $FixManufacturer.OldID }
	$NewITGManufacturer = $ITGManufacturers | Where-Object {$_.attributes.name -like $FixManufacturer.New }

	if (!$OldITGManufacturer -or !$NewITGManufacturer) {
		continue
	}

	$ModelsToMove = $ITGModels | Where-Object { $_.attributes."manufacturer-id" -eq $OldITGManufacturer.id }
	$NewManufacturersExistingModels = $ITGModels | Where-Object { $_.attributes."manufacturer-id" -eq $NewITGManufacturer.id }

	# Cleanup existing models
	foreach ($MoveModel in $ModelsToMove) {
		if ($MoveModel.attributes.name.Trim() -in $NewManufacturersExistingModels.attributes.name) {
			$NewModel = $NewManufacturersExistingModels | Where-Object { $_.attributes.name -like $MoveModel.attributes.name.Trim() } | Select-Object -First 1

			if ($NewModel) {
				$ToFixDevices = $ITG_OrgDevices | Where-Object { $_.attributes."model-id" -eq $MoveModel.id }

				foreach ($Device in $ToFixDevices) {
					$ConfigurationUpdate = @{
						'type' = 'configurations'
						'attributes' = @{
							'manufacturer-id' = $NewITGManufacturer.id
							'model-id' = $NewModel.id
						}
					}
					Set-ITGlueConfigurations -id $Device.id -data $ConfigurationUpdate | Out-Null
					Start-Sleep -Milliseconds 500
				}

				Write-Host "Delete Model (with manufacturer $($OldITGManufacturer.attributes.name)): $($MoveModel.attributes.name)" -ForegroundColor Red
				continue
			}
		}
		Set-ITGlueModels -id $MoveModel.id -data @{
			type = "models"
			attributes = @{
				name = $MoveModel.attributes.name.Trim()
				"manufacturer-id" = $NewITGManufacturer.id
			}
		}
		Start-Sleep -Milliseconds 500
	}
	Write-PSFMessage -Level Verbose -Message "Moved $($ModelsToMove.count) models from the manufacturer '$($OldITGManufacturer.attributes.name)' to '$($NewITGManufacturer.attributes.name)'."

	# Cleanup any devices that still have this manufacturer set
	$ToFixDevices = $ITG_OrgDevices | Where-Object { $_.attributes."manufacturer-id" -eq $FixManufacturer.OldID }

	foreach ($BadDevice in $ToFixDevices) {
		$ModelName = $BadDevice.attributes."model-name"

		# No model, just manufacturer
		if (!$ModelName) {
			$ConfigurationUpdate = @{
				'type' = 'configurations'
				'attributes' = @{
					'manufacturer-id' = $NewITGManufacturer.id
				}
			}
			Set-ITGlueConfigurations -id $BadDevice.id -data $ConfigurationUpdate | Out-Null
			Start-Sleep -Milliseconds 500
			continue
		}

		# Both model and manufacturer
		$CurManufacturer = $BadDevice.attributes."manufacturer-id"
		$CurModel = $ITGModels | Where-Object { $_.id -eq $BadDevice.attributes."model-id" }
		
		if ($CurModel) {
			if ($CurModel.attributes.'manufacturer-id' -eq $FixManufacturer.OldID) {
				# The current model has the bad manufacturer ID, need to update model and manufacturer
				$NewModel = $NewManufacturersExistingModels | Where-Object { $_.attributes.name -like $CurModel.attributes.name.Trim() } | Select-Object -First 1
				$ConfigurationUpdate = @{
					'type' = 'configurations'
					'attributes' = @{
						'manufacturer-id' = $NewITGManufacturer.id
						'model-id' = $NewModel.id
					}
				}
				Set-ITGlueConfigurations -id $BadDevice.id -data $ConfigurationUpdate | Out-Null
				Start-Sleep -Milliseconds 500
			} else {
				# The model is good, just update the manufacturer ID
				$ConfigurationUpdate = @{
					'type' = 'configurations'
					'attributes' = @{
						'manufacturer-id' = $CurModel.attributes.'manufacturer-id'
						'model-id' = $CurModel.id
					}
				}
				Set-ITGlueConfigurations -id $BadDevice.id -data $ConfigurationUpdate | Out-Null
				Start-Sleep -Milliseconds 500
			}
		} else {
			Write-Host "Could not find the current model for device '$($BadDevice.attributes.name)', please update manually. Url: $($BadDevice.attributes.'resource-url')" -ForegroundColor Yellow
		}
	}
	Write-PSFMessage -Level Verbose -Message "Moved $($ToFixDevices.count) devices from the manufacturer '$($OldITGManufacturer.attributes.name)' to '$($NewITGManufacturer.attributes.name)'."

	# Delete old manufacturer
	Write-Host "Deleted Old Manufacturer: $($OldITGManufacturer.attributes.name)" -ForegroundColor Red
	Write-PSFMessage -Level Verbose -Message "Deleted Old Manufacturer: $($OldITGManufacturer.attributes.name)"
}

# $ModelsWithoutMake = $ITGModels | Where-Object { !$_.attributes."manufacturer-id" }
# foreach ($BadModel in $ModelsWithoutMake) {
# 	$GoodModels = $ITGModels | Where-Object { $_.attributes.name -like $BadModel.attributes.name.Trim() -and $_.attributes."manufacturer-id" }

# 	if ($GoodModels) {
# 		if (($GoodModels | Measure-Object).Count -gt 1) {
# 			Write-Host "More than 1 replacement model found:"
# 			foreach ($GoodModel in $GoodModels) {
# 				Write-Host "$($GoodModel.attributes."manufacturer-name") - $($GoodModel.attributes.name)"
# 			}
# 			break
# 			continue
# 		} else {
# 			$GoodModel = $GoodModels
# 		}

# 		$BadDevices = $ITG_OrgDevices | Where-Object { $_.attributes.'model-id' -eq $BadModel.id }

# 		if ($BadDevices) {
# 			foreach ($BadDevice in $BadDevices) {
# 				$ConfigurationUpdate = @{
# 					'type' = 'configurations'
# 					'attributes' = @{
#						'manufacturer-id' = $GoodModel.attributes.'manufacturer-id'
# 						'model-id' = $GoodModel.id
# 					}
# 				}
# 				Set-ITGlueConfigurations -id $BadDevice.id -data $ConfigurationUpdate
# 			}
# 		}

# 		# Delete bad model
# 		Write-Host "Delete Model (without manufacturer): $($BadModel.attributes.name)" -ForegroundColor Red
# 	} else {
# 		Write-Host "No replacement model found:"
# 		Write-Host "$($BadModel.attributes."manufacturer-name") - $($BadModel.attributes.name)"
# 	}
# }
