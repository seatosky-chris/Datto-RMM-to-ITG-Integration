###
# File: \DattoRMM_to_ITG_Monitors_Integration.ps1
# Project: RMM Integration
# Created Date: Tuesday, May 16th 2023, 3:59:48 pm
# Author: Chris Jantzen
# -----
# Last Modified: Thu Jul 06 2023
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2023 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
###

. "$PSScriptRoot\Config.ps1" # Config

# A blacklist of bad monitor-specific serial numbers
# To add custom ones, add to the $IgnoreSerials variable in Config.ps1
$SNBlacklist = @(16843009, 16780800, 1513576258, "0000000000001", "VIZIO00001", "SerialNumber", "W1Zyywwnnnnn", "demoset-1")


# Fixed SSL if necessary
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
	Write-Output "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

# Import/Install any required modules
If (Get-Module -ListAvailable -Name "DattoRMM") {Import-module DattoRMM -Force} Else { install-module DattoRMM -Force; import-module DattoRMM -Force}
If (Get-Module -ListAvailable -Name "ITGlueAPI") {Import-module ITGlueAPI -Force} Else { install-module ITGlueAPI -Force; import-module ITGlueAPI -Force}

# Connect to IT Glue
if ($ITGAPIKey.Key) {
	Add-ITGlueBaseURI -base_uri $ITGAPIKey.Url
	Add-ITGlueAPIKey $ITGAPIKey.Key
}

# Connect to RMM
Set-DrmmApiParameters -Url $DattoAPIKey.URL -Key $DattoAPIKey.Key -SecretKey $DattoAPIKey.SecretKey

# Set the UDF to query
$MonitorUDF = "udf$($RMM_MonitorInfo_UDF)"

# Get auxilary ITG data
$ITGManufacturers = (Get-ITGlueManufacturers -page_size 1000).data

$ITGModels = Get-ITGlueModels -page_size "1000"
$i = 1
while ($ITGModels.links.next) {
	$i++
	$Models_Next = Get-ITGlueModels -page_size "1000" -page_number $i
	$ITGModels.data += $Models_Next.data
	$ITGModels.links = $Models_Next.links
}
$ITGModels = $ITGModels.data

# Loop through all RMM companies and match to related ITG company
$RMM_Sites = Get-DrmmAccountSites | Sort-Object -Property Name
$ITG_Sites = Get-ITGlueOrganizations -page_size 1000
$MatchedSites = @{}

if ($ITG_Sites -and $ITG_Sites.data) {
	foreach ($RMMSite in $RMM_Sites) {
		if ($RMMSite.name -eq "Deleted Devices") {
			continue
		}

		$ITGSite = $ITG_Sites.data | Where-Object { 
			if ($_.attributes.name) {
				$Return = $false
				if ($RMMSite.name) {
					$Return = $_.attributes.name.Trim() -like $RMMSite.name.Trim()
				}
				if ($RMMSite.autotaskCompanyName -and !$Return) {
					$Return = $_.attributes.name.Trim() -like $RMMSite.autotaskCompanyName.Trim() 
				}
				return $Return
			}
		}

		# Narrow down if more than 1
		if (($ITGSite | Measure-Object).Count -gt 1 -and $RMMSite.autotaskCompanyName) {
			$ITGSite_Temp = $ITGSite | Where-Object { $_.attributes.'psa-integration' -eq 'enabled' -and $_.attributes.name.Trim() -like $RMMSite.autotaskCompanyName.Trim() }
			if (($ITGSite_Temp | Measure-Object).Count -gt 0) {
				$ITGSite = $ITGSite_Temp
			}
		}
		if (($ITGSite | Measure-Object).Count -gt 1 -and $RMMSite.name) {
			$ITGSite_Temp = $ITGSite | Where-Object { $_.attributes.name.Trim() -like $RMMSite.name.Trim() }
			if (($ITGSite_Temp | Measure-Object).Count -gt 0) {
				$ITGSite = $ITGSite_Temp
			}
		}
		if (($ITGSite | Measure-Object).Count -gt 1) {
			if ($RMMSite.autotaskCompanyName) {
				$ITGSite_Temp = $ITGSite | Where-Object { $_.attributes.'psa-integration' -eq 'enabled' }
			} else {
				$ITGSite_Temp = $ITGSite | Where-Object { $_.attributes.'psa-integration' -ne 'enabled' }
			}
			if (($ITGSite_Temp | Measure-Object).Count -gt 0) {
				$ITGSite = $ITGSite_Temp
			}
		}

		if ($ITGSite) {
			$MatchedSites[$RMMSite.id] = (@($ITGSite) | Select-Object -First 1)
		} else {
			Write-Host "Could not find the RMM site '$($RMMSite.name)' in ITG." -ForegroundColor Red
		}
	}
}

# Get RMM Devices for all organizations
$RMM_Devices = Get-DrmmAccountDevices | Sort-Object -property @{Expression='sitename'; Ascending=$true}, @{Expression='description'; Ascending=$true} | Where-Object {$_.sitename -ne "Deleted Devices"}
$DevicesWithMonitors = $RMM_Devices | Where-Object { $_.udf.$MonitorUDF -and ($_.udf.$MonitorUDF -like "``[*" -or $_.udf.$MonitorUDF -like "{*") }

Function TimedPrompt($prompt,$secondsToWait){
    Write-Host -NoNewline $prompt
    $secondsCounter = 0
    $subCounter = 0
    While ( $secondsCounter -lt $secondsToWait ) {
		if ([Console]::KeyAvailable){break}
        start-sleep -m 10
        $subCounter = $subCounter + 10
        if($subCounter -eq 1000)
        {
            $secondsCounter++
            $subCounter = 0
            Write-Host -NoNewline "."
        }       
        If ($secondsCounter -eq $secondsToWait) { 
            Write-Host "`r`n"
            return $false;
        }
    }
    Write-Host "`r`n"
	$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    return $true;
}

# Get all monitor type devices from ITG
$ITG_Monitors = Get-ITGlueConfigurations -page_size "1000" -filter_configuration_type_id $ITG_MonitorTypeID -include configuration_interfaces
$i = 1
while ($ITG_Monitors.links.next) {
	$i++
	$Configurations_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -filter_configuration_type_id $ITG_MonitorTypeID -include configuration_interfaces
	$ITG_Monitors.data += $Configurations_Next.data
	$ITG_Monitors.links = $Configurations_Next.links
}
if ($ITG_Monitors -and $ITG_Monitors.data) {
	$ITG_Monitors = $ITG_Monitors.data
}

if (!$ITG_Monitors) {
	$continue = TimedPrompt "No monitors could be pulled from ITG. Would you like to continue? 'Y' to continue, otherwise the script will exit in 10 seconds." 10
	if (!$continue -or $continue.character -ne "Y") {
		exit
	}
	Write-Host "No monitors were found in ITG, user input indicates that this is a first time run." -ForegroundColor Yellow
}

# Get all Monitor EOL's from ITG
$ITG_MonitorEOLs = Get-ITGlueFlexibleAssets -page_size "1000" -filter_flexible_asset_type_id $ITG_EOL_FlexibleAssetTypeID
$i = 1
while ($ITG_MonitorEOLs.links.next) {
	$i++
	$Monitors_Next = Get-ITGlueFlexibleAssets -page_size "1000" -page_number $i -filter_flexible_asset_type_id $ITG_EOL_FlexibleAssetTypeID
	$ITG_MonitorEOLs.data += $Monitors_Next.data
	$ITG_MonitorEOLs.links = $Monitors_Next.links
}
if ($ITG_MonitorEOLs -and $ITG_MonitorEOLs.data) {
	$ITG_MonitorEOLs = $ITG_MonitorEOLs.data
	$ITG_MonitorEOLs = $ITG_MonitorEOLs | Where-Object { $_.attributes.name -like "*Monitor*" }
	$ITG_MonitorEOLs = @($ITG_MonitorEOLs)
}

if (!$ITG_MonitorEOLs) {
	$continue = TimedPrompt "No EOL assets could be pulled from ITG. Would you like to continue? 'Y' to continue, otherwise the script will exit in 10 seconds." 10
	if (!$continue -or $continue.character -ne "Y") {
		exit
	}
	Write-Host "No EOL assets were found in ITG, user input indicates that this is a first time run." -ForegroundColor Yellow
}

$DisplayTypes = $AllMonitors | Select-Object -ExpandProperty DisplayType | Sort-Object -Unique
$DisplayTypes += "DP"

$DevicesWithMonitors_Friendly = @()
$AllMonitors = @()
$MatchedITGMonitors = @()

$ManufacturerHash = @{ 
	"AAC" =	"AcerView";
    "ACI" = "ASUS";
	"ACR" = "Acer";
	"AOC" = "AOC";
    "AOP" = "AOpen";
	"AIC" = "AG Neovo";
	"APP" = "Apple";
	"AST" = "AST Research";
	"AUO" = "ASUS";
    "AUS" = "ASUS";
	"BNQ" = "BenQ";
	"CMO" = "Acer";
	"CPL" = "Compal";
	"CPQ" = "Compaq";
	"CPT" = "Chunghwa Picture Tubes";
	"CTX" = "CTX";
	"DEC" = "DEC";
	"DEL" = "Dell";
	"DPC" = "Delta";
	"DWE" = "Daewoo";
	"EIZ" = "EIZO";
    "ELO" = "Elo";
	"ELS" = "ELSA";
	"ENC" = "EIZO";
	"EPI" = "Envision";
	"FCM" = "Funai";
	"FUJ" = "Fujitsu";
	"FUS" = "Fujitsu-Siemens";
    "GBT" = "Gigabyte Technology";
	"Gigabyte" = "Gigabyte Technology";
	"GSM" = "LG";
    "GWD" = "Arzopa";
	"GWY" = "Gateway 2000";
	"HEI" = "Hyundai";
	"HIT" = "Hyundai";
    "HPN" = "HP";
	"HSL" = "Hansol";
	"HTC" = "Hitachi/Nissei";
	"HWP" = "HP";
	"IBM" = "IBM";
	"ICL" = "Fujitsu";
	"IVM" = "Iiyama";
	"KDS" = "Korea Data Systems";
    "KTC" = "KTC";
	"LEN" = "LENOVO";
	"LGD" = "ASUS";
	"LPL" = "Fujitsu";
	"MAX" = "Belinea"; 
	"MEI" = "Panasonic";
	"MEL" = "Mitsubishi Electronics";
	"MS_" = "Panasonic";
	"NAN" = "Nanao";
	"NEC" = "NEC";
	"NOK" = "Nokia Data";
	"NVD" = "Fujitsu";
    "ONN" = "ONN";
	"OPT" = "Optoma";
	"PHL" = "Philips";
	"REL" = "Relisys";
	"SAN" = "Samsung";
	"SAM" = "Samsung";
	"SBI" = "Smarttech";
	"SGI" = "SGI";
    "SHP" = "Sharp";
	"SNY" = "Sony";
	"SRC" = "Shamrock";
	"SUN" = "Sun Microsystems";
	"SEC" = "Hewlett-Packard";
	"TAT" = "Tatung";
	"TOS" = "TOSHIBA";
	"TSB" = "TOSHIBA";
    "VIZ" = "Vizio"
	"VSC" = "ViewSonic";
	"ZCM" = "Zenith";
	"UNK" = "Unknown";
	"_YV" = "Fujitsu";
}

# Levenshtein distance function for comparing similarity between two strings
function Measure-StringDistance {
    <#
        .SYNOPSIS
            Compute the distance between two strings using the Levenshtein distance formula.
        
        .DESCRIPTION
            Compute the distance between two strings using the Levenshtein distance formula.

        .PARAMETER Source
            The source string.

        .PARAMETER Compare
            The comparison string.

        .EXAMPLE
            PS C:\> Measure-StringDistance -Source "Michael" -Compare "Micheal"

            2

            There are two characters that are different, "a" and "e".

        .EXAMPLE
            PS C:\> Measure-StringDistance -Source "Michael" -Compare "Michal"

            1

            There is one character that is different, "e".

        .NOTES
            Author:
            Michael West
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([int])]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$Source = "",
        [string]$Compare = ""
    )
    $n = $Source.Length;
    $m = $Compare.Length;
    $d = New-Object 'int[,]' $($n+1),$($m+1)
        
    if ($n -eq 0){
      return $m
	}
    if ($m -eq 0){
	    return $n
	}

	for ([int]$i = 0; $i -le $n; $i++){
        $d[$i, 0] = $i
    }
    for ([int]$j = 0; $j -le $m; $j++){
        $d[0, $j] = $j
    }

	for ([int]$i = 1; $i -le $n; $i++){
	    for ([int]$j = 1; $j -le $m; $j++){
            if ($Compare[$($j - 1)] -eq $Source[$($i - 1)]){
                $cost = 0
            }
            else{
                $cost = 1
            }
		    $d[$i, $j] = [Math]::Min([Math]::Min($($d[$($i-1), $j] + 1), $($d[$i, $($j-1)] + 1)),$($d[$($i-1), $($j-1)]+$cost))
	    }
	}
	    
    return $d[$n, $m]
}

# Compares each part of a sentence, breaking it on spaces and special characters, against another sentence
# and returns a score of the similarity
# This is used when there is a tie for String Distance (see Measure-StringDistance)
function Measure-PartsEquality {
	<#
        .SYNOPSIS
            Compute the similarity between two strings by comparing each individual part of a sentence against another.
        
        .DESCRIPTION
            Compute the similarity between two strings by comparing each individual part of a sentence against another (to see if it contains it).

        .PARAMETER Source
            The source string.

        .PARAMETER Compare
            The comparison string.

        .EXAMPLE
            PS C:\> Measure-PartsEquality -Source "Hello World" -Compare "Hello Life"

            1

            "Hello" exists in the compared sentence but "World" does not, so there is 1 match

        .EXAMPLE
            PS C:\> Measure-StringDistance -Source "Michael" -Compare "Michal"

            1

            There is one character that is different, "e".
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([int])]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$Source = "",
        [string]$Compare = ""
    )

	$SourceParts = @($Source -split " |,|\/|\\|;|\.|\-")
	$CompareParts = @($Compare -split " |,|\/|\\|;|\.|\-")

	$i = 0
	foreach ($SourcePart in $SourceParts) {
		if ($SourcePart -in $CompareParts) {
			$i++
		}
	}

	$i
}

# Function to convert imported UTC date/times to local time for easier comparisons
function Convert-UTCtoLocal {
	param( [parameter(Mandatory=$true)] [String] $UTCTime )
	$strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName 
	$TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone) 
	$LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
	return $LocalTime
}

function Format-ManufacturerName ($Manufacturer) {
	if ($Manufacturer) {
		if ($Manufacturer -like "*/*") {
			$Manufacturer = ($Manufacturer -split '/')[0]
		}
		$Manufacturer = $Manufacturer.Trim()
		$Manufacturer = $Manufacturer -replace ",? ?(Inc\.?$|Corporation$|Corp\.?$|Co\.$|Ltd\.?$)", ""
		$Manufacturer = $Manufacturer.Trim()
		$Manufacturer = $Manufacturer -replace ",? ?(Inc\.?$|Corporation$|Corp\.?$|Co\.$|Ltd\.?$)", ""
		$Manufacturer = $Manufacturer.Trim()
		return $Manufacturer
	} else {
		return $false
	}
}

# Gets the related ITG Manufacturer and Model for a Monitor
# Returns a hashtable, @{Manufacturer = $ITGManufacturer; Model = $ITGModel}
function Get-ITGManufacturerAndModel ($Monitor) {
	$Manufacturer = $Monitor.Manufacturer
	$Model = $Monitor.Model.Trim()

	if ($Model -like "$($Manufacturer)*") {
		$Model = $Model -replace $Manufacturer, ""
		$Model = $Model.Trim()
	}

	if ($Manufacturer) {
		$Manufacturer = Format-ManufacturerName -Manufacturer $Manufacturer
		$ITGManufacturer = $false
		$ITGModel = $false

		if ($Model) {
			$ITGModel = $ITGModels | Where-Object { $_.attributes.name -like $Model -and $_.attributes.'manufacturer-name' -like $Manufacturer }
			if (!$ITGModel) {
				$ITGModel = $ITGModels | Where-Object { $_.attributes.name -like $Model -and $_.attributes.'manufacturer-name' -like $Monitor.Manufacturer.Trim() }
				if ($ITGModel) {
					$Manufacturer = $Monitor.Manufacturer.Trim()
				}
			}
			if (!$ITGModel) {
				$ITGModel = $ITGModels | Where-Object { $_.attributes.name -like ($Monitor.Model.Trim()) -and $_.attributes.'manufacturer-name' -like $Manufacturer }
				if ($ITGModel) {
					$Model = $Monitor.Model.Trim()
				}
				if (!$ITGModel) {
					$ITGModel = $ITGModels | Where-Object { $_.attributes.name -like ($Monitor.Model.Trim()) -and $_.attributes.'manufacturer-name' -like $Monitor.Manufacturer.Trim() }
					if ($ITGModel) {
						$Model = $Monitor.Model.Trim()
						$Manufacturer = $Monitor.Manufacturer.Trim()
					}
				}
			}

			if (($ITGModel | Measure-Object).Count -gt 1 -and ($ITGModel | Where-Object { $_.attributes.name -ceq $Model } | Measure-Object).Count -gt 0) {
				$ITGModel = $ITGModel | Where-Object { $_.attributes.name -ceq $Model }
			}
			if (($ITGModel | Measure-Object).Count -gt 1) {
				$ITGModel = $ITGModel | Select-Object -First 1
			}
		}

		if ($ITGModel -and $ITGModel.attributes.'manufacturer-id') {
			$ITGManufacturer = $ITGManufacturers | Where-Object { $_.id -eq $ITGModel.attributes.'manufacturer-id' }
		}
		if (!$ITGManufacturer) {
			$ITGManufacturer = $ITGManufacturers | Where-Object { $_.attributes.name -like $Manufacturer }
		}

		if (($ITGManufacturer | Measure-Object).Count -gt 1 -and ($ITGManufacturer | Where-Object { $_.attributes.name -ceq $Manufacturer } | Measure-Object).Count -gt 0) {
			$ITGManufacturer = $ITGManufacturer | Where-Object { $_.attributes.name -ceq $Manufacturer }
		}
		if (($ITGManufacturer | Measure-Object).Count -gt 1) {
			$ITGManufacturer = $ITGManufacturer | Select-Object -First 1
		}

		if (!$ITGManufacturer -and $Manufacturer) {
			$ITGManufacturer = New-ITGlueManufacturers -data @{
				type = "manufacturers"
				attributes = @{
					name = $Manufacturer
				}
			}
			$ITGManufacturer = $ITGManufacturer.data
			$global:ITGManufacturers += $ITGManufacturer
		}
		if (!$ITGModel -and $Model) {
			$ITGModel = New-ITGlueModels -manufacturer_id $ITGManufacturer.id -data @{
				type = "models"
				attributes = @{	
					name = $Model
					"manufacturer-id" = $ITGManufacturer.id
				}
			}
			$ITGModel = $ITGModel.data
			$global:ITGModels += $ITGModel
		}

		return @{
			Manufacturer = $ITGManufacturer
			Model = $ITGModel
		}
	} else {
		return $false
	}
}

# The below function will add more details to the RMM device (serial number, manufacturer, model, etc)
function Get-RMMDeviceDetails ($Device)
{
	if ($Device -and "serialNumber" -notin $Device.PSObject.Properties.Name) {
		$Device | Add-Member -NotePropertyName serialNumber -NotePropertyValue $false
		$Device | Add-Member -NotePropertyName manufacturer -NotePropertyValue $false
		$Device | Add-Member -NotePropertyName model -NotePropertyValue $false
		$Device | Add-Member -NotePropertyName Nics -NotePropertyValue @()
		$Device | Add-Member -NotePropertyName url -NotePropertyValue $false

		$AuditDevice = Get-DrmmAuditDevice $Device.uid
		if ($AuditDevice) {
			$Device.serialNumber = $AuditDevice.bios.serialNumber
			$Device.manufacturer = $AuditDevice.systemInfo.manufacturer
			$Device.model = $AuditDevice.systemInfo.model
			$Device.Nics = @($AuditDevice.nics | Where-Object { $Nic = $_; $_.macAddress -and ($NetworkAdapterBlacklist | Where-Object { $Nic.instance -like $_ }).Count -eq 0 } | Select-Object instance, ipv4, macAddress)
			$Device.url = $AuditDevice.portalUrl
		}
	}
}

# Gets any related ITG devices by searching the organization for devices with the same name
# It then compares mac address, serial #, etc.
# It also keeps a cache of these devices in the below $RMMToITG variable
$RMMToITG = @{}
function Get-RelatedITGDevices ($RMMDevice) {
	# First check cache
	if ($RMMToITG[$RMMDevice.id]) {
		return $RMMToITG[$RMMDevice.id].itg_devices
	}

	# Not in the cache, query ITG
	$DeviceName = $RMMDevice.hostname.Trim()
	if ($RMMDevice.description -and $RMMDevice.description.Trim() -notlike $DeviceName) {
		$DeviceName += ",$($RMMDevice.description)"
	}
	$OrgID = ($MatchedSites[$RMMDevice.siteId]).id

	$ITGDevices = Get-ITGlueConfigurations -organization_id $OrgID -filter_name $DeviceName

	if (!$ITGDevices -or !$ITGDevices.data -or ($ITGDevices.data | Measure-Object).Count -eq 0) {
		$ITGDevices = Get-ITGlueConfigurations -organization_id $OrgID -filter_rmm_id $RMMDevice.id
	}
	if (!$ITGDevices -or !$ITGDevices.data -or ($ITGDevices.data | Measure-Object).Count -eq 0) {
		Get-RMMDeviceDetails -Device $RMMDevice
		if ($RMMDevice.serialNumber) {
			$ITGDevices = Get-ITGlueConfigurations -organization_id $OrgID -filter_serial_number $RMMDevice.serialNumber
		}
	}

	if ($ITGDevices -and $ITGDevices.data -and ($ITGDevices.data | Measure-Object).Count -gt 0) {
		$ITGDevices_Matched = $ITGDevices.data | Where-Object { $_.attributes.'installed-by' -and $_.attributes.'installed-by'.Trim() -like "RMM: $($RMMDevice.uid)" }

		if (($ITGDevices.data | Measure-Object).count -ne 1) {
			Get-RMMDeviceDetails -Device $RMMDevice
			if (!$RMMDevice.serialNumber -and !$RMMDevice.Nics.macAddress) {
				return $false
			}
			$ITGDevices_Matched = $ITGDevices.data | Where-Object { $_.attributes.'serial-number' -or $_.attributes.'mac-address' -or $_.attributes.'installed-by' }
			$ITGDevices_Matched = $ITGDevices_Matched | Where-Object {
				($_.attributes.'serial-number' -and $RMMDevice.serialNumber -and $_.attributes.'serial-number'.Trim() -like $RMMDevice.serialNumber.Trim()) -or
				($_.attributes.'mac-address' -and $RMMDevice.Nics.macAddress -and $_.attributes.'mac-address'.Trim() -in $RMMDevice.Nics.macAddress) -or
				($_.attributes.'installed-by' -and $_.attributes.'installed-by'.Trim() -like "RMM: $($RMMDevice.uid)")
			}
		}

		if ($ITGDevices_Matched) {
			$RMMToITG[$RMMDevice.id] += @{
				rmm_device = $RMMDevice
				itg_devices = $ITGDevices_Matched
			}
			return $ITGDevices_Matched
		}
	}

	return $false
}

# This will parse the ITG notes of a monitor for the list of configuration ID's that are connected to it
function Get-ConfigIDsFromNotes ($Notes) {
	$IDs = @()
	$MatchFound = $Notes -match "Connected to devices?: (([\w\d\-]+) \(ID: ([\d]+)\),? ?)+"

	if ($MatchFound -and $Matches -and $Matches[0]) {
		$IDMatches = Select-String "\(ID: ([\d]+)\)" -InputObject $Matches[0] -AllMatches

		if ($IDMatches) {
			$IDMatches | ForEach-Object {
				$_.matches | ForEach-Object {
					if ($_.Groups[1]) {
						$IDs += $_.Groups[1].Value
					}
				}
			}
		}
	}

	return $IDs
}

# This will parse the ITG notes of a monitor for the display type
function Get-ConfigDisplayType ($Notes) {
	$MatchFound = $Notes -match "Connected by: ([\w]+)"

	if ($MatchFound -and $Matches -and $Matches[1]) {
		return $Matches[1]
	} else {
		return $false
	}
}

# This calculates the warranty date for a monitor based on manufacture year
function Get-WarrantyDate ($MonitorDetails) {
	$WarrantyDate = Get-Date
	if ($MonitorDetails.YearOfManufacture) {
		$YearOfManufacture = [int]$MonitorDetails.YearOfManufacture
		if ($WarrantyDate.Year -gt $YearOfManufacture) {
			$WarrantyDate = $WarrantyDate.AddYears($YearOfManufacture - $WarrantyDate.Year)
		}
	}
	$WarrantyDate = $WarrantyDate.AddYears(3)
	$WarrantyDate = Get-Date $WarrantyDate -Format "yyyy-MM-dd"
	return $WarrantyDate
}

# This calculates the end of life date for a monitor based on a current warranty date
function Get-EOLDate ($WarrantyDate) {
	$EOLDate = Get-Date $WarrantyDate
	$EOLDate = $EOLDate.AddYears(2)
	$EOLDate = Get-Date $EOLDate -Format "yyyy-MM-dd"
	return $EOLDate
}

# This looks for an existing EOL asset in ITG and if it can't find one, it creates one
# Takes an ITG monitor config asset and the EOL date
# Returns the EOL asset
function Get-RelatedEOLAssets ($ITGMonitor, $EOLDate, $ITGManufacturerAndModel = $false) {
	if (!$ITGMonitor -or !$EOLDate) {
		return
	}
	$EOLDateArr = $EOLDate.split("-")

	# Get Manufacturer / Model
	if (!$ITGManufacturerAndModel) {
		$ITGManufacturerAndModel = Get-ITGManufacturerAndModel $MonitorDetails
	}
	$ITGManufacturer = $ITGManufacturerAndModel.Manufacturer
	$ITGModel = $ITGManufacturerAndModel.Model

	$Org_EOLAssets = $ITG_MonitorEOLs | Where-Object { $_.attributes.'organization-id' -eq $ITGMonitor.attributes.'organization-id' }
	$Possible_EOLAssets = $Org_EOLAssets | Where-Object { $_.attributes.traits.'end-of-life' -like "$($EOLDateArr[0])*" }
	$Device_EOLAssets = $Possible_EOLAssets | Where-Object { $_.attributes.traits.'configuration-s' -and $_.attributes.traits.'configuration-s'.values -and $ITGMonitor.id -in $_.attributes.traits.'configuration-s'.values.id }

	if (($Device_EOLAssets | Measure-Object).count -gt 1) {
		Write-Host "Warning: Mutliple EOL assets found for '$($ITGMonitor.attributes.name)' (See: $($Device_EOLAssets.id -join ", "))" -ForegroundColor Red
	}

	if ($Device_EOLAssets) {
		$Possible_EOLAssets = $Device_EOLAssets
	} else {
		$Possible_EOLAssets = $Possible_EOLAssets | Where-Object { 
			($_.attributes.traits.'manufacturer-model' -like "*$($ITGMonitor.attributes.'manufacturer-name')*" -and $_.attributes.traits.'manufacturer-model' -like "*$($ITGMonitor.attributes.'model-name')*") -or
			($_.attributes.traits.'manufacturer-model' -like "*$($ITGManufacturer.attributes.name)*" -and $_.attributes.traits.'manufacturer-model' -like "*$($ITGModel.attributes.name)*")
		}
	}

	# Narrow down if more than 1 EOL asset is found
	if (($Possible_EOLAssets | Measure-Object).Count -gt 1) {
		$Possible_EOLAssets_Filtered = $Possible_EOLAssets | Where-Object { 
			$_.attributes.name -like "*$($ITGMonitor.attributes.name)*"
		}
		if (($Possible_EOLAssets_Filtered | Measure-Object).Count -gt 0) {
			$Possible_EOLAssets = $Possible_EOLAssets_Filtered
		}

		if (($Possible_EOLAssets | Measure-Object).Count -gt 1) {
			$Possible_EOLAssets_Filtered = $Possible_EOLAssets | Where-Object { 
				($_.attributes.traits.'manufacturer-model' -like "*$($ITGMonitor.attributes.'manufacturer-name') *" -and $_.attributes.traits.'manufacturer-model' -like "*$($ITGMonitor.attributes.'model-name')") -or
				($_.attributes.traits.'manufacturer-model' -like "*$($ITGManufacturer.attributes.name) *" -and $_.attributes.traits.'manufacturer-model' -like "*$($ITGModel.attributes.name)")
			}
			if (($Possible_EOLAssets_Filtered | Measure-Object).Count -gt 0) {
				$Possible_EOLAssets = $Possible_EOLAssets_Filtered
			}
		}

		if (($Possible_EOLAssets | Measure-Object).Count -gt 1) {
			$Possible_EOLAssets_Filtered = $Possible_EOLAssets | Where-Object { 
				$_.attributes.name -like "*$($ITGMonitor.attributes.'manufacturer-name')*" -and $_.attributes.name -like "*$($ITGMonitor.attributes.'model-name')*"
			}
			if (($Possible_EOLAssets_Filtered | Measure-Object).Count -gt 0) {
				$Possible_EOLAssets = $Possible_EOLAssets_Filtered
			}
		}

		if (($Possible_EOLAssets | Measure-Object).Count -gt 1) {
			$Possible_EOLAssets_Filtered = $Possible_EOLAssets | Where-Object { 
				$_.attributes.name -like "*$($ITGMonitor.attributes.'manufacturer-name') *" -and $_.attributes.name -like "*$($ITGMonitor.attributes.'model-name') *"
			}
			if (($Possible_EOLAssets_Filtered | Measure-Object).Count -gt 0) {
				$Possible_EOLAssets = $Possible_EOLAssets_Filtered
			}
		}

		if (($Possible_EOLAssets | Measure-Object).Count -gt 1) {
			$Possible_EOLAssets_Filtered = $Possible_EOLAssets | Where-Object { 
				$_.attributes.traits.'end-of-life' -like $EOLDate
			}
			if (($Possible_EOLAssets_Filtered | Measure-Object).Count -gt 0) {
				$Possible_EOLAssets = $Possible_EOLAssets_Filtered
			}
		}

		if (($Possible_EOLAssets | Measure-Object).Count -gt 1) {
			$Possible_EOLAssets_Filtered = $Possible_EOLAssets | Where-Object { 
				$_.attributes.traits.'notes' -like "*RMM Monitor Integration*"
			}
			if (($Possible_EOLAssets_Filtered | Measure-Object).Count -gt 0) {
				$Possible_EOLAssets = $Possible_EOLAssets_Filtered
			}
		}
		
		if (($Possible_EOLAssets | Measure-Object).Count -gt 1) {
			$Possible_EOLAssets = $Possible_EOLAssets | Sort-Object { $_.attributes.'updated-at' } -Descending | Select-Object -First 1
		}
	}

	$Unneeded_EOLAssets = $Possible_EOLAssets | Where-Object {
		$_.id -ne $Possible_EOLAssets[0].id -and 
		(($_.attributes.traits.'manufacturer-model' -like "*$($ITGMonitor.attributes.'manufacturer-name') *" -and $_.attributes.traits.'manufacturer-model' -like "*$($ITGMonitor.attributes.'model-name')") -or
		($_.attributes.traits.'manufacturer-model' -like "*$($ITGManufacturer.attributes.name) *" -and $_.attributes.traits.'manufacturer-model' -like "*$($ITGModel.attributes.name)"))
	}

	if (($Unneeded_EOLAssets | Measure-Object).count -gt 0) {
		Write-Host "Warning: Mutliple Possible EOL assets found for '$($ITGMonitor.attributes.name)' (Unneeded: $($Unneeded_EOLAssets.id -join ", "))" -ForegroundColor Yellow
	}

	# Clean up any bad EOL assets
	$AllDevice_EOLAssets = $ITG_MonitorEOLs | Where-Object { $_.attributes.traits.'configuration-s' -and $_.attributes.traits.'configuration-s'.values -and $ITGMonitor.id -in $_.attributes.traits.'configuration-s'.values.id }
	$Remove_EOLAssets =  $false
	if ($Possible_EOLAssets) {
		$Remove_EOLAssets = $AllDevice_EOLAssets | Where-Object { $_.id -ne $Possible_EOLAssets[0].id }
	}

	if ($Remove_EOLAssets) {
		foreach ($Remove_EOLAsset in $Remove_EOLAssets) {
			if (($Remove_EOLAsset.attributes.traits.'configuration-s'.values.id | Measure-Object).Count -gt 1) {
				# Just remove this device from the EOL asset
				$UpdatedConfigurations = @($Remove_EOLAsset.attributes.traits.'configuration-s'.values.id)
				$UpdatedConfigurations = $UpdatedConfigurations | Where-Object { $_ -ne $ITGMonitor.id }
				$UpdatedConfigurations = $UpdatedConfigurations | Sort-Object -Unique

				$UpdatedEOLAsset = 
				@{
					type = 'flexible-assets'
					attributes = @{
						traits = @{
							description = $Remove_EOLAsset.attributes.traits.description
							"end-of-life" = $Remove_EOLAsset.attributes.traits.'end-of-life'
							"manufacturer-model" = $Remove_EOLAsset.attributes.traits.'manufacturer-model'
							"configuration-s" = @($UpdatedConfigurations)
							notes = $Remove_EOLAsset.attributes.traits.notes
						}
					}
				}
				$null = Set-ITGlueFlexibleAssets -id $Remove_EOLAsset.id -data $UpdatedEOLAsset
				$Remove_EOLAsset.attributes.traits.'configuration-s' | ForEach-Object {
					if ($_.values.id -contains $ITGMonitor.id) {
						$_.values = $_.values | Where-Object { $_.id -ne $ITGMonitor.id }
					}
				}
			} else {
				# This is the only device in the EOL asset, remove the entire EOL asset
				Remove-ITGlueFlexibleAssets -id $Remove_EOLAsset.id
			}
		}
	}

	if (!$Possible_EOLAssets) {
		# No EOL asset found, lets create one
		$NewEOLAsset = 
		@{
			type = 'flexible-assets'
			attributes = @{
				"organization-id" = $ITGMonitor.attributes.'organization-id'
				"flexible-asset-type-id" = $ITG_EOL_FlexibleAssetTypeID
				traits = @{
					description = "Monitor - $($ITGManufacturer.attributes.name) $($ITGModel.attributes.name)"
					"end-of-life" = $EOLDate
					"manufacturer-model" = "$($ITGManufacturer.attributes.name) $($ITGModel.attributes.name)"
					"configuration-s" = @($ITGMonitor.id)
					notes = "Created by: RMM Monitor Integration"
				}
			}
		}
		$Possible_EOLAssets = New-ITGlueFlexibleAssets -organization_id $ITGMonitor.attributes.'organization-id' -data $NewEOLAsset
		if ($Possible_EOLAssets -and $Possible_EOLAssets.data -and $Possible_EOLAssets.data[0]) {
			$Possible_EOLAssets = $Possible_EOLAssets.data[0]
			$script:ITG_MonitorEOLs += $Possible_EOLAssets
		} else {
			return @()
		}
	}

	return @($Possible_EOLAssets)
}

# This function will add a monitor into ITG
function New-ITGMonitor ($MonitorDetails, $ITGManufacturerAndModel = $false)
{
	if (!$MonitorDetails) {
		return;
	}

	$ITGOrg = $MatchedSites[$MonitorDetails.RMMSiteID]

	if (!$ITGOrg) {
		Write-Error "Could not create new monitor as no matching ITG Org was found. Device: $($MonitorDetails.AttachedDevice), Serial: $($MonitorDetails.SerialNumber), RMMSiteID: $($MonitorDetails.RMMSiteID)"
		return $false
	}

	# Build Name
	$MonitorName = ""
	if ($ITGOrg.attributes.'short-name') {
		$MonitorName += $ITGOrg.attributes.'short-name'
	} else {
		$MonitorName += $ITGOrg.attributes.name
	}
	$MonitorName += "-DISP-"
	if (($MonitorName.Length + $MonitorDetails.SerialNumber.ToString().Length) -gt 98) {
		$CutLength = 98 - $MonitorName.Length
		$SerialLength = $MonitorDetails.SerialNumber.ToString().Length
		if ($CutLength -gt $SerialLength) {
			$CutLength = $SerialLength
		}
		$MonitorDetails.SerialNumber.substring($SerialLength - $CutLength, [System.Math]::Min($CutLength, $SerialLength))
	} else {
		$MonitorName += $MonitorDetails.SerialNumber
	}
	

	# Get Manufacturer / Model
	if (!$ITGManufacturerAndModel) {
		$ITGManufacturerAndModel = Get-ITGManufacturerAndModel $MonitorDetails
	}
	$ITGManufacturer = $ITGManufacturerAndModel.Manufacturer
	$ITGModel = $ITGManufacturerAndModel.Model

	# Warranty expiration
	$WarrantyDate = Get-WarrantyDate -MonitorDetails $MonitorDetails

	# End of Life
	$EndOfLife = Get-EOLDate -WarrantyDate $WarrantyDate

	# Related Device
	$RMMAttachedDevice = $RMM_Devices | Where-Object { $_.id -eq $MonitorDetails.AttachedDeviceID }
	$RelatedConfigs = Get-RelatedITGDevices -RMMDevice $RMMAttachedDevice

	# Notes
	if (($RelatedConfigs | Measure-Object).Count -gt 1) {
		$Notes = "Connected to devices: "
		foreach ($Config in $RelatedConfigs) {
			$Notes += "$($Config.attributes.name) (ID: $($Config.id)), "
		}
		$Notes = $Notes.TrimEnd(", ")
	} elseif ((($RelatedConfigs | Measure-Object).Count -eq 1)) {
		$Notes = "Connected to device: $($RelatedConfigs[0].attributes.name) (ID: $($RelatedConfigs[0].id))"
	} else {
		$Notes = "Connected to device: $($RMMAttachedDevice.hostname) (ID: 0)"
	}
	if ($MonitorDetails.DisplayType) {
		$Notes += "`nConnected by: $($MonitorDetails.DisplayType)"
	}
	if ($MonitorDetails.AttachedDeviceID) {
		$Notes += "`nRMM Device: $($MonitorDetails.AttachedDevice) (RMM ID: $($MonitorDetails.AttachedDeviceID))"
	}
	if ($MonitorDetails.YearOfManufacture) {
		$Notes += "`nManufacture Year: $($MonitorDetails.YearOfManufacture)"
	}

	$NewConfig = 
	@{
		type = 'configurations'
		attributes = @{
			name = $MonitorName
			"configuration-type-id" = $ITG_MonitorTypeID
			"configuration-status-id" = $ITG_ConfigStatusID
			"manufacturer-id" = if ($ITGManufacturer) { $ITGManufacturer.id } else { $null }
			"model-id" = if ($ITGModel) { $ITGModel.id } else { $null }
			"serial-number" = if ($MonitorDetails.SerialNumber) { $MonitorDetails.SerialNumber } else { $null }
			"warranty-expires-at" = if ($WarrantyDate) { $WarrantyDate } else { $null }
			"installed-by" = "RMM Monitor Integration"
			"notes" = $Notes
		}
	}

	if ($NewConfig) {
		try {
			$NewITGConfig = New-ITGlueConfigurations -organization_id $ITGOrg.id -data $NewConfig
		} catch {
			$NewITGConfig = $false
		}

		if ($NewITGConfig -and $NewITGConfig.data[0].id) {
			Write-Host "Added new monitor to ITG: $($NewConfig.attributes.name) (ID: $($NewITGConfig.data[0].id))" -ForegroundColor Green

			# Add the configuration interface 
			# (we do this here because the New-ITGConfigInterface command works with the 'port' field, when creating a new config it does not)
			$UpdatedRelationships = @{
				type = "configuration_interfaces"
				attributes = @{
					name = "$($MonitorDetails.DisplayType) Connection"
					port = if ($MonitorDetails.DisplayType -like "DisplayPort") { "DP" } else { $MonitorDetails.DisplayType }
					primary = $false
				}
			}
			$NewRelationships = New-ITGlueConfigurationInterfaces -conf_id $NewITGConfig.data[0].id -data $UpdatedRelationships

			# Attach the related device as a related item to the new config
			$RelatedItemsBody = @()
			foreach ($Config in $RelatedConfigs) {
				$RelatedItemsBody += @{
					type = "related_items"
					attributes = @{
						"destination-id" = $Config.id
						"destination-type" = "Configuration"
						"notes" = "Monitor Connection: $($MonitorDetails.DisplayType)"
					}
				}
			}
			if ($RelatedConfigs -and $RelatedItemsBody -and $RelatedItemsBody.count -gt 0) {
				$null = New-ITGlueRelatedItems -resource_type configurations -resource_id $NewITGConfig.data[0].id -data $RelatedItemsBody
			}

			# Add or attach to an End of Life asset
			$EOLAssets = Get-RelatedEOLAssets -ITGMonitor $NewITGConfig.data[0] -EOLDate $EndOfLife -ITGManufacturerAndModel $ITGManufacturerAndModel

			foreach ($EOLAsset in $EOLAssets) {
				if ($EOLAsset.attributes.traits.'configuration-s' -and $EOLAsset.attributes.traits.'configuration-s'.values -and $NewITGConfig.data[0].id -in $EOLAsset.attributes.traits.'configuration-s'.values.id) {
					# Device is already part of the EOL Asset, the eol asset was probably just created
					continue 
				}

				if ($EOLAsset.attributes.traits.'configuration-s' -and $EOLAsset.attributes.traits.'configuration-s'.values) {
					$UpdatedConfigurations = @($EOLAsset.attributes.traits.'configuration-s'.values.id)
					$UpdatedConfigurations += $NewITGConfig.data[0].id
					$UpdatedConfigurations = $UpdatedConfigurations | Sort-Object -Unique
				}
				$UpdatedEOLAsset = 
				@{
					type = 'flexible-assets'
					attributes = @{
						traits = @{
							description = $EOLAsset.attributes.traits.description
							"end-of-life" = $EOLAsset.attributes.traits.'end-of-life'
							"manufacturer-model" = $EOLAsset.attributes.traits.'manufacturer-model'
							"configuration-s" = @($UpdatedConfigurations)
							notes = $EOLAsset.attributes.traits.notes
						}
					}
				}
				$null = Set-ITGlueFlexibleAssets -id $EOLAsset.id -data $UpdatedEOLAsset
				$EOLAsset.attributes.traits.'configuration-s'[0].values += [PSCustomObject]@{ id = $ITGMonitor.id }
			}
		}
	}
}

# This function will update a monitor in ITG
function Update-ITGMonitor ($ITGMonitor, $MonitorDetails, $ITGManufacturerAndModel = $false)
{
	if (!$ITGMonitor -or !$MonitorDetails) {
		return;
	}

	$ITGOrg = $ITGMonitor.attributes.'organization-id'

	# Get Manufacturer / Model
	if (!$ITGManufacturerAndModel) {
		$ITGManufacturerAndModel = Get-ITGManufacturerAndModel $MonitorDetails
	}
	$ITGManufacturer = $ITGManufacturerAndModel.Manufacturer
	$ITGModel = $ITGManufacturerAndModel.Model

	# Warranty expiration
	$WarrantyDate = Get-WarrantyDate -MonitorDetails $MonitorDetails

	# End of Life
	$EndOfLife = Get-EOLDate -WarrantyDate $WarrantyDate

	# Get related devices
	$RMMAttachedDevice = $RMM_Devices | Where-Object { $_.id -eq $MonitorDetails.AttachedDeviceID }
	$RelatedConfigs = Get-RelatedITGDevices -RMMDevice $RMMAttachedDevice

	# Update connected devices in notes
	$OldNotes = $ITGMonitor.attributes.notes
	$NewNotes = $OldNotes -replace "Connected to devices?: (([\w\d\-]+) \(ID: ([\d]+)\),? ?)+(`n|\r\n|\n|<br>|<br ?\/>)?", ''
	$NewNotes = $NewNotes -replace "Connected by: ([\w]+)(`n|\r\n|\n|<br>|<br ?\/>)?", ''
	$NewNotes = $NewNotes -replace "RMM Device: ([\w\-\d \(\)\:]+)(`n|\r\n|\n|<br>|<br ?\/>)?", ''
	$NewNotes = $NewNotes -replace "Manufacturer Year: ([\-\d]+)(`n|\r\n|\n|<br>|<br ?\/>)?", ''
	$NewNotes = $NewNotes -replace "Last seen on: ([\-\d]+)(`n|\r\n|\n|<br>|<br ?\/>)?", ''
	$NewNotes = $NewNotes -replace "Last seen connected to \(ITG ID\): ([\d]+)(`n|\r\n|\n|<br>|<br ?\/>)?", ''

	if (($RelatedConfigs | Measure-Object).Count -gt 1) {
		$AddToNotes = "Connected to devices: "
		foreach ($Config in $RelatedConfigs) {
			$AddToNotes += "$($Config.attributes.name) (ID: $($Config.id)), "
		}
		$AddToNotes = $AddToNotes.TrimEnd(", ")
	} elseif ((($RelatedConfigs | Measure-Object).Count -eq 1)) {
		$AddToNotes = "Connected to device: $($RelatedConfigs[0].attributes.name) (ID: $($RelatedConfigs[0].id))"
	} else {
		$AddToNotes = "Connected to device: $($RMMAttachedDevice.hostname) (ID: 0)"
	}

	if ($MonitorDetails.DisplayType) {
		$AddToNotes += "`nConnected by: $($MonitorDetails.DisplayType)"
	}
	if ($MonitorDetails.AttachedDeviceID) {
		$AddToNotes += "`nRMM Device: $($MonitorDetails.AttachedDevice) (RMM ID: $($MonitorDetails.AttachedDeviceID))"
	}

	$AddLoc = $null
	if ($OldNotes -like "*Connected to devices: *") {
		$AddLoc = $OldNotes.IndexOf("Connected to devices:")
	} elseif ($OldNotes -like "*Connected to device: *") {
		$AddLoc = $OldNotes.IndexOf("Connected to device:")
	} elseif ($OldNotes -eq $NewNotes -and $OldNotes -like "*Manufacture Year: *") {
		$AddLoc = $OldNotes.IndexOf("Manufacture Year:")
		if ($AddLoc -ne 0) { $AddLoc-- }
	}

	if ([string]::IsNullOrEmpty($AddLoc)) {
		$NewNotes = $NewNotes.Trim() + "`n" + $AddToNotes
	} else {
		if ($AddLoc -eq 0) {
			$NewNotes = $AddToNotes + "`n" + $NewNotes.Trim()
		} else {
			$NewNotes_Temp = $NewNotes.Substring(0, $AddLoc).Trim() + "`n" + $AddToNotes + "`n"
			$NewNotes = $NewNotes_Temp + $NewNotes.Substring($AddLoc).Trim()
		}
	}
	$NewNotes = $NewNotes.Trim()
	
	$OldDisplayType = Get-ConfigDisplayType -Notes $OldNotes


	$UpdatedConfig =
	@{
		type = 'configurations'
		attributes = @{

		}
	}

	if ($ITGMonitor.attributes.'configuration-status-id' -ne $ITG_ConfigStatusID) {
		$UpdatedConfig.attributes.'configuration-status-id' = $ITG_ConfigStatusID
	}
	if ($ITGManufacturer -and $ITGMonitor.attributes.'manufacturer-id' -ne $ITGManufacturer.id) {
		$UpdatedConfig.attributes.'manufacturer-id' = $ITGManufacturer.id
	}
	if ($ITGModel -and $ITGMonitor.attributes.'model-id' -ne $ITGModel.id) {
		$UpdatedConfig.attributes.'model-id' = $ITGModel.id
	}
	if ($WarrantyDate -and (!$ITGMonitor.attributes.'warranty-expires-at' -or $ITGMonitor.attributes.'warranty-expires-at'.substring(0,4) -ne $WarrantyDate.substring(0,4))) {
		$UpdatedConfig.attributes.'warranty-expires-at' = $WarrantyDate
	}
	if (!$ITGMonitor.attributes.'serial-number' -and $MonitorDetails.SerialNumber) {
		$UpdatedConfig.attributes."serial-number" = $MonitorDetails.SerialNumber
	}
	if (!$ITGMonitor.attributes.'installed-by') {
		$UpdatedConfig.attributes."installed-by" = "RMM Monitor Integration"
	}
	if ($NewNotes) {
		$UpdatedConfig.attributes.notes = $NewNotes
	} else {
		$UpdatedConfig.attributes.notes = $ITGMonitor.attributes.notes
	}
	if ($ITGMonitor.attributes.notes -notlike "*Manufacture Year: *") {
		$UpdatedConfig.attributes.notes += "`nManufacture Year: $($MonitorDetails.YearOfManufacture)"
	}

	$UpdatesCompleted = $false
	if (!$ITGMonitor.relationships.'configuration-interfaces'.data -or $ITGMonitor.relationships.'configuration-interfaces'.data.count -lt 1) {
		# Add new
		$UpdatedRelationships = @{
			type = "configuration_interfaces"
			attributes = @{
				name = "$($MonitorDetails.DisplayType) Connection"
				port = if ($MonitorDetails.DisplayType -like "DisplayPort") { "DP" } else { $MonitorDetails.DisplayType }
				primary = $false
			}
		}
		$NewRelationships = New-ITGlueConfigurationInterfaces -conf_id $ITGMonitor.id -data $UpdatedRelationships
		if ($NewRelationships) {
			$UpdatesCompleted = $true
		}

	} elseif (!$OldDisplayType -or $OldDisplayType -ne $MonitorDetails.DisplayType) {
		# Remove old
		$OldRelationships = Get-ITGlueConfigurationInterfaces -conf_id $ITGMonitor.id
		if ($OldRelationships.data) {
			$OldRelationships = $OldRelationships.data
		}

		if ($OldRelationships) {
			if ($OldDisplayType) {
				$DisplayTypeConnections = $OldRelationships | Where-Object { $_.attributes.name -like "*Connection*" -and ($_.attributes.name -like "*$($OldDisplayType)*" -or $_.attributes.port -like $OldDisplayType) }
			} else {
				$DisplayTypeConnections = $OldRelationships | Where-Object { $_.attributes.name -like "*Connection" }
			}
			$UpdateConnections = @()
			foreach ($Connection in $DisplayTypeConnections) {
				$UpdateConnections += @{
					'type' = 'configuration_interfaces'
					'attributes' = @{
						'id' = $Connection.id
						'primary' = $false
						'name' = "$($MonitorDetails.DisplayType) Connection"
						'port' = if ($MonitorDetails.DisplayType -like "DisplayPort") { "DP" } else { $MonitorDetails.DisplayType }
					}
				}
				$OldRelationships = $OldRelationships | Where-Object { $_.id -ne $Connection.id }
			}

			if ($UpdateConnections) {
				$UpdatedInterfaces = Set-ITGlueConfigurationInterfaces -filter_id $ITGMonitor.id -data $UpdateConnections
				if ($UpdatedInterfaces) {
					$UpdatesCompleted = $true
				}
			}
		}
	}

	if ($UpdatedConfig -and ($UpdatedConfig.attributes -and $UpdatedConfig.attributes.Keys.Count -gt 0)) {
		$UpdatedConfig.attributes.archived = $false
		try {
			$UpdatedITGConfig = Set-ITGlueConfigurations -id $ITGMonitor.id -organization_id $ITGOrg -data $UpdatedConfig
		} catch {
			$UpdatedITGConfig = $false
		}
		if ($UpdatedITGConfig -and $UpdatedITGConfig.data[0].id) {
			$UpdatesCompleted = $true
		}
	}

	if ($UpdatesCompleted) {
		Write-Host "Updated monitor in ITG: $($ITGMonitor.attributes.name) (ID: $($ITGMonitor.id))" -ForegroundColor Cyan

		# Update the related items with the related device(s) if missing
		$ITGDetails = Get-ITGlueConfigurations -id $ITGMonitor.id -include 'related_items'
		if ($ITGDetails.included) {
			$Existing_RelatedItems = $ITGDetails.included
		}

		# Remove old
		if ($Existing_RelatedItems) {
			$MonitorConnections = $Existing_RelatedItems | Where-Object { $_.attributes.'asset-type' -eq 'configuration' -and $_.attributes.notes -like "Monitor Connection:*" }
			$RemoveRelated = @()
			foreach ($RelatedItem in $MonitorConnections) {
				if ($RelatedItem.attributes.'resource-id' -notin $RelatedConfigs.id -or $RelatedItem.attributes.notes -notlike "*$($MonitorDetails.DisplayType)*") {
					$RemoveRelated += @{
						'type' = 'related_items'
						'attributes' = @{
							'id' = $RelatedItem.id
						}
					}
					$Existing_RelatedItems = $Existing_RelatedItems | Where-Object { $_.id -ne $RelatedItem.id }
				}
			}

			if ($RemoveRelated) {
				$null = Remove-ITGlueRelatedItems -resource_type 'configurations' -resource_id $ITGMonitor.id -data $RemoveRelated
			}
		}

		# Add new
		$RelatedItemsBody = @()
		foreach ($Config in $RelatedConfigs) {
			if (!$Existing_RelatedItems -or ($Existing_RelatedItems | Where-Object { $_.attributes.'resource-id' -eq $Config.id -and $_.attributes.notes -like "Monitor Connection:*" } | Measure-Object).Count -eq 0) {
				$RelatedItemsBody += @{
					type = "related_items"
					attributes = @{
						"destination-id" = $Config.id
						"destination-type" = "Configuration"
						"notes" = "Monitor Connection: $($MonitorDetails.DisplayType)"
					}
				}
			}
		}
		if ($RelatedConfigs -and $RelatedItemsBody -and $RelatedItemsBody.count -gt 0) {
			$null = New-ITGlueRelatedItems -resource_type configurations -resource_id $ITGMonitor.id -data $RelatedItemsBody
		}

		# Add or attach to an End of Life asset
		$EOLAssets = Get-RelatedEOLAssets -ITGMonitor $ITGMonitor -EOLDate $EndOfLife -ITGManufacturerAndModel $ITGManufacturerAndModel

		foreach ($EOLAsset in $EOLAssets) {
			if ($EOLAsset.attributes.traits.'configuration-s' -and $EOLAsset.attributes.traits.'configuration-s'.values -and $ITGMonitor.id -in $EOLAsset.attributes.traits.'configuration-s'.values.id) {
				# Device is already part of the EOL Asset, skip it
				continue 
			}

			if ($EOLAsset.attributes.traits.'configuration-s' -and $EOLAsset.attributes.traits.'configuration-s'.values) {
				$UpdatedConfigurations = @($EOLAsset.attributes.traits.'configuration-s'.values.id)
				$UpdatedConfigurations += $ITGMonitor.id
				$UpdatedConfigurations = $UpdatedConfigurations | Sort-Object -Unique
			}
			$UpdatedEOLAsset = 
			@{
				type = 'flexible-assets'
				attributes = @{
					traits = @{
						description = $EOLAsset.attributes.traits.description
						"end-of-life" = $EOLAsset.attributes.traits.'end-of-life'
						"manufacturer-model" = $EOLAsset.attributes.traits.'manufacturer-model'
						"configuration-s" = @($UpdatedConfigurations)
						notes = $EOLAsset.attributes.traits.notes
					}
				}
			}
			$null = Set-ITGlueFlexibleAssets -id $EOLAsset.id -data $UpdatedEOLAsset
			$EOLAsset.attributes.traits.'configuration-s'[0].values += [PSCustomObject]@{ id = $ITGMonitor.id}
		}
	}
}

# This function will update an ITG monitor to disconnect it from all computers
function Update-ITGMonitor_Disconnected ($ITGMonitor)
{
	if (!$ITGMonitor) {
		return;
	}

	$ITGOrg = $ITGMonitor.attributes.'organization-id'

	$UpdatedConfig =
	@{
		type = 'configurations'
		attributes = @{

		}
	}

	# Clear connected devices in notes and add last seen (if haven't done so already)
	$OldNotes = $ITGMonitor.attributes.notes
	$NewNotes = $false
	if ($OldNotes -like "*Connected to device*") {
		$ExistingConnections = Get-ConfigIDsFromNotes -Notes $OldNotes
		$NewNotes = $OldNotes -replace "Connected to devices?: (([\w\d\-]+) \(ID: ([\d]+)\),? ?)+(`n|\r\n|\n|<br>|<br ?\/>)?", ''
		$NewNotes = $NewNotes -replace "Connected by: ([\w]+)(`n|\r\n|\n|<br>|<br ?\/>)?", ''
		$NewNotes = $NewNotes -replace "RMM Device: ([\w\-\d \(\)\:]+)(`n|\r\n|\n|<br>|<br ?\/>)?", ''

		$AddToNotes = "Last seen on: $(Get-Date -Format "yyyy-MM-dd")"

		if (($ExistingConnections | Measure-Object).Count -gt 0) {
			$AddToNotes += "`nLast seen connected to (ITG ID): "
			foreach ($ID in $ExistingConnections) {
				$AddToNotes += "$ID, "
			}
			$AddToNotes = $AddToNotes.TrimEnd(", ")
		}

		$AddLoc = $null
		if ($OldNotes -like "*Connected to devices: *") {
			$AddLoc = $OldNotes.IndexOf("Connected to devices:")
		} elseif ($OldNotes -like "*Connected to device: *") {
			$AddLoc = $OldNotes.IndexOf("Connected to device:")
		} elseif ($OldNotes -eq $NewNotes -and $OldNotes -like "*Manufacture Year: *") {
			$AddLoc = $OldNotes.IndexOf("Manufacture Year:")
			if ($AddLoc -ne 0) { $AddLoc-- }
		}

		if ([string]::IsNullOrEmpty($AddLoc)) {
			$NewNotes = $NewNotes.Trim() + "`n" + $AddToNotes
		} else {
			if ($AddLoc -eq 0) {
				$NewNotes = $AddToNotes + "`n" + $NewNotes.Trim()
			} else {
				$NewNotes_Temp = $NewNotes.Substring(0, $AddLoc).Trim() + "`n" + $AddToNotes + "`n"
				$NewNotes = $NewNotes_Temp + $NewNotes.Substring($AddLoc).Trim()
			}
		}
		$NewNotes = $NewNotes.Trim()

		if ($NewNotes -and $NewNotes -ne $OldNotes) {
			$UpdatedConfig.attributes.notes = $NewNotes
		}
	} elseif ($OldNotes -like "*Last seen on:*") {
		$Found = $OldNotes -match "Last seen on\: (\d\d\d\d\-\d\d\-\d\d)"
		if ($Found -and $Matches[1]) {
			$LastSeenDate = Get-Date $Matches[1]

			if ($LastSeenDate -and $LastSeenDate -is [DateTime]) {
				if (([DateTime]::Now - $LastSeenDate).TotalDays -gt 30) {
					$UpdatedConfig.attributes.archived = $true
				}
			}
		}
	}

	
	$UpdatesCompleted = $false
	if ($UpdatedConfig -and ($UpdatedConfig.attributes -and $UpdatedConfig.attributes.Keys.Count -gt 0)) {
		try {
			$UpdatedITGConfig = Set-ITGlueConfigurations -id $ITGMonitor.id -organization_id $ITGOrg -data $UpdatedConfig
		} catch {
			$UpdatedITGConfig = $false
		}
		if ($UpdatedITGConfig -and $UpdatedITGConfig.data[0].id) {
			$UpdatesCompleted = $true
		}
	}

	if ($UpdatesCompleted) {
		Write-Host "Updated monitor in ITG, CLEARED Connection: $($ITGMonitor.attributes.name) (ID: $($ITGMonitor.id))" -ForegroundColor Yellow

		# Update the related items with the related device(s) if missing
		$ITGDetails = Get-ITGlueConfigurations -id $ITGMonitor.id -include 'related_items'
		if ($ITGDetails.included) {
			$Existing_RelatedItems = $ITGDetails.included
		}

		# Remove old
		if ($Existing_RelatedItems) {
			$MonitorConnections = $Existing_RelatedItems | Where-Object { $_.attributes.'asset-type' -eq 'configuration' -and $_.attributes.notes -like "Monitor Connection:*" }
			$RemoveRelated = @()
			foreach ($RelatedItem in $MonitorConnections) {
				$RemoveRelated += @{
					'type' = 'related_items'
					'attributes' = @{
						'id' = $RelatedItem.id
					}
				}
				$Existing_RelatedItems = $Existing_RelatedItems | Where-Object { $_.id -ne $RelatedItem.id }
			}

			if ($RemoveRelated) {
				$null = Remove-ITGlueRelatedItems -resource_type 'configurations' -resource_id $ITGMonitor.id -data $RemoveRelated
			}
		}
	}
}


# Loop through RMM devices that have monitors and get a list of all the unique monitors (that have useable info, a lot have generic serials they use across many devices)
$i = 0
foreach ($Device in $DevicesWithMonitors) {
	$i++
	$DeviceDetails = [PSCustomObject]@{
		id = $i
		siteName = $Device.siteName
		hostname = $Device.hostname
		description = $Device.description
		monitors = @()
		portalUrl = $Device.portalUrl
	}

	$MonitorUpdatedPos = $Device.udf.$MonitorUDF.IndexOf(" |Up")
	if (!$MonitorUpdatedPos -or $MonitorUpdatedPos -le 0) {
		$MonitorUpdatedPos = $Device.udf.$MonitorUDF.IndexOf("} |") + 1
	}
	if (!$MonitorUpdatedPos -or $MonitorUpdatedPos -le 0) {
		$MonitorUpdatedPos = $Device.udf.$MonitorUDF.Length
	}
	try{
		$Monitors = $Device.udf.$MonitorUDF.Substring(0, $MonitorUpdatedPos).Trim() | ConvertFrom-Json
	} catch {
		continue
	}

	if ($Monitors) {
		foreach ($Monitor in @($Monitors)) {
			$i++
			if (!$Monitor.SN -or $Monitor.SN -eq 0 -or $Monitor.SN -eq "0" -or $Monitor.SN.length -le 2 -or $Monitor.SN -in $SNBlacklist -or $Monitor.SN -in $IgnoreSerials -or $Monitor.SN -like "123456789*") {
				continue
			}
			[Int64]$SNNumber = $null
			if ([Int64]::TryParse($Monitor.SN,[ref]$SNNumber) -and ($SNNumber -eq 0 -or $Monitor.SN -in $SNBlacklist -or $Monitor.SN -in $IgnoreSerials -or $Monitor.SN -like "123456789*")) {
				continue
			}
			$MonitorDetails = [PSCustomObject]@{
				id = $i
				Manufacturer = if ($Monitor.Mftr) { $Monitor.Mftr.Trim() } elseif ($Monitor.Man) { $Monitor.Man.Trim() } else { "" }
				Model = if ($Monitor.Mdl) { $Monitor.Mdl.Trim() } elseif ($Monitor.Mod) { $Monitor.Mod.Trim() } else { "" }
				SerialNumber = if ($Monitor.SN.Trim()) { $Monitor.SN.Trim() } else { 0 }
				DisplayType = if ($Monitor.Type) { $Monitor.Type.Trim() } else { "" }
				YearOfManufacture = if ($Monitor.ManYr) { $Monitor.ManYr } else { 0 }
			}
			if ($MonitorDetails.SN -eq 0 -or $MonitorDetails.Manufacturer -like "Acer" -or $MonitorDetails.Manufacturer -like "LTM" -or $MonitorDetails.Model -like "OptiPlex*" -or $MonitorDetails.Model -like "HDMI Extender" -or !$MonitorDetails.DisplayType -or $MonitorDetails.DisplayType -eq "NA" -or $MonitorDetails.DisplayType -eq "Internal") {
				continue
			}
			if ($MonitorDetails.Manufacturer -in $ManufacturerHash.Keys) {
				$MonitorDetails.Manufacturer = $ManufacturerHash.($MonitorDetails.Manufacturer)
			}
			$MonitorDetails.Manufacturer = Format-ManufacturerName $MonitorDetails.Manufacturer

			$DupeCheck = $AllMonitors | Where-Object { $_.Model -like $MonitorDetails.Model -and $_.SerialNumber -like $MonitorDetails.SerialNumber -and $_.YearOfManufacture -like $MonitorDetails.YearOfManufacture -and $_.RMMSiteID -eq $Device.siteId }
			if (($DupeCheck | Measure-Object).count -gt 0) {
				$DupeCheck_Device = $RMM_Devices | Where-Object { $_.id -in $DupeCheck.AttachedDeviceID }

				# Duplicate monitor, keep the one that was updated most recently (for monitor moves)
				$UDFArr = $Device.udf.$MonitorUDF.Split("|")
				if ($UDFArr[1]) {
					$Updated = $UDFArr[1]
					$Updated = Get-Date $Updated.replace("Updated: ", "")
				} elseif ($Device.lastSeen) {
					$Updated = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliseconds($Device.lastSeen))
				} else {
					$Updated = $false
				}

				$Skip = $false
				$DupeCheck_Device | ForEach-Object {
					$DupeUDFArr = $_.udf.$MonitorUDF.Split("|")
					if ($DupeUDFArr[1]) {
						$DupeUpdated = $DupeUDFArr[1]
						$DupeUpdated = Get-Date $DupeUpdated.replace("Updated: ", "")
					} elseif ($_.lastSeen) {
						$DupeUpdated = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliseconds($_.lastSeen))
					} else {
						$DupeUpdated = $false
					}

					if ($Updated -gt $DupeUpdated) {
						# Found a dupe that was updated before this monitor, remove it
						$AllMonitors = $AllMonitors | Where-Object { $_.id -ne $DupeCheck.id }
					} else {
						$Skip = $true
					}
				}

				# Duplicate monitor that was last updated before the already existing dupe, skip
				if ($Skip) {
					continue
				}
			}

			$DeviceDetails.monitors += $MonitorDetails

			$MonitorDetails | Add-Member -MemberType NoteProperty -Name "AttachedDevice" -Value $Device.hostname
			$MonitorDetails | Add-Member -MemberType NoteProperty -Name "AttachedDeviceID" -Value $Device.id
			$MonitorDetails | Add-Member -MemberType NoteProperty -Name "RMMSiteID" -Value $Device.siteId
			$AllMonitors += $MonitorDetails
		}
	}

	$DevicesWithMonitors_Friendly += $DeviceDetails
}

#$AllMonitors | Export-Csv -Path "C:\Temp\AllRMMMonitors.csv" -NoTypeInformation
$AllMonitorsCount = ($AllMonitors | Measure-Object).Count
$ii = 0

# Update and add monitors
foreach ($Monitor in $AllMonitors) {
	$ii++
	[int]$PercentComplete = ($ii / $AllMonitorsCount * 100)
	Write-Progress -Activity "Updating/adding Monitors" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "% ($($Monitor.Model) - $($Monitor.SerialNumber) on $($Monitor.AttachedDevice)))")

	$ITG_MatchedMonitors = $ITG_Monitors | Where-Object { $_.attributes.'serial-number' -and $_.attributes.'serial-number'.Trim() -like $Monitor.SerialNumber }
	$ITGManufacturerAndModel = Get-ITGManufacturerAndModel $Monitor

	# Narrow down if more than 1 monitor is found
	if (($ITG_MatchedMonitors | Measure-Object).Count -gt 1) {
		if ($Monitor.RMMSiteID -in $MatchedSites.Keys) {
			$ITG_MatchedMonitors_Filtered = $ITG_MatchedMonitors | Where-Object { 
				$_.attributes.'organization-id' -like $MatchedSites[$Monitor.RMMSiteID].id
			}
			if (($ITG_MatchedMonitors_Filtered | Measure-Object).Count -gt 0) {
				$ITG_MatchedMonitors = $ITG_MatchedMonitors_Filtered
			}
		}

		if (($ITG_MatchedMonitors | Measure-Object).Count -gt 1) {
			$ITG_MatchedMonitors_Filtered = $ITG_MatchedMonitors | Where-Object { 
				($_.attributes.'manufacturer-name' -like $Monitor.Manufacturer -and
				$_.attributes.'model-name' -like $Monitor.Model) -or
				($_.attributes.'manufacturer-id' -like $ITGManufacturerAndModel.Manufacturer.id -and
				$_.attributes.'model-id' -like $ITGManufacturerAndModel.Model.id)
			}
			if (($ITG_MatchedMonitors_Filtered | Measure-Object).Count -gt 0) {
				$ITG_MatchedMonitors = $ITG_MatchedMonitors_Filtered
			}
		}

		if (($ITG_MatchedMonitors | Measure-Object).Count -gt 1) {
			$ITG_MatchedMonitors_Filtered = $ITG_MatchedMonitors | Where-Object { 
				$_.attributes.'notes' -like "*Manufacture Year: $($Monitor.YearOfManufacture)*"
			}
			if (($ITG_MatchedMonitors_Filtered | Measure-Object).Count -gt 0) {
				$ITG_MatchedMonitors = $ITG_MatchedMonitors_Filtered
			}
		}

		if (($ITG_MatchedMonitors | Measure-Object).Count -gt 1) {
			$ITG_MatchedMonitors_Filtered = $ITG_MatchedMonitors | Where-Object { 
				$_.attributes.'notes' -like "*$($Monitor.AttachedDevice) (*"
			}
			if (($ITG_MatchedMonitors_Filtered | Measure-Object).Count -gt 0) {
				$ITG_MatchedMonitors = $ITG_MatchedMonitors_Filtered
			}
		}
	}

	# Update / Create in ITG
	if (($ITG_MatchedMonitors | Measure-Object).Count -gt 0) {
		# Update existing monitors in ITG if found, but only if it is needing updates
		foreach ($ITG_MatchedMonitor in $ITG_MatchedMonitors) {
			$MatchedITGMonitors += $ITG_MatchedMonitor.id

			$UpdateRequired = $false
			while ($UpdateRequired -eq $false) {
				if ($ITG_MatchedMonitor.attributes.'configuration-status-id' -ne $ITG_ConfigStatusID) {
					$UpdateRequired = $true
					break
				}
				if ($ITGManufacturerAndModel.Manufacturer -and !$ITG_MatchedMonitor.attributes.'manufacturer-id') {
					$UpdateRequired = $true
					break
				}
				if ($ITGManufacturerAndModel.Model -and !$ITG_MatchedMonitor.attributes.'model-id') {
					$UpdateRequired = $true
					break
				}
				if ($WarrantyDate -and !$ITG_MatchedMonitor.attributes.'warranty-expires-at') {
					$UpdateRequired = $true
					break
				}
				if (!$ITG_MatchedMonitor.attributes.'serial-number' -and $Monitor.SerialNumber) {
					$UpdateRequired = $true
					break
				}
				if (!$ITG_MatchedMonitor.attributes.'installed-by' -or $ITG_MatchedMonitor.attributes.'installed-by' -notlike "*RMM Monitor Integration*") {
					$UpdateRequired = $true
					break
				}
				if ($ITG_MatchedMonitor.attributes.notes -notlike "*Manufacture Year: *" -or $ITG_MatchedMonitor.attributes.notes -notlike "*$($Monitor.YearOfManufacture)*") {
					$UpdateRequired = $true
					break
				}
				if ($ITG_MatchedMonitor.attributes.notes -notlike "*RMM ID: $($Monitor.AttachedDeviceID)*" -or $ITG_MatchedMonitor.attributes.notes -notlike "*RMM Device: $($Monitor.AttachedDevice)*") {
					$UpdateRequired = $true
					break
				}
				if ($ITG_MatchedMonitor.attributes.notes -notlike "*Connected by: $($Monitor.DisplayType)*") {
					$UpdateRequired = $true
					break
				}
				if (($ITG_MonitorEOLs | Where-Object { $ITG_MatchedMonitor.id -in $_.attributes.traits.'configuration-s'.values.id } | Measure-Object).count -lt 1) {
					$UpdateRequired = $true
					break
				}

				break;
			}

			if ($UpdateRequired) {
				Update-ITGMonitor -MonitorDetails $Monitor -ITGMonitor $ITG_MatchedMonitor -ITGManufacturerAndModel $ITGManufacturerAndModel
			}
		}
	} else {
		New-ITGMonitor -MonitorDetails $Monitor -ITGManufacturerAndModel $ITGManufacturerAndModel
	}
}
Write-Progress -Activity "Updating/adding Monitors" -Status "Ready" -Completed

# Update monitors with no connection to remove connections, add last seen, and archive ones not seen in > 1 month
$ITGMonitors_NotFound = $ITG_Monitors | Where-Object { $_.id -notin $MatchedITGMonitors }
$ITGMonitors_ToArchive = $ITGMonitors_NotFound | Where-Object { $_.attributes.'installed-by' -and $_.attributes.'installed-by'.Trim() -like "RMM Monitor Integration" }

$ArchiveMonitorsCount = ($ITGMonitors_ToArchive | Measure-Object).Count
$ii = 0
foreach ($ArchiveMonitor in $ITGMonitors_ToArchive) {
	$ii++
	[int]$PercentComplete = ($ii / $ArchiveMonitorsCount * 100)
	Write-Progress -Activity "Clearing connections for unseen Monitors" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "% ($($ArchiveMonitor.attributes.name))")

	Update-ITGMonitor_Disconnected -ITGMonitor $ArchiveMonitor
}
Write-Progress -Activity "Clearing connections for unseen Monitors" -Status "Ready" -Completed
