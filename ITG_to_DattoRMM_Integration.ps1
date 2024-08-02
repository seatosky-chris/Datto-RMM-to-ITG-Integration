###
# File: \ITG_to_DattoRMM_Integration.ps1
# Project: RMM Integration
# Created Date: Monday, November 7th 2022, 4:13:43 pm
# Author: Chris Jantzen
# -----
# Last Modified: Fri Aug 02 2024
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2023 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
# 2024-08-02	CJ	Added updating of operating system on ITG devices
# 2024-04-02	CJ	Fixing constant archival of new SNMP devices
# 2024-02-16	CJ	Improved duplicate check for new network devices that may not have a SN or Mac address
# 2024-02-16	CJ	Implemented configuration archiving
# 2023-10-31	CJ	Implemented logging
# 2023-10-27	CJ	Upgraded Get-RMMDeviceDetails function to support esxi hosts and printers
###

param(
	$FullCheck = $false,
	$StepThroughUpdates = $false
)

. "$PSScriptRoot\Config.ps1" # Config

# Fixed SSL if necessary
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Enum]::ToObject([Net.SecurityProtocolType], 3072)
	Write-Output "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

# Setup logging
If (Get-Module -ListAvailable -Name "PSFramework") {Import-module PSFramework} Else { install-module PSFramework -Force; import-module PSFramework}
$logFile = Join-Path -path "$PSScriptRoot\Logs" -ChildPath "log-itg_to_rmm-$(Get-date -f 'yyyyMMddHHmmss').txt";
Set-PSFLoggingProvider -Name logfile -FilePath $logFile -Enabled $true;
Write-PSFMessage -Level Verbose -Message "Starting device matching script."

Function Test-IfAlreadyRunning {
    <#
    .SYNOPSIS
        Kills CURRENT instance if this script already running.
    .DESCRIPTION
        Kills CURRENT instance if this script already running.
        Call this function VERY early in your script.
        If it sees itself already running, it exits.

        Uses WMI because any other methods because we need the commandline 
    .PARAMETER ScriptName
        Name of this script
        Use the following line *OUTSIDE* of this function to get it automatically
        $ScriptName = $MyInvocation.MyCommand.Name
    .EXAMPLE
        $ScriptName = $MyInvocation.MyCommand.Name
        Test-IfAlreadyRunning -ScriptName $ScriptName
    .NOTES
        $PID is a Built-in Variable for the current script''s Process ID number
    .LINK
    #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[String]$ScriptName
	)
	#Get array of all powershell scripts currently running
	$PsScriptsRunning = get-wmiobject win32_process | where{$_.processname -eq 'powershell.exe'} | select-object commandline,ProcessId

	#Get name of current script
	#$ScriptName = $MyInvocation.MyCommand.Name #NO! This gets name of *THIS FUNCTION*

	#enumerate each element of array and compare
	ForEach ($PsCmdLine in $PsScriptsRunning){
		[Int32]$OtherPID = $PsCmdLine.ProcessId
		[String]$OtherCmdLine = $PsCmdLine.commandline
		#Are other instances of this script already running?
		If (($OtherCmdLine -match $ScriptName) -And ($OtherPID -ne $PID) ){
			Write-PSFMessage -Level Error -Message "PID [$OtherPID] is already running this script [$ScriptName]"
			Write-PSFMessage -Level Error -Message "Exiting this instance. (PID=[$PID])..."
			Start-Sleep -Second 7
			Exit
		}
	}
}

# If already running, stop
$ScriptName = $MyInvocation.MyCommand.Name 
Test-IfAlreadyRunning -ScriptName $ScriptName

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

# Setup status config value if not already set
$UpdatedConfig = $false
if (!$ITG_ConfigStatusID) {
	$ConfigStatuses = Get-ITGlueConfigurationStatuses
	if ($ConfigStatuses -and $ConfigStatuses.data -and ($ConfigStatuses.data | Measure-Object).Count -gt 0) {
		Write-Host "`$ITG_ConfigStatusID has not been set. Please select one of the following statuses to use for new configurations:" -ForegroundColor Yellow
		$i = 0
		foreach ($Status in $ConfigStatuses.data) {
			$i++
			Write-Host "$i - $($Status.attributes.name) (ID: $($Status.id))"
		}
		$StatusSelection = Read-Host "Choose an option, 1-$($i)"

		if ($StatusSelection -and $StatusSelection -in @(1..$i)) {
			$NewConfigStatus = $ConfigStatuses.data[$StatusSelection-1]
			if ($NewConfigStatus) {
				$ConfigFilePath = "$PSScriptRoot\Config.ps1"
				$ConfigFile = Get-Content $ConfigFilePath
				$ConfigFile = $ConfigFile.replace('$ITG_ConfigStatusID = $false', ('$ITG_ConfigStatusID = ' + $NewConfigStatus.id))
				$ConfigFile | Set-Content $ConfigFilePath
				$UpdatedConfig = $true
			} else {
				Write-Host "Could not find the select Config Status and could not set the configuration value. Please try running the script again or set the value manually. Exiting..." -ForegroundColor Red
				$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
				exit
			}
		} else {
			Write-Host "An incorrect Config Status selection was made. Could not set the configuration value. Please try running the script again or set the value manually. Exiting..." -ForegroundColor Red
			$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
			exit
		}
	} else {
		Write-Host "`$ITG_ConfigStatusID has not been set and no Statuses were found in ITG. Please fix this then try again. Exiting..." -ForegroundColor Red
		$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
		exit
	}
}

if ($UpdatedConfig) {
	# Reload the config if updated
	. "$PSScriptRoot\Config.ps1"
}

# Get auxilary ITG data
$global:ITGManufacturers = Get-ITGlueManufacturers -page_size 1000
if (!$global:ITGManufacturers -or $global:ITGManufacturers.Error) {
	Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing manufacturers from ITG. Exiting..."
	Write-PSFMessage -Level Error -Message $global:ITGManufacturers.Error
	exit 1
}
$global:ITGManufacturers = ($global:ITGManufacturers).data

$ITGOperatingSystems = Get-ITGlueOperatingSystems -page_size 1000
if (!$ITGOperatingSystems -or $ITGOperatingSystems.Error) {
	Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing operating systems from ITG. Exiting..."
	Write-PSFMessage -Level Error -Message $ITGOperatingSystems.Error
	exit 1
}
$ITGOperatingSystems = ($ITGOperatingSystems).data

$global:ITGModels = Get-ITGlueModels -page_size "1000"
$i = 1
while ($global:ITGModels.links.next) {
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
	$global:ITGModels.data += $Models_Next.data
	$global:ITGModels.links = $Models_Next.links
	Start-Sleep -Seconds 1
}
$global:ITGModels = $global:ITGModels.data

Write-PSFMessage -Level Verbose -Message "Grabbed $($global:ITGManufacturers.count) manufacturers, $($global:ITGModels.count) models, and $($ITGOperatingSystems.count) OS's from ITG."

if (!$global:ITGModels -or !$global:ITGManufacturers -or !$ITGOperatingSystems) {
	Write-PSFMessage -Level Error -Message "There were issues getting the Models, Manufacturers, and Operating Systems from ITG. Exiting..."
	exit 1
}

$ITGPasswords = @{} # We'll grab these later if we need them

# Check when a full check last ran, if > 1 week ago, run a full check (and it is currently the middle of the night [11PM - 5AM])
$FullCheckLastRun = $false
if (Test-Path -Path ($PSScriptRoot + "\FullCheckLastRun.txt")) {
	$FullCheckLastRun = Get-Content -Path ($PSScriptRoot + "\FullCheckLastRun.txt") -Raw
	if ([string]$FullCheckLastRun -as [DateTime])   {
		$FullCheckLastRun = Get-Date $FullCheckLastRun
	}
}

if ((!$FullCheckLastRun -or $FullCheckLastRun -lt (Get-Date).AddDays(-7)) -and ((Get-Date).Hour -gt 23 -or (Get-Date).Hour -lt 5)) {
	Write-PSFMessage -Level Verbose -Message "Performing a full check due to time of last run."
	$FullCheck = $true
}

# Loop through all RMM companies and match to related ITG company
$RMM_Sites = Get-DrmmAccountSites | Sort-Object -Property Name
$ITG_Sites = Get-ITGlueOrganizations -page_size 1000
$MatchedSites = @{}
Write-PSFMessage -Level Verbose -Message "Found $($RMM_Sites.count) RMM Sites and $($ITG_Sites.count) ITG Sites."

if (!$ITG_Sites -or $ITG_Sites.Error) {
	Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing organizations from ITG. Exiting..."
	Write-PSFMessage -Level Error -Message $ITG_Sites.Error
	exit 1
}

if ($ITG_Sites -and $ITG_Sites.data) {
	foreach ($RMMSite in $RMM_Sites) {
		if ($RMMSite.name -in @("Deleted Devices", "Managed", "OnDemand")) {
			Write-PSFMessage -Level Warning -Message "Skipped the RMM site '$($RMMSite.name)'"
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
			Write-PSFMessage -Level Verbose -Message "Matched '$($RMMSite.name)' (RMM) to $($ITGSite.attributes.name) (ITG)."
		} else {
			Write-PSFMessage -Level Error -Message "Could not find the RMM site '$($RMMSite.name)' in ITG."
		}
	}
}

# Function to convert imported UTC date/times to local time for easier comparisons
function Convert-UTCtoLocal {
	param( [parameter(Mandatory=$true)] [String] $UTCTime )
	$TZ = [System.TimeZoneInfo]::Local
	$LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
	return $LocalTime
}

# Get RMM Devices for all organizations
$RMM_Devices = Get-DrmmAccountDevices | Sort-Object -property @{Expression='sitename'; Ascending=$true}, @{Expression='description'; Ascending=$true} | Where-Object {$_.sitename -ne "Deleted Devices"}

# Get a list of SNMP devices added recently that may not have pulled all info yet
$RMM_Devices_RecentlyAuditedSNMP = $RMM_Devices | Where-Object {
	$CreationDate = Convert-UTCtoLocal(([datetime]'1/1/1970').AddMilliseconds($_.creationDate));
	$LastAuditDate = Convert-UTCtoLocal(([datetime]'1/1/1970').AddMilliseconds($_.lastAuditDate));
	$_.snmpEnabled -and
	(($_.online -and $CreationDate -gt (Get-Date).AddMinutes(-15)) -or
	((!$_.online -or $LastAuditDate -lt $CreationDate.AddMinutes(15)) -and $CreationDate -gt (Get-Date).AddDays(-1)))
}
if ($RMM_Devices_RecentlyAuditedSNMP) {
	$RMM_Devices_RecentlyAuditedSNMP = @($RMM_Devices_RecentlyAuditedSNMP.uid)
} else {
	$RMM_Devices_RecentlyAuditedSNMP = @()
}
Write-PSFMessage -Level Verbose -Message "Grabbed $($RMM_Devices.count) RMM Devices."

# The below function will add more details to the RMM device (serial number, manufacturer, model, etc)
function Get-RMMDeviceDetails ($Device)
{
	if ($Device -and "serialNumber" -notin $Device.PSObject.Properties.Name -and $Device.deviceClass -in @("device", "esxihost", "printer")) {
		$Device | Add-Member -NotePropertyName serialNumber -NotePropertyValue $false
		$Device | Add-Member -NotePropertyName manufacturer -NotePropertyValue $false
		$Device | Add-Member -NotePropertyName model -NotePropertyValue $false
		$Device | Add-Member -NotePropertyName Nics -NotePropertyValue @()
		$Device | Add-Member -NotePropertyName url -NotePropertyValue $false

		if ($Device.deviceClass -eq "device") {
			$AuditDevice = Get-DrmmAuditDevice $Device.uid
			if ($AuditDevice) {
				$Device.serialNumber = $AuditDevice.bios.serialNumber
				$Device.manufacturer = $AuditDevice.systemInfo.manufacturer
				$Device.model = $AuditDevice.systemInfo.model
				$Device.Nics = @($AuditDevice.nics | Where-Object { $Nic = $_; $_.macAddress -and ($NetworkAdapterBlacklist | Where-Object { $Nic.instance -like $_ }).Count -eq 0 } | Select-Object instance, ipv4, macAddress)
				$Device.url = $AuditDevice.portalUrl
			}
		} elseif ($Device.deviceClass -eq "esxihost") {
			$AuditDevice = Get-DrmmAuditESXi $Device.uid
			if ($AuditDevice) {
				$Device.serialNumber = $AuditDevice.systemInfo.serviceTag
				$Device.manufacturer = $AuditDevice.systemInfo.manufacturer
				$Device.model = $AuditDevice.systemInfo.model
				$Device.Nics = @($AuditDevice.nics | Where-Object { $Nic = $_; $_.macAddress -and ($NetworkAdapterBlacklist | Where-Object { $Nic.instance -like $_ }).Count -eq 0 } | Select-Object name, ipv4, macAddress)
				$Device.url = $AuditDevice.portalUrl
			}
		} elseif ($Device.deviceClass -eq "printer") {
			$AuditDevice = Get-DrmmAuditPrinter $Device.uid
			if ($AuditDevice) {
				if ($AuditDevice.snmpInfo.snmpSerial) {
					$Device.serialNumber = $AuditDevice.snmpInfo.snmpSerial
				}
				$Device.manufacturer = $AuditDevice.systemInfo.manufacturer
				$Device.model = $AuditDevice.systemInfo.model
				$Device.Nics = @()
				$Device.url = $AuditDevice.portalUrl
			}
		}
	}
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

# Attempts to get the ITG OS from the RMMDevice OS
function Get-ITGOperatingSystem {
	<#
        .SYNOPSIS
            Tries to determine the IT Glue Operating System value from the RMM Operating System value.
        
        .DESCRIPTION
            Tries to determine the IT Glue Operating System value from the RMM Operating System value. It uses a variety of matching techniques to find the best match. If it can't find a match this function will return $false.

        .PARAMETER RMMDevice
            The RMM Device from the RMM API

        .EXAMPLE
            PS C:\> Get-ITGOperatingSystem -RMMDevice $RMMDevice

            Windows 10 Pro
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([int])]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [PSCustomObject]$RMMDevice
    )

	# a hashtable matching the ITG platform-name to a 'like' search string (can be an array for multiple searches)
	# In order of priority
	$OSCategoryMatching = @{
		Linux = "Linux*"
		macOS = @("macOS *", "Mac OS *")
		Windows = @("Microsoft Windows *", "Windows *")
		Microsoft = "Microsoft Hyper*"
		VMWare = "VMware *"
		Android = "Android *"
		Citrix = "Citrix *"
		iOS = "iOS *"
		Unix = @("Unix *", "Solaris *", "OpenBSD*", "FreeBSD*")
		SonicOS = "SonicOS *"
	}

	if (!$RMMDevice.operatingSystem) {
		return $false
	}

	$ITGOperatingSystems_Filtered = $false
	$OSPlatform = $false
	foreach ($OSCategory in $OSCategoryMatching.GetEnumerator()) {
		if ($OSCategory.Value  -isnot [array]) {
			$OSCategory.Value = @($OSCategory.Value)
		}

		foreach ($CategorySearch in $OSCategory.Value) {
			if ($RMMDevice.operatingSystem -like $CategorySearch) {
				$ITGOperatingSystems_Filtered = $ITGOperatingSystems | Where-Object { $_.attributes.'platform-name' -eq $OSCategory.Name }
				$OSPlatform = $OSCategory.Name
				break
			}
		}

		if ($ITGOperatingSystems_Filtered) {
			break
		}
	}

	if (!$OSPlatform) {
		return $false
	}

	if ($OSPlatform -eq "Windows") {
		# If Windows, filter down to the main OS type (e.g. Windows 10, 7, Server 2008, etc)
		$MainOSTypeFound = $RMMDevice.operatingSystem.Trim() -match "Microsoft Windows ((Storage |Web )?Server )?(\d+\.?\d*)"
		if ($MainOSTypeFound) {
			$MainOSType = $Matches[0]
			$MainOSType = $MainOSType -replace "Microsoft ", ""
			$ITGOperatingSystems_Filtered = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -like ($MainOSType + "*") -or $_.attributes.name -like "*(Other)"  }
		}
	}

	# Now try to match the OS name
	$CleanRMMOS = $RMMDevice.operatingSystem.Trim()
	$ITGOperatingSystem = $false
	if ($OSPlatform -in ("Windows", "Microsoft")) {
		$CleanRMMOS = ($CleanRMMOS -replace "([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+)?", "").Trim()
		if ($OSPlatform -eq "Windows") {
			$CleanRMMOS = $CleanRMMOS -replace "Microsoft ", ""
		}

		if ($CleanRMMOS -notin $ITGOperatingSystems_Filtered.attributes.name) {
			$CleanRMMOS = $CleanRMMOS -replace " for .+$", ""
			$CleanRMMOS = $CleanRMMOS -replace " Home$", ""
		}

		if ($CleanRMMOS -notin $ITGOperatingSystems_Filtered.attributes.name) {
			# Attempt removing the last word as ITG has catch all categories for anything below Windows 10
			$CleanRMMOS_Temp = $CleanRMMOS -replace " \w+$", ""
			if ($CleanRMMOS_Temp -in $ITGOperatingSystems_Filtered.attributes.name) {
				$ITGOperatingSystem = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -eq $CleanRMMOS_Temp }
			}
		}

	} elseif ($OSPlatform -eq "VMWare") {
		$CleanRMMOS = ($CleanRMMOS -replace " build\d+( \d+\.\d+.\d)?$", "").Trim()
		$CleanRMMOS = ($CleanRMMOS -replace "((\d+\.\d+)(.\d))?$", "`$2").Trim()

	} elseif ($OSPlatform -eq "macOS") {
		$CleanRMMOS = ($CleanRMMOS -replace "((\d+\.\d+)(.\d))?$", "`$2").Trim()

		if ($CleanRMMOS -notin $ITGOperatingSystems_Filtered.attributes.name) {
			$ITGOperatingSystem = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -like ($CleanRMMOS + "*") }
			if (!$ITGOperatingSystem) {
				if ($CleanRMMOS -like "Mac OS X*") {
					$CleanRMMOS_Temp = $CleanRMMOS -replace "^Mac OS X", "macOS"
				} else {
					$CleanRMMOS_Temp = $CleanRMMOS -replace "^macOS", "Mac OS X"
				}
				if ($CleanRMMOS_Temp -in $ITGOperatingSystems_Filtered.attributes.name) {
					$CleanRMMOS = $CleanRMMOS_Temp
				} else {
					$ITGOperatingSystem = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -like ($CleanRMMOS_Temp + "*") }
				}
			}
		}

		if (!$ITGOperatingSystem) {
			$CleanRMMOS = ($CleanRMMOS -replace "(\d+\.)(\d)?$", ("`$1")).Trim() + "0"
			if ($CleanRMMOS -notin $ITGOperatingSystems_Filtered.attributes.name) {
				$ITGOperatingSystem = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -like ($CleanRMMOS + "*") }
			}
		}

	} elseif ($OSPlatform -eq "Linux") {
		$CleanRMMOS = $CleanRMMOS -replace "^Linux ", ""
		$CleanRMMOS = ($CleanRMMOS -replace "((\d+\.\d+)(.\d))?", "`$2").Trim()
		
		if ($CleanRMMOS -notlike "SUSE*") {
			$CleanRMMOS = $CleanRMMOS -replace "Linux ", ""
		}
		if ($CleanRMMOS -notin $ITGOperatingSystems_Filtered.attributes.name) {
			$CleanRMMOS = $CleanRMMOS -replace "( \(\w+\))$", ""
		}
		$CleanRMMOS = $CleanRMMOS.Trim()

		if ($CleanRMMOS -eq "Linux") {
			$ITGOperatingSystem = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -eq "Linux (Other)" }
		}
	}

	if (!$ITGOperatingSystem -and $CleanRMMOS -in $ITGOperatingSystems_Filtered.attributes.name) {
		$ITGOperatingSystem = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -eq $CleanRMMOS }
	} 

	if (!$ITGOperatingSystem) {
		$ITGOperatingSystem = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -like ($CleanRMMOS + "*") }
		if (($ITGOperatingSystem | Measure-Object).Count -gt 1) {
			$ITGOperatingSystems_Filtered = $ITGOperatingSystem
			$ITGOperatingSystem = $false
		}
	}
	
	if (!$ITGOperatingSystem) {
		$BestITGOS = $false
		$BestScore = $false
		foreach ($ITGOS in $ITGOperatingSystems_Filtered) {
			$Distance = Measure-StringDistance -Source $ITGOS.attributes.name -Compare $CleanRMMOS
			if ($BestScore -eq $false -or $Distance -lt $BestScore) {
				$BestScore = $Distance
				$BestITGOS = $ITGOS
			} elseif ($Distance -eq $BestScore) {
				$Equality_Existing = Measure-PartsEquality -Source $BestITGOS.attributes.name -Compare $CleanRMMOS
				$Equality_New = Measure-PartsEquality -Source $ITGOS.attributes.name -Compare $CleanRMMOS
				if ($Equality_New -gt $Equality_Existing) {	
					$BestScore = $Distance
					$BestITGOS = $ITGOS
				}
				$WriteEquality = $true
			}
		}

		$OtherOSOption = $ITGOperatingSystems_Filtered | Where-Object { $_.attributes.name -like "*(Other)" }
		$MaxThreshold = [math]::Round($CleanRMMOS.Length * 0.5)
		if ($BestScore -gt $MaxThreshold) {
			$ITGOperatingSystem = $OtherOSOption
		} elseif ($OtherOSOption) {
			$ITGOperatingSystem = $BestITGOS
		}
	}

	return $ITGOperatingSystem
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

# Gets the related ITG Manufacturer and Model for an RMM Device
# Returns a hashtable, @{Manufacturer = $ITGManufacturer; Model = $ITGModel}
function Get-ITGManufacturerAndModel ($RMMDevice) {
	$Manufacturer = $RMMDevice.manufacturer
	$Model = $RMMDevice.model.Trim()

	if ($Manufacturer) {
		$Manufacturer = Format-ManufacturerName -Manufacturer $Manufacturer
		$ITGManufacturer = $false
		$ITGModel = $false

		if ($Model) {
			$ITGModel = $global:ITGModels | Where-Object { $_.attributes.name -like $Model -and $_.attributes.'manufacturer-name' -like $Manufacturer }
			if (!$ITGModel) {
				$ITGModel = $global:ITGModels | Where-Object { $_.attributes.name -like $Model -and $_.attributes.'manufacturer-name' -like $RMMDevice.manufacturer.Trim() }
				if ($ITGModel) {
					$Manufacturer = $RMMDevice.manufacturer.Trim()
				}
			}
			if (!$ITGModel -and $Model -like "$($Manufacturer)*") {
				$Model = $Model -replace "$($Manufacturer)", ""
				$Model = $Model.Trim()
				$ITGModel = $global:ITGModels | Where-Object { $_.attributes.name -like $Model -and $_.attributes.'manufacturer-name' -like $Manufacturer }
			}

			if (($ITGModel | Measure-Object).Count -gt 1 -and ($ITGModel | Where-Object { $_.attributes.name -ceq $Model } | Measure-Object).Count -gt 0) {
				$ITGModel = $ITGModel | Where-Object { $_.attributes.name -ceq $Model }
			}
			if (($ITGModel | Measure-Object).Count -gt 1) {
				$ITGModel = $ITGModel | Select-Object -First 1
			}
		}

		if ($ITGModel -and $ITGModel.attributes.'manufacturer-id') {
			$ITGManufacturer = $global:ITGManufacturers | Where-Object { $_.id -eq $ITGModel.attributes.'manufacturer-id' }
		}
		if (!$ITGManufacturer) {
			$ITGManufacturer = $global:ITGManufacturers | Where-Object { $_.attributes.name -like $Manufacturer }
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

function Get-AssetTag ($RMMDevice) {
	$AssetTag = $null
	if ($RMMDevice.hostname -match "-(\d\d\d\d?)$") {
		if ($Matches[1]) {
			$AssetTag = $Matches[1]
		}
	}
	return $AssetTag
}

# Gets any related ITG devices by searching the organization for devices with the same name
# It then compares mac address, serial #, etc.
function Get-RelatedITGDevices ($RMMDevice) {
	Get-RMMDeviceDetails -Device $RMMDevice

	if (!$RMMDevice.serialNumber -and !$RMMDevice.Nics.macAddress) {
		if (!$RMMDevice.snmpEnabled -or !$RMMDevice.intIpAddress) {
			return $false
		}
	}

	$DeviceName = $RMMDevice.hostname.Trim()
	if ($RMMDevice.description -and $RMMDevice.description.Trim() -notlike $DeviceName) {
		$DeviceName += ",$($RMMDevice.description)"
	}
	$OrgID = ($MatchedSites[$RMMDevice.siteId]).id

	$ITGDevices = Get-ITGlueConfigurations -organization_id $OrgID -filter_name $DeviceName

	if ($ITGDevices -and $ITGDevices.data -and ($ITGDevices.data | Measure-Object).Count -gt 0) {
		if ($RMMDevice.snmpEnabled -and !$RMMDevice.serialNumber -and ($RMMDevice.Nics | Measure-Object).Count -eq 0) {
			# Network device with no S/N or Mac Address, look for a simple IP match
			$ITGDevices_Matched = $ITGDevices.data | Where-Object { $_.attributes.'primary-ip' }
			$ITGDevices_Matched = $ITGDevices_Matched | Where-Object {
				$_.attributes.'primary-ip' -and $RMMDevice.intIpAddress -and $_.attributes.'primary-ip'.Trim() -like $RMMDevice.intIpAddress.Trim()
			}
		} else {
			$ITGDevices_Matched = $ITGDevices.data | Where-Object { $_.attributes.'serial-number' -or $_.attributes.'mac-address' }
			$ITGDevices_Matched = $ITGDevices_Matched | Where-Object {
				($_.attributes.'serial-number' -and $RMMDevice.serialNumber -and $_.attributes.'serial-number'.Trim() -like $RMMDevice.serialNumber.Trim()) -or
				($_.attributes.'mac-address' -and $RMMDevice.Nics.macAddress -and $_.attributes.'mac-address'.Trim() -in $RMMDevice.Nics.macAddress)
			}
		}

		if ($ITGDevices_Matched) {
			return $ITGDevices_Matched
		}
	}

	return $false
}

# Gets any related ITG passwords by searching the organization for passwords that contain the devices name
function Get-RelatedITGPasswords ($RMMDevice) {
	if (!$RMMDevice) {
		return;
	}
	if ($RMMDevice.siteId -notin $MatchedSites.Keys) {
		return;
	}
	
	$OrgID = ($MatchedSites[$RMMDevice.siteId]).id

	# Get passwords for this organization if we haven't already
	if (!$ITGPasswords.$OrgID) {
		$ITGPasswords_ForOrg = Get-ITGluePasswords -page_size 1000 -organization_id $OrgID
		$i = 1
		while ($ITGPasswords_ForOrg.links.next) {
			$i++
			$Passwords_Next = Get-ITGluePasswords -page_size 1000 -page_number $i -organization_id $OrgID
			if (!$Passwords_Next -or $Passwords_Next.Error) {
				# We got an error querying passwords, wait and try again
				Start-Sleep -Seconds 2
				$Passwords_Next = Get-ITGluePasswords -page_size 1000 -page_number $i -organization_id $OrgID
		
				if (!$Passwords_Next -or $Passwords_Next.Error) {
					Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing passwords from ITG."
					Write-PSFMessage -Level Error -Message $Passwords_Next.Error
				}
			}
			$ITGPasswords_ForOrg.data += $Passwords_Next.data
			$ITGPasswords_ForOrg.links = $Passwords_Next.links
			Start-Sleep -Seconds 1
		}
		if ($ITGPasswords_ForOrg -and $ITGPasswords_ForOrg.data) {
			$ITGPasswords.$OrgID = $ITGPasswords_ForOrg.data
		}
	}

	if ($ITGPasswords.$OrgID) {
		$RelatedPasswords = $ITGPasswords.$OrgID | Where-Object { ($RMMDevice.hostname -and $_.attributes.name -like "*$($RMMDevice.hostname)*") -or ($RMMDevice.description -and $_.attributes.name -like "*$($RMMDevice.description)*") }
		if (($RelatedPasswords | Measure-Object).Count -gt 10) {
			$RelatedPasswords = $RelatedPasswords | Select-Object -First 10
		}
		return $RelatedPasswords
	}

	return $false
}

# This function will add a device into ITG using an RMM Device for the details
function New-ITGDevice ($RMMDevice)
{
	if (!$RMMDevice) {
		return;
	}
	if ($RMMDevice.siteId -notin $MatchedSites.Keys) {
		return;
	}
	if ($RMMDevice.uid -in $RMM_Devices_RecentlyAuditedSNMP) {
		 return;
	}

	$ConfigType = $false;

	# If the RMM device type is Router, do some extra categorization based on the device name (as RMM miscategorizes alot into this type)
	if ($RMMDevice.deviceType.type -eq "Router") {
		if ($RMMDevice.hostname -match '(-FW)|(FW\d?\d)') {
			$RMMDevice.deviceType.category = "Network Device (Firewall)"
			$RMMDevice.deviceType.type = "Firewall"
		}
		elseif ($RMMDevice.hostname -match '(-SW)|(SW\d?\d)') {
			$RMMDevice.deviceType.category = "Network Device (Switch)"
			$RMMDevice.deviceType.type = "Switch"
		}
		elseif ($RMMDevice.hostname -match '(-AP)|(-WAP)|(AP\d?\d)|(WAP\d?\d)|( WAP$)') {
			$RMMDevice.deviceType.category = "Network Device (Other)"
			$RMMDevice.deviceType.type = "Wireless AP"
		}
	}

	# Get config type	
	if ($RMMDevice.deviceType.type -in $ITG_ConfigTypeIDs.Keys) {
		$ConfigType = $ITG_ConfigTypeIDs[$RMMDevice.deviceType.type]
	} elseif ($RMMDevice.deviceType.category -in $ITG_ConfigTypeIDs.Keys) {
		$ConfigType = $ITG_ConfigTypeIDs[$RMMDevice.deviceType.category]
	} elseif ("Other" -in $ITG_ConfigTypeIDs.Keys) {
		$ConfigType = $ITG_ConfigTypeIDs["Other"]
	}

	if (!$ConfigType) {
		return;
	}

	# Verify this devices doesn't already exist in ITG (generally if the device was removed and re-added to RMM, or perhaps an OS upgrade)
	$RelatedDevices = Get-RelatedITGDevices -RMMDevice $RMMDevice
	if ($RelatedDevices -and ($RelatedDevices | Measure-Object).Count -gt 0) {
		Write-Host "Skipped adding new device to ITG: $($RMMDevice.hostname) (it appears to already exist)"
		Write-PSFMessage -Level Verbose -Message "Skipped adding new device to ITG: $($RMMDevice.hostname) (it appears to already exist)"

		if ($false -notin $RelatedDevices.attributes.archived) {
			$RelatedDevice = $RelatedDevices | Sort-Object -Property {$_.attributes."updated-at"} -Descending | Select-Object -First 1
			if ($RelatedDevice.attributes.archived) {
				$UpdatedConfig = @{
					'type' = 'configurations'
					'attributes' = @{
						'archived' = 'false'
					}
				}
				Set-ITGlueConfigurations -id $RelatedDevice.id -data $UpdatedConfig
			}
			return;
		}
	}

	# Get Manufacturer / Model
	$ITGManufacturerAndModel = Get-ITGManufacturerAndModel -RMMDevice $RMMDevice
	$ITGManufacturer = $ITGManufacturerAndModel.Manufacturer
	$ITGModel = $ITGManufacturerAndModel.Model

	$ITGOperatingSystem = Get-ITGOperatingSystem -RMMDevice $RMMDevice
	$ITGOperatingSystemNotes = $null
	if ($RMMDevice.operatingSystem -and (!$ITGOperatingSystem -or $ITGOperatingSystem -like "*(Other)")) {
		$ITGOperatingSystemNotes = $RMMDevice.operatingSystem
	}

	$AssetTag = Get-AssetTag -RMMDevice $RMMDevice

	$PrimaryMac = $RMMDevice.Nics | Where-Object { $_.ipv4 -eq $RMMDevice.intIpAddress }
	if ($PrimaryMac) {
		$PrimaryMac = $PrimaryMac.macAddress
	} else {
		$PrimaryMac = $null
	}

	$NewConfig = 
	@{
		type = 'configurations'
		attributes = @{
			name = $RMMDevice.hostname
			hostname = $RMMDevice.hostname
			"configuration-type-id" = $ConfigType
			"configuration-status-id" = $ITG_ConfigStatusID
			"manufacturer-id" = if ($ITGManufacturer) { $ITGManufacturer.id } else { $null }
			"model-id" = if ($ITGModel) { $ITGModel.id } else { $null }
			"operating-system-id" = if ($ITGOperatingSystem) { $ITGOperatingSystem.id } else { $null }
			"operating-system-notes" = $ITGOperatingSystemNotes
			"primary-ip" = if ($RMMDevice.intIpAddress) { $RMMDevice.intIpAddress } else { $null }
			"mac-address" = $PrimaryMac
			"serial-number" = if ($RMMDevice.serialNumber) { $RMMDevice.serialNumber } else { $null }
			"asset-tag" = $AssetTag
			"warranty-expires-at" = if ($RMMDevice.warrantyDate) { $RMMDevice.warrantyDate } else { $null }
			"installed-by" = "RMM: " + $RMMDevice.uid
		}
		relationships = @{
			"configuration_interfaces" = @{
				data = @(

				)
			}
		}
	}

	foreach ($Nic in $RMMDevice.Nics) {
		if ($Nic.ipv4 -and $Nic.macAddress) {
			$NewConfig['relationships']['configuration_interfaces']['data'] += @{
				type = "configuration_interfaces"
				attributes = @{
					name = $Nic.instance
					"ip-address" = $Nic.ipv4
					"mac-address" = $Nic.macAddress
					primary = if ($RMMDevice.intIpAddress -and $RMMDevice.intIpAddress -eq $Nic.ipv4) { $true } else { $false }
				}
			}
		}
	}

	if ($NewConfig) {
		$OrgID = ($MatchedSites[$RMMDevice.siteId]).id
		$NewITGConfig = New-ITGlueConfigurations -organization_id $OrgID -data $NewConfig
		Write-Host "Added new device to ITG: $($NewConfig.attributes.name)"
		Write-PSFMessage -Level Verbose -Message "Added new device to ITG: $($NewConfig.attributes.name)"

		if ($NewITGConfig -and $NewITGConfig.data[0].id) {
			# Get any related passwords and attach them as related items to the new config
			$RelatedPasswords = Get-RelatedITGPasswords -RMMDevice $RMMDevice

			$RelatedItemsBody = @()
			foreach ($Password in $RelatedPasswords) {
				$RelatedItemsBody += @{
					type = "related_items"
					attributes = @{
						"destination-id" = $Password.id
						"destination-type" = "Password"
					}
				}
			}
			if ($RelatedItemsBody -and $RelatedItemsBody.count -gt 0) {
				New-ITGlueRelatedItems -resource_type configurations -resource_id $NewITGConfig.data[0].id -data $RelatedItemsBody
			}
		}
	}
}

# This function will archive a device in
function Archive-ITGDevice ($ITG_Device_ID) {
	$UpdatedConfig = @{
		'type' = 'configurations'
		'attributes' = @{
			'archived' = 'true'
		}
	}

	try {
		Set-ITGlueConfigurations -id $ITG_Device_ID -data $UpdatedConfig
		return $true
	} catch {
		Write-PSFMessage -Level Error -Message "Could not archive ITG configuration '$ITG_Device_ID' for the reason: " + $_.Exception.Message
		return $false
	}
}

# Loop through devices and find any which have been added or deleted since the last time the script was executed
$NewDevices = [System.Collections.ArrayList]@()
$DeletedDevices = [System.Collections.ArrayList]@()
$ITGArchiveDevices = [System.Collections.ArrayList]@()

$path = "$PSScriptRoot\DeviceTracking"
If(!(test-path -PathType container $path))
{
    New-Item -ItemType Directory -Path $path | Out-Null
	Write-PSFMessage -Level Verbose -Message "Created device tracking folder: $path"
}

$MostRecent = Get-ChildItem "$PSScriptRoot\DeviceTracking\DattoRMMDeviceList*.csv" | Sort-Object -Descending | Select-Object -First 1

if ($null -eq $MostRecent){
    # If we don't have a list of machines create a baseline and exit.
    Write-Host "No existing device list found. Saving current list to create baseline."
	Write-PSFMessage -Level Verbose -Message "No existing device list found. Saving current list to create baseline."
	
    $RMM_Devices | ConvertTo-Csv -NoTypeInformation | Out-File "$PSScriptRoot\DeviceTracking\DattoRMMDeviceList-$(get-date -format yyyy-MM-dd-HHmm).csv"
	$FullCheck = $true
	Write-PSFMessage -Level Verbose -Message "Exported RMM Device List to: $PSScriptRoot\DeviceTracking\DattoRMMDeviceList-$(get-date -format yyyy-MM-dd-HHmm).csv"
} else {
    # Since there is a list available, we will start comparing the list of devices.
    write-host "Reviewing changes since $($MostRecent.LastWriteTime):"
    write-host "`nGetting current device list for DattoRMM..."
	Write-PSFMessage -Level Verbose -Message "Reviewing changes since $($MostRecent.LastWriteTime):"

    $RMM_Devices | ConvertTo-Csv -NoTypeInformation | Out-File "$PSScriptRoot\DeviceTracking\DattoRMMDeviceList-$(get-date -format yyyy-MM-dd-HHmm).csv"
	Write-PSFMessage -Level Verbose -Message "Exported RMM Device List to: $PSScriptRoot\DeviceTracking\DattoRMMDeviceList-$(get-date -format yyyy-MM-dd-HHmm).csv"
    $PreviousDevices = Import-Csv $MostRecent.FullName | sort-object -property @{Expression='sitename'; Ascending=$true}, @{Expression='description'; Ascending=$true}
	Write-PSFMessage -Level Verbose -Message "Found $(($PreviousDevices | Measure-Object).Count) previous devices."
    
	if (($PreviousDevices | Measure-Object).Count -gt 1) {
		# First, lets look for deletions.
		Write-host "`nLooking for deleted devices...`n"
		Write-PSFMessage -Level Verbose -Message "Looking for deleted devices..."
		foreach ($PrevDevice in $PreviousDevices) {
			if ($RMM_Devices.uid -notcontains $PrevDevice.uid){
				write-host "Device $($PrevDevice.hostname) deleted from $($PrevDevice.siteName)."
				Write-PSFMessage -Level Verbose -Message "Device $($PrevDevice.hostname) deleted from $($PrevDevice.siteName)."
				[void]$DeletedDevices.add($PrevDevice)
			}
		}
		if ($DeletedDevices.count -gt 0) {
			$DeletedDevices | ConvertTo-Csv -NoTypeInformation | Out-File "$PSScriptRoot\DeviceTracking\DattoRMMDeviceDeletions-$(get-date -format yyyy-MM-dd-HHmm).csv"
			Write-Host "Saved deleted devices to DeviceTracking\DattoRMMDeviceDeletions-<date stamp>.csv"
			Write-PSFMessage -Level Verbose -Message "Saved deleted devices to DeviceTracking\DattoRMMDeviceDeletions-<date stamp>.csv"

			# Mark devices for archival in ITG
			if ($DeletedDevices.Count -lt 100) { # For safety, if there is an issue we dont want to delete a bunch of duplicates
				foreach ($DeleteDevice in $DeletedDevices) {
					if (!$DeviceTypes_PreventDeletion -or $DeleteDevice.deviceType.category -notin $DeviceTypes_PreventDeletion) {
						[void]$ITGArchiveDevices.Add($DeleteDevice)
					}
				}
			} else {
				Write-PSFMessage -Level Warning -Message "Did not archive deleted devices because >100 were found to add. See DattoRMMDeviceDeletions-$(get-date -format yyyy-MM-dd-HHmm).csv"
			}
		} else {
			write-host "`nNo deleted devices found in Datto RMM."
			Write-PSFMessage -Level Verbose -Message "No deleted devices found in Datto RMM."
		}

		# Next, lets look for new devices.
		Write-host "`nLooking for new devices...`n"
		Write-PSFMessage -Level Verbose -Message "Looking for new devices..."
		foreach ($CurDevice in $RMM_Devices) {
			if ($PreviousDevices.uid -notcontains $CurDevice.uid){
				Write-host "Found new device $($CurDevice.hostname) for $($CurDevice.siteName)."
				Write-PSFMessage -Level Verbose -Message "Found new device $($CurDevice.hostname) for $($CurDevice.siteName)."
				[void]$NewDevices.add($CurDevice)
			}
		}
		if ($NewDevices.count -gt 0){
			$NewDevices | ConvertTo-Csv -NoTypeInformation | Out-File "$PSScriptRoot\DeviceTracking\DattoRMMDeviceAdditions-$(get-date -format yyyy-MM-dd-HHmm).csv"
			Write-host "Saved new devices to DeviceTracking\DattoRMMDeviceAdditions-<date stamp>.csv"
			Write-PSFMessage -Level Verbose -Message "Saved new devices to DeviceTracking\DattoRMMDeviceAdditions-<date stamp>.csv"

			# Add new devices to ITG
			if ($NewDevices.Count -lt 100) { # For safety, if there is an issue we dont want to add a bunch of duplicates
				foreach ($NewDevice in $NewDevices) {
					New-ITGDevice -RMMDevice $NewDevice
				}
			} else {
				Write-PSFMessage -Level Warning -Message "Did not add new devices because >100 were found to add. See DattoRMMDeviceAdditions-$(get-date -format yyyy-MM-dd-HHmm).csv"
			}
		} else {
			Write-host "`nNo new devices have been added to Datto RMM."
			Write-PSFMessage -Level Verbose -Message "No new devices have been added to Datto RMM."
		}

		# Cleanup old DeviceLists
		$OldDeviceLists = Get-ChildItem "$PSScriptRoot\DeviceTracking\DattoRMMDeviceList*.csv" | Sort-Object -Descending | Select-Object -Skip 5 | 
			Where-Object { $_.Name -notlike "*-$(get-date -format yyyy-MM-dd)-*" -and $_.Name -notlike "*-$(Get-Date (get-date).AddDays(-1) -format yyyy-MM-dd)-*" }

		if ($OldDeviceLists) {
			$OldDeviceLists | ForEach-Object { Remove-Item $_ }
		}
	} else {
		$FullCheck = $true
	}
}

# Archive ITG devices if necessary
if ($ITGArchiveDevices -and ($ITGArchiveDevices | Measure-Object).Count -gt 0) {
	$ArchiveSites = $ITGArchiveDevices.siteId | Sort-Object -Unique
	foreach ($ArchiveSite in $ArchiveSites) {
		$RMMSiteID = $ArchiveSite
		$RMMSite = $RMM_Sites | Where-Object { $_.id -eq $RMMSiteID }
		$ITGSite = $MatchedSites.[int]$ArchiveSite

		if (!$ITGSite) { continue }

		$SiteArchiveDevices = $ITGArchiveDevices | Where-Object { $_.siteId -eq $RMMSiteID }

		# Get ITG devices for org
		$ITG_OrgDevices = Get-ITGlueConfigurations -page_size "1000" -organization_id $ITGSite.id
		$i = 1
		while ($ITG_OrgDevices.links.next) {
			$i++
			$Devices_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -organization_id $ITGSite.id
			if (!$Devices_Next -or $Devices_Next.Error) {
				# We got an error querying configurations, wait and try again
				Start-Sleep -Seconds 2
				$Devices_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -organization_id $ITGSite.id
		
				if (!$Devices_Next -or $Devices_Next.Error) {
					Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing configurations from ITG."
					Write-PSFMessage -Level Error -Message $Devices_Next.Error
				}
			}
			$ITG_OrgDevices.data += $Devices_Next.data
			$ITG_OrgDevices.links = $Devices_Next.links
			Start-Sleep -Seconds 1
		}
		
		if (($ITG_OrgDevices.data | Measure-Object).Count -lt 1 -and $ITG_OrgDevices.meta.'total-count' -lt 1) {
			continue
		}
		$ITG_OrgDevices = $ITG_OrgDevices.data

		# Loop through Archive devices, find match in ITG, and archive
		foreach ($RMMDevice in $SiteArchiveDevices) {
			# RMM to ITG device match
			$ITGDevice = $ITG_OrgDevices | Where-Object { 
				$Return = $false
				if ($_.attributes."installed-by") {
					$Return = $_.attributes."installed-by".Trim() -eq ("RMM: " + $RMMDevice.uid)
				}
				if ($RMMDevice.hostname -and !$Return) {
					$Return = $_.attributes.name.Trim() -eq $RMMDevice.hostname.Trim()
				}
				if ($RMMDevice.description -and !$Return) {
					$Return = $_.attributes.name.Trim() -like $RMMDevice.description.Trim()
				}

				if ($_.attributes.hostname -and !$Return) {
					if ($RMMDevice.hostname -and !$Return) {
						$Return = $_.attributes.hostname.Trim() -eq $RMMDevice.hostname.Trim()
					}
					if ($RMMDevice.description -and !$Return) {
						$Return = $_.attributes.hostname.Trim() -like $RMMDevice.description.Trim()
					}
				}

				return $Return
			}

			# Narrow down if more than 1 device found
			if (($ITGDevice | Measure-Object).Count -gt 1) {
				$ITGDevice_Temp = $ITGDevice | Where-Object {
					$_.attributes."installed-by" -and $_.attributes."installed-by".Trim() -eq ("RMM: " + $RMMDevice.uid)
				}
				if (($ITGDevice_Temp | Measure-Object).Count -gt 0) {
					$ITGDevice = $ITGDevice_Temp
				}
			}
			if (($ITGDevice | Measure-Object).Count -gt 1) {
				$ITGDevice_Temp = $ITGDevice | Where-Object {
					!$_.attributes.archived
				}
				if (($ITGDevice_Temp | Measure-Object).Count -gt 0) {
					$ITGDevice = $ITGDevice_Temp
				}
			}
			if (($ITGDevice | Measure-Object).Count -gt 1) {
				$ITGDevice = $ITGDevice | Select-Object -First 1
			}

			if ($ITGDevice) {
				# Match found, archive device
				Archive-ITGDevice -ITG_Device_ID $ITGDevice.id
				Write-PSFMessage -Level Verbose -Message "Archived ITG Device ID $($ITGDevice.id) (Name: $($ITGDevice.id) Type: $($ITGDevice.attributes.'configuration-type-name') Org: $($ITGDevice.attributes.'organization-name'))."
			}
		}
	}
}


# Occasionally do a full audit and check each RMM device against ITG directly (not using csv's) (for new devices only)
if ($FullCheck) {
	$MatchedDevices = @{}
	$NewDevices = [System.Collections.ArrayList]@()
	$DeletedDevices = [System.Collections.ArrayList]@()
	$ITG_Devices = @{}

	Write-PSFMessage -Level Verbose -Message "==============================="
	Write-PSFMessage -Level Verbose -Message "Running a Full Audit on $($MatchedSites.count) matched sites."

	$MatchedSites.GetEnumerator() | ForEach-Object {
		$RMMSiteID = $_.key
		$RMMSite = $RMM_Sites | Where-Object { $_.id -eq $RMMSiteID }
		$ITGSite = $_.value
		$MatchedDevices[$RMMSite.id] = [System.Collections.ArrayList]@()

		$RMM_OrgDevices = $RMM_Devices | Where-Object { $_.siteId -eq $RMMSite.id }
		$RMMDeviceCount = ($RMM_OrgDevices | Measure-Object).Count
		Write-PSFMessage -Level Verbose -Message "Auditing - RMM Site: $($RMMSite.name), ITG Site: $($ITGSite.attributes.name), Device Count: $RMMDeviceCount"
		if ($RMMDeviceCount -lt 1) {
			continue
		}

		# Add RMM device details for matching
		$i = 0
		$RMM_OrgDevices | ForEach-Object { 
			$i++
			[int]$PercentComplete = ($i / $RMMDeviceCount * 100)
			Write-Progress -Activity "Getting RMM device details for site '$($RMMSite.Name)'" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%")
			Get-RMMDeviceDetails -Device $_
		 }
		 Write-Progress -Activity "Getting RMM device details for site '$($RMMSite.Name)'" -Status "Ready" -Completed
		
		# Get ITG devices for org
		$ITG_OrgDevices = Get-ITGlueConfigurations -page_size "1000" -organization_id $ITGSite.id
		$i = 1
		while ($ITG_OrgDevices.links.next) {
			$i++
			$Devices_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -organization_id $ITGSite.id
			if (!$Devices_Next -or $Devices_Next.Error) {
				# We got an error querying configurations, wait and try again
				Start-Sleep -Seconds 2
				$Devices_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -organization_id $ITGSite.id
		
				if (!$Devices_Next -or $Devices_Next.Error) {
					Write-PSFMessage -Level Error -Message "An error occurred trying to get the existing configurations from ITG."
					Write-PSFMessage -Level Error -Message $Devices_Next.Error
				}
			}
			$ITG_OrgDevices.data += $Devices_Next.data
			$ITG_OrgDevices.links = $Devices_Next.links
			Start-Sleep -Seconds 1
		}
		Write-PSFMessage -Level Verbose -Message "Found $(($ITG_OrgDevices.data | Measure-Object).Count) ITG devices. (Total Count: $($ITG_OrgDevices.meta.'total-count'))"
		if (($ITG_OrgDevices.data | Measure-Object).Count -lt 1 -and $ITG_OrgDevices.meta.'total-count' -lt 1) {
			continue
		}
		$ITG_OrgDevices = $ITG_OrgDevices.data
		$ITG_Devices[$ITGSite.id] = $ITG_OrgDevices
		
		# Loop through RMM devices and look for any missing in ITG
		foreach ($RMMDevice in $RMM_OrgDevices) {
			# RMM to ITG device match
			$ITGDevice = $ITG_OrgDevices | Where-Object { 
				$Return = $false
				if ($_.attributes."installed-by") {
					$Return = $_.attributes."installed-by".Trim() -eq ("RMM: " + $RMMDevice.uid)
				}
				if ($RMMDevice.hostname -and !$Return) {
					$Return = $_.attributes.name.Trim() -eq $RMMDevice.hostname.Trim()
				}
				if ($RMMDevice.description -and !$Return) {
					$Return = $_.attributes.name.Trim() -like $RMMDevice.description.Trim()
				}

				if ($_.attributes.hostname -and !$Return) {
					if ($RMMDevice.hostname -and !$Return) {
						$Return = $_.attributes.hostname.Trim() -eq $RMMDevice.hostname.Trim()
					}
					if ($RMMDevice.description -and !$Return) {
						$Return = $_.attributes.hostname.Trim() -like $RMMDevice.description.Trim()
					}
				}
				
				if ($_.attributes.'serial-number' -and $RMMDevice.serialNumber -and $RMMDevice.serialNumber -notin $IgnoreSerials -and $RMMDevice.serialNumber -notlike "123456789*" -and !$Return) {
					$Return = $_.attributes.'serial-number'.Trim() -like $RMMDevice.serialNumber.Trim()
				}

				return $Return
			}

			# Narrow down if more than 1 device found
			if (($ITGDevice | Measure-Object).Count -gt 1) {
				$ITGDevice_Temp = $ITGDevice | Where-Object {
					$_.attributes."installed-by" -and $_.attributes."installed-by".Trim() -eq ("RMM: " + $RMMDevice.uid)
				}
				if (($ITGDevice_Temp | Measure-Object).Count -gt 0) {
					$ITGDevice = $ITGDevice_Temp
				}
			}
			if (($ITGDevice | Measure-Object).Count -gt 1) {
				$ITGDevice_Temp = $ITGDevice | Where-Object {
					$_.attributes.name -eq $RMMDevice.hostname -and
					$_.attributes.'serial-number' -like $RMMDevice.serialNumber
				}
				if (($ITGDevice_Temp | Measure-Object).Count -gt 0) {
					$ITGDevice = $ITGDevice_Temp
				}
			}
			if (($ITGDevice | Measure-Object).Count -gt 1) {
				$ITGDevice_Temp = $ITGDevice | Where-Object {
					!$_.attributes.archived
				}
				if (($ITGDevice_Temp | Measure-Object).Count -gt 0) {
					$ITGDevice = $ITGDevice_Temp
				}
			}
			if (($ITGDevice | Measure-Object).Count -gt 1) {
				$ITGDevice = $ITGDevice | Select-Object -First 1
			}

			if ($ITGDevice) {
				# Add to Matched Devices
				[void]$MatchedDevices[$RMMSite.id].Add(
					[PsCustomObject]@{
						id = New-Guid
						rmm_match = $RMMDevice.id
						rmm_hostname = $RMMDevice.hostname
						itg_match = $ITGDevice.id
						itg_hostname = $ITGDevice.attributes.name
					}
				)
			} else {
				# Add to New Devices (if seen in the last 2 months)
				$LastSeen = $false
				if ($RMMDevice.online -eq "True") {
					$LastSeen = Get-Date
				} else {
					$LastSeen = Convert-UTCtoLocal(([datetime]'1/1/1970').AddMilliseconds($RMMDevice.lastSeen))
				}

				if ($LastSeen -and $LastSeen -gt ((Get-Date).AddMonths(-2))) {
					[void]$NewDevices.Add($RMMDevice)	
				}
			}
		}

		$Unmatched = @()
		# Loop through ITG devices and find any that are unmatched
		foreach ($ITGDevice in $ITG_OrgDevices) {
			if ($ITGDevice.id -in $MatchedDevices[$RMMSite.id].itg_match) {
				continue
			}
			if ($ITGDevice.attributes.'configuration-type-name' -notin @("Workstation", "Laptop", "Server")) {
				continue
			}
			if ($ITGDevice.attributes.archived) {
				continue
			}
			$Unmatched += $ITGDevice
		}
	}
	Write-PSFMessage -Level Verbose -Message "Device Counts - New: $($NewDevices.count), Unmatched: $($Unmatched.count)"

	if ($NewDevices.count -gt 0) {
        Write-host "New devices found, adding to ITG"
		Write-PSFMessage -Level Verbose -Message "New devices found, adding to ITG"

		# Add new devices to ITG
		if ($NewDevices.Count -lt 100) { # For safety, if there is an issue we dont want to add a bunch of duplicates
			foreach ($NewDevice in $NewDevices) {
				New-ITGDevice -RMMDevice $NewDevice
			}
		} else {
			Write-PSFMessage -Level Warning -Message "Did not add new devices because >100 were found to add. See DattoRMMDeviceAdditions-$(get-date -format yyyy-MM-dd-HHmm).csv"
		}
    }

	# Check if any updates are required in ITG
	$MatchedSites.GetEnumerator() | ForEach-Object {
		$RMMSiteID = $_.key
		$RMMSite = $RMM_Sites | Where-Object { $_.id -eq $RMMSiteID }
		$ITGSite = $_.value
		Write-PSFMessage -Level Verbose -Message "Checking for Updates - RMM Site: $($RMMSite.name)"

		if (!$RMMSite -or !$ITGSite) {
			Write-PSFMessage -Level Error -Message "Could not find RMM site or ITG site. Skipping..."
			continue
		}

		if (!$MatchedDevices[$RMMSite.id] -or !$ITG_Devices[$ITGSite.id]) {
			Write-PSFMessage -Level Error -Message "Found no matched devices or no ITG devices. Skipping..."
			continue
		}
		Write-PSFMessage -Level Verbose -Message "Found $($MatchedDevices[$RMMSite.id].count) Matched Devices"

		foreach ($Device in $MatchedDevices[$RMMSite.id]) {
			$RMMDevice = $RMM_Devices | Where-Object { $_.id -eq $Device.rmm_match }
			$ITGDevice = $ITG_Devices[$ITGSite.id] | Where-Object { $_.id -eq $Device.itg_match }

			if (!$RMMDevice -or !$ITGDevice) {
				continue
			}

			$UpdatedITGDevice = @{}
			$UpdateRequired = $false

			# If changed, update
			if ($RMMDevice.hostname -and (!$ITGDevice.attributes.name -or $RMMDevice.hostname.Trim() -ne $ITGDevice.attributes.name.Trim())) {
				$UpdatedITGDevice.name = $RMMDevice.hostname.Trim()
				$UpdateRequired = $true
			}
			if ($RMMDevice.intIpAddress -and $RMMDevice.intIpAddress -ne $ITGDevice.attributes."primary-ip") {
				$UpdatedITGDevice."primary-ip" = $RMMDevice.intIpAddress.Trim()
				$UpdateRequired = $true
			}
			if ($RMMDevice.warrantyDate -and $RMMDevice.warrantyDate -ne $ITGDevice.attributes."warranty-expires-at") {
				$UpdatedITGDevice."warranty-expires-at" = $RMMDevice.warrantyDate
				$UpdateRequired = $true
			}
			if ($RMMDevice.operatingSystem -and ($RMMDevice.operatingSystem -notlike "*$($ITGDevice.attributes.'operating-system-name'.Trim())*" -or !$ITGDevice.attributes.'operating-system-id')) {
				$ITGOperatingSystem = Get-ITGOperatingSystem -RMMDevice $RMMDevice
				if ($ITGOperatingSystem -and $ITGOperatingSystem.id -ne $ITGDevice.attributes.'operating-system-id') {
					$UpdatedITGDevice."operating-system-id" = $ITGOperatingSystem.id
					$UpdateRequired = $true
					if ($RMMDevice.operatingSystem -and (!$ITGOperatingSystem -or $ITGOperatingSystem -like "*(Other)")) {
						$UpdatedITGDevice."operating-system-notes" = $RMMDevice.operatingSystem
					}
				}
			}

			# If missing/not set, update
			if ($RMMDevice.serialNumber -and $RMMDevice.serialNumber.Trim() -and !$ITGDevice.attributes."serial-number") {
				$UpdatedITGDevice."serial-number" = $RMMDevice.serialNumber.Trim()
				$UpdateRequired = $true
			}
			
			$ITGManufacturerAndModel = $false
			if ($RMMDevice.manufacturer -and $RMMDevice.manufacturer.Trim() -and !$ITGDevice.attributes."manufacturer-id") {
				$ITGManufacturerAndModel = Get-ITGManufacturerAndModel -RMMDevice $RMMDevice
				$ITGManufacturer = $ITGManufacturerAndModel.Manufacturer
				if ($ITGManufacturer) {
					$UpdatedITGDevice."manufacturer-id" = $ITGManufacturer.id
					$UpdateRequired = $true
				}
			}
			if ($RMMDevice.model -and $RMMDevice.model.Trim() -and (!$ITGDevice.attributes."model-id" -or $UpdatedITGDevice."manufacturer-id")) {
				if (!$ITGManufacturerAndModel) {
					$ITGManufacturerAndModel = Get-ITGManufacturerAndModel -RMMDevice $RMMDevice
				}
				$ITGModel = $ITGManufacturerAndModel.Model
				if ($ITGModel) {
					$UpdatedITGDevice."model-id" = $ITGModel.id
					$UpdateRequired = $true
				}
			}
			if ($RMMDevice.Nics -and !$ITGDevice.attributes.'mac-address') {
				$PrimaryMac = $RMMDevice.Nics | Where-Object { $_.ipv4 -eq $RMMDevice.intIpAddress }
				if ($PrimaryMac) {
					$PrimaryMac = $PrimaryMac.macAddress
				} else {
					$PrimaryMac = $null
				}
				if ($PrimaryMac) {
					$UpdatedITGDevice."mac-address" = $PrimaryMac.Trim()
					$UpdateRequired = $true
				}
			}
			if (!$ITGDevice.attributes."asset-tag") {
				$AssetTag = Get-AssetTag -RMMDevice $RMMDevice
				if ($AssetTag) {
					$UpdatedITGDevice."asset-tag" = $AssetTag
					$UpdateRequired = $true
				}
			}
			# If asset tag is an RMM ID, update the asset tag and set the installed-by to the RMM ID
			if (
				$ITGDevice.attributes."asset-tag" -and 
				(
					$ITGDevice.attributes."asset-tag" -match "^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$" -or
					$ITGDevice.attributes."asset-tag" -match "^[0-9a-fA-F]{8}\b-([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
				)
			) {
				if ($ITGDevice.attributes."installed-by" -notlike "RMM: *") {
					$UpdatedITGDevice."installed-by" = "RMM: " + $Matches[0]
					$UpdateRequired = $true
				}
				$AssetTag = Get-AssetTag -RMMDevice $RMMDevice
				if ($AssetTag) {
					$UpdatedITGDevice."asset-tag" = $AssetTag
					$UpdateRequired = $true
				}
			}
			if ($ITGDevice.attributes.archived) {
				$UpdatedITGDevice.'archived' = 'false'
				$UpdateRequired = $true
			}

			# Update
			if ($UpdateRequired) {

				Write-Host "Updating device: $($ITGDevice.attributes.name)" -ForegroundColor Green
				Write-PSFMessage -Level Verbose -Message "Updating device: $($ITGDevice.attributes.name)"
				$UpdatedITGDevice
				if ($StepThroughUpdates) {
					Write-Host "Press any key to continue..."
					$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
				}

				$ConfigurationUpdate = @{
					'type' = 'configurations'
					'attributes' = $UpdatedITGDevice
				}
				Set-ITGlueConfigurations -id $ITGDevice.id -data $ConfigurationUpdate
				Write-Host "Updated in ITG: $($ITGDevice.attributes.name) using RMM: $($RMMDevice.hostname)"
				Write-PSFMessage -Level Verbose -Message "Updated in ITG: $($ITGDevice.attributes.name) using RMM: $($RMMDevice.hostname)"
			}
		}
	}

	(Get-Date).ToString() | Out-File -FilePath ($PSScriptRoot + "\FullCheckLastRun.txt")
}
Wait-PSFMessage