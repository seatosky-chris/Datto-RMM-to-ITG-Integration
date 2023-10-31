# ITG to DattoRMM Integration

This is a custom integration that will sync devices and device info from Datto RMM into ITGlue. We found we had numerous issues with the built-in integration in ITG where it wouldn't sync all the data we wanted, and just generally took too long. We use this custom integration to improve on this situation.

This script is still a **WIP**. We have been using it for a few months with success, but I cannot guarantee you won't run into any issues. Use it at your own risk.

The script will automatically export logs to the Logs folder local to this integration. It will clean up any older than 1 week.

### Important things to know
1. Currently the script will add devices and update them, but it will not remove or archive devices in ITG. We opted not to do this as sometimes devices would fall out of RMM but still be active in another one of our systems. I use our Device Audit script to instead compare activity in all our systems and archive devices in ITG that are no longer active anywhere. Currently it will output devices deleted in RMM to a csv file named: `DattoRMMDeviceDeletions-<date stamp>.csv`. It should be fairly easy to add auto-archive functionality, see line 829.

2. This script will cleanup Manufacturer names. If you do not want this, you will want to comment this out. Just search for the `Format-ManufacturerName` function and have it return the original manufacturer name (or add your own cleanup script). I have also included the helper script `ITG_Manufacturer_and_Model_Cleanup.ps1`, this can be used to cleanup manufacturer names of existing assets in ITG. It will try to create clean manufacturer names, move the models over, then delete the old manufacturer. There is a bug in ITG that sometimes prevents Manufacturers/Models from being deleted though.

3. This script uses the `installed-by` field in ITG to keep track of the RMM ID that an asset is synced to. If you use this field, you will need to modify this to a different field that you do not need. Unfortunately, ITG does not provide any way of adding a new field to configurations for this purpose, and even if you are using the built-in RMM integration, the API does not allow you to get the RMM ID that is synced with a configuration. As such, we've hijacked this field for this purpose.

4. For safety, I have added a check that will prevent device creation if there are more than 100 devices to add to ITG. Once we had the API fail and it mass added all of our devices over again. I have since put in checks to watch for API failures, but as an extra safety, I have left in the code to kill things if adding >100 devices. You may want/need to remove this on your first run temporarily, or permanently if you have a very large number of devices being added weekly (>100). These kill switches can be found on lines 847 and 1021.

5. This script will not work nicely if you have an ITG PSA integration syncing configurations into IT Glue. The Autotask PSA integration blocks any API editing of synced configurations, and I suspect other PSA integrations will do the same. The Datto RMM ITG integrations is fine as it just creates and overlay which does not block API editing. You can still use the PSA integration, just uncheck the option to sync configurations, or uncheck the device types that exist in RMM for syncing, so they won't sync through from your PSA.

### How it works
On each run it will export a full list of all the devices in RMM to a csv file (`DattoRMMDeviceList-date.csv`). It will then compare the current list against the last list to look for any changes. It then creates csv files containing all the new devices (`DattoRMMDeviceAdditions-date.csv`) and one for deleted devices (`DattoRMMDeviceDeletions-date.csv`). At this point it will also cleanup any old DeviceLists, keeping only the 5 most recent. Currently it never deletes Addition or Deletions csv's. For each new device found, it will create a new device in ITG. Currently it will not do anything for deleted devices other than export the csv of them. 

Once a week, the integration will perform a full audit where it checks each RMM device against ITG directly. All RMM devices are compared against each ITG device (within their respective organizations) and matched. Ideally this matching is performed on RMM ID (from the installed-by field), but if an ITG configuration is missing this, it will still attempt to match based on hostname, serial number, etc. It will then add any missing devices that have been seen in the last 2 months in RMM. It will also look for any changes to devices in RMM where the fields dont match the data in ITG, and update this data where appropriate. Full checks will automatically happen if one hasn't occurred in over 1 week and it is currently the middle of the night (11PM - 5AM). You can force trigger a full update as well with the FullCheck flag when running the script. By default, if running the script in a Window, after any device update you will be required to press any key to continue to the next update. This is useful for verifying the system is working correctly and allows you to step through and verify all updates. You can disable this by setting the StepThroughUpdates flag to false. It will automatically be disabled when running the script unattended through the task scheduler.

### Setup
1. Create a Config.ps1 file from the Config.ps1.template. 
2. Get the ID of the Status you want to use for new configurations from ITG and use this for `$ITG_ConfigStatusID`. (Navigate to Account > Configuration Statuses, Edit the status then get the ID from the URL). The `Active` status can be particularly difficult to get so I have implemented a helper function into the integration. If you leave this variable `$false`, the script will prompt you to choose an option on its first run and will automatically update the config value with the proper ID.
3. Configure `$ITG_ConfigTypeIDs` for each RMM Device Type filling in device type ID's from ITG. (Navigate to Account > Configuration Types, Edit the type then get the ID from the URL)
4. Fill in `$ITGAPIKey` with your ITG API details and `$DattoAPIKey` with your Datto RMM API details. If you use an ITG API key with password access, the integration will also tag existing passwords to newly created configurations.
5. See the important points above, you may want to make changes to add auto device archiving, prevent manufacturer name cleanup, change the RMM ID field away from `installed-by`, and you may need to remove the safety check that prevents >100 devices being added to ITG.
6. If you are ok with it cleaning up manufacturer names, you may want to run the `ITG_Manufacturer_and_Model_Cleanup.ps1` script to clean things up initially.
7. Place the script on a device that is always on and setup a task scheduler to run it. This can be ran quite often. I have ours setup to trigger daily at 12:05 AM, then it repeats every 10 minutes for a duration of 1 day. This way it syncs new devices into ITG every 10 minutes. If you want to do full updates more often, you could add a second scheduler to run the integration with the ForceCheck flag on a regular schedule as well.

# Datto RMM to ITG Monitors Integration

This is a separate set of components/scripts that will update and add ITG documentation for Monitors found in RMM. This integration allows you to keep track of a monitor's location, when when it is moved from 1 device to another. It consists of 2 parts:
* An RMM that queries all Windows devices for attached monitors and their info, and then updates a UDF with this info.
* A PowerShell script that daily queries the RMM UDF, parses the monitor information for each device, and updates ITG.

### How it works
The RMM component should be ran daily. This will query each device for attached monitors and get their info. The info gathered includes:
* Manufacturer
* Model
* Serial Number
* Display Type (e.g. DP, HDMI, DVI, etc.)
* Year of Manufacture
The component will then update a UDF in RMM with this info in JSON format. It will look something like this:
`{"Mftr":"Dell","Mdl":"DELL U2412M","SN":"YMYH14DK565S","Type":"DVI","ManYr":2013} |Updated: 2023-07-04`

The PowerShell script should also be ran daily, sometime after the RMM Component has run. When the script runs, it will pull all devices from RMM that have the specified UDF populated. It will parse the UDF fields to get the unique info for each monitor from these devices and make a list of all found monitors with unique serial numbers. Note that we have blacklisted certain serial numbers that aren't unique, and you can further configure this in the config.ps1 file. All Acer monitors have also been blacklisted as they don't seem to use unique serial numbers. 

The script then runs through each monitor and attempts to link it to a monitor config in ITG, with matching based on Organization and Serial Number. If no existing monitor is found, it creates a new monitor in ITG. If an existing monitor is found, it updates it if necessary. The following information is added/updated for monitors in ITG:
* Configuration Status (Active)
* Manufacturer
* Model
* Warranty Expiry (3 years from the year of manufacture)
* End of Life (creates an EOL asset set to 5 years from the year of manufacture)
* Serial Number
* Installed By (RMM Monitor Integration)
* Monitor name (only for new devices, uses the format: ORGAcronym-DISP-SerialNumber)
* Connects the related workstation as a related item and in the notes adds the display type connection
* Notes, includes: Connected devices (ITG and RMM), Manufacture Year, Last Seen (when disconnected from a device)
* Configuration interfaces (we cannot attach a device here via a script so it just adds the display type as an interface)

The script will then go through any monitors found in ITG that were not found in RMM, these monitors have been disconnected from devices. It will update these to disconnect them from past devices and add a "Last Seen" note to the monitor config in ITG. If this monitor was last seen over 1 month ago, the asset will also be archived.

### Setup
1. Add the `Attached Monitor Info to UDF` component to RMM. You can find it here: https://github.com/seatosky-chris/RMM-Scripts-and-Components/blob/main/Components/Custom%20RMM%20Components/Attached%20Monitor%20Info%20to%20UDF%20(STS).ps1
2. Schedule the RMM component to run daily. Choose an empty UDF # to add the monitor data to, you may wish to rename this UDF in RMM as well. Target **All Windows Desktops**. You may also want to set a long expiry time (12 hours or 1 day) in case a device is not online when this job runs.
3. Create/update the Config.ps1 file from Config.ps1.template. Note that this is the same config file that is used by the regular ITG to Datto RMM integration documented above. See Setup instructions above for configuration of variables, variables only used by this integration are documented below.
4. Configure `$ITG_MonitorTypeID` with the configuration type ID of the **Monitor** configuration type. This is found in: `Account > Configuration Types`.
5. Configure `$ITG_EOL_FlexibleAssetTypeID` with the flexible asset ID of the **End of Life** flexible asset type.
6. Configure `$RMM_MonitorInfo_UDF` with the UDF # that you will your RMM component is updating.
7. Place the script (`DattoRMM_to_ITG_Monitors_Integration.ps1`) on a device that is always on and setup a task scheduler to run it. This should be ran sometime after the RMM component above has ran, I personally run it 1 hour after the components scheduled time.