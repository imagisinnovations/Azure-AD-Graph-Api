cls

Write-Host "
                                          _____                    _   _____       _                       _____      _               
     /\                             /\   |  __ \                  | | |_   _|     | |                     / ____|    | |              
    /  \    _____   _ _ __ ___     /  \  | |  | |   __ _ _ __   __| |   | |  _ __ | |_ _   _ _ __   ___  | (___   ___| |_ _   _ _ __  
   / /\ \  |_  / | | | '__/ _ \   / /\ \ | |  | |  / _` | '_ \ / _` |   | | | '_ \| __| | | | '_ \ / _ \  \___ \ / _ \ __| | | | '_ \ 
  / ____ \  / /| |_| | | |  __/  / ____ \| |__| | | (_| | | | | (_| |  _| |_| | | | |_| |_| | | | |  __/  ____) |  __/ |_| |_| | |_) |
 /_/    \_\/___|\__,_|_|  \___| /_/    \_\_____/   \__,_|_| |_|\__,_| |_____|_| |_|\__|\__,_|_| |_|\___| |_____/ \___|\__|\__,_| .__/ 
                                                                                                                               | |    
                                                                                                                               |_|            

" -ForegroundColor Green

######################################################### AUTH

function Get-AuthToken {

    <#
    .SYNOPSIS
    This function is used to authenticate with the Graph API REST interface
    .DESCRIPTION
    The function authenticate with the Graph API Interface with the tenant name
    .EXAMPLE
    Get-AuthToken
    Authenticates you with the Graph API interface
    .NOTES
    NAME: Get-AuthToken
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory=$true)]
        $User
    )
    
    $userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
    
    $tenant = $userUpn.Host
    
    Write-Host "Checking for AzureAD module..."
    
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    
        if ($AadModule -eq $null) {
    
            Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
            $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
    
        }
    
        if ($AadModule -eq $null) {
            write-host
            write-host "AzureAD Powershell module not installed..." -f Red
            write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
            write-host "Script can't continue..." -f Red
            write-host
            exit
        }
    
    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version
    
        if($AadModule.count -gt 1){
    
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
    
            $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
    
                # Checking if there are multiple versions of the same module found
    
                if($AadModule.count -gt 1){
    
                $aadModule = $AadModule | select -Unique
    
                }
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
        else {
    
            $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
            $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
    
        }
    
    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
    
    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
    
    $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    
    $resourceAppIdURI = "https://graph.microsoft.com"
    
    $authority = "https://login.microsoftonline.com/$Tenant"
    
        try {
    
        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    
        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    
        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
    
        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    
        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result
    
            # If the accesstoken is valid then create the authentication header
    
            if($authResult.AccessToken){
    
            # Creating header for Authorization token
    
            $authHeader = @{
                'Content-Type'='application/json'
                'Authorization'="Bearer " + $authResult.AccessToken
                'ExpiresOn'=$authResult.ExpiresOn
                }
    
            return $authHeader
    
            }
    
            else {
    
            Write-Host
            Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
            Write-Host
            break
    
            }
    
        }
    
        catch {
    
        write-host $_.Exception.Message -f Red
        write-host $_.Exception.ItemName -f Red
        write-host
        break
    
        }
    
    }

    ############################################################################### Test-JSON

    Function Test-JSON(){

        <#
        .SYNOPSIS
        This function is used to test if the JSON passed to a REST Post request is valid
        .DESCRIPTION
        The function tests if the JSON passed to the REST Post is valid
        .EXAMPLE
        Test-JSON -JSON $JSON
        Test if the JSON is valid before calling the Graph REST interface
        .NOTES
        NAME: Test-JSON
        #>
        
        param (
        
        $JSON
        
        )
        
            try {
        
            $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
            $validJson = $true
        
            }
        
            catch {
        
            $validJson = $false
            $_.Exception
        
            }
        
            if (!$validJson){
            
            Write-Host "Provided JSON isn't in valid JSON format" -f Red
            break
        
            }
        
        }

        #################################################################  Add Compliance

        Function Add-DeviceCompliancePolicy(){

            <#
            .SYNOPSIS
            This function is used to add a device compliance policy using the Graph API REST interface
            .DESCRIPTION
            The function connects to the Graph API Interface and adds a device compliance policy
            .EXAMPLE
            Add-DeviceCompliancePolicy -JSON $JSON
            Adds an Android device compliance policy in Intune
            .NOTES
            NAME: Add-DeviceCompliancePolicy
            #>
            
            [cmdletbinding()]
            
            param
            (
                $JSON
            )
            
            $graphApiVersion = "v1.0"
            $Resource = "deviceManagement/deviceCompliancePolicies"
                
                try {
            
                    if($JSON -eq "" -or $JSON -eq $null){
            
                    write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red
            
                    }
            
                    else {
            
                    Test-JSON -JSON $JSON
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
                    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
            
                    }
            
                }
                
                catch {
            
                Write-Host
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Host "Response content:`n$responseBody" -f Red
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                write-host
                break
            
                }
            
            }

            #############################################  Add Compliance Assignment
        
            Function Add-DeviceCompliancePolicyAssignment(){

<#
.SYNOPSIS
This function is used to add a device compliance policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy assignment
.EXAMPLE
Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CompliancePolicyId -TargetGroupId $TargetGroupId
Adds a device compliance policy assignment in Intune
.NOTES
NAME: Add-DeviceCompliancePolicyAssignment
#>

[cmdletbinding()]

param
(
    $CompliancePolicyId,
    $TargetGroupId
)

$graphApiVersion = "v1.0"
$Resource = "deviceManagement/deviceCompliancePolicies/$CompliancePolicyId/assign"
    
    try {

        if(!$CompliancePolicyId){

        write-host "No Compliance Policy Id specified, specify a valid Compliance Policy Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

$JSON = @"

    {
        "assignments": [
        {
            "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId"
            }
        }
        ]
    }
    
"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

######################### Get AAD Group

Function Get-AADGroup(){

    <#
    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Groups registered with AAD
    .EXAMPLE
    Get-AADGroup
    Returns all users registered with Azure AD
    .NOTES
    NAME: Get-AADGroup
    #>
    
    [cmdletbinding()]
    
    param
    (
        $GroupName,
        $id,
        [switch]$Members
    )
    
    # Defining Variables
    $graphApiVersion = "v1.0"
    $Group_resource = "groups"
        
        try {
    
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=id eq '$id'"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
            }
            
            elseif($GroupName -eq "" -or $GroupName -eq $null){
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)"
            (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
            
            }
    
            else {
                
                if(!$Members){
    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
                (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
                
                }
                
                elseif($Members){
                
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)?`$filter=displayname eq '$GroupName'"
                $Group = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
                
                    if($Group){
    
                    $GID = $Group.id
    
                    $Group.displayName
                    write-host
    
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Group_resource)/$GID/Members"
                    (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
                    }
    
                }
            
            }
    
        }
    
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }


    ####################################  Create AAD Group

    Function Add-MDMApplication(){

<#
.SYNOPSIS
This function is used to add an MDM application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an MDM application from the itunes store
.EXAMPLE
Add-MDMApplication -JSON $JSON
Adds an application into Intune
.NOTES
NAME: Add-MDMApplication
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

    try {

        if(!$JSON){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Add-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

[cmdletbinding()]

param
(
    $ApplicationId,
    $TargetGroupId,
    $InstallIntent
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
    
    try {

        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        
        if(!$InstallIntent){

        write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
        break

        }

$JSON = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
    }
    ]
}
"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################


    Function Add-MDMApplication(){

<#
.SYNOPSIS
This function is used to add an MDM application using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an MDM application from the itunes store
.EXAMPLE
Add-MDMApplication -JSON $JSON
Adds an application into Intune
.NOTES
NAME: Add-MDMApplication
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

    try {

        if(!$JSON){

        write-host "No JSON was passed to the function, provide a JSON variable" -f Red
        break

        }

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken

    }

    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Add-ApplicationAssignment(){

<#
.SYNOPSIS
This function is used to add an application assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a application assignment
.EXAMPLE
Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
Adds an application assignment in Intune
.NOTES
NAME: Add-ApplicationAssignment
#>

[cmdletbinding()]

param
(
    $ApplicationId,
    $TargetGroupId,
    $InstallIntent
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
    
    try {

        if(!$ApplicationId){

        write-host "No Application Id specified, specify a valid Application Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        
        if(!$InstallIntent){

        write-host "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment" -f Red
        break

        }

$JSON = @"
{
    "mobileAppAssignments": [
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId"
        },
        "intent": "$InstallIntent"
    }
    ]
}
"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################


$JSON_Android = @"

    {
        "@odata.type":  "microsoft.graph.androidCompliancePolicy",
        "roleScopeTagIds":  [
                                "0"
                            ],
        "description":  "Android Compliance Policy",
        "displayName":  "Android Compliance Policy",
        "version":  2,
        "passwordRequired":  true,
        "passwordMinimumLength":  6,
        "passwordRequiredType":  "alphanumericWithSymbols",
        "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
        "passwordMinutesOfInactivityBeforeLock":  null,
        "passwordExpirationDays":  null,
        "passwordPreviousPasswordBlockCount":  null,
        "passwordSignInFailureCountBeforeFactoryReset":  null,
        "securityPreventInstallAppsFromUnknownSources":  false,
        "securityDisableUsbDebugging":  false,
        "securityRequireVerifyApps":  false,
        "deviceThreatProtectionEnabled":  false,
        "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
        "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
        "securityBlockJailbrokenDevices":  true,
        "securityBlockDeviceAdministratorManagedDevices":  false,
        "osMinimumVersion":  null,
        "osMaximumVersion":  null,
        "minAndroidSecurityPatchLevel":  null,
        "storageRequireEncryption":  true,
        "securityRequireSafetyNetAttestationBasicIntegrity":  false,
        "securityRequireSafetyNetAttestationCertifiedDevice":  false,
        "securityRequireGooglePlayServices":  false,
        "securityRequireUpToDateSecurityProviders":  false,
        "securityRequireCompanyPortalAppIntegrity":  false,
        "conditionStatementId":  null,
        "restrictedApps":  [
    
                           ]
    }

"@

####################################################

$JSON_iOS = @"

  {
  "@odata.type": "microsoft.graph.iosCompliancePolicy",
  "description": "iOS Compliance Policy",
  "displayName": "iOS Compliance Policy",
  "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
  "passcodeBlockSimple":  true,
    "passcodeExpirationDays":  null,
    "passcodeMinimumLength":  8,
    "passcodeMinutesOfInactivityBeforeLock":  null,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  null,
    "passcodePreviousPasscodeBlockCount":  null,
    "passcodeMinimumCharacterSetCount":  1,
    "passcodeRequiredType":  "alphanumeric",
    "passcodeRequired":  true,
    "osMinimumVersion":  null,
    "osMaximumVersion":  null,
    "osMinimumBuildVersion":  null,
    "osMaximumBuildVersion":  null,
    "securityBlockJailbrokenDevices":  true,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "managedEmailProfileRequired":  false,
    "restrictedApps":  [

                       ]
  }

"@

####################################################

$JSON_Win = @"
{
    "@odata.type": "microsoft.graph.windows10CompliancePolicy",
  "description": "Windows 10 Compliance Policy",
  "displayName": "Windows 10 Compliance Policy",
  "scheduledActionsForRule":[{"ruleName":"Win10Rule","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":""}]}],
    "passwordRequired":  false,
    "passwordBlockSimple":  false,
    "passwordRequiredToUnlockFromIdle":  false,
    "passwordMinutesOfInactivityBeforeLock":  null,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  null,
    "passwordMinimumCharacterSetCount":  null,
    "passwordRequiredType":  "deviceDefault",
    "passwordPreviousPasswordBlockCount":  null,
    "requireHealthyDeviceReport":  false,
    "osMinimumVersion":  null,
    "osMaximumVersion":  null,
    "mobileOsMinimumVersion":  null,
    "mobileOsMaximumVersion":  null,
    "earlyLaunchAntiMalwareDriverEnabled":  false,
    "bitLockerEnabled":  false,
    "secureBootEnabled":  false,
    "codeIntegrityEnabled":  false,
    "storageRequireEncryption":  true,
    "activeFirewallRequired":  false,
    "defenderEnabled":  false,
    "defenderVersion":  null,
    "signatureOutOfDate":  false,
    "rtpEnabled":  false,
    "antivirusRequired":  false,
    "antiSpywareRequired":  false,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "configurationManagerComplianceRequired":  false,
    "tpmRequired":  false,
    "validOperatingSystemBuildRanges":  [

                                        ]

}

"@


$JSON_AutoPilotGroup = @"
{
    "description": "SG-AutoPilotDevices",
    "displayName": "SG-AutoPilotDevices",
    "groupTypes": [
        "DynamicMembership"
    ],
    "mailNickname": "sg-autopilot",
    "mailEnabled": false,
    "securityEnabled": true,
    "membershipRule": '(device.devicePhysicalIDs -any _ -contains "[ZTDId]")',
    "membershipRuleProcessingState": "on"
}

"@

$JSON_IntuneUsersGroup = @"
{
    "description": "SG-IntuneUsers",
    "displayName": "SG-IntuneUsers",
    "groupTypes": [
    ],
    "mailNickname": "sg-intuneusers",
    "mailEnabled": false,
    "securityEnabled": true
}

"@

$JSON_ManuallyEnrolled = @"
{
    "description": "SG-ManuallyEnrolledDevices",
    "displayName": "SG-ManuallyEnrolledDevices",
    "groupTypes": [
    ],
    "mailNickname": "sg-ManuallyEnrolledDevices",
    "mailEnabled": false,
    "securityEnabled": true
}

"@

$Android = @"

{
    "@odata.type": "#microsoft.graph.androidGeneralDeviceConfiguration",
    "description": "",
    "displayName": "Android Device Restriction Policy",
    "appsBlockClipboardSharing":  false,
    "appsBlockCopyPaste":  false,
    "appsBlockYouTube":  false,
    "bluetoothBlocked":  false,
    "cameraBlocked":  false,
    "cellularBlockDataRoaming":  false,
    "cellularBlockMessaging":  false,
    "cellularBlockVoiceRoaming":  false,
    "cellularBlockWiFiTethering":  false,
    "compliantAppListType":  "none",
    "diagnosticDataBlockSubmission":  false,
    "locationServicesBlocked":  false,
    "googleAccountBlockAutoSync":  false,
    "googlePlayStoreBlocked":  false,
    "kioskModeBlockSleepButton":  false,
    "kioskModeBlockVolumeButtons":  false,
    "dateAndTimeBlockChanges":  false,
    "nfcBlocked":  false,
    "passwordBlockFingerprintUnlock":  false,
    "passwordBlockTrustAgents":  false,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  8,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  15,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "passwordRequiredType":  "alphanumericWithSymbols",
    "passwordRequired":  true,
    "powerOffBlocked":  false,
    "factoryResetBlocked":  false,
    "screenCaptureBlocked":  false,
    "deviceSharingAllowed":  false,
    "storageBlockGoogleBackup":  false,
    "storageBlockRemovableStorage":  false,
    "storageRequireDeviceEncryption":  true,
    "storageRequireRemovableStorageEncryption":  false,
    "voiceAssistantBlocked":  false,
    "voiceDialingBlocked":  false,
    "webBrowserBlockPopups":  false,
    "webBrowserBlockAutofill":  false,
    "webBrowserBlockJavaScript":  false,
    "webBrowserBlocked":  false,
    "webBrowserCookieSettings":  "browserDefault",
    "wiFiBlocked":  false,
    "securityRequireVerifyApps":  false,
    "compliantAppsList":  [

                          ],
    "kioskModeApps":  [

                      ],
    "appsInstallAllowList":  [

                             ],
    "appsLaunchBlockList":  [

                            ],
    "appsHideList":  [

                     ]
}

"@

$iOS = @"

{
    "@odata.type": "#microsoft.graph.iosGeneralDeviceConfiguration",
    "description": "",
    "displayName": "iOS Device Restriction Policy",
    "accountBlockModification":  false,
    "activationLockAllowWhenSupervised":  false,
    "airDropBlocked":  false,
    "airDropForceUnmanagedDropTarget":  false,
    "airPlayForcePairingPasswordForOutgoingRequests":  false,
    "appleWatchBlockPairing":  false,
    "appleWatchForceWristDetection":  false,
    "appleNewsBlocked":  false,
    "appsVisibilityListType":  "none",
    "appStoreBlockAutomaticDownloads":  false,
    "appStoreBlocked":  false,
    "appStoreBlockInAppPurchases":  false,
    "appStoreBlockUIAppInstallation":  false,
    "appStoreRequirePassword":  false,
    "autoFillForceAuthentication":  false,
    "bluetoothBlockModification":  false,
    "cameraBlocked":  false,
    "cellularBlockDataRoaming":  false,
    "cellularBlockGlobalBackgroundFetchWhileRoaming":  false,
    "cellularBlockPerAppDataModification":  false,
    "cellularBlockPersonalHotspot":  false,
    "cellularBlockPlanModification":  false,
    "cellularBlockVoiceRoaming":  false,
    "certificatesBlockUntrustedTlsCertificates":  false,
    "classroomAppBlockRemoteScreenObservation":  false,
    "classroomAppForceUnpromptedScreenObservation":  false,
    "classroomForceAutomaticallyJoinClasses":  false,
    "classroomForceUnpromptedAppAndDeviceLock":  false,
    "compliantAppListType":  "none",
    "configurationProfileBlockChanges":  false,
    "definitionLookupBlocked":  false,
    "deviceBlockEnableRestrictions":  false,
    "deviceBlockEraseContentAndSettings":  false,
    "deviceBlockNameModification":  false,
    "diagnosticDataBlockSubmission":  false,
    "diagnosticDataBlockSubmissionModification":  false,
    "documentsBlockManagedDocumentsInUnmanagedApps":  false,
    "documentsBlockUnmanagedDocumentsInManagedApps":  false,
    "emailInDomainSuffixes":  [

                              ],
    "enterpriseAppBlockTrust":  false,
    "enterpriseAppBlockTrustModification":  false,
    "esimBlockModification":  false,
    "faceTimeBlocked":  false,
    "findMyFriendsBlocked":  false,
    "gamingBlockGameCenterFriends":  false,
    "gamingBlockMultiplayer":  false,
    "gameCenterBlocked":  false,
    "hostPairingBlocked":  false,
    "iBooksStoreBlocked":  false,
    "iBooksStoreBlockErotica":  false,
    "iCloudBlockActivityContinuation":  false,
    "iCloudBlockBackup":  false,
    "iCloudBlockDocumentSync":  false,
    "iCloudBlockManagedAppsSync":  false,
    "iCloudBlockPhotoLibrary":  false,
    "iCloudBlockPhotoStreamSync":  false,
    "iCloudBlockSharedPhotoStream":  false,
    "iCloudRequireEncryptedBackup":  false,
    "iTunesBlockExplicitContent":  false,
    "iTunesBlockMusicService":  false,
    "iTunesBlockRadio":  false,
    "keyboardBlockAutoCorrect":  false,
    "keyboardBlockDictation":  false,
    "keyboardBlockPredictive":  false,
    "keyboardBlockShortcuts":  false,
    "keyboardBlockSpellCheck":  false,
    "kioskModeAllowAssistiveSpeak":  false,
    "kioskModeAllowAssistiveTouchSettings":  false,
    "kioskModeAllowAutoLock":  false,
    "kioskModeBlockAutoLock":  false,
    "kioskModeAllowColorInversionSettings":  false,
    "kioskModeAllowRingerSwitch":  false,
    "kioskModeBlockRingerSwitch":  false,
    "kioskModeAllowScreenRotation":  false,
    "kioskModeBlockScreenRotation":  false,
    "kioskModeAllowSleepButton":  false,
    "kioskModeBlockSleepButton":  false,
    "kioskModeAllowTouchscreen":  false,
    "kioskModeBlockTouchscreen":  false,
    "kioskModeEnableVoiceControl":  false,
    "kioskModeAllowVoiceControlModification":  false,
    "kioskModeAllowVoiceOverSettings":  false,
    "kioskModeAllowVolumeButtons":  false,
    "kioskModeBlockVolumeButtons":  false,
    "kioskModeAllowZoomSettings":  false,
    "kioskModeAppStoreUrl":  null,
    "kioskModeBuiltInAppId":  null,
    "kioskModeRequireAssistiveTouch":  false,
    "kioskModeRequireColorInversion":  false,
    "kioskModeRequireMonoAudio":  false,
    "kioskModeRequireVoiceOver":  false,
    "kioskModeRequireZoom":  false,
    "kioskModeManagedAppId":  null,
    "lockScreenBlockControlCenter":  false,
    "lockScreenBlockNotificationView":  false,
    "lockScreenBlockPassbook":  false,
    "lockScreenBlockTodayView":  false,
    "mediaContentRatingAustralia":  null,
    "mediaContentRatingCanada":  null,
    "mediaContentRatingFrance":  null,
    "mediaContentRatingGermany":  null,
    "mediaContentRatingIreland":  null,
    "mediaContentRatingJapan":  null,
    "mediaContentRatingNewZealand":  null,
    "mediaContentRatingUnitedKingdom":  null,
    "mediaContentRatingUnitedStates":  null,
    "mediaContentRatingApps":  "allAllowed",
    "messagesBlocked":  false,
    "notificationsBlockSettingsModification":  false,
    "passcodeBlockFingerprintUnlock":  false,
    "passcodeBlockFingerprintModification":  false,
    "passcodeBlockModification":  false,
    "passcodeBlockSimple":  true,
    "passcodeExpirationDays":  null,
    "passcodeMinimumLength":  8,
    "passcodeMinutesOfInactivityBeforeLock":  null,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  null,
    "passcodeMinimumCharacterSetCount":  null,
    "passcodePreviousPasscodeBlockCount":  null,
    "passcodeSignInFailureCountBeforeWipe":  null,
    "passcodeRequiredType":  "alphanumeric",
    "passcodeRequired":  true,
    "podcastsBlocked":  false,
    "proximityBlockSetupToNewDevice":  false,
    "safariBlockAutofill":  false,
    "safariBlockJavaScript":  false,
    "safariBlockPopups":  false,
    "safariBlocked":  false,
    "safariCookieSettings":  "browserDefault",
    "safariManagedDomains":  [

                             ],
    "safariPasswordAutoFillDomains":  [

                                      ],
    "safariRequireFraudWarning":  false,
    "screenCaptureBlocked":  false,
    "siriBlocked":  false,
    "siriBlockedWhenLocked":  false,
    "siriBlockUserGeneratedContent":  false,
    "siriRequireProfanityFilter":  false,
    "softwareUpdatesEnforcedDelayInDays":  null,
    "softwareUpdatesForceDelayed":  false,
    "spotlightBlockInternetResults":  false,
    "voiceDialingBlocked":  false,
    "wallpaperBlockModification":  false,
    "wiFiConnectOnlyToConfiguredNetworks":  false,
    "classroomForceRequestPermissionToLeaveClasses":  false,
    "keychainBlockCloudSync":  false,
    "pkiBlockOTAUpdates":  false,
    "privacyForceLimitAdTracking":  false,
    "enterpriseBookBlockBackup":  false,
    "enterpriseBookBlockMetadataSync":  false,
    "airPrintBlocked":  false,
    "airPrintBlockCredentialsStorage":  false,
    "airPrintForceTrustedTLS":  false,
    "airPrintBlockiBeaconDiscovery":  false,
    "filesNetworkDriveAccessBlocked":  false,
    "filesUsbDriveAccessBlocked":  false,
    "wifiPowerOnForced":  false,
    "blockSystemAppRemoval":  false,
    "vpnBlockCreation":  false,
    "appRemovalBlocked":  false,
    "usbRestrictedModeBlocked":  false,
    "passwordBlockAutoFill":  false,
    "passwordBlockProximityRequests":  false,
    "passwordBlockAirDropSharing":  false,
    "dateAndTimeForceSetAutomatically":  false,
    "contactsAllowManagedToUnmanagedWrite":  false,
    "contactsAllowUnmanagedToManagedRead":  false,
    "cellularBlockPersonalHotspotModification":  false,
    "continuousPathKeyboardBlocked":  false,
    "findMyDeviceInFindMyAppBlocked":  false,
    "findMyFriendsInFindMyAppBlocked":  false,
    "iTunesBlocked":  false,
    "appsSingleAppModeList":  [

                              ],
    "appsVisibilityList":  [

                           ],
    "compliantAppsList":  [

                          ],
    "networkUsageRules":  [

                          ]
}

"@


$mac = @"

{
    "@odata.type": "#microsoft.graph.macOSGeneralDeviceConfiguration",
    "description": "",
    "displayName": "MacOS Device Restriction Policy",
    "compliantAppListType":  "none",
    "emailInDomainSuffixes":  [

                              ],
    "passwordBlockSimple":  true,
    "passwordExpirationDays":  null,
    "passwordMinimumCharacterSetCount":  1,
    "passwordMinimumLength":  8,
    "passwordMinutesOfInactivityBeforeLock":  15,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  10,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordRequiredType":  "alphanumeric",
    "passwordRequired":  true,
    "keychainBlockCloudSync":  false,
    "airPrintBlocked":  false,
    "airPrintForceTrustedTLS":  false,
    "airPrintBlockiBeaconDiscovery":  false,
    "safariBlockAutofill":  false,
    "cameraBlocked":  false,
    "iTunesBlockMusicService":  false,
    "spotlightBlockInternetResults":  false,
    "keyboardBlockDictation":  false,
    "definitionLookupBlocked":  false,
    "appleWatchBlockAutoUnlock":  false,
    "iTunesBlockFileSharing":  false,
    "iCloudBlockDocumentSync":  false,
    "iCloudBlockMail":  false,
    "iCloudBlockAddressBook":  false,
    "iCloudBlockCalendar":  false,
    "iCloudBlockReminders":  false,
    "iCloudBlockBookmarks":  false,
    "iCloudBlockNotes":  false,
    "airDropBlocked":  false,
    "passwordBlockModification":  false,
    "passwordBlockFingerprintUnlock":  false,
    "passwordBlockAutoFill":  false,
    "passwordBlockProximityRequests":  false,
    "passwordBlockAirDropSharing":  false,
    "softwareUpdatesEnforcedDelayInDays":  null,
    "softwareUpdatesForceDelayed":  false,
    "contentCachingBlocked":  false,
    "iCloudBlockPhotoLibrary":  false,
    "screenCaptureBlocked":  false,
    "classroomAppBlockRemoteScreenObservation":  false,
    "classroomAppForceUnpromptedScreenObservation":  false,
    "classroomForceAutomaticallyJoinClasses":  false,
    "classroomForceRequestPermissionToLeaveClasses":  false,
    "classroomForceUnpromptedAppAndDeviceLock":  false,
    "iCloudBlockActivityContinuation":  false,
    "compliantAppsList":  [

                          ]
}

"@

$office365 = @"
{
  "@odata.type": "#microsoft.graph.officeSuiteApp",
  "autoAcceptEula": true,
  "description": "Office 365 ProPlus - Assigned",
  "developer": "Microsoft",
  "displayName": "Office 365 ProPlus - Assigned",
  "excludedApps": {
    "groove": true,
    "infoPath": true,
    "sharePointDesigner": true
  },
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "localesToInstall": [
    "en-us"
  ],
  "notes": "",
  "officePlatformArchitecture": "x86",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "productIds": [
    "o365ProPlusRetail",
    "projectProRetail",
    "visioProRetail"
  ],
  "publisher": "Microsoft",
  "updateChannel": "firstReleaseCurrent",
  "useSharedComputerActivation": false
}
"@


#################################################### Create AD Group

Function Add-AADGroup(){

    <#
    .SYNOPSIS
    This function is used to add a device compliance policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device compliance policy
    .EXAMPLE
    Add-DeviceCompliancePolicy -JSON $JSON
    Adds an Android device compliance policy in Intune
    .NOTES
    NAME: Add-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "v1.0"
    $Resource = "groups"
        
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
            }
    
        }
        
        catch {
    
        Write-Host
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }


########################## Config Policy


####################################################

Function Add-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
Write-Verbose "Resource: $DCP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Add-DeviceConfigurationPolicyAssignment(){

<#
.SYNOPSIS
This function is used to add a device configuration policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy assignment
.EXAMPLE
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
Adds a device configuration policy assignment in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicyAssignment
#>

[cmdletbinding()]

param
(
    $ConfigurationPolicyId,
    $TargetGroupId
)

$graphApiVersion = "Beta"
$Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assign"
    
    try {

        if(!$ConfigurationPolicyId){

        write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
        break

        }

        if(!$TargetGroupId){

        write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
        break

        }

        $ConfPolAssign = "$ConfigurationPolicyId" + "_" + "$TargetGroupId"

$JSON = @"

{
  "deviceConfigurationGroupAssignments": [
    {
      "@odata.type": "#microsoft.graph.deviceConfigurationGroupAssignment",
      "id": "$ConfPolAssign",
      "targetGroupId": "$TargetGroupId"
    }
  ]
}

"@

    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

    }
    
    catch {

    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################










################## AUTH

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion


############################################
            



        $menu="
        1 Create Azure AD Groups
        2 Import and Assign Compliance Policies
        3 Import and Assign Configuration Policies
        4 Deploy Office 365 ProPlus
                                
       Plese select a task by number or Q to quit
                               "        
Write-Host $menu -ForegroundColor Cyan
$choice = Read-Host

Switch ($choice) {
    "1" {

       # Write-Host "Creating AutoPilot"
       # Add-AADGroup -JSON $JSON_AutoPilotGroup

        Write-Host "Creating Intune Users Group"
        Add-AADGroup -JSON $JSON_IntuneUsersGroup

        Write-Host "Creating Intune Manually Enrolled Devices Group"
        Add-AADGroup -JSON $JSON_ManuallyEnrolled



    }

    "2"{

####################################################

# Setting application user AAD Group

#$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned"
$UserAADGroup = "SG-IntuneUsers"
$UserTargetGroupId = (get-AADGroup -GroupName "$UserAADGroup").id

    if($UserTargetGroupId -eq $null -or $UserTargetGroupId -eq ""){

    Write-Host "AAD Group - '$UserAADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host


# Setting application computer AAD Group

#$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned"
$ComputerAADGroup = "SG-ManuallyEnrolledDevices"
$ComputerTargetGroupId = (get-AADGroup -GroupName "$ComputerAADGroup").id

    if($ComputerTargetGroupId -eq $null -or $ComputerTargetGroupId -eq ""){

    Write-Host "AAD Group - '$ComputerAADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host

####################################################

Write-Host "Adding Android Compliance Policy from JSON..." -ForegroundColor Yellow

$CreateResult_Android = Add-DeviceCompliancePolicy -JSON $JSON_Android

Write-Host "Compliance Policy created as" $CreateResult_Android.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$UserAADGroup'" -f Cyan

$Assign_Android = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_Android.id -TargetGroupId $UserTargetGroupId

Write-Host "Assigned '$UserAADGroup' to $($CreateResult_Android.displayName)/$($CreateResult_Android.id)"
Write-Host

####################################################

Write-Host "Adding iOS Compliance Policy from JSON..." -ForegroundColor Yellow
Write-Host

$CreateResult_iOS = Add-DeviceCompliancePolicy -JSON $JSON_iOS

Write-Host "Compliance Policy created as" $CreateResult_iOS.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$UserAADGroup'" -f Cyan

$Assign_iOS = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_iOS.id -TargetGroupId $UserTargetGroupId

Write-Host "Assigned '$UserAADGroup' to $($CreateResult_iOS.displayName)/$($CreateResult_iOS.id)"
Write-Host

####################################################


Write-Host "Adding Win 10 Compliance Policy from JSON..." -ForegroundColor Yellow
Write-Host

$CreateResult_win = Add-DeviceCompliancePolicy -JSON $JSON_Win

Write-Host "Compliance Policy created as" $CreateResult_win.id
write-host
write-host "Assigning Compliance Policy to AAD Group '$UserAADGroup'" -f Cyan

$Assign_win = Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CreateResult_win.id -TargetGroupId $UserTargetGroupId

Write-Host "Assigned '$UserAADGroup' to $($CreateResult_win.displayName)/$($CreateResult_win.id)"
Write-Host






    }

    "3" {

# Setting application user AAD Group

#$AADGroup = Read-Host -Prompt "Enter the Azure AD Group name where policies will be assigned"
$UserAADGroup = "SG-IntuneUsers"
$UserTargetGroupId = (get-AADGroup -GroupName "$UserAADGroup").id

    if($UserTargetGroupId -eq $null -or $UserTargetGroupId -eq ""){

    Write-Host "AAD Group - '$UserAADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
    Write-Host
    exit

    }

Write-Host        

################################


Write-Host "Adding Android Device Restriction Policy from JSON..." -ForegroundColor Yellow

$CreateResult_AndroidConfig = Add-DeviceConfigurationPolicy -JSON $Android

Write-Host "Device Restriction Policy created as" $CreateResult_AndroidConfig.id
write-host
write-host "Assigning Device Restriction Policy to AAD Group '$UserAADGroup'" -f Cyan

$Assign_AndroidConfig = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_AndroidConfig.id -TargetGroupId $UserTargetGroupId

Write-Host "Assigned '$UserAADGroup' to $($CreateResult_AndroidConfig.displayName)/$($CreateResult_AndroidConfig.id)"
Write-Host

#####################

Write-Host "Adding iOS Device Restriction Policy from JSON..." -ForegroundColor Yellow

$CreateResult_iosconfig = Add-DeviceConfigurationPolicy -JSON $ios

Write-Host "Device Restriction Policy created as" $CreateResult_iosConfig.id
write-host
write-host "Assigning Device Restriction Policy to AAD Group '$UserAADGroup'" -f Cyan

$Assign_iosConfig = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_iosConfig.id -TargetGroupId $UserTargetGroupId

Write-Host "Assigned '$UserAADGroup' to $($CreateResult_iosConfig.displayName)/$($CreateResult_iosConfig.id)"
Write-Host

#####################

Write-Host "Adding MacOS Device Restriction Policy from JSON..." -ForegroundColor Yellow

$CreateResult_macosconfig = Add-DeviceConfigurationPolicy -JSON $mac

Write-Host "Device Restriction Policy created as" $CreateResult_macosconfig.id
write-host
write-host "Assigning Device Restriction Policy to AAD Group '$UserAADGroup'" -f Cyan

$Assign_macosConfig = Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $CreateResult_macosConfig.id -TargetGroupId $UserTargetGroupId

Write-Host "Assigned '$UserAADGroup' to $($CreateResult_macosConfig.displayName)/$($CreateResult_macossConfig.id)"
Write-Host




    }

    "4"{

        $ComputerAADGroup = "SG-ManuallyEnrolledDevices"
        $ComputerTargetGroupId = (get-AADGroup -GroupName "$ComputerAADGroup").id
        
            if($ComputerTargetGroupId -eq $null -or $ComputerTargetGroupId -eq ""){
        
            Write-Host "AAD Group - '$ComputerAADGroup' doesn't exist, please specify a valid AAD Group..." -ForegroundColor Red
            Write-Host
            exit
        
            }

Write-Host        


write-host "Publishing" ($office365 | ConvertFrom-Json).displayName -ForegroundColor Yellow

$Create_Application = Add-MDMApplication -JSON $office365

Write-Host "Application created as $($Create_Application.displayName)/$($create_Application.id)"

$ApplicationId = $Create_Application.id

$Assign_Application = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $ComputerTargetGroupId -InstallIntent "required"
Write-Host "Assigned '$ComputerAADGroup' to $($Create_Application.displayName)/$($Create_Application.id) with" $Assign_Application.InstallIntent "install Intent"

Write-Host




    }


    "Q" {
        Write-Host "Good bye!" -ForegroundColor Green
    }
     
    default {
        Write-Host "Invalid choice, please try again." -ForegroundColor Yellow
     }


}




