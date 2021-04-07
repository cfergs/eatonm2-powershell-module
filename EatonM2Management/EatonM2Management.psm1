Function Connect-EatonM2 {
  <#
  .SYNOPSIS
    Connect to M2 UPS.

  .PARAMETER UserName
    Username.

  .PARAMETER Passwd
    Password.

  .PARAMETER Credential
    Secure credentials entered from a Get-Credentials variable

  .PARAMETER Card
    Card IP or hostname.

  .EXAMPLE
    #Connect using clear text credentials (only good for initially setting up a new UPS)
    Connect-EatonM2 -Card 192.168.0.1 -UserName admin -Passwd admin

  .EXAMPLE
    #Connect using secure credential
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
  #>

  Param (
    [string]$UserName,
    [string]$Passwd,
    [PSCredential]$Credential,
    [Parameter(Mandatory=$true)][string]$Card
  )

  if($Passwd) {
    $Password = $Passwd
  }

  # Check using Powershell v7
  If(!($PSVersionTable.PSVersion.Major -ge 7)) {
    Write-Information -MessageData "Exiting. This can only be run on powershell 7 or newer" -InformationAction Continue
    return
  }

  if($PSBoundParameters.ContainsKey('Credential')) {
    $username = $Credential.UserName
    $password = $Credential.GetNetworkCredential().Password
  }

  if(!$username -or !$password) {
    Write-Information -MessageData "ERROR: No credentials specified. Exiting" -InformationAction Continue
    return
  }

  try {
    $global:headers = $null
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")

    $body = "{
      `n    `"username`":`"$Username`",
      `n    `"password`":`"$Password`",
      `n    `"grant_type`":`"password`",
      `n    `"scope`":`"GUIAccess`"
      `n}"

    $response = Invoke-RestMethod "https://$Card/rest/mbdetnrs/1.0/oauth2/token" -Method 'POST' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop

    # 1.1 Add accesstoken
    $headers.Add("Authorization", "Bearer $($response.access_token)")
    $headers.Add("UPSCard", "$($Card)")

    Write-Information -MessageData "Connected to UPS: $Card" -InformationAction Continue
    $global:headers = $headers

  } catch {
    Write-Information -MessageData "ERROR: Unable to connect to $Card." -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2FirmwareVersion {
  <#
  .SYNOPSIS
    Get firmware version.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Get-M2FirmwareVersion
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/firmwares" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    $value = $(($response.members | Where-Object {$_.status -eq 4}).firmwareversion)
  } catch {
    Write-Information -MessageData "ERROR: Unable to get firmware version" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $value
}

Function Get-M2SystemDetails {
  <#
  .SYNOPSIS
    Get system details.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Get-M2SystemDetails
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/identification/" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to get UPS details" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
  return $response
}

Function Set-M2SystemDetails {
  <#
  .SYNOPSIS
    Set system details.

  .PARAMETER UPSName
    Name of UPS.

  .PARAMETER EmailContact
    Email address of who will be supporting the UPS. Field can only contain an email address.

  .PARAMETER Location
    Specify the physical location of the UPS.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Set-M2SystemDetails -UPSName EXUPS01 -EmailContact user@example.com -Location "Server Room 1"
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$UPSName,
    [string]$EmailContact,
    [string]$Location
  )

  #Input sanitization
  $UPSName = $UPSName.ToUpper()

  try {
    $body = "{
      `n    `"name`": `"$UPSName`",
      `n    `"contact`": `"$EmailContact`",
      `n    `"location`": `"$Location`"
      `n}"

    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/identification/" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set UPS Details" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to set UPS details" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2NTPSettings {
  <#
  .SYNOPSIS
    Get NTP settings set on the card.

  .EXAMPLE
    #Get settings
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $response = Get-M2NTPSettings
    $response
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/timeService" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to get NTP details" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Set-M2NTPSettings {
  <#
  .SYNOPSIS
    Set NTP details.

  .PARAMETER TimeZone
    Timezone for the UPS card.

  .PARAMETER Enabled
    If NTP will be enabled or not. Can either be True or False.

  .PARAMETER NTPServer1
    First NTP server. Specify as fqdn or IP address.

  .PARAMETER NTPServer2
    Second NTP server. Specify as fqdn or IP address.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Set-M2NTPSettings -TimeZone 'Pacific/Auckland' -Enabled true -NTPServer1 ntp.example.com
  #>

  Param (
    [string]$TimeZone = 'Pacific/Auckland',
    [bool]$Enabled = $true,
    [string]$NTPServer1,
    [string]$NTPServer2
  )

  if($enabled -eq $true){
    $enabledvalue = "true"
  } else {
    $enabledvalue = "false"
  }

  $body = "{
    `n    `"timeZone`": `"$TimeZone`",
    `n    `"ntp`": {
    `n        `"enabled`": $enabledvalue,
    `n        `"servers`": {
    `n        	`"preferredServer`": `"$NTPServer1`",
    `n        	`"alternateServer`": `"$NTPServer2`"
    `n        }
    `n    }
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/timeService" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set NTP details" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to set NTP details" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2SMTPGlobalSettings {
  <#
  .SYNOPSIS
    Get SMTP Server Settings currently set on the card.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Get-M2SMTPGlobalSettings
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/smtp" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to get mail server settings" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Set-M2SMTPGlobalSettings {
  <#
  .SYNOPSIS
    Set SMTP Server Settings.

  .PARAMETER Enabled
    Global option to enable or disable sending of email. By default set to true.

  .PARAMETER EmailServer
    EmailServer that will route the mail to recipients.

  .PARAMETER SMTPPort
    SMTP port for receiving email traffic on emailserver. By default set to 25.

  .PARAMETER RequireAuth
    Specify if authentication is required to send email. By default set to false.

  .PARAMETER EmailUser
    Username required to send email (only needed if RequireAuth enabled).

  .PARAMETER EmailPwd
    Password of user required to send email (only needed if RequireAuth enabled).

  .PARAMETER FromAddress
    Email address of UPS card (uniquely idenfify what device is sending it).

  .PARAMETER TLSSecurityProtocol
    This determines the protocol used when TLS is enabled. The options are none, StartTLS or SSL. Depending on the firmware version what is sent to the API will be different

    For 1.7.5
    none is set to false. Selecting StartTLS or SSL will set it to true

    For 2.0.5 ->
    In the API their set with values 1,2,3 (respectively). The default is none (0).

  .PARAMETER VerifyTLSCert
    Will TLS cert be validated before email can be sent. By default set to false.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Set-M2SMTPGlobalSettings -EmailServer smtp.example.com -FromAddress UPS01@example.com -Enabled $true
  #>

  Param (
    [bool]$Enabled = $true,
    [Parameter(Mandatory=$true)][string]$EmailServer,
    [string]$SMTPPort = 25,
    [bool]$RequireAuth = $false,
    [string]$EmailUser,
    [string]$EmailPwd,
    [Parameter(Mandatory=$true)][string]$FromAddress,
    [ValidateSet('None','StartTLS','SSL')][string]$TLSSecurityProtocol = "None",
    [bool]$VerifyTLSCert = $false
  )

  if($Enabled -eq $true){
    $EnabledValue = "true"
  } else {
    $EnabledValue = "false"
  }

  if($RequireAuth -eq $true){
    $RequireAuthValue = "true"
  } else {
    $RequireAuthValue = "false"
  }

  if($VerifyTLSCert -eq $true){
    $VerifyTLSCertValue = "true"
  } else {
    $VerifyTLSCertValue = "false"
  }

  # 1.7.5 uses different settings for auth vs 2.0.5 ->
  $UPSFirmwareversion = Get-M2FirmwareVersion
  if($UPSFirmwareversion -like '1.7.5') {
    if($TLSSecurityProtocol -like 'none'){
      $tlsline = "`"requireTls`": false,`n`"verifyTlsCert`": $VerifyTLSCertValue"
    } else {
      $tlsline = "`"requireTls`": true,`n`"verifyTlsCert`": $VerifyTLSCertValue"
    }
  }

  if($UPSFirmwareversion -gt '1.7.5') {
    if($TLSSecurityProtocol -like 'none') { #set as 0
      $tlsline = "`"security`": {`n`"ssl`": 0,`n`"verifyTlsCert`": $VerifyTLSCertValue`n}"
    } elseif($TLSSecurityProtocol -like 'starttls') { #set as 1
      $tlsline = "`"security`": {`n`"ssl`": 1,`n`"verifyTlsCert`": $VerifyTLSCertValue`n}"
    } elseif($TLSSecurityProtocol -like 'ssl') { #set as 2
      $tlsline = "`"security`": {`n`"ssl`": 2,`n`"verifyTlsCert`": $VerifyTLSCertValue`n}"
    }
  }

  $body = "{
    `n  `"serviceAvailable`": false,
    `n  `"enabled`": $Enabledvalue,
    `n  `"server`": `"$EmailServer`",
    `n  `"port`": $SMTPPort,
    `n  `"requireAuth`": $RequireAuthValue,
    `n  `"user`": `"$EmailUser`",
    `n  `"password`": `"$EmailPwd`",
    `n  `"fromAddress`": `"$FromAddress`",
    `n  $tlsline
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/smtp" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set email server as $EmailServer" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to set email server" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2EmailAlertConfigurations {
  <#
  .SYNOPSIS
    Get the email alert configurations set on the card.

  .DESCRIPTION
    This command will provide all the Email Alert configurations that have been created. There is no current option to simply specify an individual configuration.

    This command will only display the id of each alert and is useless on it's own. To get detailed information you will be piping this commands output to Get-M2EmailAlertIndividualConfiguration.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Get-M2EmailAlertConfigurations
  #>

  # 1.7.5 uses different URL
  $UPSFirmwareversion = Get-M2FirmwareVersion
  if($UPSFirmwareversion -like '1.7.5') {
    $url = "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/emailService/configurations"
  } else {
    $url = "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/emailService/settings/configurations"
  }

  try {
    $response = Invoke-RestMethod $url -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to get email notification alerts" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Get-M2EmailAlertIndividualConfiguration {
  <#
  .SYNOPSIS
    Get the settings of an individual email alert.

  .DESCRIPTION
    The Get-M2EmailAlertIndividualConfiguration provides detailed information about a configured email alert.

    This email alert will either be specified manually using the EmailAlertID parameter or by piping it in using the Get-M2EmailAlertConfiguration command.

  .PARAMETER EmailAlertID
    ID of EmailAlert. EG '/rest/mbdetnrs/1.0/managers/1/emailService/settings/configurations/1CWe1JeETuywOjd9z-l2MQ'

  .EXAMPLE
    #Show details for every email alert
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $emailalerts = (Get-M2EmailAlertConfigurations).Members
    foreach($emailalert in $emailalerts) {
      Get-M2EmailAlertIndividualConfiguration -EmailAlertID $emailalert
    }

  .EXAMPLE
    #Pipe in a specified email alert - in this case the second alert
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    (Get-M2EmailAlertConfigurations).Members[1] | Get-M2EmailAlertIndividualConfiguration

  .EXAMPLE
    #Display details without piping - note that ID string is different from 1.7.5 vs 2.0.5 ->
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Get-M2EmailAlertIndividualConfiguration -EmailAlertID '/rest/mbdetnrs/1.0/managers/1/emailService/configurations/12345678_90123'
  #>

  Param (
    [Parameter(Mandatory=$true,ValueFromPipeline)][string]$EmailAlertID
  )

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)$($EmailAlertID -replace '@{@id=' -replace '}')" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to get email notification alerts" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Set-M2EmailAlertNotification {
  <#
  .SYNOPSIS
    Create an email alert notification.

  .DESCRIPTION
    This email alert notification will be sent when predetermined events occur. These are for powerloss or UPS faults.

  .PARAMETER AlertName
    The name of the email alert. By default this is set to 'emailalert'

  .PARAMETER Recipient
    Who will receive the email.

  .EXAMPLE
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Set-M2EmailAlertNotification -Recipient recipient@example.com
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$Recipient,
    [string]$AlertName = 'emailalert'
  )

  $body = "{
    `n    `"name`": `"$AlertName`",
    `n    `"emailAddress`": `"$Recipient`",
    `n    `"enabled`": true,
    `n    `"notifyOnEvent`": {
    `n        `"enabled`": true,
    `n        `"cardEvents`": {
    `n            `"critical`": {
    `n                `"subscribe`": true,
    `n                `"attachEventsLog`": true
    `n            },
    `n            `"warning`": {
    `n                `"subscribe`": true,
    `n                `"attachEventsLog`": false
    `n            },
    `n            `"info`": {
    `n                `"subscribe`": false,
    `n                `"attachEventsLog`": false
    `n            }
    `n        },
    `n        `"devicesEvents`": {
    `n            `"critical`": {
    `n                `"subscribe`": true,
    `n                `"attachEventsLog`": true,
    `n                `"attachMeasuresLog`": false
    `n            },
    `n            `"warning`": {
    `n                `"subscribe`": true,
    `n                `"attachEventsLog`": false,
    `n                `"attachMeasuresLog`": false
    `n            },
    `n            `"info`": {
    `n                `"subscribe`": false,
    `n                `"attachEventsLog`": false,
    `n                `"attachMeasuresLog`": false
    `n            }
    `n        },
    `n        `"exceptions`": {
    `n            `"notifiedEvents`": `"`",
    `n            `"noneNotifiedEvents`": `"`"
    `n        }
    `n    },
    `n    `"periodicReport`": {
    `n        `"enabled`": false,
    `n        `"card`": {
    `n            `"subscribe`": false,
    `n            `"attachEventsLog`": false
    `n        },
    `n        `"devices`": {
    `n            `"subscribe`": false,
    `n            `"attachEventsLog`": false,
    `n            `"attachMeasuresLog`": false
    `n        }
    `n    },
    `n    `"message`": {
    `n        `"sender`": `"`",
    `n        `"subject`": `"`"
    `n    }
    `n}"

  # 1.7.5 uses different URL
  $UPSFirmwareversion = Get-M2FirmwareVersion
  if($UPSFirmwareversion -like '1.7.5') {
    $url = "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/emailService/configurations"
  } else {
    $url = "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/emailService/settings/configurations"
  }

  try {
    $response = Invoke-RestMethod $url -Method 'POST' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set email notification alert for recipient: $Recipient" -InformationAction Continue
    $emailid = $response.id
  } catch {
    Write-Information -MessageData "ERROR: Unable to set email notification alert to recipient: $Recipient" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $emailid
}

Function Remove-M2EmailAlertNotification {
  <#
  .SYNOPSIS
    Remove a specific email alert

  .PARAMETER AlertID
    ID of Alert. EG '/rest/mbdetnrs/1.0/managers/1/emailService/settings/configurations/1CWe1JeETuywOjd9z-l2MQ'

  .EXAMPLE
    #Remove all Email Alert Notification Settings
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $emailalerts = (Get-M2EmailAlertConfigurations).Members
    foreach($emailalert in $emailalerts) {
      Remove-M2EmailAlertNotification -AlertID $emailalert
    }

  .EXAMPLE
    #Remove only 1 email alert notification
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Remove-M2EmailAlertNotification -AlertID '/rest/mbdetnrs/1.0/managers/1/emailService/settings/configurations/1CWe1JeETuywOjd9z-l2MQ'
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$AlertID
  )

  try {
    $remove =  Invoke-RestMethod "https://$($headers.UPSCard)$($AlertID -replace '@{@id=' -replace '}')" -Method 'DELETE' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Deleted $($AlertID -replace '@{@id=' -replace '}')" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to delete $($AlertID -replace '@{@id=' -replace '}')" -InformationAction Continue
  }
}

Function Test-M2EmailAlertNotification {
  <#
  .SYNOPSIS
    Test email alert.

  .PARAMETER AlertID
    ID of alert. This will be it's shortened ID vs the /rest/ URL.

  .EXAMPLE
    #Test sending email after setting an alert
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $emailnotif = Set-M2EmailAlertNotification -Recipient recipient@example.com
    Test-M2EmailAlertNotification -AlertID $emailnotif

  .EXAMPLE
    #Test email notification seperately
    Connect using secure credential
    $cred = Get-Credential
    Test-M2EmailAlertNotification -AlertID '1CWe1JeETuywOjd9z-l2MQ'
  #>

  Param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$AlertID
  )

  # 1.7.5 uses different URL
  $UPSFirmwareversion = Get-M2FirmwareVersion
  if($UPSFirmwareversion -like '1.7.5') {
    $url = "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/emailService/configurations/$AlertID/actions/test"
  } else {
    $url = "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/emailService/settings/configurations/$AlertID/actions/test"
  }

  $response = Invoke-RestMethod $url -Method 'POST' -Headers $headers -SkipCertificateCheck
  if($response.retVal -like 'OK') {
    Write-Information -MessageData "SUCCESS: Sending Test email" -InformationAction Continue
  } else {
    Write-Information -MessageData "ERROR: Test email not sent. Please investigate" -InformationAction Continue
  }
}

Function Get-M2LDAPProvider {
  <#
  .SYNOPSIS
    Get LDAP Provider settings.

  .DESCRIPTION
    This command shows all LDAP provider settings. Running the command on it's own will only show the top level of LDAP settings - Refer to the EXAMPLES for this command on how to get information about baseAccess or requestParameter settings.

  .EXAMPLE
    #Get overall settings
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Get-M2LDAPProvider

  .EXAMPLE
    #Get PrimaryLDAP settings
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    (Get-M2LDAPProvider).baseAccess

  .EXAMPLE
    #Get uid/group settings
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    (Get-M2LDAPProvider).requestParameters
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/remoteAccounts/providers/ldap" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to get LDAP config" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Set-M2LDAPProvider {
  <#
  .SYNOPSIS
    Setup LDAP Provider.

  .PARAMETER Enabled
    Enabled = True or false. Default is true.

  .PARAMETER VerifyTLSCert
    True or false. Default is false.

  .PARAMETER PrimaryLDAPName
    Name you will call the primary ldap config.

  .PARAMETER PrimaryLDAPHostName
    Hostname of LDAP server.

  .PARAMETER PrimaryLDAPPort
    389 or 636. Defaults to 636.

  .PARAMETER SecondaryLDAPName
    Name you will call the secondary ldap config.

  .PARAMETER SecondaryLDAPHostName
    Hostname of secondary LDAP server.

  .PARAMETER SecondaryLDAPPort
    Port for the secondary LDAP server. By default this is set to 0 as typically only the PrimaryLDAP values are required - if no value is set then this breaks the whole command.

  .PARAMETER CredentialsAnonymousSearchBind
    Either set this value to True or false. By default is set to false.

  .PARAMETER SearchUserDN
    Credentials used to connect to LDAP.

  .PARAMETER SearchUserPwd
    Password for SearchUser account.

  .PARAMETER SearchBaseDN
    Top searchbase. Typically DC=example,DC=com.

  .PARAMETER RequestAttribute
    Set to sAMAccountName by default.

  .PARAMETER RequestSID
    The ObjectSID to look for. This will be the domainSID of your LDAP environment.It will be in the format of: 'objectSID:S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX'. Refer to http://portal.sivarajan.com/2011/09/objectsid-and-active-directory.html for further details.

  .EXAMPLE
    #Setup PrimaryLDAP settings
    $cred = Get-Credential
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    Set-M2LDAPProvider -Enabled $true -VerifyTLSCert $false -PrimaryLDAPName 'LDAP1' PrimaryLDAPHostName 'ldap1.example.com' -SearchUserDN 'CN=svc.upsauth,DC=example,DC=com' -SearchUserPwd Password1 -SearchBaseDN 'DC=example,DC=com' -RequestSID 'objectSID:S-1-5-21-XXXXXXXXX-XXXXXXXXX-XXXXXXXXX'
  #>

  Param (
    [bool]$Enabled,
    [bool]$VerifyTLSCert = $false,
    [string]$PrimaryLDAPName,
    [string]$PrimaryLDAPHostName,
    [string]$PrimaryLDAPPort = 636,
    [string]$SecondaryLDAPName,
    [string]$SecondaryLDAPHostName,
    [string]$SecondaryLDAPPort = 0,
    [bool]$CredentialsAnonymousSearchBind = $false,
    [string]$SearchUserDN,
    [string]$SearchUserPwd,
    [string]$SearchBaseDN,
    [string]$RequestAttribute = 'sAMAccountName',
    [string]$RequestSID
  )

  if($enabled -eq $true){
    $enabledvalue = "true"
  } else {
    $enabledvalue = "false"
  }

  if($VerifyTLSCert -eq $true){
    $VerifyTLSCertValue = "true"
  } else {
    $VerifyTLSCertValue = "false"
  }

  if($CredentialsAnonymousSearchBind -eq $true){
    $CredentialsAnonymousSearchBindValue = "true"
  } else {
    $CredentialsAnonymousSearchBindValue = "false"
  }

  $body = "{
    `n    `"enabled`": $enabledvalue,
    `n    `"baseAccess`": {
    `n        `"security`": {
    `n            `"ssl`": 3,
    `n            `"verifyTlsCert`": $VerifyTLSCertValue
    `n        },
    `n        `"primary`": {
    `n            `"name`": `"$PrimaryLDAPName`",
    `n            `"hostname`": `"$PrimaryLDAPHostName`",
    `n            `"port`": $PrimaryLDAPPort
    `n        },
    `n        `"secondary`": {
    `n            `"name`": `"$SecondaryLDAPName`",
    `n            `"hostname`": `"$SecondaryLDAPHostName`",
    `n            `"port`": $SecondaryLDAPPort
    `n        },
    `n        `"credentials`": {
    `n            `"anonymousSearchBind`": $CredentialsAnonymousSearchBindValue,
    `n            `"searchUserDN`": `"$SearchUserDN`",
    `n            `"password`": `"$SearchUserPwd`"
    `n        },
    `n        `"searchBase`": {
    `n            `"searchBaseDN`": `"$SearchBaseDN`"
    `n        }
    `n    },
    `n    `"requestParameters`": {
    `n        `"userBaseDN`": `"$SearchBaseDN`",
    `n        `"userNameAttribute`": `"$RequestAttribute`",
    `n        `"uidAttribute`": `"$RequestSID`",
    `n        `"groupBaseDN`": `"$SearchBaseDN`",
    `n        `"groupNameAttribute`": `"$RequestAttribute`",
    `n        `"gidAttribute`": `"$RequestSID`"
    `n    }
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/remoteAccounts/providers/ldap" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set LDAP Config" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to set LDAP config" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2LDAPMapping {
  <#
  .SYNOPSIS
    Get LDAP remote group mapping.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2LDAPMapping
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/remoteAccounts/providers/ldap/profileMapping/" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to get LDAP Mappings" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $($response.members)
}

Function Set-M2LDAPMapping {
  <#
  .SYNOPSIS
    Map a remote LDAP group to a internal group role. Allowing login to members of that LDAP group

  .PARAMETER LDAPGroup
    Name of the LDAP group from AD.

  .PARAMETER MappedProfile
    What membership members will have on the card - Administrator, Viewer or Operator.

  .PARAMETER Mapping
    Which Mapped number on card these settings will be stored in - can map upto 5 groups on a card.

  .EXAMPLE
    #Set AD Group UPS-Admins as Administrators and assign to mapping 1
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Set-M2LDAPMapping -LDAPGroup UPS-Admins -MappedProfile Administrator -Mapping 1
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$LDAPGroup,
    [Parameter(Mandatory=$true)][ValidateSet('Administrator','Viewer','Operator')][string]$MappedProfile,
    [Parameter(Mandatory=$true)][string]$Mapping
  )

  if($MappedProfile -like 'Administrator') {
    $MappedProfileNumber = '1'
  }

  if($MappedProfile -like 'Viewer') {
    $MappedProfileNumber = '2'
  }

  if($MappedProfile -like 'Operator') {
    $MappedProfileNumber = '3'
  }

  $body = "{
    `n    `"remoteGroup`": `"$LDAPGroup`",
    `n    `"profile`": `"/rest/mbdetnrs/1.0/accountsService/profiles/$MappedProfileNumber`"
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/remoteAccounts/providers/ldap/profileMapping/$Mapping" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: LDAP: Set $LDAPGroup Profile as $MappedProfile" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to Set $LDAPGroup LDAP Profile as $MappedProfile" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Remove-M2LDAPMapping {
  <#
  .SYNOPSIS
    Remove LDAP AD Group Mapping.

  .PARAMETER MappingID
    Mapped ID - found from running Get-M2LDAPMapping.

  .EXAMPLE
    #Remove Mapping 3
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Remove-M2LDAPMapping -MappingID 3
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$MappingID
  )

  $body = "{
    `n    `"remoteGroup`": `"`",
    `n    `"profile`": `"`"
    `n}"

  try {
    $getremotegroup = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/remoteAccounts/providers/ldap/profileMapping/$MappingID" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/remoteAccounts/providers/ldap/profileMapping/$MappingID" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: LDAP: Removed Mapping $MappingID which was linked to remote group $($getremotegroup.remoteGroup)" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to delete mapping $MappingID" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2LDAPCerts {
  <#
  .SYNOPSIS
    Get all LDAP certificates.

  .DESCRIPTION
    This command will provide all LDAP certs. There is no current option to simply specify an individual cert.

    This command will only display the id of each cert and is useless on it's own. To get detailed information you will be piping this commands output to Get-M2LDAPIndividualCertDetails.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    (Get-M2LDAPCerts).Members
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/ldap/clientsAuthentication/certificateAuthorities" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Cannot query LDAP certificates" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Get-M2LDAPIndividualCertDetails {
  <#
  .SYNOPSIS
    Get details of a specified certificate.

  .DESCRIPTION
    The Get-M2LDAPIndividualCertDetails provides detailed information about a LDAP certificate.

    This LDAP cert will either be specified manually using the CertID parameter or by piping it in using the Get-M2LDAPCerts command.

  .PARAMETER CertID
    ID of certificate. EG '/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/ldap/clientsAuthentication/certificateAuthorities/certXYZ.123'

  .EXAMPLE
    #Show details for every ldap cert
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    $certs = (Get-M2LDAPCerts).Members
    foreach($cert in $certs) {
      Get-M2LDAPIndividualCertDetails -CertID $cert
    }

  .EXAMPLE
    #Pipe in a specified cert - in this case the second cert
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    (Get-M2LDAPCerts).Members[1] | Get-M2LDAPIndividualCertDetails

  .EXAMPLE
    #Display details without piping
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2LDAPIndividualCertDetails -CertID '/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/ldap/clientsAuthentication/certificateAuthorities/certXYZ.123'
  #>

  Param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$CertID
  )

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)$($CertID -replace '@{@id=' -replace '}')" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Cannot get certificate details" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Add-M2LDAPCert {
  <#
  .SYNOPSIS
    Import ROOTCA certificate for LDAP.

  .PARAMETER File
    Full file path to certificate.

  .EXAMPLE
    #add certificate c:\temp\cert.crt
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Add-M2LDAPCert -File c:\temp\cert.crt
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$File
  )

  #First grab data from cert file
  $pattern = "-----BEGIN CERTIFICATE----- (.*?) -----END CERTIFICATE-----"
  $certificate = Get-Content "$file"
  $output = [regex]::Match($certificate,$pattern).Groups[1].Value

  $body = "{
    `n
    `n  `"certificate`":  `"-----BEGIN CERTIFICATE-----`\n$output`\n-----END CERTIFICATE-----`\n`",
    `n
    `n  `"format`": `"PEM`"
    `n
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/ldap/clientsAuthentication/certificateAuthorities" -Method 'POST' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Added ROOT LDAP Cert" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Cannot add ROOT LDAP cert" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Remove-M2LDAPCert {
  <#
  .SYNOPSIS
    Remove a specific LDAP certificate.

  .PARAMETER CertID
    ID of certificate. EG '/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/ldap/clientsAuthentication/certificateAuthorities/certXYZ.123'

  .EXAMPLE
    #Remove all LDAP certificates
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    $ldapcerts = (Get-M2LDAPCerts).Members
    foreach($ldapcert in $ldapcerts) {
      Remove-M2LDAPCert -CertID $ldapcert
    }

  .EXAMPLE
    #Remove only 1 ldapcert
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Remove-M2LDAPCert -CertID '/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/ldap/clientsAuthentication/certificateAuthorities/certXYZ.123'
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$CertID
  )

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)$($CertID -replace '@{@id=' -replace '}')" -Method 'DELETE' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Unable to remove cert $CertID" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

}

Function Get-M2DNSSettings {
  <#
  .SYNOPSIS
    Get DNS fqdn and server settings.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2DNSSettings
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/networkInterfaces/1/domain/settings" -Headers $headers -Method 'GET' -SkipCertificateCheck -ErrorAction:Stop

    $obj = New-Object -TypeName PSObject
    $obj | Add-Member -MemberType NoteProperty -Name HostName -Value $response.hostname
    $obj | Add-Member -MemberType NoteProperty -Name DomainName -Value $response.manual.domainname
    $obj | Add-Member -MemberType NoteProperty -Name PrimaryDNS -Value $response.manual.dns.preferredserver
    $obj | Add-Member -MemberType NoteProperty -Name SecondaryDNS -Value $response.manual.dns.alternateserver
    $report += $obj
    return $report

  } catch {
    Write-Information -MessageData "ERROR: Cannot get DNS Settings" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Set-M2DNSSettings {
  <#
  .SYNOPSIS
    Set DNS fqdn and server settings.

  .PARAMETER Hostname
    name of card.

  .PARAMETER DomainName
    DNS Domainname.

  .PARAMETER PrimaryDNS
    Primary DNS Server.

  .PARAMETER SecondaryDNS
    Secondary DNS Server.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Set-M2DNSSettings -HostName UPS01Card -DomainName example.com -PrimaryDNS 1.2.3.4 -SecondaryDNS 2.3.4.5
  #>

  Param (
    [string]$HostName,
    [string]$DomainName,
    [string]$PrimaryDNS,
    [string]$SecondaryDNS
  )

  $body = "{
    `n  `"hostname`": `"$HostName`",
    `n  `"mode`": 0,
    `n  `"manual`": {
    `n    `"domainName`": `"$DomainName`",
    `n    `"dns`": {
    `n        `"preferredServer`": `"$PrimaryDNS`",
    `n        `"alternateServer`": `"$SecondaryDNS`"
    `n      }
    `n  }
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/networkInterfaces/1/domain/settings" -Headers $headers -Method 'PUT' -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set DNS Settings" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Cannot set DNS Settings" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2IPv4Settings {
  <#
  .SYNOPSIS
    Get network IPv4 address settings.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2IPv4Settings
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/networkInterfaces/1/ipv4" -Headers $headers -Method 'GET' -SkipCertificateCheck -ErrorAction:Stop
    return $response
  } catch {
    Write-Information -MessageData "ERROR: Cannot get IPv4 Settings" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2SNMPSettings {
  <#
  .SYNOPSIS
    Get SNMPv1/v3 settings.

  .EXAMPLE
    #Get overall SNMP settings - enabled/disabled, port etc
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2SNMPSettings

  .EXAMPLE
    #Get snmp v1 communities
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    (Get-M2SNMPSettings).v1.communities.members
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Cannot enable SNMP" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Set-M2SNMPSettings {
  <#
  .SYNOPSIS
    Enable or Disable SNMPv1/v3.

  .PARAMETER SNMPEnabled
    Enable or disable SNMP (overall). You set it globally then either enable/disable snmpv1/3 seperately.

  .PARAMETER SNMPPort
    Defaults to 161.

  .PARAMETER SNMPv1Enable
    Enable or disable snmpv1. Disabled by default. True or false.

  .PARAMETER SNMPv3Enable
    Enable or disable snmpv3.

  .EXAMPLE
    Enable SNMPv3 (by default v1 is disabled)
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Set-M2SNMPSettings -SNMPEnabled $true -SNMPv3Enable $true
  #>

  Param (
    [bool]$SNMPEnabled,
    [string]$SNMPPort = 161,
    [bool]$SNMPv1Enable = $false,
    [bool]$SNMPv3Enable
  )

  if($SNMPEnabled -eq $true){
    $snmpenabledvalue = "true"
  } else {
    $snmpenabledvalue = "false"
  }

  if($SNMPv1Enable -eq $true){
    $SNMPv1EnableValue = "true"
  } else {
    $SNMPv1EnableValue = "false"
  }

  if($SNMPv3Enable -eq $true){
    $SNMPv3EnableValue = "true"
  } else {
    $SNMPv3EnableValue = "false"
  }

  $body = "{
    `n        `"enabled`": $SNMPEnabledValue,
    `n        `"port`": $SNMPPort,
    `n        `"v1`": {
    `n            `"enabled`": $SNMPv1EnableValue
    `n        },
    `n        `"v3`": {
    `n            `"enabled`": $SNMPv3EnableValue
    `n        }
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set SNMP Functionality" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Cannot enable SNMP" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2SNMPv3Accounts {
  <#
  .SYNOPSIS
    Get SNMPv3 account settings

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2SNMPv3Accounts
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/v3/users" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    return $response.members
  } catch {
    Write-Information -MessageData "ERROR: Cannot get SNMPv3 Account Details" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Set-M2SNMPv3Account {
  <#
  .SYNOPSIS
    Set SNMPv3 account details.

  .PARAMETER Name
    Name of SNMPv3 account.

  .PARAMETER Enabled
    Enable or disable account from being used.

  .PARAMETER UserID
    ID of the user. Card only lets you add 2x v3 users. Can either be 1 or 2. Run Get-M2SNMPv3Accounts beforehand to view current details.

  .PARAMETER AccessType
    Set the account as having either global read only or read/write access - you then limit the scope using the AllowAuth/AllowPrivileged parameters (EG account r/w but no auth access).

  .PARAMETER AllowAuth
    Grant account the ability to authenticate. Disabled by default.

  .PARAMETER AuthPwd
    Password required for Authentication. Command won't run if this value isn't set when AllowAuth parameter specified.

  .PARAMETER AllowPrivileged
    Grant account privileged access. Disabled by default.

  .PARAMETER PrivilegedPwd
    Password required for privileged access. Command won't run if this value isn't set when AllowPrivileged parameter specified.

  .EXAMPLE
    #Set readonly user - set as UserID 1
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Set-M2SNMPv3Account -Name ReadOnly -Enabled $true -UserID 1

  .EXAMPLE
    #Allow write access - set as UserID 2
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Set-M2SNMPv3Account -Name ReadWrite -Enabled $true -AccessType AccessType ReadWrite -AllowAuth $true -AuthPwd 'SuperComplexPW' -AllowPrivileged $true -PrivilegedPwd 'SuperComplexPrivPW' -UserID 2
  #>

  Param (
    [string]$Name,
    [bool]$Enabled,
    [ValidateSet('1','2')][string]$UserID,
    [ValidateSet('ReadOnly','ReadWrite')][string]$AccessType = 'ReadOnly',
    [bool]$AllowAuth = $false,
    [string]$AuthPwd,
    [bool]$AllowPrivileged = $false,
    [string]$PrivilegedPwd
  )

  #json doesnt like PS boolean
  if($Enabled -eq $true){
    $enabledvalue = "true"
  } else {
    $enabledvalue = "false"
  }

  if($AccessType -eq 'ReadOnly'){
    $accesstypevalue = "false"
  } else {
    $accesstypevalue = "true"
  }

  if($AllowAuth -eq $true){
    $AllowAuthvalue = "true"
  } else {
    $AllowAuthvalue = "false"
  }

  if($AllowPrivileged -eq $true){
    $AllowPrivilegedvalue = "true"
  } else {
    $AllowPrivilegedvalue = "false"
  }

  #check if password being set with auth or privileged access.
  if($AllowAuth -eq $true -and !$AuthPwd){
    Write-Information -MessageData "ERROR: Auth access enabled without a password set. For security reasons you must set a password. Please retry" -InformationAction Continue
    return
  }

  if($AllowPrivileged -eq $true -and !$PrivilegedPwd){
    Write-Information -MessageData "ERROR: Privileged access enabled without a password set. For security reasons you must set a password. Please retry" -InformationAction Continue
    return
  }

  $body = "{
  `n    `"name`": `"$Name`",
  `n    `"enabled`": $Enabledvalue,
  `n    `"allowWrite`": $accesstypevalue,
  `n    `"auth`": {
  `n        `"enabled`": $AllowAuthvalue,
  `n        `"algorithm`": 2,
  `n        `"password`": {
  `n            `"authPassword`": `"$AuthPwd`"
  `n        }
  `n    },
  `n    `"priv`": {
  `n        `"enabled`": $AllowPrivilegedvalue,
  `n        `"algorithm`": 1,
  `n        `"password`": {
  `n            `"privPassword`": `"$PrivilegedPwd`"
  `n        }
  `n    }
  `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/v3/users/$UserID" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Set SNMPv3 $name account settings" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Cannot set SNMPv3 $name account settings" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Get-M2SNMPTrapReceivers {
  <#
  .SYNOPSIS
    Get all SNMP Trap Receivers

  .DESCRIPTION
    This command will provide all SNMP trap receivers. There is no current option to simply specify an individual trap.

    This command will only display the id of each trap and is useless on it's own. To get detailed information you will be piping this commands output to Get-M2SNMPIndividualTrapReceiver.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2SNMPTrapReceivers
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/traps/receivers" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Cannot enable SNMPv3 Trap Receiver" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Get-M2SNMPIndividualTrapReceiver {
  <#
  .SYNOPSIS
    Get an individual SNMP Trap Receivers settings

  .DESCRIPTION
    The Get-M2SNMPIndividualTrapReceiver provides detailed information about a snmp trap.

    This trap will either be specified manually using the TrapID parameter or by piping it in using the Get-M2SNMPTrapReceivers command.

  .PARAMETER TrapID
    ID of trap. EG '/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/traps/receivers/n5KQ5mZySeSgaulcuCv0MQ'

  .EXAMPLE
    #Show details for every trap
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    $traps = (Get-M2SNMPTrapReceivers).Members
    foreach($trap in $traps) {
      Get-M2SNMPIndividualTrapReceiver -TrapID $trap
    }

  .EXAMPLE
    #Pipe in a specified trap - in this case the second trap
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    (Get-M2SNMPTrapReceivers).Members[1] | Get-M2SNMPIndividualTrapReceiver

  .EXAMPLE
    #Display details without piping
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2SNMPIndividualTrapReceiver -TrapID '/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/traps/receivers/n5KQ5mZySeSgaulcuCv0MQ'
  #>

  Param (
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$TrapID
  )

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)$($TrapID -replace '@{@id=' -replace '}')" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
  } catch {
    Write-Information -MessageData "ERROR: Cannot get Trap Receiver" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $response
}

Function Set-M2SNMPTrapReceiver {
  <#
  .SYNOPSIS
    Create a SNMPv3 Trap receiver.

  .PARAMETER Name
    Name of SNMP Trap.

  .PARAMETER Enabled
    Enable or disable trap.

  .PARAMETER Destination
    Where alerts will be sent to.

  .PARAMETER Port
    Port on destination server for receiving trap. Default is 162.

  .PARAMETER Protocol
    Set as v1 or v3 SNMP.

  .PARAMETER Community
    Set Community. Only used in v1.

  .PARAMETER SNMPv3User
    User used for snmp v3 trap. Either user 1 or 2.

  .EXAMPLE
    #Create SNMPv3 trap receiver using readonly account sending data to snmp.example.com
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Set-M2SNMPTrapReceiver -Name ReadOnly -Enabled $true -Protocol 3 -Destination snmp.example.com -Port 162 -SNMPUser 1

  .EXAMPLE
    #Create SNMPv1 trap receiver to public community and send data to snmp.example.com
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Set-M2SNMPTrapReceiver -Name snmptrap -Enabled $true -Protocol 1 -Community public -Destination snmp.example.com -Port 162
  #>

  Param (
    [string]$Name = "trap",
    [string]$Enabled,
    [Parameter(Mandatory=$true)][string]$Destination,
    [string]$Port = 162,
    [Parameter(Mandatory=$true)][ValidateSet('1','3')][string]$Protocol,
    [string]$Community,
    [ValidateSet('1','2')][string]$SNMPv3User
  )

  #json doesnt like PS boolean
  if($Enabled -eq $true){
    $EnabledValue = "true"
  } else {
    $EnabledValue = "false"
  }

  #v1 vs v3 have 1 line that's different.
  if($Protocol -eq 1 -and $community) {
    $specialline = "`"community`": `"$Community`""
  } elseif($Protocol -eq 3 -and $SNMPv3User) {
    $specialline = "`"user`": `"/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/v3/users/$SNMPv3User`""
  } else {
    Write-Information -MessageData "ERROR: You have specified a Protocol without either the appropriate community or v3 user. Please retry" -InformationAction Continue
    return
  }

  $body = "{
    `n  `"name`": `"$name`",
    `n  `"enabled`": $EnabledValue,
    `n  `"host`": `"$Destination`",
    `n  `"port`": $Port,
    `n  `"protocol`": $Protocol,
    `n  $specialline
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/traps/receivers" -Method 'POST' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Enabled SNMP v$Protocol Trap Receiver to $Destination" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Cannot enable SNMP v$Protocol Trap Receiver to $Destination" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Remove-M2SNMPTrapReceiver {
  <#
  .SYNOPSIS
    Remove a SNMP Trap Receiver.

  .EXAMPLE
    #Remove all SNMP Traps
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    $traps = (Get-M2SNMPTrapReceivers).Members
    foreach($trap in $traps) {
      Remove-M2SNMPTrapReceiver -TrapID $trap
    }

  .EXAMPLE
    #Remove only 1 trap notification
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Remove-M2SNMPTrapReceiver -TrapID 'rest/mbdetnrs/1.0/managers/1/networkService/protocols/snmp/traps/receivers/1CWe1JeETuywOjd9z-l2MQ'
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$TrapID
  )

  try {
    $remove =  Invoke-RestMethod "https://$($headers.UPSCard)$($TrapID -replace '@{@id=' -replace '}')" -Method 'DELETE' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Deleted $($TrapID -replace '@{@id=' -replace '}')" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to delete $($TrapID -replace '@{@id=' -replace '}')" -InformationAction Continue
  }
}

Function Get-M2WebCertSigningRequest {
  <#
  .SYNOPSIS
    Request a web certificate signing request. This can then be sent to a CA for approval.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    $response = Get-M2WebCertSigningRequest
    $response | Out-File c:\temp\request.req
  #>

  try {
    $req = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/webserver/serverAuthentication/csr/actions/generate" -Method 'POST' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Generated HTTPS Cert request" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Cannot generate HTTPS cert" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

  return $req
}

Function Import-M2WebCert {
   <#
  .SYNOPSIS
    Import signed web certificate.

  .PARAMETER File
    full file path to cer file.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Import-M2WebCert -File c:\temp\cert.cer
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$File
  )

  #First grab data from cert file
  $pattern = "-----BEGIN CERTIFICATE----- (.*?) -----END CERTIFICATE-----"
  $certificate = Get-Content "$file"
  $output = [regex]::Match($certificate,$pattern).Groups[1].Value

  $body = "{
    `n
    `n  `"certificate`":  `"-----BEGIN CERTIFICATE-----`\n$output`\n-----END CERTIFICATE-----`\n`",
    `n
    `n  `"format`": `"PEM`"
    `n
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/certificatesManager/services/webserver/serverAuthentication/certificate/actions/import" -Method 'POST' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: Imported HTTPS Cert" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Cannot import HTTPS cert" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Reset-M2UserPassword {
   <#
  .SYNOPSIS
    Reset password of an account.

  .PARAMETER Card
    Card IP or hostname.

  .PARAMETER UserName
    username of the account that requires a password reset.

  .PARAMETER OldPwd
    Current old password of the account.

  .PARAMETER NewPwd
    New password the account will now use.

  .EXAMPLE
    Reset-M2UserPassword -Card 192.168.0.1 -UserName admin -OldPwd admin -NewPwd Password1
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$Card,
    [string]$UserName,
    [string]$OldPwd,
    [string]$NewPwd
  )

  $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
  $headers.Add("Content-Type", "application/json")

  $body = "{`"user`":{`"username`":`"$UserName`",`"current_pwd`":`"$OldPwd`",`"new_pwd`":`"$NewPwd`"}}"

  $response = Invoke-RestMethod "https://$Card/rest/mbdetnrs/1.0/card/users/password" -Method 'PUT' -Headers $headers -Body $body -SkipCertificateCheck

  if($($response.pwd_change.code) -eq 0) {
    Write-Information -MessageData "SUCCESS: Password for $UserName has been successfully changed" -InformationAction Continue
  } else {
    Write-Information -MessageData "ERROR: Unable to reset password for $UserName account." -InformationAction Continue
  }
}

Function Get-M2UserNames {
  <#
  .SYNOPSIS
    Get local user accounts.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Get-M2UserNames
  #>

  $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/accounts/" -Method 'GET' -Headers $headers -SkipCertificateCheck

  $userstocheck = $response.Members
  $report = @()
  foreach($usertocheck in $userstocheck) {
    $user = Invoke-RestMethod "https://$($headers.UPSCard)$($Usertocheck -replace '@{@id=' -replace '}')/credentials" -Method 'GET' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    $obj = New-Object -TypeName PSObject
    $obj | Add-Member -MemberType NoteProperty -Name UserName -Value $user.username
    $obj | Add-Member -MemberType NoteProperty -Name UserID -Value $($Usertocheck -replace '@{@id=' -replace '}')
    $obj | Add-Member -MemberType NoteProperty -Name UserProfile -Value $user.profile
    $report += $obj
  }

  return $report

}

Function Update-M2UserName {
  <#
  .SYNOPSIS
    Update username of first local account.

  .PARAMETER NewUserName
    What the new name of the user will be called.

  .EXAMPLE
    #Update admin account to be called upsadmin
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Update-M2UserName -NewUserName upsadmin
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$NewUserName
  )

  #Check if a local account already exists called newusername
  $users = Get-M2UserNames
  if($($users.username -like $NewUserName)) {
    Write-Information -MessageData "STATUS: Account already exists called $NewUserName" -InformationAction Continue
    continue
  }

  try {
    $body = "{`n `"username`": `"$NewUserName`"`n}"
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/accounts/1/credentials" -Method 'PUT' -Headers $headers -body $body -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "SUCCESS: username set to $NewUserName" -InformationAction Continue
  } catch {
      Write-Information -MessageData "ERROR: Unable to update username to $NewUserName" -InformationAction Continue
      Write-Information -MessageData $_ -InformationAction Continue
  }

}

Function Approve-M2UserEULA {
  <#
  .SYNOPSIS
    Accept EULA for a specified account.

  .DESCRIPTION
    This will manually accept the EULA for a local account. This command will need to be run against each local account (must be accepted on a per user basis)

  .PARAMETER UserID
    ID of local user account that will have the EULA accepted.

  .EXAMPLE
    #Accept EULA for USERID 1
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Accept-M2UserEULA -UserID 1
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$UserID
  )

  $body = "{
    `n `"licenseAgreed`": true
    `n}"

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/accountsService/accounts/$UserID/preferences" -Method 'PUT' -Headers $headers -body $body -SkipCertificateCheck
    Write-Information -MessageData "SUCCESS: EULA for UserID $UserID account accepted" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: unable to accept EULA for UserID $UserID, will need to do manually. May alread be accepted." -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}

Function Update-M2Firmware {
  <#
  .SYNOPSIS
    update firmware version. As part of this it will pause for 420seconds to wait for upgrade to complete.

  .DESCRIPTION
    This command will update the firmware of the UPS card. This command takes some time to run and currently doesn't check the status of the firmware upgrade.

  .PARAMETER FilePath
    Full location of tar file.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Update-M2Firmware -FilePath C:\temp\web_eaton_network_m2_2.0.5.tar
  #>

  Param (
    [Parameter(Mandatory=$true)][string]$FilePath
  )

  try {
    $multipartContent = [System.Net.Http.MultipartFormDataContent]::new()
    $multipartFile = $FilePath
    $FileStream = [System.IO.FileStream]::new($multipartFile, [System.IO.FileMode]::Open)
    $fileHeader = [System.Net.Http.Headers.ContentDispositionHeaderValue]::new("form-data")
    $fileHeader.Name = "upgradeFile"
    $fileHeader.FileName = "$((Get-ChildItem -Path $FilePath).Name)"
    $fileContent = [System.Net.Http.StreamContent]::new($FileStream)
    $fileContent.Headers.ContentDisposition = $fileHeader
    $multipartContent.Add($fileContent)

    $body = $multipartContent

    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/actions/upgrade" -Method 'POST' -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop

    Write-Information -MessageData "INFO: Uploading firmware $((Get-ChildItem -Path $FilePath).Name)" -InformationAction Continue
    Write-Information -MessageData "Pausing for 420 seconds to allow firmware upgrade to complete" -InformationAction Continue
    Start-Sleep -Seconds 420
  } catch {
    Write-Information -MessageData "ERROR: Unable to load firmware" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }

}

Function Restart-M2Card {
  <#
  .SYNOPSIS
    Reboot M2 card.

  .DESCRIPTION
    This command will reboot the M2 management card. This command is required after updating the hostname for the card so a new webcertificate can be generated to reflect the card's new name.

    This command may also be needed after changing DNS or IP settings.

    It takes around ~4minutes after a reboot for the card to be responsive.

  .EXAMPLE
    Connect-EatonM2 -Card 192.168.0.1 -Credential $cred
    $cred = Get-Credential
    Restart-M2Card
  #>

  try {
    $response = Invoke-RestMethod "https://$($headers.UPSCard)/rest/mbdetnrs/1.0/managers/1/actions/reboot" -Method 'POST' -Headers $headers -SkipCertificateCheck -ErrorAction:Stop
    Write-Information -MessageData "STATUS: Rebooting network card $($headers.UPSCard)" -InformationAction Continue
  } catch {
    Write-Information -MessageData "ERROR: Unable to Reboot card $($headers.UPSCard)" -InformationAction Continue
    Write-Information -MessageData $_ -InformationAction Continue
  }
}