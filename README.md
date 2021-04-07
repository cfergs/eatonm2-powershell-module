# eatonm2-powershell-module
Powershell module to manage various settings on Eaton M2 network cards. This requires Powershell 7.0 or newer to run. 

For further examples of what can be done using the EatonM2 API refer to https://documenter.getpostman.com/view/7058770/S1EQTJ3z#intro

# Command Overview

## Connect-EatonM2
Create a authentication session with a Eaton M2 card. Required so other commands can be run.

## Get-M2FirmwareVersion
Get the current version running on an Eaton M2 card.

## Get-M2SystemDetails
Get system details such as name, location, email contact.

## Set-M2SystemDetails
Set system details such as name, location, email contact.

## Get-M2NTPSettings
Get the current NTP settings.

## Set-M2NTPSettings
Set NTP server details, and enable/disable NTP.

## Get-M2SMTPGlobalSettings
Get SMTP Server Settings currently set on the card.

## Set-M2SMTPGlobalSettings
Set SMTP Server Settings.

## Get-M2EmailAlertConfigurations
Get the email alert configurations set on the card. This can then be piped to the Get-M2EmailAlertIndividualConfiguration command. This command just gets the configuration ID.

## Get-M2EmailAlertIndividualConfiguration
The Get-M2EmailAlertIndividualConfiguration provides detailed information about a configured email alert. This email alert will either be specified manually using the EmailAlertID parameter or by piping it in using the Get-M2EmailAlertConfiguration command.

## Set-M2EmailAlertNotification
Create an email alert notification to a specified email address that will be sent when predetermined events occur. These are for powerloss or UPS faults.

## Remove-M2EmailAlertNotification
Remove a specific email alert. This email alert will either be specified manually using the EmailAlertID parameter or by piping it in using the Get-M2EmailAlertConfiguration command.

## Test-M2EmailAlertNotification
Test email alert. This will use it's shortened ID vs the /rest/ URL.

## Get-M2LDAPProvider
This command shows all LDAP provider settings. Running the command on it's own will only show the top level of LDAP settings - Refer to the EXAMPLES for this command on how to get information about baseAccess or requestParameter settings.

## Set-M2LDAPProvider
Setup a LDAP provider.

## Get-M2LDAPMapping 
Get LDAP remote group mappings currently configured.

## Set-M2LDAPMapping
Map a remote LDAP group to a internal group role. Allowing login to members of that LDAP group

## Remove-M2LDAPMapping
Remove a LDAP AD Group Mapping.

## Get-M2LDAPCerts
This command will provide all LDAP certs. There is no current option to simply specify an individual cert. This command will only display the id of each cert and is useless on it's own. To get detailed information you will be piping this commands output to Get-M2LDAPIndividualCertDetails.

## Get-M2LDAPIndividualCertDetails
The Get-M2LDAPIndividualCertDetails provides detailed information about a LDAP certificate. This LDAP cert will either be specified manually using the CertID parameter or by piping it in using the Get-M2LDAPCerts command.

## Add-M2LDAPCert
Import ROOTCA certificate for LDAP authentication.

## Remove-M2LDAPCert
Remove a specified LDAP certificate.

## Get-M2DNSSettings
Get DNS fqdn and server settings.

## Set-M2DNSSettings
Set DNS fqdn and server settings.

## Get-M2IPv4Settings
Get network IPv4 address settings.

## Get-M2SNMPSettings
Get SNMPv1/v3 settings.

## Set-M2SNMPSettings
Enable or Disable SNMPv1/v3.

## Get-M2SNMPv3Accounts
Get SNMPv3 account settings

## Set-M2SNMPv3Account
Set SNMPv3 account details.

## Get-M2SNMPTrapReceivers
This command will provide all SNMP trap receivers. There is no current option to simply specify an individual trap. This command will only display the id of each trap and is useless on it's own. To get detailed information you will be piping this commands output to Get-M2SNMPIndividualTrapReceiver.

## Get-M2SNMPIndividualTrapReceiver
Get an individual SNMP Trap Receivers settings. This trap will either be specified manually using the TrapID parameter or by piping it in using the Get-M2SNMPTrapReceivers command.

## Set-M2SNMPTrapReceiver
Create a SNMPv3 Trap receiver.

## Remove-M2SNMPTrapReceiver
Remove a SNMP Trap Receiver.

## Get-M2WebCertSigningRequest
Request a web certificate signing request. This can then be sent to a CA for approval.

## Import-M2WebCert
Import signed web certificate.

## Reset-M2UserPassword
Reset password of an account.

## Get-M2UserNames
Get local user accounts.

## Update-M2UserName
Update username of first local account.

## Approve-M2UserEULA
This will manually accept the EULA for a local account. This command will need to be run against each local account (must be accepted on a per user basis).

## Update-M2Firmware
This command will update the firmware of the UPS card. This command takes some time to run and currently doesn't check the status of the firmware upgrade.

## Restart-M2Card
Reboot a M2 card. This is required after changing various settings such as hostname or DNS settings.