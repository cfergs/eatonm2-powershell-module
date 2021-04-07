<#
.SYNOPSIS
  Automate M2 settings

.DESCRIPTION
  This script will configure various settings on an Eaton M2 card such as:
  - resetting admin password
  - configure location and card name
  - configure email
  - configure snmp
  - configure ntp
  - configure ldap
  - configure certificates

  It is designed to be used on brand new or existing cards.

  This script will not:
  - set static IP address settings.

  NOTE: The cards https certificate will be regenerated when an IP is manually set or during a firmware upgrade (potentially).
  When pre-configuring a card run the command without the HTTPSCertGeneration parameter. Once the IP is set correctly run the appropriate example to create a https cert.
    
  NOTE2: This script can only be run with PS7.0 due to limitations with Invoke-RestMethod in PS5.1

  Run "get-help .\Configure-EatonM2.ps1 -detailed" to see parameters and examples

.NOTES
  Name: Configure-EatonM2.ps1
  Author: Colin Fergusson 
  Requires:
    - PowerShell v7 onwards
    - ADM Active Directory Account (for setting DNS record - optional)

.LINK
  As from https://documenter.getpostman.com/view/7058770/S1EQTJ3z#intro

.PARAMETER Card
  Used to connect to API. Either use a IP or DNS value.

.PARAMETER UPSName
  Name of UPS in short format EG: UPS01.

.PARAMETER Username
  Default is admin. Change if different.

.PARAMETER Location
  Location of UPS.

.PARAMETER ResetPassword
  Specify if admin password is to be changed.

.PARAMETER ResetCurrentSettings
  Remove existing Email notifications, SNMP Trap Receivers and LDAP Root CA certificates.

.PARAMETER UPSFirmwareUpgradeFile
  Upgrade firmware. Specify full file path to firmware, EG: C:\temp\firmwarefile.tar.

.PARAMETER ConfigureCardSettings
  Configure all settings for the card such as name, DNS, email and snmp.

.PARAMETER Passwd
  Password to login with the card.

.PARAMETER OldPwd
  Must be specified if ResetPassword option used.

.PARAMETER TestEmail
  Test email sending functionality

.PARAMETER LDAPPwd
  Password for ldap account (if required).

.PARAMETER HTTPSCertGeneration
  Generate a HTTPS certificate that is trusted by a RootCA. This will eliminate "not secure" errors when accessing the card.

.EXAMPLE
  #Configure brand new card UPS01 192.168.0.50. Also reset admin password. Card is being pre-configured in advance.
  Configure-EatonM2.ps1 -Card 192.168.0.50 -UPSName UPS01 -ConfigureCardSettings -ResetPassword -Password SuperComplexPW -OldPassword admin -Location "Server Room - Rack 1 - R1:R6" -LDAPPassword Password1

  #When card is unboxed and IP set correctly you will need to rerun example for HTTPSCertGeneration

.EXAMPLE
  # Update existing card UPS01 and re-apply correct settings. Do not reset admin password. Send test email.
  Configure-EatonM2.ps1 -Card UPS01 -UPSName UPS01 -Password SuperComplexPW -ConfigureCardSettings -HTTPSCertGeneration -Location "Datacenter - Rack 1 - R1:R6" -LDAPPassword Password1 -TestEmail

.EXAMPLE
  # Generate HTTP certificate for UPS01. This card has just had IP set statically and everything else is configured.
  Configure-EatonM2.ps1 -Card UPS01 -UPSName UPS01 -Password SuperComplexPW -HTTPSCertGeneration

.EXAMPLE
  # Update firmware on card UPS01
  Configure-EatonM2.ps1 -Card UPS01 -UPSName UPS01 -Password SuperComplexPW -UPSFirmwareUpgradeFile "c:\temp\web_eaton_network_m2_2.0.5.tar"
  #>

  Param(
    [Parameter(Mandatory=$true)][string]$Card,
    [Parameter(Mandatory=$true)][string]$UPSName,
    [string]$Username = "admin",
    [Parameter(Mandatory=$true)][string]$Passwd,
    [switch]$ConfigureCardSettings,
    [switch]$HTTPSCertGeneration,
    [string]$Location,
    [switch]$ResetPassword,
    [switch]$ResetCurrentSettings,
    [string]$UPSFirmwareUpgradeFile,
    [string]$OldPwd,
    [switch]$TestEmail,
    [string]$LDAPPwd
  )
  
#Input sanitization
$UPSName = $UPSName.ToUpper()
  
#global variables - modify yourself if being used
$emailcontact = ''
$ntpserver = ''
$emailserver = ''
$emaildomain = ''
$emailnotificationrecipient = ''
$CertificateTemplate = ''
$CertificateAuthority = ''
$Domain = ''
  
# Check using Powershell v7
If(!($PSVersionTable.PSVersion.Major -eq 7)) {
  Write-host "Exiting. Please install Powershell v7 then re-run script"
  exit
}
  
###############
## Functions ##
###############
  # Web server certificate
Function Certreqsign {
  $value = certreq.exe -f -q -attrib "CertificateTemplate:$CertificateTemplate\nSAN:DNS=$UPSName.$domain&DNS=$UPSName&ipaddress=$((Get-M2IPv4Settings).address)" -submit -config "$CertAuthority" -attrib "CertificateTemplate:$CertificateTemplate" "c:\temp\$UPSName.req" "c:\temp\$UPSName.csr"
}
  
  
###########################
## Code to run Functions ##
###########################
  
Import-Module EatonM2Management
  
Write-Host "***Configuring Card: $UPSName ***"
if($ResetPassword) {
  if(!$OldPwd) { #check if you entered oldpassword, otherwise exit. $newPW is set as mandatory.
    Write-Host "ERROR: Missing `$OldPassword variable. Re-run with value entered"
    exit
  }
  Reset-M2UserPassword -Card $card -UserName $UserName -OldPwd $OldPwd -NewPwd $Passwd
}

if($UPSFirmwareUpgradeFile) {
  Connect-EatonM2 -UserName $username -Passwd $Passwd -Card $card
  Write-Host "INFO: FirmwareUpgrade commencing"
  Update-M2Firmware -FilePath $UPSFirmwareUpgradeFile #function will wait X minutes for upgrade to commence
}
  
Connect-EatonM2 -UserName $username -Passwd $Passwd -Card $card
Get-M2FirmwareVersion
  
#reset settings - by default below settings append vs overwrite
if($ResetCurrentSettings) {
  #remove email alerts
  $emailalerts = (Get-M2EmailAlertConfigurations).Members
  foreach($emailalert in $emailalerts) {
    Remove-M2EmailAlertNotification -AlertID $emailalert
  }
    
  #remove SNMP trap receivers
  $traps = (Get-M2SNMPTrapReceivers).Members
  foreach($trap in $traps) {
    Remove-M2SNMPTrapReceiver -TrapID $trap
  }
  
  #Remove LDAP CA
  $ldapcerts = (Get-M2LDAPCerts).Members
  foreach($ldapcert in $ldapcerts) {
    Remove-M2LDAPCert -CertID $ldapcert
  }
  
}
  
#do the bulk of configuring
if($ConfigureCardSettings) {
  Connect-EatonM2 -UserName $username -Passwd $Passwd -Card $card
  Approve-M2UserEULA -UserID 1
    
  if(!$Location) {
    Write-Host "INFO: Skipping the setting of SystemDetails as Location not specified"
  } else {
    Set-M2SystemDetails -UPSName $UPSName -EmailContact $EmailContact -Location $Location
  }
    
  Set-M2NTPSettings -TimeZone 'Pacific/Auckland' -Enabled $true -NTPServer1 $ntpserver
  
  if(!$LDAPPassword) {
    Write-Host "INFO: Skipping setting LDAP provider,mappings and LDAPcert as LDAPPassword not specified"
  } else {
    #Configure LDAP
    Set-M2LDAPProvider -Enabled $true -PrimaryLDAPName ldap-vip -PrimaryLDAPHostName ldap.example.com -SearchUserDN 'CN=svc.upsldap,OU=Users,DC=example,DC=com'  -SearchUserPwd $LDAPPwd -SearchBaseDN 'DC=example,DC=com' -RequestSID 'objectSID:S-1-5-21-123456789-123456789-123456789'
    Set-M2LDAPMapping -LDAPGroup RBAC_UPSAdmins -MappedProfile Administrator -Mapping 1
    Set-M2LDAPMapping -LDAPGroup RBAC_UPSViewer -MappedProfile Viewer -Mapping 2
    Add-M2LDAPCert -File C:\Temp\RootCA.crt
  }
    
  #Configure Email
  Set-M2SMTPGlobalSettings -Enabled $true -EmailServer $emailserver -FromAddress "$UPSName@$domain"
  $emailnotif = Set-M2EmailAlertNotification -Recipient $emailnotificationrecipient
  if($TestEmail) {
    Write-Host "STATUS: Testing email functionality. Please wait"
    Test-M2EmailAlertNotification -AlertID $emailnotif
  }
  
  #Configure SNMP
  Set-M2SNMPSettings -SNMPEnabled $true -SNMPv3Enable $true
  Set-M2SNMPv3Account -Name readonly -Enabled $true -UserID 1
  Set-M2SNMPTrapReceiver -Name trap -Enabled $true -Protocol 3 -Destination server.example.com -Port 162 -SNMPv3User 1
  
  #Configure DNS
  #need to reboot after this for it to have the correct name
  Set-M2DNSSettings -HostName $UPSName -DomainName example.com -PrimaryDNS 1.2.3.4 -SecondaryDNS 1.2.3.4
    
}
  
if($HTTPSCertGeneration) {
  if($ConfigureCardSettings) {
    Write-Host "Rebooting Card"
    Restart-M2Card
    Start-Sleep -Seconds 180
  }
  
  Connect-EatonM2 UserName $username -Passwd $Passwd -Card $card
  
  Write-Host "STATUS: Generate Eaton Webcert request - may take 15seconds"
  $response = Get-M2WebCertSigningRequest
  
  $response | Out-File -File c:\temp\$UPSName.req
  
  Certreqsign
  Import-M2Webcert -File c:\temp\$UPSName.csr
  Remove-Item -Path "c:\temp\$UPSName.*" -Include *.csr,*.rsp,*.req -Force
}
  
Connect-EatonM2 UserName $username -Passwd $Passwd -Card $card
  
#Lastly update the admin username if required
Update-M2UserName -CurrentAccount $username -NewUserName upsadmin
  
Write-Host "***CARD: $UPSName has been configured***"