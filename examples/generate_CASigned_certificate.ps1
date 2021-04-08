<#
  .SYNOPSIS
    Generate a cert request, sign against a windows CA and import the signed cert. 
    
    Will add short, fqdn and card IP as subject alternate names.

  .EXAMPLE
  generate_CASigned_certificate.ps1 -card 192.168.0.1 -User admin -Pass admin -CertificateTemplate "Example-OOBM" -CertificateAuthority "Example.com \Issuing Certification Authority" -Domain example.com
#>

Param (
  [string]$Card,
  [string]$User,
  [string]$Pass,
  [string]$CertificateTemplate,
  [string]$CertificateAuthority,
  [string]$Domain
)

Function Certreqsign {
  $value = certreq.exe -f -q -attrib "CertificateTemplate:$CertificateTemplate\nSAN:DNS=$Card.$domain&DNS=$Card&ipaddress=$((Get-M2IPv4Settings).address)" -submit -config $CertificateAuthority -attrib "CertificateTemplate:$CertificateTemplate" "c:\temp\$Card.req" "c:\temp\$Card.csr"
}

Connect-EatonM2 -UserName $user -Passwd $Pass -Card $card

Write-Host "STATUS: Generate Eaton Webcert request - may take 15seconds"
$response = Get-M2WebCertSigningRequest

$response | Out-File -File c:\temp\$Card.req

Certreqsign
Import-M2Webcert -File c:\temp\$Card.csr

Remove-Item -Path "c:\temp\$Card.*" -Include *.csr,*.rsp,*.req -Force