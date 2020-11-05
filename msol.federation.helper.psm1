function Backup-MSOLFederationSettings {
    param(
        [Parameter(Mandatory=$true)][string]$filename,
        [Parameter(Mandatory=$false)][string]$domain
    )
    Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
    if($?) {} else {
        Connect-MSOLService
    }
    if ($domain -eq "") {
        $domains = Get-MsolDomain | where Authentication -eq "Federated"
        if ($domains.count -gt 1) {
            Write-Warning "Multiple federated domains present. Exporting first domain. Use -domain to specify other domains."
        }
        $domain = ($domains | select-object -first 1 -wait).name
    }
    $federationsettings = Get-MsolDomainFederationSettings -domain $domain
    $federationsettings | add-member -NotePropertyName federatedDomain -NotePropertyValue $domain
    $federationsettings | ConvertTo-JSON | Out-File $filename
}
Export-ModuleMember -Function Backup-MSOLFederationSettings

function Restore-MSOLFederationSettings {
    param(
        [Parameter(Mandatory=$true)][string]$filename
    )
    Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
    if($?) {} else {
        Connect-MSOLService
    }
    $federationSettings = get-content $filename | convertfrom-json
    Set-MsolDomainAuthentication -DomainName $federationSettings.federatedDomain -Authentication Managed
    Set-MsolDomainAuthentication -DomainName $federationSettings.federatedDomain -Authentication Federated `
        -FederationBrandName $federationSettings.federationBrandName -IssuerUri $federationSettings.issuerUri `
        -PassiveLogOnUri $federationSettings.passiveLogOnUri -ActiveLogOnUri $federationSettings.activeLogOnUri `
        -MetadataExchangeUri $federationSettings.metadataExchangeUri -LogOffUri $federationSettings.logOffUri `
        -SigningCertificate $federationSettings.signingCertificate -NextSigningCertificate $federationSettings.nextSigningCertificate `
        -SupportsMfa $federationSettings.supportsMfa -PreferredAuthenticationProtocol $federationSettings.preferredAuthenticationProtocol `
        -DefaultInteractiveAuthenticationMethod $federationSettings.defaultInteractiveAuthenticationMethod `
        -OpenIdConnectDiscoveryEndpoint $federationSettings.openIdConnectDiscoveryEndpoint -SigningCertificateUpdateStatus $federationSettings.signingCertificateUpdateStatus `
        -PromptLoginBehavior $federationSettings.promptLoginBehavior
}
Export-ModuleMember -Function Restore-MSOLFederationSettings

function Restore-MSOLFedSetFromMetadata {
    param(
        [Parameter(Mandatory=$true,ParameterSetName="byFile")][string]$filename,
        [Parameter(Mandatory=$true,ParameterSetName="byUrl")][string]$Url,
        [Parameter(Mandatory=$true)][string]$domain
    )
    if ($filename -ne "") {
       $Metadata = Get-Content -Path $filename
    } elseif ($bundleId -ne "") {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $Metadata = Invoke-RestMethod -Uri $Url
    }
    [xml]$IdPMetadata = $Metadata
        Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
    if($?) {} else {
        Connect-MSOLService
    }
    Set-MsolDomainAuthentication -DomainName $domain -Authentication Managed
    Set-MsolDomainAuthentication -DomainName $domain -Authentication Federated -IssuerUri $IdPMetadata.EntityDescriptor.entityID `
        -PassiveLogOnUri $federationSettings.$IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleSignOnService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"} | % {$_.Location} `
        -ActiveLogOnUri $IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleSignOnService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT"} | % {$_.Location} `
        -SigningCertificate $IdPMetadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor |  ? {$_.use -eq "signing"} | Select-Object -Last 1 | % {$_.KeyInfo.X509Data.X509Certificate}
}
Export-ModuleMember -Function Restore-MSOLFedSetFromMetadata