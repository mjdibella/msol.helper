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
        [Parameter(Mandatory=$true)][string]$domain,
        [Parameter(Mandatory=$false)][string]$brand
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
    $federationSettings = New-Object PSObject
    $federationSettings | Add-Member Noteproperty DomainName $domain
    $federationSettings | Add-Member Noteproperty Authentication "Federated"
    $federationSettings | Add-Member Noteproperty IssuerUri $IdPMetadata.EntityDescriptor.entityID
    if ($brand -ne "") {
        $federationSettings | Add-Member Noteproperty FederationBrandName $brand
    } else {
        $federationSettings | Add-Member Noteproperty FederationBrandName $domain
    }
    $federationSettings | Add-Member Noteproperty PassiveLogOnUri ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleSignOnService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"} | % {$_.Location})
    $federationSettings | Add-Member Noteproperty ActiveLogOnUri $federationSettings.PassiveLogOnUri
    $federationSettings | Add-Member Noteproperty LogOffUri ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleLogOutService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"} | % {$_.Location})
    $federationSettings | Add-Member Noteproperty MetadataExchangeUri $IdPMetadata.EntityDescriptor.AdditionalMetadataLocation.'#text'
    $federationSettings | Add-Member Noteproperty SigningCertificate ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor |  ? {$_.use -eq "signing"} | Select-Object -Last 1 | % {$_.KeyInfo.X509Data.X509Certificate})
    Set-MsolDomainAuthentication -DomainName $domain -Authentication Managed
    Set-MsolDomainAuthentication -DomainName $federationSettings.DomainName -Authentication $federationSettings.Authentication -IssuerUri $federationSettings.IssuerUri `
        -FederationBrandName $federationSettings.FederationBrandName -PassiveLogOnUri $federationSettings.PassiveLogOnUri `
        -ActiveLogOnUri $federationSettings.ActiveLogOnUri -SigningCertificate $federationSettings.SigningCertificate
}
Export-ModuleMember -Function Restore-MSOLFedSetFromMetadata