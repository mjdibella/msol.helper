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

function ConvertFrom-FederationMetaData {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline)][xml]$IdPMetadata,
        [Parameter()][string]$filename,
        [Parameter()][string]$Url
    )
    if ($filename -ne $null) {
        $Metadata = Get-Content -Path $filename
        [xml]$IdPMetadata = $Metadata
    } elseif ($Url -ne $null) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $Metadata = Invoke-RestMethod -Uri $Url
        [xml]$IdPMetadata = $Metadata
    }
    $federationSettings = New-Object PSObject
    $federationSettings | Add-Member Noteproperty IssuerUri $IdPMetadata.EntityDescriptor.entityID
    $federationSettings | Add-Member Noteproperty PassiveLogOnUri ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleSignOnService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"} | % {$_.Location})
    $federationSettings | Add-Member Noteproperty ActiveLogOnUri $federationSettings.PassiveLogOnUri
    $federationSettings | Add-Member Noteproperty LogOffUri ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleLogOutService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"} | % {$_.Location})
    $federationSettings | Add-Member Noteproperty MetadataExchangeUri $IdPMetadata.EntityDescriptor.AdditionalMetadataLocation.'#text'
    $federationSettings | Add-Member Noteproperty SigningCertificate ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor |  ? {$_.use -eq "signing"} | Select-Object -Last 1 | % {$_.KeyInfo.X509Data.X509Certificate})
    $federationsettings
}
Export-ModuleMember -Function ConvertFrom-FederationMetaData

function Get-MSOLFederationScript {
    param(
        [Parameter(Mandatory=$true,ParameterSetName="byFile")][string]$filename,
        [Parameter(Mandatory=$true,ParameterSetName="byUrl")][string]$Url,
        [Parameter(Mandatory=$true)][string]$domain,
        [Parameter(Mandatory=$false)][string]$brand
    )
    if ($filename -ne $null) {
        $federationSettings = ConvertFrom-FederationMetadata -filename $filename
    } elseif ($bundleId -ne $null) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $federationSettings = ConvertFrom-FederationMetadata -Url $Url
    }
    $federationSettings | Add-Member Noteproperty DomainName $domain
    $federationSettings | Add-Member Noteproperty Authentication "Federated"
    if ($brand -ne "") {
        $federationSettings | Add-Member Noteproperty FederationBrandName $brand
    } else {
        $federationSettings | Add-Member Noteproperty FederationBrandName $domain
    }
    write-output "Set-MsolDomainAuthentication -DomainName $($federationSettings.DomainName) -Authentication Managed"
    write-output "Set-MsolDomainAuthentication -DomainName $($federationSettings.DomainName) ``"
    write-output "    -Authentication $($federationSettings.Authentication) ``"
    write-output "    -IssuerUri $($federationSettings.IssuerUri) ``"
    write-output "    -FederationBrandName `"$($federationSettings.FederationBrandName)`" ``"
    write-output "    -PassiveLogOnUri $($federationSettings.PassiveLogOnUri) ``"
    write-output "    -ActiveLogOnUri $($federationSettings.ActiveLogOnUri) ``"
    write-output "    -MetadataExchangeUri $($federationSettings.metadataExchangeUri) ``"
    write-output "    -SigningCertificate $($federationSettings.SigningCertificate)"
}
Export-ModuleMember -Function Get-MSOLFederationScript

function Restore-MSOLFedSetFromMetadata {
    param(
        [Parameter(Mandatory=$true,ParameterSetName="byFile")][string]$filename,
        [Parameter(Mandatory=$true,ParameterSetName="byUrl")][string]$Url,
        [Parameter(Mandatory=$true)][string]$domain,
        [Parameter(Mandatory=$false)][string]$brand
    )
    if ($filename -ne $null) {
        $federationSettings = ConvertFrom-FederationMetadata -filename $filename
    } elseif ($bundleId -ne $null) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $federationSettings = ConvertFrom-FederationMetadata -Url $Url
    }
    Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
    if($?) {} else {
        Connect-MSOLService
    }
    $federationSettings | Add-Member Noteproperty DomainName $domain
    $federationSettings | Add-Member Noteproperty Authentication "Federated"
    if ($brand -ne "") {
        $federationSettings | Add-Member Noteproperty FederationBrandName $brand
    } else {
        $federationSettings | Add-Member Noteproperty FederationBrandName $domain
    }
    Set-MsolDomainAuthentication -DomainName $domain -Authentication Managed
    Set-MsolDomainAuthentication -DomainName $federationSettings.DomainName -Authentication $federationSettings.Authentication -IssuerUri $federationSettings.IssuerUri `
        -FederationBrandName $federationSettings.FederationBrandName -PassiveLogOnUri $federationSettings.PassiveLogOnUri `
        -ActiveLogOnUri $federationSettings.ActiveLogOnUri -MetadataExchangeUri $federationSettings.metadataExchangeUri -SigningCertificate $federationSettings.SigningCertificate
}
Export-ModuleMember -Function Restore-MSOLFedSetFromMetadata

