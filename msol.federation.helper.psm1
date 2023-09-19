function Get-MSOLTenantName {
    (Get-MSOLDomain | Where-Object {$_.Name -like '*.onmicrosoft.com' -and $_.Name -NotLike '*.mail.onmicrosoft.com'}).Name
}
Export-ModuleMember -Function Get-MSOLTenantName

function Get-MSOLDefaultDomain {
    (Get-MSOLDomain | Where-Object {$_.IsDefault -eq $True}).Name
}
Export-ModuleMember -Function Get-MSOLDefaultDomain

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
        if ($domains.count -lt 1) {
            Write-Warning "No federated domains present."
        } elseif ($domains.count -gt 1) {
            Write-Warning "Multiple federated domains present. Exporting $domain. Use -domain to specify other domains."
        }
        $domain = ($domains | select-object -first 1 -wait).name
    }
    if ($domain -ne "") {
        if ((Get-MsolDomain -DomainName $domain).Authentication -eq "Managed") {
            Write-warning "Domain $domain is not federated."
        } else {
            $federationsettings = Get-MsolDomainFederationSettings -domain $domain
            $federationsettings | add-member -NotePropertyName federatedDomain -NotePropertyValue $domain
            $federationsettings | ConvertTo-JSON | Out-File $filename
        }
    }
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
    Set-MsolDomain -Name $(Get-MSOLTenantName) -IsDefault
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

function Get-SigningCertFromMetadata {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline)][xml]$IdPMetadata,
        [Parameter()][string]$filename,
        [Parameter()][string]$Url
    )
    if ($filename) {
        $Metadata = Get-Content -Path $filename
        [xml]$IdPMetadata = $Metadata
    } elseif ($Url) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $Metadata = (Invoke-WebRequest -Uri $Url).Content
        [xml]$IdPMetadata = $Metadata
    }
    $signingCertificateData = ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor |  ? {$_.use -eq "signing"} | Select-Object -Last 1 | % {$_.KeyInfo.X509Data.X509Certificate})
    if (-not ($signingCertificateData)) {
        $signingCertificateData = ($IdPMetadata.EntityDescriptor.SPSSODescriptor.KeyDescriptor |  ? {$_.use -eq "signing"} | Select-Object -Last 1 | % {$_.KeyInfo.X509Data.X509Certificate})
    }
    if ($signingCertificateData) {
        $signingCertificateData = $signingCertificateData.Replace("`n","")
        $signingCertificateData = $signingCertificateData.Replace("`r","")
        "-----BEGIN CERTIFICATE-----"
        $signingCertificateData -Split '(.{64})' | ? {$_}
        "-----END CERTIFICATE-----"
    }
}
Export-ModuleMember -Function Get-SigningCertFromMetadata

function ConvertFrom-FederationMetaData {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipeline)][xml]$IdPMetadata,
        [Parameter()][string]$filename,
        [Parameter()][string]$Url
    )
    if ($filename) {
        $Metadata = Get-Content -Path $filename
        [xml]$IdPMetadata = $Metadata
    } elseif ($Url) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $Metadata = (Invoke-WebRequest -Uri $Url).Content
        [xml]$IdPMetadata = $Metadata
    }
    $federationSettings = New-Object PSObject
    $federationSettings | Add-Member Noteproperty IssuerUri $IdPMetadata.EntityDescriptor.entityID
    $federationSettings | Add-Member Noteproperty PassiveLogOnUri ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleSignOnService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"} | % {$_.Location})
    $federationSettings | Add-Member Noteproperty ActiveLogOnUri $federationSettings.PassiveLogOnUri
    $federationSettings | Add-Member Noteproperty LogOffUri ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.SingleLogOutService | ? {$_.Binding -eq "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"} | % {$_.Location})
    if ($url -and (-not ($IdPMetadata.EntityDescriptor.AdditionalMetadataLocation.'#text'))) {
        $federationSettings | Add-Member Noteproperty MetadataExchangeUri $Url
    } else {
        $federationSettings | Add-Member Noteproperty MetadataExchangeUri $IdPMetadata.EntityDescriptor.AdditionalMetadataLocation.'#text'
    }
    $federationSettings | Add-Member Noteproperty SigningCertificate ($IdPMetadata.EntityDescriptor.IDPSSODescriptor.KeyDescriptor |  ? {$_.use -eq "signing"} | Select-Object -Last 1 | % {$_.KeyInfo.X509Data.X509Certificate})
    $federationsettings
}
Export-ModuleMember -Function ConvertFrom-FederationMetaData

function Get-MSOLFederationScript {
    param(
        [cmdletbinding(DefaultParameterSetName='byUrl')]
        [Parameter(Mandatory=$true,ParameterSetName="byFile")][string]$filename,
        [Parameter(Mandatory=$true,ParameterSetName="byUrl")][string]$Url,
        [Parameter(Mandatory=$true)][string]$domain,
        [Parameter(Mandatory=$false)][string]$brand
    )
    if ($filename) {
        $federationSettings = ConvertFrom-FederationMetadata -filename $filename
    } elseif ($Url) {
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
    $issuerURI = $federationSettings.IssuerURI
    write-output "# connect to MSOL if necessary"
    write-output "Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null"
    write-output "if(`$?) {} else {"
    write-output "    Connect-MSOLService"
    write-output "}"
    write-output "# can't federate the default domain, so set the tenant name domain default instead"
    write-output "if ((Get-MSOLDomain | Where-Object {`$_.IsDefault -eq `$True}).Name -eq '$domain') {"
    write-output "    Set-MsolDomain -Name (Get-MSOLDomain | Where-Object {`$_.Name -like '*.onmicrosoft.com' -and `$_.Name -NotLike '*.mail.onmicrosoft.com'}).Name -IsDefault"
    write-output "}"
    write-output "# reset authentication settings to defaults"
    write-output "Set-MsolDomainAuthentication -DomainName $($federationSettings.DomainName) -Authentication Managed"
    write-output "# federate the domain"
    write-output "Set-MsolDomainAuthentication -DomainName $($federationSettings.DomainName) ``"
    write-output "    -Authentication $($federationSettings.Authentication) ``"
    write-output "    -IssuerUri $($federationSettings.IssuerUri) ``"
    write-output "    -FederationBrandName `"$($federationSettings.FederationBrandName)`" ``"
    write-output "    -PassiveLogOnUri $($federationSettings.PassiveLogOnUri) ``"
    write-output "    -ActiveLogOnUri $($federationSettings.ActiveLogOnUri) ``"
    write-output "    -LogOffURI $($federationSettings.LogOffUri) ``"
    if ($url -and (-not ($federationSettings.metadataExchangeUri))) {
        write-output "    -MetadataExchangeUri $($url) ``"
    } else {
        write-output "    -MetadataExchangeUri $($federationSettings.metadataExchangeUri) ``"
    }
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
    if ($filename) {
        $federationSettings = ConvertFrom-FederationMetadata -filename $filename
    } elseif ($Url) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
        $federationSettings = ConvertFrom-FederationMetadata -Url $Url
    }
    Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
    if($?) {} else {
        Connect-MSOLService
    }
    $federationSettings | Add-Member Noteproperty DomainName $domain
    $federationSettings | Add-Member Noteproperty Authentication "Federated"
    if ($brand) {
        $federationSettings | Add-Member Noteproperty FederationBrandName $brand
    } else {
        $federationSettings | Add-Member Noteproperty FederationBrandName $domain
    }
    if ((Get-MSOLDomain | Where-Object {`$_.IsDefault -eq `$True}).Name -eq '$domain') {
        Set-MsolDomain -Name (Get-MSOLDomain | Where-Object {`$_.Name -like '*.onmicrosoft.com' -and `$_.Name -NotLike '*.mail.onmicrosoft.com'}).Name -IsDefault
    }
    Set-MsolDomainAuthentication -DomainName $domain -Authentication Managed
    Set-MsolDomainAuthentication -DomainName $federationSettings.DomainName -Authentication $federationSettings.Authentication `
        -IssuerUri $federationSettings.IssuerUri -FederationBrandName $federationSettings.FederationBrandName `
        -PassiveLogOnUri $federationSettings.PassiveLogOnUri -ActiveLogOnUri $federationSettings.ActiveLogOnUri `
        -LogOffURI $federationSettings.LogOffUri -MetadataExchangeUri $federationSettings.metadataExchangeUri `
        -SigningCertificate $federationSettings.SigningCertificate
}
Export-ModuleMember -Function Restore-MSOLFedSetFromMetadata

function ConvertTo-FederatedMailbox {
    # Get-ADUser -filter "mail -like '*'" | ConvertTo-FederatedMailbox
    # Get-MSOLUser | ConvertTo-FederatedMailbox
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName,Mandatory=$true,ParameterSetName="byUPN")][string[]]$UserPrincipalName,
        [Parameter()][string]$aDAttribute = 'userPrincipalName',
        [Parameter()][string]$mSOLAttribute = 'UserPrincipalName',
        [Parameter()][string]$sourceAnchor = 'objectGUID'
    )
    begin {
        Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
        if($?) {} else {
            Connect-MSOLService
        }
        Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
        if($?) {
            $MSOLConnected = $True
        } else {
            $MSOLConnected = $False
        }
    }
    process {
        if ($MSOLConnected -eq $True) {
            foreach ($UPN in $UserPrincipalName) {
                $MSOLUser = Get-MSOLUser -UserPrincipalName $UPN -ErrorAction SilentlyContinue
                if ($MSOLUser -eq $null) {
                    Write-Warning "No MSOL user found for $UPN."
                } else {
                    if ($MSOLUser.ImmutableId -ne $null) {
                        Write-Warning "ImmutableID already set for $UPN."
                    } else {
                        $ADFilter = "$aDAttribute -eq '$($MSOLUser.$mSOLAttribute)'"
                        $ADUser = Get-ADUser -Filter $ADFilter -Properties $sourceAnchor
                        if ($ADUser -eq $null) {
                            Write-Warning "No AD user found with $aDAttribute $($MSOLUser.$mSOLAttribute)."
                        } else {
                            if ($($AdUser.$sourceAnchor) -eq $null) {
                                Write-Warning "Source anchor $sourceAnchor is null for $AdUser.DistinguishedName."
                            } else {
                                $immutableID = (ConvertFrom-ImmutableId -Value $AdUser.$sourceAnchor).String
                                Set-MsolUser –UserPrincipalName $UPN –ImmutableID $immutableId
                                Set-MsolUserPrincipalName -UserPrincipalName $UPN -NewUserPrincipalName $($AdUser.userPrincipalName)
                            }
                        }
                    }
                }
            }
        }
    }
    end {}
}
Export-ModuleMember -Function ConvertTo-FederatedMailbox

function ConvertTo-ManagedMailbox {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName,Mandatory=$true,ParameterSetName="byUPN")][string[]]$UserPrincipalName,
        [Parameter()][string]$upnAttribute
    )
    begin {
        Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
        if($?) {} else {
            Connect-MSOLService
        }
        Get-MsolDomain -ErrorAction SilentlyContinue | Out-Null
        if($?) {
            $MSOLConnected = $True
        } else {
            $MSOLConnected = $False
        }
    }
    process {
        if ($MSOLConnected -eq $True) {
            foreach ($UPN in $UserPrincipalName) {
                $MSOLUser = Get-MSOLUser -UserPrincipalName $UPN -ErrorAction SilentlyContinue
                if ($MSOLUser -eq $null) {
                    Write-Warning "No MSOL user found for $UPN."
                } else {
                    if ($upnAttribute -eq '') {
                        $userId = $UPN.Substring(0,$UPN.IndexOf("@"))
                        $newUpn = "$userId@" + $(Get-MSOLTenantName)
                    } else {
                        $newUpn = (Get-ADUser -filter "userPrincipalName -eq '$($UserPrincipalName)'" -properties $upnAttribute).$upnAttribute
                    }
                    if ($newUpn -eq '') {
                        Write-Warning "Cannot convert mailbox to null UserPrincipalName." 
                    } else {
                        Set-MsolUserPrincipalName -UserPrincipalName $UPN -NewUserPrincipalName $newUPN
                        Set-Msoluser -UserPrincipalName $newUpn -ImmutableID ''
                    }
                }
            }
        }
    }
    end {}
}
Export-ModuleMember -Function ConvertTo-ManagedMailbox

function ConvertFrom-ImmutableId {
    [CmdletBinding()]
    param (
	    [Parameter(ValueFromPipeline,Mandatory = $true)][string]$Value
    )

    # identification helper functions
    function isGUID ($data) { 
	    try {
            $guid = [GUID]$data 
		    return 1 
	    } catch { 
            return 0
        } 
    }

    function isBase64 ($data) { 
	    try { 	
            $decodedII = [system.convert]::frombase64string($data) 
            return 1
        } catch { 
            return 0
        } 
    }

    function isHEX ($data) { 
        try {
     	    $decodedHEX = "$data" -split ' ' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}
		    return 1
        } catch { 
            return 0 
        } 
    }

    function isDN ($data) { 
	    If ($data.ToLower().StartsWith("cn={")) {
		    return 1
        } else {
            return 0 
        }
    }

    # conversion functions
    function ConvertIItoDecimal ($data) {
	    if (isBase64 $data) {
		    $dec = ([system.convert]::FromBase64String("$data") | ForEach-Object ToString) -join ' '
		    return $dec
	    }
    }

    function ConvertIIToHex ($data) {
	    if (isBase64 $data) {
		    $hex = ([system.convert]::FromBase64String("$data") | ForEach-Object ToString X2) -join ' '
		    return $hex
	    }	
    }

    function ConvertIIToGuid ($data) {
	    if (isBase64 $data) {
		    $guid = [system.convert]::FromBase64String("$data")
		    return [guid]$guid
	    }
    }

    function ConvertHexToII ($data) {
	    if (isHex $data) {
		    $bytearray = "$data" -split ' ' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}
		    $ImmID = [system.convert]::ToBase64String($bytearray)
		    return $ImmID
	    }
    }

    function ConvertIIToDN ($data) {
	    if (isBase64 $data) {
		    $enc = [system.text.encoding]::utf8
		    $result = $enc.getbytes($data)
		    $dn = $result | foreach { ([convert]::ToString($_,16)) }
		    $dn = $dn -join ''
		    return "CN={$dn}"
	    }
    }

    function ConvertDNtoII ($data) {
	    if (isDN $data) {
		    $hexstring = $data.replace("CN={","")
		    $hexstring = $hexstring.replace("}","")
		    $array = @{}
		    $array = $hexstring -split "(..)" | ? {$_}
		    $ImmID = $array | FOREACH { [CHAR][BYTE]([CONVERT]::ToInt16($_,16))}
		    $ImmID = $ImmID -join ''
		    return $ImmID
	    }
    }

    function ConvertGUIDToII ($data) {
	    if (isGUID $data) {
		    $guid = [GUID]$data
    		    $bytearray = $guid.tobytearray()
    		    $ImmID = [system.convert]::ToBase64String($bytearray)
		    return $ImmID
	    }
    }

    # from byte string (converted to byte array)
    If ( ($value -replace ' ','') -match "^[\d\.]+$") {
	    $bytearray = ("$value" -split ' ' | foreach-object {[System.Convert]::ToByte($_)})
	    $HEXID = ($bytearray| ForEach-Object ToString X2) -join ' '
	    $identified = "1"
	    $ImmID = ConvertHexToII $HEXID
	    $dn = ConvertIIToDN $ImmID
	    $GUIDImmutableID = ConvertIIToGuid $ImmID
    }

    # from hex
    If ($value -match " ") {
	    If ( ($value -replace ' ','') -match "^[\d\.]+$") {
		    Return
	    }
	    $identified = "1"
	    $ImmID = ConvertHexToII $value
	    $dec = ConvertIItoDecimal $ImmID
	    $dn = ConvertIIToDN $ImmID
	    $GUIDImmutableID = ConvertIIToGuid $ImmID
        $HEXID = $Value
    }

    # from immutableid
    If ($value.EndsWith("==")) {
	    $identified = "1"
	    $dn = ConvertIIToDn $Value	
	    $HEXID = ConvertIIToHex $Value
	    $GUIDImmutableID = ConvertIIToGuid $Value
	    $dec = ConvertIItoDecimal $value
        $ImmID = $Value
    }

    # from  dn
    If ($value.ToLower().StartsWith("cn={")) {
	    $identified = "1"
	    $ImmID = ConvertDNToII $Value
	    $HEXID = ConvertIIToHex $ImmID
	    $GUIDImmutableID = ConvertIIToGuid $ImmID
	    $dec = ConvertIItoDecimal $ImmID
        $DN = $Value
    }

    # from guid
    if ( isGuid $Value) {
	    $identified = "1"
	    $ImmID = ConvertGUIDToII $Value
	    $dn = ConvertIIToDN $ImmID
	    $HEXID = ConvertIIToHex $ImmID
	    $dec = ConvertIItoDecimal $ImmID
        $GUIDImmutableID = $Value
    }

    If (-not($identified)) {
	    Write-warning 'Value was neither an ImmutableID (ended with ==), a DN (started with "CN={"), a GUID, a HEX-value, nor a Decimal-value.'
    } else {
        $converted = New-Object PSObject
        $converted | Add-Member Noteproperty Decimal $dec
        $converted | Add-Member Noteproperty String $ImmID
        $converted | Add-Member Noteproperty HEX $HEXID
        $converted | Add-Member Noteproperty DN $dn
        $converted | Add-Member Noteproperty GUID $GUIDImmutableID
        return $converted
    }
}
Export-ModuleMember -Function ConvertFrom-ImmutableId

function Find-SourceAnchor {
    [cmdletbinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName,Mandatory=$true)][string]$ImmutableId
    )
    $attributeList = ('objectGuid','mS-DS-ConsistencyGuid','msDS-sourceAnchor')
    foreach ($searchAttribute in $attributeList) {
        $searchValue = '\' + (ConvertFrom-ImmutableId -Value $ImmutableId).Hex -replace ' ','\'
        $LDAPFilter = "($searchAttribute=$searchValue)"
        $ADUser = Get-ADUser -LDAPFilter $LDAPFilter
        if ($ADUser -ne $null) {
            $results = New-Object PSObject
            $results | Add-Member Noteproperty Name $ADUser.Name
            $results | Add-Member Noteproperty UserPrincipalName $ADUser.UserPrincipalName
            $results | Add-Member Noteproperty DistinguishedName $ADUser.DistinguishedName
            $results | Add-Member Noteproperty SourceAnchor $searchAttribute
            $results | Add-Member Noteproperty SearchValue $searchValue
            $results | Add-Member Noteproperty searchFilter $LDAPFilter
            break
        }
    }
    if ($results -ne $null) {
        return $results
    } else {
        write-warning "No AD user found for that ImmutableId."
    }
}
Export-ModuleMember -Function Find-SourceAnchor

function Get-MSOLFederationMetadata {
    param(
        [Parameter(Mandatory=$true)][string]$filename
    )
    $filepath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($filename)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
    $xml = (Invoke-WebRequest -Uri 'https://nexus.microsoftonline-p.com/federationmetadata/saml20/federationmetadata.xml').Content
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($filepath, $xml, $Utf8NoBomEncoding)
}
Export-ModuleMember Get-MSOLFederationMetadata