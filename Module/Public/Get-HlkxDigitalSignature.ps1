function Get-HlkxDigitalSignature {
<#

.SYNOPSIS
Verifies OPC digital signatures on an HLKX (or other Open XML package) file and returns signer certificate details.

.DESCRIPTION
Opens the path as a System.IO.Packaging package (same container format as .hlkx), uses PackageDigitalSignatureManager to report whether the package is signed and the aggregate VerifySignatures result, then enumerates each PackageDigitalSignature. For each signature the command records signing metadata, the VerifyCertificate chain flag summary, and extended X509 fields (subject, issuer, validity, EKU, key usage, basic constraints, thumbprint, serial number, public key algorithm).

Requires the WindowsBase assembly (System.IO.Packaging), which is available on Windows for Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Path
One or more paths to .hlkx or other OPC package files.

.PARAMETER EmbeddedSignatureOnly
When set, passes $true to VerifySignatures so only embedded signature semantics are validated. The default is full-package verification ($false).

.PARAMETER RevocationMode
Revocation behavior used when building the X509 chain for additional status detail (default: Online).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://learn.microsoft.com/dotnet/api/system.io.packaging.packagedigitalsignaturemanager

.EXAMPLE
Get-HlkxDigitalSignature -Path C:\kits\MyPackage.hlkx | Format-Table

.EXAMPLE
Get-ChildItem *.hlkx | Get-HlkxDigitalSignature | Where-Object { $_.OpcVerifyResult -ne 'Success' }

#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [string[]]$Path,

        [Parameter(Mandatory = $false)]
        [switch]$EmbeddedSignatureOnly,

        [Parameter(Mandatory = $false)]
        [System.Security.Cryptography.X509Certificates.X509RevocationMode]$RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
    )

    begin {
        try {
            Add-Type -AssemblyName WindowsBase -ErrorAction Stop
        }
        catch {
            throw "Get-HlkxDigitalSignature requires the WindowsBase assembly (System.IO.Packaging). $($_.Exception.Message)"
        }

        $dataTable = New-Object System.Data.DataTable 'HLKX digital signatures'
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn FilePath, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn ProcessingError, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn PackageIsSigned, ([bool])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn OpcVerifyResult, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SignatureCount, ([int])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SignatureIndex, ([int])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SignaturePartUri, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SignatureType, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SigningTime, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn TimeFormat, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn CertificateEmbeddingOption, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn OpcVerifyCertificateFlags, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn Subject, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn Issuer, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SerialNumber, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn Thumbprint, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn NotBefore, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn NotAfter, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn WithinValidityPeriod, ([bool])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SignatureAlgorithm, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn PublicKeyAlgorithm, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn EnhancedKeyUsage, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn KeyUsage, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn BasicConstraints, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn SubjectAlternativeDnsNames, ([string])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn ChainBuilt, ([bool])))
        [void]$dataTable.Columns.Add($(New-Object System.Data.DataColumn ChainStatusSummary, ([string])))

        function Get-HlkxExtensionText {
            param(
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
                [string]$OidValue
            )
            if ($null -eq $Certificate) {
                return [string]::Empty
            }
            foreach ($ext in $Certificate.Extensions) {
                if ($ext.Oid.Value -ne $OidValue) {
                    continue
                }
                if ($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                    $oids = @($ext.EnhancedKeyUsages | ForEach-Object { $_.Value })
                    return ($oids -join '; ')
                }
                if ($ext -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
                    return $ext.KeyUsages.ToString()
                }
                if ($ext -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
                    return "CA=$($ext.CertificateAuthority); PathLengthConstraint=$($ext.PathLengthConstraint)"
                }
            }
            return [string]::Empty
        }

        function Add-HlkxSignatureRow {
            param(
                [System.Data.DataTable]$Table,
                [string]$ResolvedPath,
                [string]$ProcessingError,
                [bool]$PackageIsSigned,
                [string]$OpcVerifyResult,
                [int]$SignatureCount,
                [int]$SignatureIndex,
                [System.IO.Packaging.PackageDigitalSignature]$Signature,
                [System.IO.Packaging.PackageDigitalSignatureManager]$Manager,
                [System.Security.Cryptography.X509Certificates.X509RevocationMode]$Revocation
            )

            $row = $Table.NewRow()
            $row.FilePath = $ResolvedPath
            $row.ProcessingError = $ProcessingError
            $row.PackageIsSigned = $PackageIsSigned
            $row.OpcVerifyResult = $OpcVerifyResult
            $row.SignatureCount = $SignatureCount
            $row.SignatureIndex = $SignatureIndex
            $empty = [string]::Empty
            $row.SignaturePartUri = $empty
            $row.SignatureType = $empty
            $row.SigningTime = $empty
            $row.TimeFormat = $empty
            $row.CertificateEmbeddingOption = $empty
            $row.OpcVerifyCertificateFlags = $empty
            $row.Subject = $empty
            $row.Issuer = $empty
            $row.SerialNumber = $empty
            $row.Thumbprint = $empty
            $row.NotBefore = $empty
            $row.NotAfter = $empty
            $row.WithinValidityPeriod = $false
            $row.SignatureAlgorithm = $empty
            $row.PublicKeyAlgorithm = $empty
            $row.EnhancedKeyUsage = $empty
            $row.KeyUsage = $empty
            $row.BasicConstraints = $empty
            $row.SubjectAlternativeDnsNames = $empty
            $row.ChainBuilt = $false
            $row.ChainStatusSummary = $empty

            if ($null -ne $Signature) {
                if ($null -ne $Signature.SignaturePart -and $null -ne $Signature.SignaturePart.Uri) {
                    $row.SignaturePartUri = $Signature.SignaturePart.Uri.ToString()
                }
                $row.SignatureType = [string]$Signature.SignatureType
                if ($Signature.SigningTime -ne [datetime]::MinValue) {
                    $row.SigningTime = $Signature.SigningTime.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                $row.TimeFormat = [string]$Signature.TimeFormat
                $row.CertificateEmbeddingOption = $Signature.CertificateEmbeddingOption.ToString()

                if ($null -ne $Manager -and $null -ne $Signature.Signer) {
                    try {
                        $flags = $Manager.VerifyCertificate($Signature.Signer)
                        $row.OpcVerifyCertificateFlags = $flags.ToString()
                    }
                    catch {
                        $row.OpcVerifyCertificateFlags = "VerifyCertificate failed: $($_.Exception.Message)"
                    }
                }

                if ($null -ne $Signature.Signer) {
                    $cert2 = $null
                    try {
                        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Signature.Signer
                    }
                    catch {
                        $row.Subject = "Could not load signer certificate: $($_.Exception.Message)"
                    }

                    if ($null -ne $cert2) {
                        try {
                            $row.Subject = $cert2.Subject
                            $row.Issuer = $cert2.Issuer
                            $row.SerialNumber = $cert2.SerialNumber
                            $row.Thumbprint = $cert2.Thumbprint
                            $row.NotBefore = $cert2.NotBefore.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                            $row.NotAfter = $cert2.NotAfter.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture)
                            $utcNow = [datetime]::UtcNow
                            $row.WithinValidityPeriod = ($utcNow -ge $cert2.NotBefore.ToUniversalTime()) -and ($utcNow -le $cert2.NotAfter.ToUniversalTime())
                            $row.SignatureAlgorithm = $cert2.SignatureAlgorithm.FriendlyName
                            if ($null -ne $cert2.PublicKey -and $null -ne $cert2.PublicKey.Oid) {
                                $row.PublicKeyAlgorithm = $cert2.PublicKey.Oid.FriendlyName
                            }
                            $row.EnhancedKeyUsage = Get-HlkxExtensionText -Certificate $cert2 -OidValue '2.5.29.37'
                            $row.KeyUsage = Get-HlkxExtensionText -Certificate $cert2 -OidValue '2.5.29.15'
                            $row.BasicConstraints = Get-HlkxExtensionText -Certificate $cert2 -OidValue '2.5.29.19'
                            try {
                                $dns = @($cert2.DnsNameList | ForEach-Object { $_.Unicode })
                                $row.SubjectAlternativeDnsNames = ($dns -join '; ')
                            }
                            catch {
                                $row.SubjectAlternativeDnsNames = [string]::Empty
                            }

                            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                            $chain.ChainPolicy.RevocationMode = $Revocation
                            try {
                                $row.ChainBuilt = $chain.Build($cert2)
                                $statusTexts = @(
                                    $chain.ChainStatus |
                                        ForEach-Object {
                                            '{0}: {1}' -f $_.Status.ToString(), $_.StatusInformation.Trim()
                                        } |
                                        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                                )
                                $row.ChainStatusSummary = ($statusTexts -join ' | ')
                            }
                            catch {
                                $row.ChainBuilt = $false
                                $row.ChainStatusSummary = "Chain.Build failed: $($_.Exception.Message)"
                            }
                            finally {
                                if ($null -ne $chain) {
                                    $chain.Reset()
                                }
                            }
                        }
                        finally {
                            $cert2.Dispose()
                        }
                    }
                }
            }

            [void]$Table.Rows.Add($row)
        }
    }

    process {
        foreach ($singlePath in $Path) {
            $resolved = $null
            try {
                $resolved = (Resolve-Path -LiteralPath $singlePath -ErrorAction Stop).Path
            }
            catch {
                $err = $_.Exception.Message
                Add-HlkxSignatureRow -Table $dataTable -ResolvedPath $singlePath -ProcessingError $err -PackageIsSigned $false -OpcVerifyResult [string]::Empty -SignatureCount 0 -SignatureIndex -1 -Signature $null -Manager $null -Revocation $RevocationMode
                continue
            }

            $package = $null
            try {
                $package = [System.IO.Packaging.Package]::Open(
                    $resolved,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::Read)
            }
            catch {
                Add-HlkxSignatureRow -Table $dataTable -ResolvedPath $resolved -ProcessingError $_.Exception.Message -PackageIsSigned $false -OpcVerifyResult [string]::Empty -SignatureCount 0 -SignatureIndex -1 -Signature $null -Manager $null -Revocation $RevocationMode
                continue
            }

            try {
                $manager = New-Object System.IO.Packaging.PackageDigitalSignatureManager -ArgumentList $package
                $isSigned = $manager.IsSigned
                $opcResult = [string]::Empty
                if ($isSigned) {
                    $verify = $manager.VerifySignatures($EmbeddedSignatureOnly.IsPresent)
                    $opcResult = $verify.ToString()
                }
                else {
                    $opcResult = 'NotSigned'
                }

                if (-not $isSigned -or $null -eq $manager.Signatures -or $manager.Signatures.Count -eq 0) {
                    Add-HlkxSignatureRow -Table $dataTable -ResolvedPath $resolved -ProcessingError [string]::Empty -PackageIsSigned $isSigned -OpcVerifyResult $opcResult -SignatureCount 0 -SignatureIndex -1 -Signature $null -Manager $manager -Revocation $RevocationMode
                }
                else {
                    $index = 0
                    foreach ($sig in $manager.Signatures) {
                        Add-HlkxSignatureRow -Table $dataTable -ResolvedPath $resolved -ProcessingError [string]::Empty -PackageIsSigned $isSigned -OpcVerifyResult $opcResult -SignatureCount $manager.Signatures.Count -SignatureIndex $index -Signature $sig -Manager $manager -Revocation $RevocationMode
                        $index++
                    }
                }
            }
            finally {
                if ($null -ne $package) {
                    $package.Close()
                }
            }
        }
    }

    end {
        return ,$dataTable
    }
}
