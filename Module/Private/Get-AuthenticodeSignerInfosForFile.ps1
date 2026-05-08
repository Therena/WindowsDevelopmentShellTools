function Get-AuthenticodeSignerInfosForFile {
<#

.SYNOPSIS
Reads embedded PKCS#7 signer information from a PE file on disk.

.DESCRIPTION
Calls CryptQueryObject to extract an embedded CMS signature and returns SignerInfo objects. Used by Get-AuthenticodeDetails. This command is not exported from the module.

.PARAMETER FilePath
Path to a signed portable executable or other file Authenticode can query.

#>
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    return [Therena.Encryption.Certificate]::GetCertificates($FilePath)
}
