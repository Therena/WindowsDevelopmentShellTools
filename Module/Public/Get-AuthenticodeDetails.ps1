function Get-AuthenticodeDetails {
<#

.SYNOPSIS
Lists Authenticode certificates and public key material for a file.

.DESCRIPTION
Loads PKCS signer infos from the file, fills a DataTable with subject, issuer, digest algorithm, thumbprint, and public key (hex), then walks Microsoft nested-signature attributes (OID 1.3.6.1.4.1.311.2.4.1) when present.

.PARAMETER File
Path to the file to inspect (typically a signed PE).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://www.sysadmins.lv/blog-en/reading-multiple-signatures-from-signed-file-with-powershell.aspx

.EXAMPLE
Get-AuthenticodeDetails C:\Windows\System32\drivers\dumpfve.sys


Subject         : CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
Issuer          : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
DigestAlgorithm : sha256
Thumbprint      : 419E77AED546A1A6CF4DC23C1F977542FE289CF7
PublicKey       : 30 82 01 0A 02 82 01 01 00 CA E0 A8 0C CC D6 94 D5 42 FA F8 60 DD 5F BA 35 7E 90 B8 A2 C0 8D 92 6E 5F 10 DD A0 62 75 7A 8F 19 65 3B 65 87 98 38 EB 62 D5 D0 B4 75 B7 C9 9B 41 01 39 89 4D D0
                  86 D7 52 AD E4 2F 57 D3 92 7D 02 8B 2C 17 E0 3D DF D2 F0 92 AC 03 98 66 A5 00 7B F8 64 E2 06 32 39 F7 F5 B6 4F 70 0D 76 96 EC CD 82 7B 47 B5 A3 1D C0 43 BC 24 4A FB 69 B8 74 53 A3 4B 8E 4E
                  CB 32 2C 12 9A 78 D7 50 5C 59 B3 96 06 93 81 8A E9 45 3A CA AF 3E 16 94 5A 76 8C 7E FD EE F7 93 70 73 54 67 14 D2 64 48 F3 DA FF 9D 20 0F 86 1E 83 60 66 7D AE DC DD D0 D0 AF DA 54 E9 82 72
                  BE AE D6 86 76 25 F6 0D FE AA B2 CD FD EE F5 5C 77 3D BE 32 44 90 83 33 7E 9E B9 E1 AD C4 80 CD 5F BD F7 1F 46 85 E7 07 C8 30 00 51 81 5B 08 20 0E EC 58 23 B2 22 89 3A B4 DA B7 E4 C4 A1 65
                  C9 90 26 B8 9A 86 ED AB DC 92 60 6B 43 02 03 01 00 01

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelinebyPropertyName=$True)]
        [string]$File   
    )
        
    $Table = New-Object System.Data.DataTable "File Certificates"
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Subject, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Issuer, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn DigestAlgorithm, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn Thumbprint, ([string])))
    [void]$Table.Columns.Add($(New-Object system.Data.DataColumn PublicKey, ([string])))
    
    $CertificateList = Get-AuthenticodeSignerInfosForFile -FilePath $File
    $DnsName = [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName;
    
    foreach($Cert in $CertificateList) {
        $Row = $Table.NewRow()
    
        $Row.Subject = $Cert.Certificate.Subject;
        $Row.Issuer = $Cert.Certificate.Issuer;
        $Row.DigestAlgorithm = $Cert.DigestAlgorithm.FriendlyName;
        $Row.Thumbprint = $Cert.Certificate.Thumbprint;
        $Row.PublicKey = [System.BitConverter]::ToString($Cert.Certificate.PublicKey.EncodedKeyValue.RawData).Replace("-", " ")

        [void]$Table.Rows.Add($Row)
        
        Get-NestedAuthenticodeDetails -Certificate $Cert -Table $Table
    }

    return ,$Table
}
