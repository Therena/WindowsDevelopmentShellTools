function Get-NestedAuthenticodeDetails {
<#

.SYNOPSIS
Recursively expands nested Authenticode signatures into the certificate table.

.DESCRIPTION
Looks for PKCS signer unsigned attributes with OID 1.3.6.1.4.1.311.2.4.1 (nested signature). Each attribute value is decoded as a CMS signed message; nested signers are appended to the DataTable and processed recursively. This command is not exported from the module.

.PARAMETER Certificate
A System.Security.Cryptography.Pkcs.SignerInfo from the outer or parent signature.

.PARAMETER Table
DataTable with Subject, Issuer, DigestAlgorithm, Thumbprint, and PublicKey columns (same shape as Get-AuthenticodeDetails).

.LINK
https://github.com/Therena/Windows-Development-Shell-Tools
https://www.sysadmins.lv/blog-en/reading-multiple-signatures-from-signed-file-with-powershell.aspx

.EXAMPLE
Get-NestedAuthenticodeDetails -Certificate $Cert -Table $Table

#>
    [CmdletBinding()]
    param (
        [parameter(Mandatory=$true)]
        [System.Security.Cryptography.Pkcs.SignerInfo]$Certificate,
        
        [parameter(Mandatory=$true)]
        [System.Data.DataTable]$Table  
    )

    $NestedCerts = $Certificate.UnsignedAttributes | Where-Object {$_.Oid.Value -eq "1.3.6.1.4.1.311.2.4.1"}
    $DnsName = [System.Security.Cryptography.X509Certificates.X509NameType]::DnsName;
    
    foreach($RawSubCert in $NestedCerts) {
        $CertificateList = [Therena.Encryption.Certificate]::DecodeCertificateData($RawSubCert.Values[0].RawData)
        
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
    }
}
