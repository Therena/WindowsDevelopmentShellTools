# One-off / maintenance: regenerates nested-authenticode-attribute.cms for Pester.
# Run from repo root: pwsh -File Tests/Fixtures/_Generate-NestedAuthenticodeFixture.ps1
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'nested-authenticode-attribute.cms'

$innerCert = New-SelfSignedCertificate -Subject 'CN=Inner Nested Fixture' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(1)
$outerCert = New-SelfSignedCertificate -Subject 'CN=Outer Fixture' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation 'Cert:\CurrentUser\My' -NotAfter (Get-Date).AddYears(1)
try {
    $contentInner = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]3)
    $innerCms = New-Object System.Security.Cryptography.Pkcs.SignedCms $contentInner, $false
    $innerSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $innerCert
    $innerSigner.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    $innerCms.ComputeSignature($innerSigner)
    $innerBytes = $innerCms.Encode()

    $contentOuter = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]5)
    $outerCms = New-Object System.Security.Cryptography.Pkcs.SignedCms $contentOuter, $false
    $outerSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $outerCert
    $nestedOid = [System.Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.2.4.1')
    $asn = [System.Security.Cryptography.AsnEncodedData]::new($nestedOid, $innerBytes)
    $coll = [System.Security.Cryptography.AsnEncodedDataCollection]::new()
    [void]$coll.Add($asn)
    $attr = [System.Security.Cryptography.CryptographicAttributeObject]::new($nestedOid, $coll)
    [void]$outerSigner.UnsignedAttributes.Add($attr)
    $outerCms.ComputeSignature($outerSigner)
    $fixture = $outerCms.Encode()
    [System.IO.File]::WriteAllBytes($out, $fixture)
    Write-Host "Wrote $out ($($fixture.Length) bytes)"
}
finally {
    Remove-Item -Path ('Cert:\CurrentUser\My\' + $innerCert.Thumbprint) -Force -ErrorAction SilentlyContinue
    Remove-Item -Path ('Cert:\CurrentUser\My\' + $outerCert.Thumbprint) -Force -ErrorAction SilentlyContinue
}
