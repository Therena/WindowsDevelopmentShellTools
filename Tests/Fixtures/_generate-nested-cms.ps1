# Dev helper: builds nested SignedCms (OID 1.3.6.1.4.1.311.2.4.1) and writes nested-authenticode-attribute.cms
$ErrorActionPreference = 'Stop'
$pwshDir = Split-Path -Parent (Get-Command -Name pwsh.exe -CommandType Application | Select-Object -First 1).Source
$pkcs = Join-Path $pwshDir 'System.Security.Cryptography.Pkcs.dll'
if (-not (Test-Path -LiteralPath $pkcs)) {
    $pkcs = Join-Path $PSHOME 'System.Security.Cryptography.Pkcs.dll'
}
[void][System.Reflection.Assembly]::LoadFrom($pkcs)
$fixturesDir = $PSScriptRoot
$outFile = Join-Path $fixturesDir 'nested-authenticode-attribute.cms'

$certInner = New-SelfSignedCertificate -Subject 'CN=Inner Nested Fixture' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
$certOuter = New-SelfSignedCertificate -Subject 'CN=Outer Nested Fixture' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
try {
    $innerContent = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]0x41)
    $innerCms = New-Object System.Security.Cryptography.Pkcs.SignedCms $innerContent, $false
    $innerSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $certInner
    $innerCms.ComputeSignature($innerSigner)
    $innerEncoded = $innerCms.Encode()

    $nestOid = [System.Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.2.4.1')
    $nestValue = New-Object System.Security.Cryptography.AsnEncodedData $nestOid, $innerEncoded
    $nestColl = New-Object System.Security.Cryptography.AsnEncodedDataCollection
    [void]$nestColl.Add($nestValue)
    $nestAttr = New-Object System.Security.Cryptography.CryptographicAttributeObject $nestOid, $nestColl

    $outerContent = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]0x42)
    $outerCms = New-Object System.Security.Cryptography.Pkcs.SignedCms $outerContent, $false
    $outerSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $certOuter
    [void]$outerSigner.UnsignedAttributes.Add($nestAttr)
    $outerCms.ComputeSignature($outerSigner)
    $bytes = $outerCms.Encode()
    [System.IO.File]::WriteAllBytes($outFile, $bytes)
    Write-Host "Wrote $($bytes.Length) bytes to $outFile"
} finally {
    Remove-Item -Path ('Cert:\CurrentUser\My\' + $certInner.Thumbprint) -Force -ErrorAction SilentlyContinue
    Remove-Item -Path ('Cert:\CurrentUser\My\' + $certOuter.Thumbprint) -Force -ErrorAction SilentlyContinue
}
