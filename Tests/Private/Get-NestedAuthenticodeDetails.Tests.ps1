. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-NestedAuthenticodeDetails' -Skip:(-not $script:IsWindowsOs) {
    It 'adds no rows when the signer has no nested PKCS attributes' {
        $signers = $null
        $cert = New-SelfSignedCertificate -Subject 'CN=NestedPath Signer' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddHours(1)
        try {
            $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]2)
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms $content, $false
            $cmsSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $cert
            $cms.ComputeSignature($cmsSigner)
            $signers = [Therena.Encryption.Certificate]::DecodeCertificateData($cms.Encode())
        } finally {
            Remove-Item -Path ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
        InModuleScope $script:ModuleName -ArgumentList @(, $signers) -ScriptBlock {
            param($SignerArray)
            $tbl = New-Object System.Data.DataTable 'NestedTest'
            [void]$tbl.Columns.Add('Subject', [string])
            [void]$tbl.Columns.Add('Issuer', [string])
            [void]$tbl.Columns.Add('DigestAlgorithm', [string])
            [void]$tbl.Columns.Add('Thumbprint', [string])
            [void]$tbl.Columns.Add('PublicKey', [string])
            Get-NestedAuthenticodeDetails -Certificate $SignerArray[0] -Table $tbl
            $tbl.Rows.Count | Should -Be 0
        }
    }

    It 'expands nested Microsoft OID 1.3.6.1.4.1.311.2.4.1 using checked-in CMS fixture' {
        $fixture = Join-Path $PSScriptRoot '..\Fixtures\nested-authenticode-attribute.cms'
        Test-Path -LiteralPath $fixture | Should -BeTrue
        $raw = [System.IO.File]::ReadAllBytes($fixture)
        $outer = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $outer.Decode($raw)
        $signerInfo = $outer.SignerInfos[0]
        InModuleScope $script:ModuleName -ArgumentList $signerInfo -ScriptBlock {
            param($Si)
            $tbl = New-Object System.Data.DataTable 'NestedFixture'
            [void]$tbl.Columns.Add('Subject', [string])
            [void]$tbl.Columns.Add('Issuer', [string])
            [void]$tbl.Columns.Add('DigestAlgorithm', [string])
            [void]$tbl.Columns.Add('Thumbprint', [string])
            [void]$tbl.Columns.Add('PublicKey', [string])
            Get-NestedAuthenticodeDetails -Certificate $Si -Table $tbl
            $tbl.Rows.Count | Should -BeGreaterThan 0
            @($tbl.Rows | Where-Object { $_.Subject -like '*Inner Nested Fixture*' }).Count | Should -Be 1
        }
    }
}


