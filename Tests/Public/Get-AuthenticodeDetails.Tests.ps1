. (Join-Path $PSScriptRoot '..\TestSetup.ps1')

Describe 'Get-AuthenticodeDetails' -Skip:(-not $script:IsWindowsOs) {
    BeforeAll {
        $signers = $null
        $cert = New-SelfSignedCertificate -Subject 'CN=Test Authenticode Row' -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddHours(1)
        try {
            $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,[byte]1)
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms $content, $false
            $cmsSigner = New-Object System.Security.Cryptography.Pkcs.CmsSigner $cert
            $cms.ComputeSignature($cmsSigner)
            $signers = [Therena.Encryption.Certificate]::DecodeCertificateData($cms.Encode())
        } finally {
            Remove-Item -Path ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
        if ($null -eq $signers -or $signers.Length -lt 1) {
            throw 'Failed to build PKCS signer fixture for Get-AuthenticodeDetails test.'
        }
        $global:__WDS_TestAuthenticodeSigners = $signers
        InModuleScope $script:ModuleName {
            Mock Get-AuthenticodeSignerInfosForFile { return ,$global:__WDS_TestAuthenticodeSigners }
            Mock Get-NestedAuthenticodeDetails { }
        }
    }

    AfterAll {
        Remove-Variable -Name __WDS_TestAuthenticodeSigners -Scope Global -Force -ErrorAction SilentlyContinue
    }

    It 'fills the certificate table from PKCS signer metadata' {
        $path = Join-Path $TestDrive 'auth-dummy.bin'
        [System.IO.File]::WriteAllBytes($path, [byte[]](0))
        $path = (Resolve-Path -LiteralPath $path).Path
        $t = Get-ModuleDataTableResult -Name 'Get-AuthenticodeDetails' -Parameters @{ File = $path }
        $t.Rows.Count | Should -BeGreaterThan 0
        $t.Rows[0]['Subject'] | Should -Match 'Test Authenticode Row'
        $t.Rows[0]['DigestAlgorithm'] | Should -Match 'sha256'
        $t.Rows[0]['Thumbprint'] | Should -Match '^[0-9A-F]{40}$'
    }

    It 'returns certificate rows for a system file with embedded PKCS' {
        $picked = $null
        $table = $null
        foreach ($rel in @('System32\ntdll.dll', 'System32\kernel32.dll', 'System32\win32u.dll')) {
            $full = Join-Path $env:SystemRoot $rel
            if (-not (Test-Path -LiteralPath $full)) {
                continue
            }
            $t = Get-ModuleDataTableResult -Name 'Get-AuthenticodeDetails' -Parameters @{ File = $full }
            if ($t.Rows.Count -gt 0) {
                $picked = $full
                $table = $t
                break
            }
        }
        $picked | Should -Not -BeNullOrEmpty
        $table.Rows[0]['Subject'] | Should -Not -BeNullOrEmpty
        $table.Rows[0]['Thumbprint'] | Should -Match '^[0-9A-F]{40}$'
    }
}
