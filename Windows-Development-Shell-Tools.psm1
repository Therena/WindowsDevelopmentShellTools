#
# Root module bootstrap.
# Loads split module functions from .\Module\Private and .\Module\Public.
#

Set-StrictMode -Version Latest

$privateDir = Join-Path -Path $PSScriptRoot -ChildPath 'Module\Private'
$publicDir = Join-Path -Path $PSScriptRoot -ChildPath 'Module\Public'

if (-not (Test-Path -LiteralPath $privateDir)) {
    throw "Private function directory not found: $privateDir"
}
if (-not (Test-Path -LiteralPath $publicDir)) {
    throw "Public function directory not found: $publicDir"
}

Get-ChildItem -LiteralPath $privateDir -Filter '*.ps1' -File |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

Get-ChildItem -LiteralPath $publicDir -Filter '*.ps1' -File |
    Sort-Object Name |
    ForEach-Object { . $_.FullName }

$publicFunctions = Get-ChildItem -LiteralPath $publicDir -Filter '*.ps1' -File |
    Sort-Object Name |
    ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }

Export-ModuleMember -Function $publicFunctions
