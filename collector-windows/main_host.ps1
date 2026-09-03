[CmdletBinding()]
param([switch]$NoPack, [string]$ConfigFile = "")
$entry = Join-Path $PSScriptRoot "OraSentry.ps1"
& $entry -HostCheck -NoPack:$NoPack -ConfigFile $ConfigFile
exit $LASTEXITCODE
