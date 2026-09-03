[CmdletBinding()]
param([switch]$NoPack, [switch]$InteractiveLogin, [string]$ConfigFile = "")
$entry = Join-Path $PSScriptRoot "OraSentry.ps1"
& $entry -DatabaseCheck -NoPack:$NoPack -InteractiveLogin:$InteractiveLogin -ConfigFile $ConfigFile
exit $LASTEXITCODE
