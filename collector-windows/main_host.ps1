[CmdletBinding()]
param([switch]$NoPack, [string]$ConfigFile = "")
$entry = Join-Path $PSScriptRoot "OraSentry.ps1"
$arguments = @("-HostCheck")
if ($NoPack) { $arguments += "-NoPack" }
if ($ConfigFile) { $arguments += @("-ConfigFile", $ConfigFile) }
& $entry @arguments
exit $LASTEXITCODE
