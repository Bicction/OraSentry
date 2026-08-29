[CmdletBinding()]
param([switch]$NoPack, [switch]$InteractiveLogin, [string]$ConfigFile = "")
$entry = Join-Path $PSScriptRoot "OraSentry.ps1"
$arguments = @("-DatabaseCheck")
if ($NoPack) { $arguments += "-NoPack" }
if ($InteractiveLogin) { $arguments += "-InteractiveLogin" }
if ($ConfigFile) { $arguments += @("-ConfigFile", $ConfigFile) }
& $entry @arguments
exit $LASTEXITCODE
