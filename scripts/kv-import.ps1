# Requires Azure CLI (az) and logged-in context with access to the target Key Vault
param(
  [Parameter(Mandatory=$true)][string]$VaultName,
  [Parameter(Mandatory=$true)][string]$EnvFilePath
)

if (-not (Test-Path $EnvFilePath)) { throw "Env file not found: $EnvFilePath" }
Get-Content $EnvFilePath | ForEach-Object {
  $line = $_.Trim()
  if ([string]::IsNullOrWhiteSpace($line)) { return }
  if ($line.StartsWith('#')) { return }
  $parts = $line -split '=', 2
  if ($parts.Length -ne 2) { return }
  $name = $parts[0].Trim()
  $val = $parts[1]
  # In Azure Key Vault, secrets names are typically lowercase with dashes; map __ to -- and : to --
  $secretName = $name.ToLower().Replace('__','--').Replace(':','--')
  Write-Host "Setting secret $secretName"
  az keyvault secret set --vault-name $VaultName --name $secretName --value "$val" | Out-Null
}
Write-Host "Done."

