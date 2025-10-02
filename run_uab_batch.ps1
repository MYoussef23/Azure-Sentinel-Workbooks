param(
  [Parameter(Mandatory=$true)][string]$WorkspaceId,   # your LA workspace GUID
  [Parameter(Mandatory=$true)][string]$TenantId,   # your AAD tenant GUID
  [string]$WorkbookPath = "User_Analytics_Behaviour.json",
  [string]$OutFile = "results.html"
)

# UPNs to run
$UPNs = @(      # Separate multiple with commas
  "myuser@corp.com",
  "myuser2@corp.com"
)

# Create a fresh HTML shell
@"
"@ | Out-File -Encoding UTF8 $OutFile

function Run-One {
  param(
    [int]$Index,
    [string]$Timespan,
    [string]$Upn,
    [int]$Limit = 200
  )
  # temp fragment file
  $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.html'

  # Build args; index 11 needs limit 10 per your spec
  $limitArg = $Limit
  if ($Index -eq 11) { $limitArg = 10 }

  # Call the runner to export HTML to a fragment
  python .\UAB_workbook_runner_cli.py run `
    --index $Index `
    --tenant_id $TenantId `
    --workspace_id $WorkspaceId `
    --timespan $Timespan `
    --UserPrincipalName $Upn `
    --workbook_path $WorkbookPath `
    --output html `
    --outfile $tmp `
    --limit $limitArg `
    --quiet_kql true | Out-Null

  # Append with headings
  @"
"@ | Out-File -Append -Encoding UTF8 $OutFile
  Get-Content -Raw $tmp | Out-File -Append -Encoding UTF8 $OutFile
  "" | Out-File -Append -Encoding UTF8 $OutFile

  Remove-Item $tmp -ErrorAction SilentlyContinue
}

foreach ($upn in $UPNs) {
  Run-One -Index 1  -Timespan "P30D" -Upn $upn -Limit 200
  Run-One -Index 10 -Timespan "P1D"  -Upn $upn -Limit 200
  Run-One -Index 11 -Timespan "P1D"  -Upn $upn -Limit 10
}

"" | Out-File -Append -Encoding UTF8 $OutFile

Write-Host "Done. Open $OutFile"

# Example usage:
# .\run_uab_batch.ps1 -WorkspaceId "your-guid-here" -TenantId "your-tenant-id-guid-here"
