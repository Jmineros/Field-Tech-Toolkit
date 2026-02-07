@{
  RootModule        = 'PowerUp.UserOps.psm1'
  ModuleVersion     = '2.0.0'
  GUID              = 'c2b0c7c0-2f4b-4f83-9d6c-2d6dfb7f0d3b'
  Author            = 'Josh Mineros'
  CompanyName       = ''
  Copyright         = ''
  Description       = 'PowerUp UserOps – Unified AD + Entra ID user administration console.'
  PowerShellVersion = '5.1'
  FunctionsToExport = @(
    'Start-UserOpsConsole'
  )
  CmdletsToExport   = @()
  VariablesToExport = '*'
  AliasesToExport   = @()
}
