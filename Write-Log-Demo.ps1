# Demo code to illustrate using the lib/Write-Log.ps1 logging module
# Based on code by Martin Norlunn: 
#   https://www.norlunn.net/2020/06/07/powershell-write-log-function/
# 
# To run:
#      & '.\Write-Log-Demo.ps1 -Verbose'

[CmdletBinding()]
param ()
# Cmdletbinding is required to run script with -Verbose
 
# Import the log function, or declare it directly here
. ".\lib\Write-Log.ps1"
 
# Write an informational message
Write-Log -Message "Script invoked as user: $env:USERNAME"
 
# Write a warning
Write-Log -Warning "This is a warning"
 
# Handle errors
try
{
    # Some code that may fail
    Write-Log2
}
catch
{
    Write-Log -ErrorObj $_
}
Output
