function Write-Log
{
    [CmdletBinding()]
    param
    (
        [String]$Message,
        [String]$Warning,
        [System.Management.Automation.ErrorRecord]$ErrorObj,
        [String]$LogFolderPath = "$PSScriptRoot\Logs",
        [String]$LogFilePrefix = 'Log'
    )
 
    $Date = Get-Date -Format "dd_MMMM_yyyy"
    $Time = Get-Date -Format "HH:mm:ss.f"
    $LogFile = "$LogFolderPath\$LogFilePrefix`_$Date.log"
 
    if (-not (Test-Path -Path $LogFolderPath))
    {
        [Void](New-Item -ItemType Directory -Path $LogFolderPath -Force)
    }
 
    if (-not (Test-Path -Path $LogFile))
    {
        [Void](New-Item -ItemType File -Path $LogFile -Force)
    }
 
    $LogMessage = "[$Time] "
 
    if ($PSBoundParameters.ContainsKey("ErrorObj"))
    {
        $LogMessage += "Error: $ErrorObj $($ErrorObj.ScriptStackTrace.Split("`n") -join ' <-- ')"
        Write-Error -Message $LogMessage
    }
    elseif ($PSBoundParameters.ContainsKey("Warning"))
    {
        $LogMessage += "Warning: $Warning"
        Write-Warning -Message $LogMessage
    }
    else
    {
        $LogMessage += "Info: $Message"
        Write-Verbose -Message $LogMessage
    }
 
    Add-Content -Path $LogFile -Value "$LogMessage"
}
