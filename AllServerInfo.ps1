<#

    This script is used to generate a list of all servers within a domain.
    It must we run from a server within the required domain.

    The output is a file that contains the object array data.

    This has always been run from within Powershell ISE
    
	Author : Chris Severns

	History:

	    1.0 2018/02 	Initial Version.
        2.0 2018/06     Changed to execute requests to multiple computers at the same time.
                        For any server that fails to return data the first time it will try again individually using 
                        multiple methods.
#>

<#
    Find root domain
#>

Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete (1 / 20 * 100) -CurrentOperation "Scanning AD"

$Root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$DSRoot = $Root.rootDomainNamingContext

$DSSearcher = New-Object System.DirectoryServices.DirectorySearcher
$DSSearcher.Filter = "(OperatingSystem=Window*Server*)"

$DSDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DSRoot")
$DSSearcher.SearchRoot = $DSDomain

$All_Servers_DS = $DSSearcher.FindAll() | Sort-Object Path

if ($Root.rootDomainNamingContext -ne $Root.defaultNamingContext)
{
    $DSDefault = $Root.defaultNamingContext
    $DSDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DSDefault")
    $DSSearcher.SearchRoot = $DSDomain

    $All_Servers_DS += $DSSearcher.FindAll() | Sort-Object Path
}

Write-Verbose -Message ("Number of server from AD " +  $All_Servers_DS.Count)

#$All_Servers_DS = $All_Servers_DS | Where-Object {$_.Properties["name"] -eq "GAWVMEXP007"}

$All_Server_Names = @()

foreach ($Server_DS in $All_Servers_DS)
{
    $All_Server_Names += $Server_DS.Properties["dnshostname"]
}

$All_CIM_Sessions = @()
$All_Server_OS_Info = @()
$All_Server_HW_Info = @()
$All_Server_CPU_Info = @()
$All_Server_Mem_Info = @()
$All_Server_BIOS_Info = @()
$All_Server_Services = @()
$All_Clusters = @()

$Progress_Factor = 0

foreach ($Session_Option_String in "WSMan","DCOM")
{
Write-Verbose -Message ("Number of server for scan ($Session_Option_String) " +  $All_Server_Names.Count)

    $Session_Option = New-CimSessionOption -Protocol $Session_Option_String

    Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((2 + $Progress_Factor) / 20 * 100) -CurrentOperation "Creating Sessions"
    $Cur_CIM_Sessions = New-CimSession -ComputerName $All_Server_Names -SessionOption $Session_Option -OperationTimeoutSec 30 -ErrorAction SilentlyContinue

    if ($Cur_CIM_Sessions -ne $null)
    {
        Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((3 + $Progress_Factor) / 20 * 100) -CurrentOperation "Collecting OS Info"
        $All_Server_OS_Info += Get-CimInstance CIM_OperatingSystem -CimSession $Cur_CIM_Sessions -ErrorAction SilentlyContinue

        Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((4 + $Progress_Factor) / 20 * 100) -CurrentOperation "Collecting HW Info"
        $All_Server_HW_Info += Get-CimInstance CIM_ComputerSystem -CimSession $Cur_CIM_Sessions -ErrorAction SilentlyContinue

        Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((5 + $Progress_Factor) / 20 * 100) -CurrentOperation "Collecting CPU Info"
        $All_Server_CPU_Info += Get-CimInstance CIM_Processor -CimSession $Cur_CIM_Sessions -ErrorAction SilentlyContinue

        Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((6 + $Progress_Factor) / 20 * 100) -CurrentOperation "Collecting Mem Info"
        $All_Server_Mem_Info += Get-CimInstance CIM_PhysicalMemory -CimSession $Cur_CIM_Sessions -ErrorAction SilentlyContinue

        Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((7 + $Progress_Factor) / 20 * 100) -CurrentOperation "Collecting BIOS Info"
        $All_Server_BIOS_Info += Get-CimInstance CIM_BIOSElement -CimSession $Cur_CIM_Sessions -ErrorAction SilentlyContinue

        Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((8 + $Progress_Factor) / 20 * 100) -CurrentOperation "Collecting Service Info"
        $All_Server_Services += Get-CimInstance CIM_Service -CimSession $Cur_CIM_Sessions -ErrorAction SilentlyContinue

        Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((9 + $Progress_Factor) / 20 * 100) -CurrentOperation "Collecting Cluster Info"
        $All_Clusters += Get-CimInstance -ClassName CIM_Cluster -CimSession $Cur_CIM_Sessions -Namespace "root\MSCluster" -ErrorAction SilentlyContinue
    }

    Write-Progress -Activity "Scanning servers" -Status "Progress" -PercentComplete ((10 + $Progress_Factor) / 20 * 100) -CurrentOperation "Removing Sessions"
    Get-CimSession | Remove-CimSession

    $All_Server_Names = $All_Server_Names | Where-Object {$All_Server_OS_Info.PSComputerName -notcontains $_}
    $All_CIM_Sessions += $Cur_CIM_Sessions | Where-Object {$All_Server_OS_Info.PSComputerName -contains $_.ComputerName}
    $Progress_Factor = 9
}

Write-Verbose -Message ("Number of server remaining after all scans " +  $All_Server_Names.Count)

Write-Progress -Activity "Scanning servers" -Status "Complete" -Completed

$All_Server_Info = @{}

foreach ($Server_DS in $All_Servers_DS)
{
    Write-Verbose -Message ("Creating information for " +  $Server_DS.Properties["name"])

    Write-Progress -Activity "Scanning servers" -Status "Checking network for" -PercentComplete (($All_Server_Info.Count / $All_Servers_DS.Count) * 100) -CurrentOperation $Server_DS.Properties["name"]

    $Server_DNS_Name = $Server_DS.Properties["dnshostname"]

    $Server_Test_Connection = @(Test-Connection -ComputerName $Server_DNS_Name -Count 1 -Delay 1 -ErrorAction SilentlyContinue)
    $Server_Online = ($Server_Test_Connection.Count -ne 0)

    if ($Server_Online -eq $false)
    { # The single ping failed, so for slower servers lets try again
        $Server_Test_Connection = @(Test-Connection -ComputerName $Server_DNS_Name -Count 3 -Delay 3 -ErrorAction SilentlyContinue)
        $Server_Online = ($Server_Test_Connection.Count -ne 0)
    }

    $Server_Resolved_Name = $null
    $Server_VG_Info = $null
    $Server_App_Info = $null

    if ($Server_Online)
    {
<#
        The following line can generate an error that we are not bothered about, so we will suppress the error.
#>
        $Save_ErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = "SilentlyContinue"

        $Server_Resolved_Name = ([System.Net.Dns]::GetHostEntry($Server_Test_Connection[0].IPV4Address.IPAddressToString)).HostName
<#
        Pull some information out of the registry
#>
        $Temp_Guest = Invoke-Command -ComputerName $Server_DNS_Name -ScriptBlock {(Get-Item 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest').SubKeyCount}
        If (($Temp_Guest -ne 0) -and ($Temp_Guest -ne $null))
        {
            $Server_VG_Info = Invoke-Command -ComputerName $Server_DNS_Name -ScriptBlock {Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters'}
        }

        $Server_App_Info = $null
        # 64-bit Software
        $Server_App_Info = Invoke-Command -ComputerName $Server_DNS_Name -ScriptBlock {Get-ItemProperty 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'}
        # 32-bit Software
        $Server_App_Info += Invoke-Command -ComputerName $Server_DNS_Name -ScriptBlock {Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'}

        $ErrorActionPreference = $Save_ErrorActionPreference
    }

    $Server_WSMan = $null
    $Server_WSMan = Test-WSMan -ComputerName $Server_DNS_Name -ErrorAction SilentlyContinue
<#
    Use the Operating system version from the server if we have it, otherwise use the one from AD.
#>
    $Temp_Version = [string]$Server_DS.Properties["operatingsystemversion"] -replace "(\d)\.(\d) \((\d*)\)",'$1.$2.$3'
    if ($Server_OS_Info -ne $null)
    {
        $Temp_Version = $Server_OS_Info.Version
    }

    if ($All_Server_Info["$Server_DNS_Name"] -eq $null)
    {
        $new_obj = New-Object -TypeName psObject -Property @{
            Name = ([string]$Server_DS.Properties["name"])
            Description = ([string]$Server_DS.Properties["description"])
            AccountDisabled = ([int32][string]$Server_DS.Properties["useraccountcontrol"] -band 0x0002) -ne 0
            AccountControl = [int32][string]$Server_DS.Properties["useraccountcontrol"]
            AccountLastLogon = [timezone]::CurrentTimeZone.ToLocalTime([datetime]::FromFileTimeUtc([int64][string]$Server_DS.Properties["lastlogontimestamp"]))
            OperatingSystemName = ([string]$Server_DS.Properties["operatingsystem"])
            OperatingSystemVersion = $Temp_Version
            ServerDNSName = ([string]$Server_DS.Properties["dnshostname"])

            ServerOnline = $Server_Online
            ServerResolvedName = $Server_Resolved_Name
            ServerResolves = if ($Server_Resolved_Name -ne $null) {($Server_DNS_Name.ToLower() -eq $Server_Resolved_Name.ToLower())} else {$false}
           # Win32_PrinterDriver
           # Win32_Service
           # Win32_SystemDriver
           # Win32_ApplicationService
            ServerServices = @() #$Server_Services | Where-Object {$_.CreationClassName -eq "Win32_Service"}
            ServerDrivers = @() #$Server_Services | Where-Object {$_.CreationClassName -eq "Win32_SystemDriver"}
            ServerOSInfo = $null
            ServerHWInfo = $null
            ServerCPUInfo = @()
            ServerMemInfo = @()
            ServerBIOSInfo = $null
            ServerTest = $Server_Test_Connection
            ServerCIMSession = $null
            ServerWSMan = $Server_WSMan
            ServerVGInfo = $Server_VG_Info
            ServerAppInfo = $Server_App_Info
            ServerCluster = $null
            ServerDSProperties = $Server_DS.Properties
        }
        $All_Server_Info.Add($new_obj.ServerDNSName, $new_obj)
    }
}

Write-Progress -Activity "Scanning servers" -Status "Complete" -Completed

Write-Verbose -Message ("Updating information for " +  $All_CIM_Sessions.Count + " servers")

$Server_Count = 1
$All_CIM_Sessions | ForEach-Object {
    Write-Progress -Activity "Updating" -Status "Storing CIM session Information for" -PercentComplete (($Server_Count / $All_CIM_Sessions.Count) * 100) -CurrentOperation $_.ComputerName

    $All_Server_Info[$_.ComputerName].ServerCIMSession = $_
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1
$All_Server_OS_Info | ForEach-Object {
    Write-Progress -Activity "Updating" -Status "Storing OS Information for" -PercentComplete (($Server_Count / $All_Server_OS_Info.Count) * 100) -CurrentOperation $_.PSComputerName

    $All_Server_Info[$_.PSComputerName].ServerOSInfo = $_
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1
$All_Server_HW_Info | ForEach-Object {
    Write-Progress -Activity "Updating" -Status "Storing HW Information for" -PercentComplete (($Server_Count / $All_Server_HW_Info.Count) * 100) -CurrentOperation $_.PSComputerName

    $All_Server_Info[$_.PSComputerName].ServerHWInfo = $_
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1
$All_Server_CPU_Info | ForEach-Object {
    Write-Progress -Activity "Updating" -Status "Storing CPU Information for" -PercentComplete (($Server_Count / $All_Server_CPU_Info.Count) * 100) -CurrentOperation $_.PSComputerName

    $All_Server_Info[$_.PSComputerName].ServerCPUInfo += $_
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1
$All_Server_Mem_Info | ForEach-Object {
    Write-Progress -Activity "Updating" -Status "Storing Mem Information for" -PercentComplete (($Server_Count / $All_Server_Mem_Info.Count) * 100) -CurrentOperation $_.PSComputerName

    $All_Server_Info[$_.PSComputerName].ServerMemInfo += $_
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1
$All_Server_BIOS_Info | ForEach-Object {
    Write-Progress -Activity "Updating" -Status "Storing BIOS Information for" -PercentComplete (($Server_Count / $All_Server_BIOS_Info.Count) * 100) -CurrentOperation $_.PSComputerName

    $All_Server_Info[$_.PSComputerName].ServerBIOSInfo += $_
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1
foreach ($Service_Entry in $All_Server_Services)
{
    Write-Progress -Activity "Updating" -Status "Storing Service Information for" -PercentComplete (($Server_Count / $All_Server_Services.Count) * 100) -CurrentOperation $Service_Entry.PSComputerName

    switch ($Service_Entry.CreationClassName)
    {
        "Win32_Service" {$All_Server_Info[$Service_Entry.PSComputerName].ServerServices += $Service_Entry}
        "Win32_SystemDriver" {$All_Server_Info[$Service_Entry.PSComputerName].ServerDrivers += $Service_Entry}
    }
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1
$All_Clusters | ForEach-Object {
    Write-Progress -Activity "Updating" -Status "Storing Cluster Information for" -PercentComplete (($Server_Count / $All_Clusters.Count) * 100) -CurrentOperation $_.PSComputerName

    $All_Server_Info[$_.PSComputerName].ServerCluster = $_
    $Server_Count += 1
}
Write-Progress -Activity "Updating" -Status "Complete" -Completed

$Server_Count = 1

foreach ($Server_Name in $All_Server_Info.Keys)
{
    Write-Progress -Activity "Updating" -Status "Collecting Missing Data using WMI for" -PercentComplete (($Server_Count / $All_Server_Info.Count) * 100) -CurrentOperation $Server_Name
<#
    If anything is still missing then try WMI
#>
    $Temp_OS_Info = $null

    if ($All_Server_Info[$Server_Name].ServerOnline -eq $true)
    {
        Write-Verbose -Message ("Updating missing information for server " +  $All_Server_Info[$Server_Name].Name)

        $Temp_OS_Info = Get-WmiObject Win32_OperatingSystem -ComputerName $Server_Name -ErrorAction SilentlyContinue
<#
        If this is still empty then there is no point trying any others.
#>
        if ($Temp_OS_Info -ne $null)
        {
            if ($All_Server_Info[$Server_Name].ServerOSInfo -eq $null)
            {
                $All_Server_Info[$Server_Name].ServerOSInfo = $Temp_OS_Info
            }

            if ($All_Server_Info[$Server_Name].ServerHWInfo -eq $null)
            {
                $All_Server_Info[$Server_Name].ServerHWInfo = Get-WmiObject Win32_ComputerSystem -ComputerName $Server_Name -ErrorAction SilentlyContinue
            }

            if ($All_Server_Info[$Server_Name].ServerCPUInfo.Count -eq 0)
            {
                $All_Server_Info[$Server_Name].ServerCPUInfo = Get-WmiObject Win32_Processor -ComputerName $Server_Name -ErrorAction SilentlyContinue
            }

            if ($All_Server_Info[$Server_Name].ServerMemInfo.Count -eq 0)
            {
                $All_Server_Info[$Server_Name].ServerMemInfo = Get-WmiObject Win32_PhysicalMemory -ComputerName $Server_Name -ErrorAction SilentlyContinue
            }

            if ($All_Server_Info[$Server_Name].ServerBIOSInfo -eq $null)
            {
                $All_Server_Info[$Server_Name].ServerBIOSInfo = Get-WmiObject Win32_BIOS -ComputerName $Server_Name -ErrorAction SilentlyContinue
            }

            if ($All_Server_Info[$Server_Name].ServerServices -eq $null)
            {
                $Temp_Services = Get-WmiObject Win32_Service -ComputerName $Server_Name -ErrorAction SilentlyContinue

                $All_Server_Info[$Server_Name].ServerServices = $Temp_Services | Where-Object {$_.CreationClassName -eq "Win32_Service"}
                $All_Server_Info[$Server_Name].ServerDrivers = $Temp_Services | Where-Object {$_.CreationClassName -eq "Win32_SystemDriver"}
            }
        }
    }
    $Server_Count += 1
}

Write-Progress -Activity "Updating" -Status "Complete" -Completed

Write-Host "Total no of servers in AD" $All_Server_Info.Count
Write-Host "Total number of servers online" @($All_Server_Info.Values | Where-Object {$_.ServerOnline}).Count

#$All_Server_Info.Values | Sort-Object Name | Out-GridView

$All_Server_Info | Export-Clixml -Path "$($env:USERPROFILE)\Desktop\AllServerInfo-$($env:USERDOMAIN).xml"
