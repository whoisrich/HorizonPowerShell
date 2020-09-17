#Requires -Version 5
#Requires -Module ActiveDirectory
#Requires -Module VMware.VimAutomation.HorizonView

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Global:AdPoolPrefix   = 'R_HZ.'
$Global:AdAccessPrefix = 'U_HZ.'
$Global:LogoffMinutes  = 30

# Server and credentials stored separate from code, one value per line in a text file.
$settingsFile    = Get-Content -Path ($PSScriptRoot + '\SETTINGS.txt')
$Global:HzServer = $settingsFile[0].Trim()
$Global:HzDomain = $settingsFile[1].Trim()
$Global:HzUser   = $settingsFile[2].Trim()
$Global:HzPass   = ConvertTo-SecureString $settingsFile[3].Trim() -AsPlainText -Force

<#-----------------------------------------------------------------------------------------------------------------------------+

    - This script syncs Active Directory computer groups with VMWare Horizon MANUAL desktop pools.

    - This script DOES NOT remove pools or entitlements if their source AD group is removed.

    - Finds AD groups with the prefix setting, creates a matching Horizon pool and global entitlement,
    - Gets computers from the AD group, including any nested groups, and adds the ones registered in Horizon into the pool.
    - Gives permission on the global entitlement if a matching AD user access group exists.
    - Updates the display name for the pool and global entitlement as long as the pool name remains the same.
    - Although coded to generate a display name from the group name, it could be loaded from a separate group attribute.

    - By Richard Perry, Last updated 2020-09-17.

-------------------------------------------------------------------------------------------------------------------------------+

    ONE TIME ENVIRONMENT SETUP:

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module VMware.PowerCLI

    Set-PowerCLIConfiguration -ParticipateInCEIP $false        -Scope AllUsers -Confirm:$false
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope AllUsers -Confirm:$false

    Download and extract whole project zip from: https://github.com/vmware/PowerCLI-Example-Scripts
    Copy 'VMware.Hv.Helper' folder from 'PowerCLI-Example-Scripts-master\Modules' into 'C:\Program Files\WindowsPowerShell\Modules'

    Close any PowerShell windows or ISE and re-open so changes and modules are loaded.

-------------------------------------------------------------------------------------------------------------------------------+

    CODE AND VMWARE.HV.HELPER 1.3.1 NOTES:

    Get-ADGroupMember is limited by DC setting 'MaxGroupOrMemberEntries' which by default is 5000 members returned.

    The 'Get-HVMachineSummary' was found buggy, where after time it starts returning partial results like a limit had been set,
    and required a connection service restart to fix. Instead 'Get-HVQueryResult' is used which seems unaffected by the issue.

    The 'New-HVPool' param -VM is the machines to be added, at least one must be provided as empty new pools are not allowed.
    If a machine specified is not registered or used by another pool, it gives a very unhelpful error:
    Exception calling "Desktop_Create" with "2" argument(s): "There is an error in the XML document."

    The 'New-HVPool' param -GlobalEntitlement does not seem to work, instead use a delay and 'Set-HVPool' after creation.

    The 'New-HVPool' param -AutomaticLogoffPolicy has mistakenly been restricted to CLONE type pools, so errors on MANUAL.
    Also 'Set-HVPool' does not have AutomaticLogoffPolicy, or support setting its Key, so we use our own helper function.

    The 'Set-HVPool' param -Key is cAsE SeNsItiVe, for example 'base.displayname' instead of 'base.displayName' gives:
    Exception calling "Desktop_Update" with "3" argument(s): "ExceptionType : VMware.Hv.InvalidArgument

    The 'Set-HVPool' param -PoolName is optional and will silently return nothing if there was no pool specified.

    The 'Get-HVPoolSummary' has 'DesktopSummaryData.NumMachine' but it does not update after adding or removing machines,
    only after re-connecting. Instead array wrap 'Get-HVMachineSummary' and count the number of entries.

    The 'Add-HVDesktop' adds machines to an existing pool, but HV.Helper has no 'Remove' or 'Move' function.
    There is a tempting 'Remove-HVMachine' but this unregisters physical desktops from the inventory database.
    Good news is the low-level API does contain a remove from pool option, so we use our own helper function.

------------------------------------------------------------------------------------------------------------------------------#>

function Get-HVAdGroupMachines()
{
    $duplicateCheck = @{}

    $adGroups = Get-ADGroup -Filter "name -like '$($Global:AdPoolPrefix)*'" | Select-Object name,distinguishedName
    foreach ($adGroup in $adGroups)
    {
        "Getting recursive group membership, $($adGroup.Name)" | LogMessage -Color Green

        $adMembers  = Get-ADGroupMember -Identity $adGroup.distinguishedName -Recursive
        $adMachines = foreach ($adMember in $adMembers)
        {
            if ($adMember.objectClass -ne 'computer') { continue }

            $suffixStart  = $adMember.distinguishedName.IndexOf('DC=')
            $suffixLength = $adMember.distinguishedName.Length - $suffixStart
            $suffix       = $adMember.distinguishedName.Substring($suffixStart, $suffixLength).Replace('DC=', '.').Replace(',', '')
            $machineDns   = $adMember.Name + $suffix

            # Machines can only be a member of one pool, so log and ignore duplicate memberships.
            if ($duplicateCheck.ContainsKey($machineDns))
            {
                "Machine in multiple pool groups, $machineDns, $($adGroup.Name), $($duplicateCheck[$machineDns])" | LogMessage -Color Red
                continue
            }
            $duplicateCheck.Add($machineDns, $adGroup.Name)

            # Directing foreach output into a variable builds an array without the overhead of adding.
            $machineDns
        }

        # Display name is what people see, can change, and could be a custom attribute.
        # Remove prefix to just leave the name and change underscores to spaces.
        $hzDisplayName = $adGroup.Name
        $hzDisplayName = $hzDisplayName.Replace($Global:AdPoolPrefix, '').Replace('_', ' ')

        # Pool should be treated as a fixed ID as changing it will create a new pool.
        # Remove prefix to just leave the name and replace any unsupported pool name characters.
        $hzPoolName = $adGroup.Name
        $hzPoolName = $hzPoolName.Replace($Global:AdPoolPrefix, '')
        $hzPoolName = $hzPoolName -replace '[^a-zA-Z0-9_-]', '_'

        # Sync AD computer group with Horizon.
        Sync-HVPool -PoolName $hzPoolName -DisplayName $hzDisplayName -Machines $adMachines

        # Sync AD user group with Horizon. Assumes user group is same name as computer group, but with a different prefix.
        $hzDomainGroupName = $Global:HzDomain + '\' + $adGroup.Name.Replace($Global:AdPoolPrefix, $Global:AdAccessPrefix)
        Sync-HVPoolAccess -PoolName $hzPoolName -DisplayName $hzDisplayName -DomainGroupName $hzDomainGroupName -ResourceType GlobalEntitlement
    }
}

function Sync-HVPoolAccess()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $PoolName,

        [Parameter(Mandatory = $true)]
        [string]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [string]
        $DomainGroupName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Desktop','GlobalEntitlement')]
        [string]
        $ResourceType
    )

    "Syncing pool access, $PoolName, $DisplayName, $DomainGroupName" | LogMessage -Color Yellow

    # Note that type 'Desktop' means set access on the pool.
    $resourceName = if ($ResourceType -eq 'GlobalEntitlement') { $DisplayName } else { $PoolName }

    # Note DomainGroupName can be 'DOMAIN\GroupName' or 'GroupName@DOMAIN' style, and we ignore the DOMAIN in the check.
    $entitlementCheck = (Get-HVEntitlement -ResourceType $ResourceType -ResourceName $resourceName) | Where-Object { $DomainGroupName -like "*\$($_.Base.Name)" -or $DomainGroupName -like "$($_.Base.Name)@*" }

    # Check if entitlement already exists just to prevent failure events being logged in Horizon monitoring.
    if ($entitlementCheck)
    {
        "Access already set, $($entitlementCheck.Base.DisplayName)" | LogMessage -Color Cyan
        return
    }

    # Try to add the group and let Horizon check the pool, entitlement, group exist.
    try
    {
        New-HVEntitlement -ResourceName $resourceName -ResourceType $ResourceType -Type Group -User $DomainGroupName
    }
    catch
    {
        Write-Host $_ -ForegroundColor Cyan
    }
}

function Sync-HVPool()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-zA-Z0-9_-]+$', Options='None')]
        [string]
        $PoolName,

        [Parameter(Mandatory = $true)]
        [string]
        $DisplayName,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [string[]]
        $Machines
    )

    # If machines to sync is null, change it to an empty array.
    if (!$Machines) { $Machines = @() }

    "Syncing pool, $PoolName, $($Machines.Count)" | LogMessage -Color Yellow

    # Get a list of current pool machines and remove any that should no longer be in it.
    $poolMachines = $Global:HVMachinesInPool.GetEnumerator() | ForEach-Object { if ($_.Value -eq $PoolName) { $_.Name } }
    foreach ($machineName in $poolMachines)
    {
        # Uses contains operator instead of method as it needs to be case insensitive.
        if ($Machines -notcontains $machineName)
        {
            "Machine no longer in a pool, $machineName" | LogMessage
            Remove-HVDesktopFromPool -Machines $machineName

            $Global:HVMachinesInPool.Remove($machineName)
            $Global:HVMachinesNonPool.Add($machineName, 'POOL_SYNC')
        }
    }

    # Remove machines in a different pool so they can be added to the new pool.
    foreach ($machineName in $Machines)
    {
        if ($Global:HVMachinesInPool.ContainsKey($machineName) -and $Global:HVMachinesInPool[$machineName] -ne $PoolName)
        {
            "Machine moving from another pool, $machineName" | LogMessage
            Remove-HVDesktopFromPool -Machines $machineName

            $Global:HVMachinesInPool.Remove($machineName)
            $Global:HVMachinesNonPool.Add($machineName, 'POOL_SYNC')
        }
    }

    # Make a list of machines to add that are registered in the inventory.
    $machineNamesToAdd = foreach ($machineName in $Machines)
    {
        if (!$Global:HVMachinesInPool.ContainsKey($machineName) -and !$Global:HVMachinesNonPool.ContainsKey($machineName))
        {
            "Machine not registered, $machineName" | LogMessage
            continue
        }

        if ($Global:HVMachinesInPool.ContainsKey($machineName) -and $Global:HVMachinesInPool[$machineName] -eq $PoolName)
        {
            "Machine in correct pool, $machineName" | LogMessage
            continue
        }

        "Machine to be added, $machineName" | LogMessage
        $machineName

        $Global:HVMachinesNonPool.Remove($machineName)
        $Global:HVMachinesInPool.Add($machineName, $PoolName)
    }

    # Check if the pool needs to be created or updated.
    $poolSummary = Get-HVPoolSummary -PoolName $PoolName -SuppressInfo $true
    if (!$poolSummary)
    {
        # Need at least one machine as creating an empty pool is not allowed.
        if (!$machineNamesToAdd)
        {
            "No machines available to create pool, $PoolName" | LogMessage -Color Yellow
            return
        }

        "Creating new pool, $PoolName, $DisplayName" | LogMessage -Color Yellow
        New-HVPool -Manual -PoolName $PoolName -PoolDisplayName $DisplayName -VM $machineNamesToAdd -Source UNMANAGED -UserAssignment FLOATING -defaultDisplayProtocol BLAST -allowUsersToChooseProtocol $false -Enable $true

        # With a 'Pod' setup, pools need to be nested into a 'global entitlement' for permissions.
        $geSummary = Get-HVGlobalEntitlement -DisplayName $DisplayName -SuppressInfo $true
        if (!$geSummary)
        {
            "Creating global entitlement, $DisplayName" | LogMessage -Color Yellow
            New-HVGlobalEntitlement -DisplayName $DisplayName -Type DESKTOP_ENTITLEMENT -MultipleSessionAutoClean $true -DefaultDisplayProtocol BLAST -AllowUsersToChooseProtocol $false -Enabled $true
        }

        # Artificial delay to prevent 'not found' errors on a newly created pool or entitlement.
        Start-Sleep -Seconds 2

        # Now we can add the pool into the global entitlement.
        "Adding pool to global entitlement, $PoolName, $DisplayName" | LogMessage -Color Yellow
        Set-HVPool -PoolName $PoolName -globalEntitlement $DisplayName

        # Set the default logoff time for a new pool.
        Set-HVPoolLogOff -PoolName $PoolName -AutomaticLogoffPolicy AFTER -AutomaticLogoffMinutes $Global:LogoffMinutes

        return
    }

    # Update the pool display name if needed.
    $poolDisplayName = $poolSummary.DesktopSummaryData.DisplayName
    if ($poolDisplayName -cne $DisplayName)
    {
        "Updating pool display name, $PoolName, $poolDisplayName, $DisplayName" | LogMessage -Color Yellow
        Set-HVPool -PoolName $PoolName -Key 'base.displayName' -Value $DisplayName
    }
    else
    {
        "Pool display name matches, $DisplayName" | LogMessage -Color Green
    }

    # Check if pool is in a global entitlement.
    if ($poolSummary.DesktopSummaryData.GlobalEntitlement)
    {
        # Pool summary only has the ID of its global entitlement, so we need to look up the current display name.
        $geIdId    = $poolSummary.DesktopSummaryData.GlobalEntitlement.Id
        $geSummary = Get-HVQueryResult -EntityType GlobalEntitlementSummaryView | Where-Object { $_.Id.Id -eq $geIdId }
        if ($geSummary)
        {
            $geDisplayName = $geSummary.Base.DisplayName
            if ($geDisplayName -cne $DisplayName)
            {
                "Updating global entitlement display name, $geDisplayName, $DisplayName" | LogMessage -Color Yellow
                Set-HVGlobalEntitlement -displayName $geDisplayName -Key 'base.displayName' -Value $DisplayName
            }
            else
            {
                "Global entitlement display name matches, $DisplayName" | LogMessage -Color Green
            }
        }
    }

    # Check there are machines to add.
    if (!$machineNamesToAdd)
    {
        "No machines to sync, $PoolName" | LogMessage -Color Yellow
        return
    }

    # Pool already exists, so add the extra machines.
    "Adding machines to existing pool, $PoolName" | LogMessage -Color Yellow
    Add-HVDesktop -PoolName $PoolName -Machines $machineNamesToAdd
}

function Set-HVGlobalMachineList()
{
    # Put machines that are in a pool or available into a global hashtable for fast lookup.

    $Global:HVMachinesInPool = @{}
    $machineSummary = Get-HVQueryResult -EntityType MachineNamesView
    foreach ($machine in $machineSummary)
    {
        $Global:HVMachinesInPool.Add($machine.Base.Name, $machine.Base.DesktopName)
    }

    $Global:HVMachinesNonPool = @{}
    $queryResult = Get-HVQueryResult -EntityType RegisteredPhysicalMachineInfo
    foreach ($machine in $queryResult)
    {
        $Global:HVMachinesNonPool.Add($machine.MachineBase.Name, $machine.Status)
    }
}

function Set-HVPoolLogOff()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $PoolName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('IMMEDIATELY', 'NEVER', 'AFTER')]
        [string]
        $AutomaticLogoffPolicy,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1,[int]::MaxValue)]
        [int]
        $AutomaticLogoffMinutes = 0
    )

    $poolSummary = Get-HVPoolSummary -PoolName $PoolName -SuppressInfo $true
    if (!$poolSummary)
    {
        "Pool not found, $PoolName" | LogMessage -Color Red
        return
    }

    # While Set-HVPool has a Key Value option, it only allows setting a single entry at a time.
    # LogoffMinutes is discarded when LogoffPolicy is set to 'IMMEDIATELY' or 'NEVER'.
    # LogoffPolicy 'AFTER' requires LogoffMinutes be specified at the same time.
    # This prevents running Set-HVPool twice for 'AFTER' and -Spec param only supports external files.
    # So instead we go down a layer and build our own multi-value update entry.

    $poolUpdates = @()

    $mapEntry        = New-Object VMware.Hv.MapEntry
    $mapEntry.Key    = 'desktopSettings.logoffSettings.automaticLogoffPolicy'
    $mapEntry.Value  = $AutomaticLogoffPolicy
    $poolUpdates    += $mapEntry

    if ($AutomaticLogoffPolicy -eq 'AFTER')
    {
        $mapEntry        = New-Object VMware.Hv.MapEntry
        $mapEntry.Key    = 'desktopSettings.logoffSettings.automaticLogoffMinutes'
        $mapEntry.Value  = $AutomaticLogoffMinutes
        $poolUpdates    += $mapEntry
    }

    "Updating pool logoff, $PoolName, $AutomaticLogoffPolicy, $AutomaticLogoffMinutes" | LogMessage -Color Magenta

    try
    {
        $hvServices = $Global:DefaultHVServers.ExtensionData
        $hvServices.Desktop.Desktop_Update($poolSummary.Id, $poolUpdates)
    }
    catch
    {
        "Failed to update pool logoff." | LogMessage -Color Red
    }
}

function Remove-HVDesktopFromPool()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $Machines
    )

    foreach ($machineName in $Machines)
    {
        $machineSummary = Get-HVQueryResult -EntityType MachineNamesView -Filter (Get-HVQueryFilter base.name -eq $machineName)

        if (!$machineSummary)
        {
            "Machine not found, $machineName" | LogMessage -Color Red
            continue
        }

        $machineId = $machineSummary.Id
        $PoolId    = $machineSummary.Base.Desktop
        $PoolName  = $machineSummary.Base.DesktopName

        "Removing machine from pool, $machineName, $PoolName" | LogMessage -Color Magenta

        try
        {
            $hvServices = $Global:DefaultHVServers.ExtensionData
            $hvServices.Desktop.Desktop_RemoveMachineFromManualDesktop($PoolId, $machineId)
        }
        catch
        {
            "Failed to remove machine from pool." | LogMessage -Color Red
            # "Machines left in pool, $PoolName, $(Get-HVPoolMachineCount -PoolName $PoolName)" | LogMessage
        }
    }
}

function Get-HVPoolMachineCount()
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $PoolName
    )

    $poolSummary    = Get-HVQueryResult -EntityType DesktopSummaryView -Filter (Get-HVQueryFilter desktopSummaryData.name -eq $PoolName)
    $machineSummary = Get-HVQueryResult -EntityType MachineNamesView   -Filter (Get-HVQueryFilter base.desktop -eq $poolSummary.Id)

    @($machineSummary).Count
}

function LogDelete()
{
    param # Deletes log when over sized or always with the switch.
    (
        [ValidatePattern('^[a-zA-Z0-9]+$')][String]$Name,
        [switch]$AlwaysDelete
    )

    # Find parent script in the stack so it works within a helper library.
    if (!$PSScriptRoot) { Throw 'LogDelete must be used in a saved file.' }
    $logPath = ((Get-PSCallStack | Where-Object ScriptName -ne $null)[-1].ScriptName) + "$(if ($Name) { '-' + $Name }).log"

    # Check log file exists and if needed delete it.
    if (!(Test-Path -LiteralPath $logPath)) { return }
    if (!$AlwaysDelete -and (Get-Item $logPath).Length -lt 2MB) { return }
    Remove-Item -LiteralPath $logPath -Force
}

function LogMessage()
{
    param # Puts text into a log based on the parent PS path with optional Name suffix.
    (
        [Parameter(ValueFromPipeline=$true)][String]$inputText,
        [ValidatePattern('^[a-zA-Z0-9]+$')][String]$Name,
        [String]$Color
    )

    # Find parent script in the stack so it works within a helper library.
    if (!$PSScriptRoot) { Throw 'LogMessage must be used in a saved file.' }
    $logPath = ((Get-PSCallStack | Where-Object ScriptName -ne $null)[-1].ScriptName) + "$(if ($Name) { '-' + $Name }).log"

    # Use 'parameter splatting' to pass optional to Write-Host.
    $optionalParam = @{}
    if ($Color) { $optionalParam.Add('ForegroundColor', $Color) }

    # Datestamp and write message to the log and console.
    "$(Get-Date -Format 'u') - $inputText" | Tee-Object -Append -FilePath $logPath | Write-Host @optionalParam
}

# Start clean and check log size.
Clear-Host
LogDelete

"Started." | LogMessage -Color Green

# Only connect once for quicker debug runs, but must comment out the force disconnect below.
if (!(Test-Path variable:Global:DefaultHVServers) -or !$Global:DefaultHVServers)
{
    try
    {
        "Connecting to Horizon server, $($Global:HzServer)" | LogMessage -Color Cyan
        Connect-HVServer -Server $Global:HzServer -Domain $Global:HzDomain -User $Global:HzUser -Password $Global:HzPass
    }
    catch
    {
        "Failed to connect, $_" | LogMessage -Color Red
    }
}

# Get available Horizon machines.
Set-HVGlobalMachineList
"Total pool and non-pool machines, $($Global:HVMachinesInPool.Count), $($Global:HVMachinesNonPool.Count)" | LogMessage -Color Magenta

# Start the AD search and pool sync.
Get-HVAdGroupMachines
"Total pool and non-pool machines, $($Global:HVMachinesInPool.Count), $($Global:HVMachinesNonPool.Count)" | LogMessage -Color Magenta

# Actively disconnect from the Horizon server.
Disconnect-HVServer -Confirm:$false

"Finished." | LogMessage -Color Green
