
# Reason reference: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/failedevent.aspx?failedeventID=4625

$reasons = @{
    'C0000064' = 'User name does not exist'
    'C000006A' = 'Incorrect password'
    'C0000234' = 'User account is locked out'
    'C0000072' = 'User account is disabled'
    'C000006F' = 'User tried to log on in restricted period'
    'C0000070' = 'Workstation restriction, or Authentication Policy Silo violation'
    'C0000193' = 'User account expired'
    'C0000071' = 'User password expired'
    'C0000133' = 'Time between workstation and DC too far out of sync'
    'C0000224' = 'User required to change password at next logon'
    'C0000225' = 'Evidently a bug in Windows and not a risk'
    'C000015B' = 'The user has not been granted the requested logon type (aka logon right) at this machine'
}

$logonTypes = @{
    2 = 'Interactive'
    3 = 'Network'
    4 = 'Batch'
    5 = 'Service'
    7 = 'Unlock'
    8 = 'NetworkClearText'
    9 = 'NewCredentials'
    10 = 'RemoteInteractive'
    11 = 'CachedInteractive'
}

<#
.SYNOPSIS
    Retrieves logon events in the format of auth.log

.DESCRIPTION
    Get-LogonEvents retrieves logon events from the Security log with optional filtering based on specified criteria.

.PARAMETER Max
    Specifies the maximum entries processed for each event ID.

.PARAMETER NoServices
    Excludes logon events where the username is a built-in service such as SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-*, UMFD-*.

.PARAMETER NoTerms
    Excludes logon events associated with session terminations, which might be confusing.(!4634)

.PARAMETER NoSuperUsers
    Excludes logon events associated with superuser accounts.(!4672)

.EXAMPLE
    Get-LogonEvents -Max 50 -NoServices
    Retrieves logon events excluding those associated with built-in services.

.EXAMPLE
    Get-LogonEvents -Max 50 -NoServices -NoTerms
    Retrieves logon events excluding builtin services and session terminations. 

.EXAMPLE
    Get-LogonEvents -Max 50 -NoSuperUsers
    Retrieves logon events excluding those associated with superuser accounts. 

.NOTES
    Author: box777555888
    Version: 1.0
    Date: 15.5.2024
#>
function Get-LogonEvents {
    
    param (
    [Parameter(Mandatory=$true)][int]$Max,
    [switch]$NoServices,
    [switch]$NoTerms,
    [switch]$NoSuperUsers
    )

    function Check-Name {
    param (
        [string]$Name
    )

    if ($Name -in @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE') -or $Name -like 'DWM-*' -or $Name -like 'UMFD-*') {
        return $true
    } else {
        return $false
    }
    }

    # Create empty arrays to store sentences and timestamps
    $sentences = @()
    $timestamps = @()


    # Event ID 4625 - Failed logon
    $failedEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents $Max
    foreach ($failedEvent in $failedEvents) {
        $timeCreated = $failedEvent.TimeCreated.ToString('d MMMM yyyy HH:mm:ss')
        $userName = $failedEvent.Properties[5].Value
        $domain = $failedEvent.Properties[6].Value
        $logonType = $logonTypes[[int]$failedEvent.Properties[10].Value]
        $ip = $failedEvent.Properties[19].Value
        $port = $failedEvent.Properties[20].Value
        $substatus = $failedEvent.Properties[9].Value.ToString("X")
        $reason = $reasons[$substatus]
        
        $sentence = "{0} {1} logon: Failed logon for {2}\{3} from {4} port {5} for reason: {6}" -f $timeCreated, $logonType, $domain,$userName, $ip, $port, $reason
        $sentences += $sentence
        $timestamps += $failedEvent.TimeCreated
    }

    # Event ID 4624 - Successful logon
    $successEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents $Max
    foreach ($successEvent in $successEvents) {
        $timeCreated = $successEvent.TimeCreated.ToString('d MMMM yyyy HH:mm:ss')
        $userName = $successEvent.Properties[5].Value
        if ($NoServices -and (Check-Name -name $userName)) {
            continue # Skip service entries of -noservices
        }

        $domain = $successEvent.Properties[6].Value
        $logonType = $logonTypes[[int]$successEvent.Properties[8].Value]
        $logonId = $successEvent.Properties[7].Value.ToString("X")
        $ip = $successEvent.Properties[18].Value
        $port = $successEvent.Properties[19].Value
        $sentence = "{0} {1} logon: Session: {6} Successful logon for {2}\{3} from {4} port {5}" -f $timeCreated, $logonType,$domain, $userName, $ip, $port,$logonId
        $sentences += $sentence
        $timestamps += $successEvent.TimeCreated
    }

    if (-not $NoTerms){
        # Event ID 4634 - Logoff or session terminated
        $logoffEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4634} -MaxEvents $Max
        foreach ($logoffEvent in $logoffEvents) {
            $timeCreated = $logoffEvent.TimeCreated.ToString('d MMMM yyyy HH:mm:ss')
            $logonType = $logonTypes[[int]$logoffEvent.Properties[4].Value]
            $userName = $logoffEvent.Properties[1].Value

            if ($NoServices -and (Check-Name -name $userName)) {
                continue # Skip service entries of -noservices
            }
            $domain = $logoffEvent.Properties[2].Value
            $logonId = $logoffEvent.Properties[3].Value.ToString("X")
            $sentence = "{0} {1} logon: Session {2} was terminated for {3}\{4}" -f $timeCreated,$logonType,$logonId, $domain,$userName
            $sentences += $sentence
            $timestamps += $logoffEvent.TimeCreated
        }
    }


    # Event ID 4647 - User initiated logoff
    $userLogoffEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4647} -MaxEvents $Max
    foreach ($userLogoffEvent in $userLogoffEvents) {
        $timeCreated = $userLogoffEvent.TimeCreated.ToString('d MMMM yyyy HH:mm:ss')
        $userName = $userLogoffEvent.Properties[1].Value
        $logonId = $userLogoffEvent.Properties[3].Value.ToString("X")
        $sentence = "{0} Session {1} closed. {2} logged out" -f $timeCreated,$logonId, $userName
        $sentences += $sentence
        $timestamps += $userLogoffEvent.TimeCreated
    }

    # Event 4672 Superuser logons
    if (-not $NoSuperUsers){
        $superLogonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} -MaxEvents $Max
        foreach ($superLogonEvent in $superLogonEvents) {
            $timeCreated = $superLogonEvent.TimeCreated.ToString('d MMMM yyyy HH:mm:ss')
            $username = $superLogonEvent.Properties[1].Value
            if ($NoServices -and (Check-Name -name $userName)) {
                continue # Skip service entries of -noservices
            }

            $domain = $superLogonEvent.Properties[2].Value
            $logonId = $superLogonEvent.Properties[3].Value.ToString("X")
            $sentence = "{0} Session: {1} Superuser logon: {2}\{3}" -f $timeCreated,$logonId,$domain,$username
            $sentences += $sentence
            $timestamps += $superLogonEvent.TimeCreated
        }

    }

    # Combine sentences and timestamps into custom objects
    $combined = for ($i = 0; $i -lt $sentences.Count; $i++) {
        [PSCustomObject]@{
            Sentence = $sentences[$i]
            TimeStamp = $timestamps[$i]
        }
    }
    # Sort combined objects by timestamp
    $sorted = $combined | Sort-Object TimeStamp
    # Output sorted entries
    foreach ($item in $sorted) {
        Write-Output $item.Sentence
    }
}
