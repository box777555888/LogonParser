# LogonParser
Parses Windows event log entries in the style of auth.log

# Preview
```powershell
Get-LogonEvents -Max 10 -Noservices
```
```
26 April 2024 19:32:17 Session 4B5EC closed. defaultuser0 logged out
26 April 2024 19:33:45 Session 1C31B closed. defaultuser0 logged out
26 April 2024 19:37:02 Session 92B30 closed. boxlocal logged out
26 April 2024 20:43:23 Session 195CB closed. boxlocal logged out
26 April 2024 20:47:41 Session 1AF9C closed. boxlocal logged out
26 April 2024 22:09:13 Network logon: Session 572B9 was terminated for WEBBY\BOX-COMPUTER$
28 April 2024 15:44:51 Network logon: Session 45D38 was terminated for WEBBY\BOX-COMPUTER$
28 April 2024 15:44:51 Network logon: Session 49EA4 was terminated for WEBBY\BOX-COMPUTER$
28 April 2024 15:44:57 Network logon: Session 593B1 was terminated for WEBBY\BOX-COMPUTER$
28 April 2024 15:49:27 Unlock logon: Session B09C8 was terminated for WEBBY\john
28 April 2024 15:49:27 Unlock logon: Session B088D was terminated for WEBBY\john
28 April 2024 16:06:17 Session B0811 closed. john logged out
12 May 2024 00:00:53 Interactive logon: Failed logon for BOX-COMPUTER\box from 127.0.0.1 port 0 for reason: User name does not exist
12 May 2024 00:01:02 Interactive logon: Failed logon for BOX-COMPUTER\boxlocal from 127.0.0.1 port 0 for reason: Incorrect password
12 May 2024 00:02:20 Session 6E354 closed. boxlocal logged out
15 May 2024 21:06:44 CachedInteractive logon: Failed logon for WEBBY\Administrator from ::1 port 0 for reason: 
15 May 2024 21:06:56 Interactive logon: Failed logon for WEBBY\Administrator from ::1 port 0 for reason: 
15 May 2024 21:08:23 CachedInteractive logon: Failed logon for WEBBY\Administrator from ::1 port 0 for reason: 
15 May 2024 21:27:03 CachedInteractive logon: Session: 15789E Successful logon for WEBBY\Administrator from ::1 port 0
15 May 2024 21:27:03 Session: 15789E Superuser logon: WEBBY\Administrator
15 May 2024 21:27:04 Network logon: Failed logon for BOX-COMPUTER\Guest from - port - for reason: User account is disabled
15 May 2024 21:27:04 Network logon: Failed logon for BOX-COMPUTER\Guest from - port - for reason: User account is disabled
15 May 2024 21:27:04 Network logon: Failed logon for BOX-COMPUTER\Guest from - port - for reason: User account is disabled
15 May 2024 21:27:04 Network logon: Failed logon for BOX-COMPUTER\Guest from - port - for reason: User account is disabled
15 May 2024 21:28:02 CachedInteractive logon: Session 15789E was terminated for WEBBY\Administrator
15 May 2024 21:29:29 Network logon: Failed logon for MicrosoftAccount\Letmein from 192.168.18.1 port 51110 for reason: User name does not exist
15 May 2024 21:29:57 Session: 1ADB59 Superuser logon: WEBBY\Administrator
15 May 2024 21:29:57 Network logon: Session: 1ADB59 Successful logon for WEBBY\Administrator from 192.168.18.1 port 51111
```

# Usage
```powershell
. .\LogonParser.ps1
```
```powershell
Get-Help Get-LogonEvents -detailed
```

```
NAME
    Get-LogonEvents

SYNOPSIS
    Retrieves logon events in the format of auth.log


SYNTAX
    Get-LogonEvents [-Max] <Int32> [-NoServices] [-NoTerms] [-NoSuperUsers] [<CommonParameters>]


DESCRIPTION
    Get-LogonEvents retrieves logon events from the Security log with optional filtering based on specified criteria.


PARAMETERS
    -Max <Int32>
        Specifies the maximum entries processed for each event ID.

    -NoServices [<SwitchParameter>]
        Excludes logon events where the username is a built-in service such as SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM-*, UMFD-*.

    -NoTerms [<SwitchParameter>]
        Excludes logon events associated with session terminations, which might be confusing.(!4634)

    -NoSuperUsers [<SwitchParameter>]
        Excludes logon events associated with superuser accounts.(!4672)

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).

    -------------------------- EXAMPLE 1 --------------------------

    PS C:\>Get-LogonEvents -Max 50 -NoServices

    Retrieves logon events excluding those associated with built-in services.



    -------------------------- EXAMPLE 2 --------------------------

    PS C:\>Get-LogonEvents -Max 50 -NoServices -NoTerms

    Retrieves logon events excluding builtin services and session terminations.



    -------------------------- EXAMPLE 3 --------------------------

    PS C:\>Get-LogonEvents -Max 50 -NoSuperUsers

    Retrieves logon events excluding those associated with superuser accounts.

```
