param (
    [Parameter(Position = 0)]
    [string]$Username,
    [string]$ComputerName
)

# ===========================================================================
# Setup
# ===========================================================================

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "The Active Directory module is not installed. Install RSAT with:" -ForegroundColor Red
    Write-Host "  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Red
    return
}

Import-Module ActiveDirectory

# All AD reads and writes go to the PDC Emulator, which always has current lockout data
try {
    $script:DC = (Get-ADDomain -ErrorAction Stop).PDCEmulator
} catch {
    Write-Host "Could not contact the domain: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$script:SelectedUser     = $null
$script:SelectedComputer = $null
$script:HKLM             = [uint32]2147483650

$script:UserProps = @(
    'DisplayName', 'Mail', 'Enabled', 'LockedOut', 'AccountLockoutTime',
    'BadLogonCount', 'LastBadPasswordAttempt', 'PasswordExpired', 'PasswordLastSet',
    'PasswordNeverExpires', 'msDS-UserPasswordExpiryTimeComputed',
    'LastLogonDate', 'AccountExpirationDate', 'Title', 'Department', 'Manager',
    'Office', 'OfficePhone', 'Description', 'CanonicalName', 'whenCreated',
    'whenChanged', 'MemberOf'
)

$script:ComputerProps = @(
    'Description', 'OperatingSystem', 'OperatingSystemVersion',
    'LastLogonDate', 'IPv4Address', 'CanonicalName'
)

# ===========================================================================
# Shared helpers
# ===========================================================================

function Read-YesNo {
    param(
        [string]$Prompt,
        [bool]$Default = $true
    )
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Prompt $hint").Trim()
        if ($answer -eq '')            { return $Default }
        if ($answer -in 'y', 'yes')    { return $true }
        if ($answer -in 'n', 'no')     { return $false }
    }
}

function Write-Row {
    param(
        [string]$Label,
        $Value,
        [string]$Color
    )
    $text = "{0,-24}{1}" -f "$($Label):", $Value
    if ($Color) { Write-Host $text -ForegroundColor $Color } else { Write-Host $text }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n--- $Title ---" -ForegroundColor Cyan
}

function Format-Date {
    param($Date)
    if ($Date) { ([datetime]$Date).ToString('dd-MMM-yyyy hh:mm tt') } else { '' }
}

function Read-Days {
    param([string]$Prompt, [int]$Default)
    $value = (Read-Host "$Prompt [Default: $Default]").Trim()
    if ($value -match '^\d+$') { [int]$value } else { $Default }
}

function Save-HelpdeskCsv {
    # Saves rows to a timestamped CSV on the Desktop
    param($Rows, [string]$BaseName)
    $path = Join-Path ([Environment]::GetFolderPath('Desktop')) "$($BaseName)_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    try {
        $Rows | Export-Csv -Path $path -NoTypeInformation -ErrorAction Stop
        Write-Host "Saved to: $path" -ForegroundColor Green
    } catch {
        Write-Host "Could not save CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===========================================================================
# User functions
# ===========================================================================

function New-TempPassword {
    param([int]$Length = 12)

    # Ambiguous characters (0/O, 1/l/I) removed; symbols limited to ones easy to say over the phone
    $sets  = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#$%?')
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(4)

    $chars = foreach ($i in 0..($Length - 1)) {
        # First four characters take one from each set so every category is present
        $set = if ($i -lt $sets.Count) { $sets[$i] } else { -join $sets }
        $rng.GetBytes($bytes)
        $set[[BitConverter]::ToUInt32($bytes, 0) % $set.Length]
    }

    # Shuffle so the guaranteed characters aren't always at the front
    -join ($chars | Sort-Object { $rng.GetBytes($bytes); [BitConverter]::ToUInt32($bytes, 0) })
}

function Get-PasswordExpiryText {
    param($User)
    $raw = $User.'msDS-UserPasswordExpiryTimeComputed'
    if ($null -eq $raw)                   { return 'Unknown' }
    if ($raw -eq 0)                       { return 'Must change at next logon' }
    if ($raw -eq 9223372036854775807)     { return 'Never expires' }
    return [datetime]::FromFileTime($raw).ToString('dd-MMM-yyyy hh:mm tt')
}

function Find-HelpdeskUser {
    # Accepts sAMAccountName, UPN, or email address. Returns the user or $null.
    param([string]$Identity)

    $Identity = $Identity.Trim()
    if (-not $Identity) { return $null }

    try {
        return Get-ADUser -Identity $Identity -Server $script:DC -Properties $script:UserProps -ErrorAction Stop
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Not a sAMAccountName; try UPN or email
    } catch {
        Write-Host "Lookup failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }

    $escaped = $Identity -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'
    try {
        $found = @(Get-ADUser -LDAPFilter "(|(userPrincipalName=$escaped)(mail=$escaped))" `
                    -Server $script:DC -Properties $script:UserProps -ErrorAction Stop)
    } catch {
        Write-Host "Lookup failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }

    if ($found.Count -eq 1) { return $found[0] }
    if ($found.Count -gt 1) {
        Write-Host "Multiple accounts match '$Identity'. Use the sAMAccountName instead." -ForegroundColor Red
    } else {
        Write-Host "User '$Identity' was not found in Active Directory." -ForegroundColor Red
    }
    return $null
}

function Get-NameFromDN {
    # "CN=Smith\, John,OU=Sales,DC=..." -> "Smith, John"
    param([string]$DN)
    if ($DN -match '^CN=((?:\\,|[^,])+)') { $Matches[1] -replace '\\,', ',' } else { $DN }
}

function Write-UserWarnings {
    # Flag conditions an unlock or reset won't fix, plus the common ticket causes
    param($User)
    if (-not $User.Enabled) {
        Write-Host "WARNING: Account is DISABLED." -ForegroundColor Red
    }
    if ($User.AccountExpirationDate -and $User.AccountExpirationDate -lt (Get-Date)) {
        Write-Host "WARNING: Account has EXPIRED." -ForegroundColor Red
    }
    if ($User.LockedOut) {
        Write-Host "Account is locked out." -ForegroundColor Yellow
    }
    if ($User.PasswordExpired) {
        Write-Host "Password is expired." -ForegroundColor Yellow
    }
}

function Show-HelpdeskUserSummary {
    # Quick lookup: identity plus the status fields most tickets need
    param($User)

    Write-Host "`n------------------------------------------------"
    Write-Row 'Name'                 $User.DisplayName
    Write-Row 'Username'             $User.SamAccountName
    Write-Row 'Email'                $User.Mail
    Write-Row 'Title'                $User.Title
    Write-Row 'Enabled'              $User.Enabled
    Write-Row 'Locked out'           $User.LockedOut
    Write-Row 'Password expired'     $User.PasswordExpired
    Write-Row 'Password expires'     (Get-PasswordExpiryText $User)
    Write-Row 'Last logon (approx)'  (Format-Date $User.LastLogonDate)
    Write-Host "------------------------------------------------"

    Write-UserWarnings $User
}

function Show-HelpdeskUserReport {
    # Full report: everything in the quick lookup plus org details, lockout detail, and groups
    param($User)

    $ou = if ($User.CanonicalName) { $User.CanonicalName.Substring(0, $User.CanonicalName.LastIndexOf('/')) } else { '' }

    Write-Row 'Lookup time' (Get-Date -Format 'dd-MMM-yyyy hh:mm:ss tt')

    Write-Section 'Identity'
    Write-Row 'Name'                 $User.DisplayName
    Write-Row 'Username'             $User.SamAccountName
    Write-Row 'UPN'                  $User.UserPrincipalName
    Write-Row 'Email'                $User.Mail
    Write-Row 'Title'                $User.Title
    Write-Row 'Department'           $User.Department
    Write-Row 'Manager'              (& { if ($User.Manager) { Get-NameFromDN $User.Manager } })
    Write-Row 'Office'               $User.Office
    Write-Row 'Phone'                $User.OfficePhone
    Write-Row 'Description'          $User.Description
    Write-Row 'OU'                   $ou
    Write-Row 'Created'              (Format-Date $User.whenCreated)
    Write-Row 'Last modified'        (Format-Date $User.whenChanged)

    Write-Section 'Account'
    Write-Row 'Enabled'              $User.Enabled
    Write-Row 'Account expires'      (& { if ($User.AccountExpirationDate) { Format-Date $User.AccountExpirationDate } else { 'Never' } })
    Write-Row 'Last logon (approx)'  (Format-Date $User.LastLogonDate)
    Write-Row 'Locked out'           $User.LockedOut
    Write-Row 'Lockout time'         (Format-Date $User.AccountLockoutTime)
    Write-Row 'Bad password count'   $User.BadLogonCount
    Write-Row 'Last bad password'    (Format-Date $User.LastBadPasswordAttempt)

    Write-Section 'Password'
    Write-Row 'Last set'             (Format-Date $User.PasswordLastSet)
    Write-Row 'Expires'              (Get-PasswordExpiryText $User)
    Write-Row 'Expired'              $User.PasswordExpired
    Write-Row 'Never expires'        $User.PasswordNeverExpires

    $groups = @($User.MemberOf | ForEach-Object { Get-NameFromDN $_ } | Sort-Object)
    Write-Section "Groups ($($groups.Count) direct; primary group not shown)"
    if ($groups.Count) {
        foreach ($g in $groups) { Write-Host "  $g" }
    } else {
        Write-Host "  (none besides primary group)"
    }

    Write-Host ""
    Write-UserWarnings $User
}

function Unlock-HelpdeskUser {
    param($User)

    if (-not $User.LockedOut) {
        Write-Host "Account is not locked."
        return
    }
    if (-not (Read-YesNo "Unlock $($User.SamAccountName)?" -Default $true)) {
        Write-Host "Account remains locked."
        return
    }

    try {
        Unlock-ADAccount -Identity $User -Server $script:DC -ErrorAction Stop
        Write-Host "Account has been unlocked." -ForegroundColor Green
    } catch {
        Write-Host "Unlock failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Reset-HelpdeskPassword {
    param($User)

    if (-not (Read-YesNo "Reset password for $($User.SamAccountName)?" -Default $false)) {
        return
    }

    $mode = Read-Host "(1) Generate a temporary password or (2) enter one manually [Default: 1]"
    $plainPwd = $null
    $success  = $false

    for ($attempt = 1; $attempt -le 3 -and -not $success; $attempt++) {
        if ($mode -eq '2') {
            $securePwd = Read-Host "Enter new password (blank to cancel)" -AsSecureString
            if ($securePwd.Length -eq 0) { Write-Host "Cancelled."; return }

            # Ask twice and compare so a typo can't slip through unseen
            $confirmPwd = Read-Host "Confirm new password" -AsSecureString
            $first  = [System.Net.NetworkCredential]::new('', $securePwd).Password
            $second = [System.Net.NetworkCredential]::new('', $confirmPwd).Password
            $match  = $first -ceq $second
            $first  = $null
            $second = $null
            if (-not $match) {
                Write-Host "Passwords do not match. Try again." -ForegroundColor Red
                continue
            }
        } else {
            $plainPwd  = New-TempPassword
            $securePwd = ConvertTo-SecureString $plainPwd -AsPlainText -Force
        }

        try {
            Set-ADAccountPassword -Identity $User -Server $script:DC -NewPassword $securePwd -Reset -ErrorAction Stop
            $success = $true
        } catch [Microsoft.ActiveDirectory.Management.ADPasswordComplexityException] {
            Write-Host "Password rejected by domain policy (length, complexity, or history)." -ForegroundColor Red
        } catch {
            Write-Host "Reset failed: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
    }

    if (-not $success) {
        Write-Host "Password was not changed." -ForegroundColor Red
        return
    }

    Write-Host "Password has been reset." -ForegroundColor Green
    if ($plainPwd) {
        Write-Host "Temporary password: $plainPwd" -ForegroundColor Yellow
        try { Set-Clipboard -Value $plainPwd; Write-Host "(Copied to clipboard)" } catch { }
    }

    if (Read-YesNo "Require password change at next logon?" -Default $false) {
        try {
            Set-ADUser -Identity $User -Server $script:DC -ChangePasswordAtLogon $true -ErrorAction Stop
            Write-Host "User must change password at next logon." -ForegroundColor Green
        } catch {
            Write-Host "Could not set change-at-logon: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    if ($User.LockedOut) {
        Write-Host "Note: a password reset does not unlock the account. Use option 3 if needed." -ForegroundColor Yellow
    }
}

function Show-HelpdeskAllUsersReport {
    # Exports every AD user with account, password, and org details, and flags common
    # cleanup items. AD-only query, so no remote connections and it runs in seconds.

    $days = (Read-Host "Flag enabled accounts inactive for how many days? [Default: 90]").Trim()
    if ($days -notmatch '^\d+$') { $days = 90 }
    $cutoff = (Get-Date).AddDays(-[int]$days)

    $ou = (Read-Host "Limit to an OU (distinguished name), or blank for the whole domain").Trim()

    $adParams = @{
        Filter      = '*'
        Properties  = $script:UserProps
        Server      = $script:DC
        ErrorAction = 'Stop'
    }
    if ($ou) { $adParams.SearchBase = $ou }

    Write-Host "`nQuerying Active Directory..." -ForegroundColor Cyan
    try {
        $users = @(Get-ADUser @adParams)
    } catch {
        Write-Host "AD query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    if (-not $users.Count) {
        Write-Host "No users found." -ForegroundColor Yellow
        return
    }

    $now = Get-Date
    $rows = foreach ($u in $users) {
        # Flags only apply to enabled accounts; new accounts aren't flagged as inactive
        $flags = @()
        if (-not $u.Enabled) {
            $flags += 'Disabled'
        } else {
            if ($u.LockedOut)            { $flags += 'Locked out' }
            if ($u.PasswordExpired)      { $flags += 'Password expired' }
            if ($u.PasswordNeverExpires) { $flags += 'Password never expires' }
            if ($u.AccountExpirationDate -and $u.AccountExpirationDate -lt $now) { $flags += 'Account expired' }
            if ($u.whenCreated -lt $cutoff) {
                if (-not $u.LastLogonDate)             { $flags += 'Never logged on' }
                elseif ($u.LastLogonDate -lt $cutoff)  { $flags += "Inactive $days+ days" }
            }
        }

        $groups = @($u.MemberOf | ForEach-Object { Get-NameFromDN $_ } | Sort-Object)
        $ouPath = if ($u.CanonicalName) { $u.CanonicalName.Substring(0, $u.CanonicalName.LastIndexOf('/')) } else { '' }

        [pscustomobject]@{
            Name                     = $u.DisplayName
            Username                 = $u.SamAccountName
            UPN                      = $u.UserPrincipalName
            Email                    = $u.Mail
            Title                    = $u.Title
            Department               = $u.Department
            Manager                  = if ($u.Manager) { Get-NameFromDN $u.Manager } else { '' }
            Office                   = $u.Office
            Phone                    = $u.OfficePhone
            OU                       = $ouPath
            Enabled                  = $u.Enabled
            'Locked Out'             = $u.LockedOut
            'Last Logon'             = Format-Date $u.LastLogonDate
            'Days Since Logon'       = if ($u.LastLogonDate) { ($now - $u.LastLogonDate).Days } else { 'Never' }
            Created                  = Format-Date $u.whenCreated
            'Password Last Set'      = Format-Date $u.PasswordLastSet
            'Password Expires'       = Get-PasswordExpiryText $u
            'Password Never Expires' = $u.PasswordNeverExpires
            'Account Expires'        = if ($u.AccountExpirationDate) { Format-Date $u.AccountExpirationDate } else { 'Never' }
            'Group Count'            = $groups.Count
            Groups                   = $groups -join '; '
            Description              = $u.Description
            Flags                    = $flags -join '; '
        }
    }

    $enabledRows = @($rows | Where-Object { $_.Enabled })
    function Get-FlagCount([string]$Flag) { @($rows | Where-Object { $_.Flags -like "*$Flag*" }).Count }

    Write-Section 'Summary'
    Write-Row 'Total accounts'          $rows.Count
    Write-Row 'Enabled'                 $enabledRows.Count
    Write-Row 'Disabled'                ($rows.Count - $enabledRows.Count)
    Write-Row 'Locked out'              (Get-FlagCount 'Locked out')
    Write-Row 'Password expired'        (Get-FlagCount 'Password expired')
    Write-Row 'Password never expires'  (Get-FlagCount 'Password never expires')
    Write-Row 'Account expired'         (Get-FlagCount 'Account expired')
    Write-Row "Inactive $days+ days"    (Get-FlagCount 'Inactive')
    Write-Row 'Never logged on'         (Get-FlagCount 'Never logged on')

    Write-Section 'Enabled users by department'
    $enabledRows | Group-Object Department |
        ForEach-Object {
            [pscustomobject]@{
                Department = if ($_.Name) { $_.Name } else { '(none)' }
                Users      = $_.Count
            }
        } |
        Sort-Object Users -Descending |
        Format-Table -AutoSize | Out-Host

    $csv = Join-Path ([Environment]::GetFolderPath('Desktop')) "AllUsers_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    try {
        $rows | Sort-Object @{ e = { $_.Enabled }; Descending = $true }, Department, Name |
            Export-Csv -Path $csv -NoTypeInformation -ErrorAction Stop
        Write-Host "Full results saved to: $csv" -ForegroundColor Green
    } catch {
        Write-Host "Could not save CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===========================================================================
# Machine functions
# ===========================================================================

function New-HelpdeskCimSession {
    # Try WinRM first; fall back to DCOM if WinRM isn't enabled on the target
    param([string]$ComputerName)
    try {
        return New-CimSession -ComputerName $ComputerName -OperationTimeoutSec 15 -ErrorAction Stop
    } catch {
        try {
            $dcom = New-CimSessionOption -Protocol Dcom
            return New-CimSession -ComputerName $ComputerName -SessionOption $dcom -OperationTimeoutSec 15 -ErrorAction Stop
        } catch {
            Write-Host "Could not connect to $ComputerName : $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
}

function Get-OptionalCim {
    # Returns $null instead of failing, so one bad class doesn't stop the whole report
    param(
        $Session,
        [string]$ClassName,
        [string]$Filter,
        [string]$Namespace = 'root/cimv2'
    )
    $params = @{ CimSession = $Session; ClassName = $ClassName; Namespace = $Namespace; ErrorAction = 'Stop' }
    if ($Filter) { $params.Filter = $Filter }
    try { Get-CimInstance @params } catch { $null }
}

function Get-RemoteRegValue {
    param(
        $Session,
        [string]$Key,
        [string]$Name,
        [switch]$Dword
    )
    $method = if ($Dword) { 'GetDWORDValue' } else { 'GetStringValue' }
    try {
        $r = Invoke-CimMethod -CimSession $Session -Namespace root/default -ClassName StdRegProv -MethodName $method `
                -Arguments @{ hDefKey = $script:HKLM; sSubKeyName = $Key; sValueName = $Name } -ErrorAction Stop
        if ($Dword) { $r.uValue } else { $r.sValue }
    } catch { $null }
}

function Test-RemoteRegKey {
    param(
        $Session,
        [string]$ParentKey,
        [string]$ChildName
    )
    try {
        $r = Invoke-CimMethod -CimSession $Session -Namespace root/default -ClassName StdRegProv -MethodName EnumKey `
                -Arguments @{ hDefKey = $script:HKLM; sSubKeyName = $ParentKey } -ErrorAction Stop
        return ($r.sNames -contains $ChildName)
    } catch { return $false }
}

function Get-HelpdeskADComputer {
    # Returns the AD computer object or $null (with a message)
    param([string]$ShortName)
    try {
        return Get-ADComputer -Identity $ShortName -Server $script:DC -Properties $script:ComputerProps -ErrorAction Stop
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Host "No computer named '$ShortName' in Active Directory." -ForegroundColor Yellow
    } catch {
        Write-Host "AD lookup failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    return $null
}

function Write-DnsMismatchWarning {
    # Stale DNS can point a hostname at a different PC; make that obvious
    param([string]$Name, [string]$ShortName, [bool]$IsIp, $ComputerSystem)
    if (-not $IsIp -and $ComputerSystem -and $ComputerSystem.Name -ne $ShortName) {
        Write-Host "WARNING: '$Name' answered as '$($ComputerSystem.Name)'. DNS may be stale - this may be a different PC." -ForegroundColor Red
    }
}

function Show-HelpdeskComputerSummary {
    # Quick lookup: the handful of details most tickets need. Returns $true if anything was found.
    param([string]$ComputerName)

    $name = $ComputerName.Trim()
    if (-not $name) { return $false }

    $parsedIp  = $null
    $isIp      = [ipaddress]::TryParse($name, [ref]$parsedIp)
    $shortName = if ($isIp) { $name } else { ($name -split '\.')[0] }

    Write-Host "`nQuerying $name ..." -ForegroundColor Cyan

    $ad = if (-not $isIp) { Get-HelpdeskADComputer $shortName }

    $cs = $bios = $os = $nics = $displayVersion = $null
    $session = New-HelpdeskCimSession $name
    if ($session) {
        try {
            $cs             = Get-OptionalCim $session 'Win32_ComputerSystem'
            $bios           = Get-OptionalCim $session 'Win32_BIOS'
            $os             = Get-OptionalCim $session 'Win32_OperatingSystem'
            $nics           = Get-OptionalCim $session 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = True'
            $displayVersion = Get-RemoteRegValue $session 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'DisplayVersion'
        } finally {
            Remove-CimSession $session
        }
    }

    Write-Host "------------------------------------------------"
    Write-Row 'Computer'             (& { if ($cs) { $cs.Name } elseif ($ad) { $ad.Name } else { $name } })
    Write-Row 'Status'               (& { if ($session) { 'Online' } else { 'Offline / unreachable' } }) `
                                     (& { if ($session) { 'Green' } else { 'Red' } })
    if ($ad -and -not $ad.Enabled) {
        Write-Row 'AD account'       'DISABLED' 'Red'
    }
    if ($cs) {
        Write-Row 'Logged-on user'   (& { if ($cs.UserName) { $cs.UserName } else { 'None at console' } })
        Write-Row 'Model'            "$($cs.Manufacturer) $($cs.Model)"
    }
    if ($bios) {
        Write-Row 'Serial / Service Tag' $bios.SerialNumber.Trim() 'Green'
    }
    if ($os) {
        $uptime = (Get-Date) - $os.LastBootUpTime
        Write-Row 'OS'               "$($os.Caption) $displayVersion"
        Write-Row 'Last boot'        ("{0}  (up {1}d {2}h)" -f (Format-Date $os.LastBootUpTime), $uptime.Days, $uptime.Hours) `
                                     (& { if ($uptime.TotalDays -gt 7) { 'Yellow' } })
    }
    if ($ad) {
        Write-Row 'Last logon (approx)' (Format-Date $ad.LastLogonDate)
    }
    # One line per active adapter so each IP stays paired with its MAC
    if ($nics) {
        foreach ($n in $nics) {
            $ipv4 = ($n.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }) -join ', '
            Write-Row 'IPv4 / MAC'       "$ipv4  /  $($n.MACAddress)"
        }
    } elseif ($ad) {
        Write-Row 'IPv4 (DNS)'           $ad.IPv4Address
    }
    Write-Host "------------------------------------------------"

    Write-DnsMismatchWarning $name $shortName $isIp $cs

    return [bool]($ad -or $session)
}

function Show-HelpdeskComputerReport {
    # Full report: everything the quick lookup shows plus hardware, storage, BitLocker and network detail.
    # Accepts a hostname, FQDN, or IP. Returns $true if anything was found.
    param([string]$ComputerName)

    $name = $ComputerName.Trim()
    if (-not $name) { return $false }

    $parsedIp  = $null
    $isIp      = [ipaddress]::TryParse($name, [ref]$parsedIp)
    $shortName = if ($isIp) { $name } else { ($name -split '\.')[0] }

    Write-Host "`nQuerying $name ..." -ForegroundColor Cyan
    Write-Row 'Lookup time' (Get-Date -Format 'dd-MMM-yyyy hh:mm:ss tt')

    # --- Active Directory (available even when the PC is offline) ---
    $ad = if (-not $isIp) { Get-HelpdeskADComputer $shortName }

    if ($ad) {
        $ou = if ($ad.CanonicalName) { $ad.CanonicalName.Substring(0, $ad.CanonicalName.LastIndexOf('/')) } else { '' }
        Write-Section 'Active Directory'
        Write-Row 'Name'                 $ad.Name
        Write-Row 'Enabled'              $ad.Enabled (& { if (-not $ad.Enabled) { 'Red' } })
        Write-Row 'OU'                   $ou
        Write-Row 'Description'          $ad.Description
        Write-Row 'OS (per AD)'          "$($ad.OperatingSystem) $($ad.OperatingSystemVersion)"
        Write-Row 'Last logon (approx)'  (Format-Date $ad.LastLogonDate)
        Write-Row 'IPv4 (DNS)'           $ad.IPv4Address
    }

    # --- Connectivity ---
    Write-Section 'Connectivity'
    $pingOk = Test-Connection -ComputerName $name -Count 1 -Quiet -ErrorAction SilentlyContinue
    Write-Row 'Ping' (& { if ($pingOk) { 'Replied' } else { 'No reply (may be offline or ICMP blocked)' } }) `
              (& { if (-not $pingOk) { 'Yellow' } })

    $session = New-HelpdeskCimSession $name
    if (-not $session) {
        Write-Row 'Remote query' 'Failed - live details unavailable' 'Red'
        return [bool]$ad
    }
    Write-Row 'Remote query' "Connected ($($session.Protocol))" 'Green'

    try {
        $cs   = Get-OptionalCim $session 'Win32_ComputerSystem'
        $bios = Get-OptionalCim $session 'Win32_BIOS'
        $os   = Get-OptionalCim $session 'Win32_OperatingSystem'
        $cpu  = Get-OptionalCim $session 'Win32_Processor' | Select-Object -First 1
        $disks = Get-OptionalCim $session 'Win32_LogicalDisk' -Filter 'DriveType = 3'
        $nics  = Get-OptionalCim $session 'Win32_NetworkAdapterConfiguration' -Filter 'IPEnabled = True'

        Write-DnsMismatchWarning $name $shortName $isIp $cs

        # --- System ---
        Write-Section 'System'
        if ($cs) {
            Write-Row 'Computer name'     $cs.Name
            Write-Row 'Manufacturer'      $cs.Manufacturer
            Write-Row 'Model'             $cs.Model
            Write-Row 'RAM'               ('{0} GB' -f [math]::Round($cs.TotalPhysicalMemory / 1GB, 1))
            Write-Row 'Logged-on user'    (& { if ($cs.UserName) { $cs.UserName } else { 'None at console' } })
        }
        if ($bios) {
            Write-Row 'Serial / Service Tag' $bios.SerialNumber.Trim() 'Green'
            $biosDate = if ($bios.ReleaseDate) { " ($(([datetime]$bios.ReleaseDate).ToString('dd-MMM-yyyy')))" } else { '' }
            Write-Row 'BIOS version'      "$($bios.SMBIOSBIOSVersion)$biosDate"
        }
        if ($cpu) {
            Write-Row 'CPU'               $cpu.Name.Trim()
        }

        # --- Operating system ---
        Write-Section 'Operating System'
        if ($os) {
            $ntKey          = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $displayVersion = Get-RemoteRegValue $session $ntKey 'DisplayVersion'
            $ubr            = Get-RemoteRegValue $session $ntKey 'UBR' -Dword
            $build          = if ($null -ne $ubr) { "$($os.BuildNumber).$ubr" } else { $os.BuildNumber }
            $uptime         = (Get-Date) - $os.LastBootUpTime

            Write-Row 'OS'                $os.Caption
            Write-Row 'Version / Build'   "$displayVersion  (build $build)"
            Write-Row 'Installed'         (Format-Date $os.InstallDate)
            Write-Row 'Last boot'         (Format-Date $os.LastBootUpTime)
            Write-Row 'Uptime'            ('{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes) `
                                          (& { if ($uptime.TotalDays -gt 7) { 'Yellow' } })
        }

        $rebootReasons = @()
        if (Test-RemoteRegKey $session 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'RebootRequired') {
            $rebootReasons += 'Windows Update'
        }
        if (Test-RemoteRegKey $session 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing' 'RebootPending') {
            $rebootReasons += 'Component Servicing'
        }
        if ($rebootReasons) {
            Write-Row 'Pending reboot' "Yes ($($rebootReasons -join ', '))" 'Yellow'
        } else {
            Write-Row 'Pending reboot' 'No'
        }

        # --- Storage ---
        Write-Section 'Storage'
        foreach ($d in $disks) {
            if (-not $d.Size) { continue }
            $freeGB = [math]::Round($d.FreeSpace / 1GB, 1)
            $sizeGB = [math]::Round($d.Size / 1GB, 1)
            $pct    = [math]::Round(($d.FreeSpace / $d.Size) * 100)
            Write-Row $d.DeviceID "$freeGB GB free of $sizeGB GB ($pct% free)" (& { if ($pct -lt 10) { 'Red' } elseif ($pct -lt 20) { 'Yellow' } })
        }

        $sysDrive = if ($os) { $os.SystemDrive } else { 'C:' }
        $bl = Get-OptionalCim $session 'Win32_EncryptableVolume' -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' `
                -Filter "DriveLetter = '$sysDrive'"
        $blText = if (-not $bl)                     { 'Unavailable (needs admin rights)' }
                  elseif ($bl.ProtectionStatus -eq 1) { 'On' }
                  elseif ($bl.ProtectionStatus -eq 0) { 'Off' }
                  else                                { 'Unknown' }
        Write-Row "BitLocker ($sysDrive)" $blText (& { if ($blText -ne 'On') { 'Yellow' } })

        # --- Network ---
        Write-Section 'Network'
        foreach ($n in $nics) {
            $ipv4 = $n.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' }
            Write-Host "  $($n.Description)"
            Write-Row '    IPv4'          ($ipv4 -join ', ')
            Write-Row '    MAC'           $n.MACAddress
            Write-Row '    Gateway'       ($n.DefaultIPGateway -join ', ')
            Write-Row '    DHCP'          $n.DHCPEnabled
        }
    } finally {
        Remove-CimSession $session
    }

    return $true
}

function Search-HelpdeskSoftware {
    # Searches the target's uninstall registry keys (what Programs and Features shows).
    # Blank search term lists everything. Returns $true if the PC was reached.
    param([string]$ComputerName)

    $name = $ComputerName.Trim()
    if (-not $name) { return $false }

    $parsedIp  = $null
    $isIp      = [ipaddress]::TryParse($name, [ref]$parsedIp)
    $shortName = if ($isIp) { $name } else { ($name -split '\.')[0] }

    $term = (Read-Host "Search for (name or publisher, blank lists all)").Trim()
    Write-Host "`nSearching $name ..." -ForegroundColor Cyan

    $remote = {
        param($Term)
        $paths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        # Per-user installs (Zoom, Teams, etc.) for anyone currently logged on
        Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } |
            ForEach-Object { $paths += "Registry::HKEY_USERS\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" }

        $apps = Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -and $_.SystemComponent -ne 1 -and
                (-not $Term -or $_.DisplayName -like "*$Term*" -or $_.Publisher -like "*$Term*")
            } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,
                @{ n = 'Scope'; e = { if ($_.PSPath -match 'HKEY_USERS') { 'User' } else { 'Machine' } } }

        [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Apps = @($apps) }
    }

    try {
        $opt    = New-PSSessionOption -OpenTimeout 15000
        $result = Invoke-Command -ComputerName $name -ScriptBlock $remote -ArgumentList $term -SessionOption $opt -ErrorAction Stop
    } catch {
        Write-Host "Could not query $name over WinRM: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }

    Write-DnsMismatchWarning $name $shortName $isIp ([pscustomobject]@{ Name = $result.ComputerName })

    $apps = @($result.Apps | Where-Object { $_.DisplayName } | Sort-Object DisplayName, DisplayVersion -Unique)
    if (-not $apps.Count) {
        $what = if ($term) { "matching '$term'" } else { 'found' }
        Write-Host "No installed programs $what on $($result.ComputerName)." -ForegroundColor Yellow
        return $true
    }

    $apps | Format-Table -AutoSize `
        @{ n = 'Name';      e = { $_.DisplayName } },
        @{ n = 'Version';   e = { $_.DisplayVersion } },
        'Publisher',
        @{ n = 'Installed'; e = {
            if ($_.InstallDate -match '^\d{8}$') {
                [datetime]::ParseExact($_.InstallDate, 'yyyyMMdd', $null).ToString('dd-MMM-yyyy')
            } else { $_.InstallDate }
        } },
        'Scope' | Out-Host

    Write-Host "$($apps.Count) program(s) on $($result.ComputerName)." -ForegroundColor Green
    return $true
}

function Show-HelpdeskFleetModelReport {
    # Scans all active Windows workstations in parallel and groups them by model.
    # Collects the same core details as the quick lookup, but fans out over WinRM
    # so hundreds of PCs finish in minutes instead of hours.

    $days = (Read-Host "Include PCs active in AD within how many days? [Default: 90]").Trim()
    if ($days -notmatch '^\d+$') { $days = 90 }
    $cutoff = (Get-Date).AddDays(-[int]$days)

    $ou = (Read-Host "Limit to an OU (distinguished name), or blank for the whole domain").Trim()

    $adParams = @{
        Filter      = 'Enabled -eq $true -and OperatingSystem -like "*Windows*" -and OperatingSystem -notlike "*Server*"'
        Properties  = 'LastLogonDate', 'OperatingSystem', 'CanonicalName'
        Server      = $script:DC
        ErrorAction = 'Stop'
    }
    if ($ou) { $adParams.SearchBase = $ou }

    try {
        $adComputers = @(Get-ADComputer @adParams | Where-Object { $_.LastLogonDate -gt $cutoff })
    } catch {
        Write-Host "AD query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $adComputers.Count) {
        Write-Host "No matching computers found." -ForegroundColor Yellow
        return
    }
    if (-not (Read-YesNo "Scan $($adComputers.Count) computers?" -Default $true)) { return }

    $adLookup = @{}
    foreach ($c in $adComputers) { $adLookup[$c.Name] = $c }

    $scan = {
        $cs    = Get-CimInstance Win32_ComputerSystem
        $bios  = Get-CimInstance Win32_BIOS
        $cpu   = Get-CimInstance Win32_Processor | Select-Object -First 1
        $os    = Get-CimInstance Win32_OperatingSystem
        $nt    = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
        $disk  = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = '$($os.SystemDrive)'"
        $nics  = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True')

        # Windows feature version (older Windows 10 builds use ReleaseId instead of DisplayVersion)
        $release    = if ($nt.DisplayVersion) { $nt.DisplayVersion } else { $nt.ReleaseId }
        $winVersion = "$release (build $($nt.CurrentBuild).$($nt.UBR))"

        [pscustomobject]@{
            Name         = $env:COMPUTERNAME
            Manufacturer = $cs.Manufacturer
            Model        = $cs.Model
            Serial       = "$($bios.SerialNumber)".Trim()
            CPU          = "$($cpu.Name)".Trim()
            BIOSVersion  = $bios.SMBIOSBIOSVersion
            BIOSDate     = $bios.ReleaseDate
            OS           = $os.Caption
            WinVersion   = $winVersion
            FreeGB       = if ($disk.Size) { [math]::Round($disk.FreeSpace / 1GB, 1) } else { $null }
            FreePct      = if ($disk.Size) { [math]::Round($disk.FreeSpace / $disk.Size * 100) } else { $null }
            IPv4         = ($nics | ForEach-Object { $_.IPAddress | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } }) -join '; '
            MAC          = ($nics.MACAddress | Where-Object { $_ }) -join '; '
            User         = $cs.UserName
        }
    }

    Write-Host "`nScanning $($adComputers.Count) computers (offline PCs time out after ~15 seconds)..." -ForegroundColor Cyan
    $opt     = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 60000
    $results = @(Invoke-Command -ComputerName $adComputers.Name -ScriptBlock $scan -SessionOption $opt `
                    -ThrottleLimit 32 -ErrorAction SilentlyContinue)

    function Get-OuPath($c) {
        if ($c.CanonicalName) { $c.CanonicalName.Substring(0, $c.CanonicalName.LastIndexOf('/')) } else { '' }
    }

    $rows = @()
    foreach ($r in $results) {
        $ad = $adLookup[$r.PSComputerName]
        $rows += [pscustomobject]@{
            Computer           = $r.PSComputerName
            Status             = if ($r.Name -ne $r.PSComputerName) { "Online - answered as $($r.Name)" } else { 'Online' }
            OU                 = Get-OuPath $ad
            Manufacturer       = $r.Manufacturer
            Model              = $r.Model
            Serial             = $r.Serial
            CPU                = ($r.CPU -replace '\(R\)|\(TM\)|CPU|@.*$', '' -replace '\s+', ' ').Trim()
            OS                 = $r.OS
            'Windows Version'  = $r.WinVersion
            'Disk Free GB'     = $r.FreeGB
            'Disk Free %'      = $r.FreePct
            IPv4               = $r.IPv4
            MAC                = $r.MAC
            'BIOS Version'     = $r.BIOSVersion
            'BIOS Date'        = if ($r.BIOSDate) { ([datetime]$r.BIOSDate).ToString('yyyy-MM-dd') } else { '' }
            'Current User'     = $r.User
            'Last Logon'       = Format-Date $ad.LastLogonDate
        }
    }

    $reached = @($results.PSComputerName)
    foreach ($c in $adComputers | Where-Object { $_.Name -notin $reached }) {
        $rows += [pscustomobject]@{
            Computer           = $c.Name
            Status             = 'Unreachable'
            OU                 = Get-OuPath $c
            Manufacturer       = ''
            Model              = ''
            Serial             = ''
            CPU                = ''
            OS                 = $c.OperatingSystem
            'Windows Version'  = ''
            'Disk Free GB'     = ''
            'Disk Free %'      = ''
            IPv4               = ''
            MAC                = ''
            'BIOS Version'     = ''
            'BIOS Date'        = ''
            'Current User'     = ''
            'Last Logon'       = Format-Date $c.LastLogonDate
        }
    }

    # Sorted by manufacturer and model; unreachable PCs go to the bottom
    $sorted = $rows | Sort-Object @{ e = { $_.Status -eq 'Unreachable' } }, Manufacturer, Model, Computer
    $online = @($sorted | Where-Object { $_.Status -ne 'Unreachable' })
    $offline = $rows.Count - $online.Count

    Write-Host "`n$($online.Count) online, $offline unreachable." -ForegroundColor Green

    Write-Section 'Devices by model'
    $online | Group-Object Manufacturer, Model |
        ForEach-Object {
            [pscustomobject]@{
                Manufacturer = $_.Group[0].Manufacturer
                Model        = $_.Group[0].Model
                Count        = $_.Count
            }
        } |
        Sort-Object Manufacturer, Model |
        Format-Table -AutoSize | Out-Host

    $csv = Join-Path ([Environment]::GetFolderPath('Desktop')) "FleetModels_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
    try {
        $sorted | Export-Csv -Path $csv -NoTypeInformation -ErrorAction Stop
        Write-Host "Full results (including unreachable PCs) saved to: $csv" -ForegroundColor Green
    } catch {
        Write-Host "Could not save CSV: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ===========================================================================
# Domain functions - Structure & inventory
# ===========================================================================

function Get-ParentDN {
    # "CN=Smith\, John,OU=Sales,DC=..." -> "OU=Sales,DC=..."
    param([string]$DN)
    $DN -replace '^(?:\\,|[^,])+,', ''
}

function Show-DomainOuTree {
    Write-Host "`nReading OU structure..." -ForegroundColor Cyan
    try {
        $domain    = Get-ADDomain -Server $script:DC -ErrorAction Stop
        $ous       = @(Get-ADOrganizationalUnit -Filter * -Server $script:DC -ErrorAction Stop)
        $users     = @(Get-ADUser -Filter * -Server $script:DC -ErrorAction Stop)
        $computers = @(Get-ADComputer -Filter * -Server $script:DC -ErrorAction Stop)
    } catch {
        Write-Host "AD query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Count objects sitting directly inside each OU or container
    $userCount = @{}
    foreach ($u in $users) { $userCount[(Get-ParentDN $u.DistinguishedName)]++ }
    $computerCount = @{}
    foreach ($c in $computers) { $computerCount[(Get-ParentDN $c.DistinguishedName)]++ }

    # Parent -> children map, including the default Users and Computers containers
    $nodes = @($ous | ForEach-Object { [pscustomobject]@{ DN = $_.DistinguishedName; Name = $_.Name; IsContainer = $false } })
    foreach ($dn in $domain.UsersContainer, $domain.ComputersContainer) {
        $nodes += [pscustomobject]@{ DN = $dn; Name = Get-NameFromDN $dn; IsContainer = $true }
    }
    $children = @{}
    foreach ($n in $nodes) {
        $parent = Get-ParentDN $n.DN
        if (-not $children.ContainsKey($parent)) { $children[$parent] = @() }
        $children[$parent] += $n
    }

    function Write-OuBranch([string]$ParentDN, [int]$Depth) {
        if (-not $children.ContainsKey($ParentDN)) { return }
        foreach ($n in ($children[$ParentDN] | Sort-Object Name)) {
            $u    = [int]$userCount[$n.DN]
            $c    = [int]$computerCount[$n.DN]
            $tag  = if ($n.IsContainer) { ' [default container]' } else { '' }
            $line = '{0}{1}{2}  ({3} users, {4} computers)' -f ('    ' * $Depth), $n.Name, $tag, $u, $c
            if (($u + $c -eq 0) -and -not $children.ContainsKey($n.DN)) {
                Write-Host $line -ForegroundColor DarkGray
            } else {
                Write-Host $line
            }
            Write-OuBranch $n.DN ($Depth + 1)
        }
    }

    Write-Host ""
    Write-Host $domain.DNSRoot -ForegroundColor Cyan
    Write-OuBranch $domain.DistinguishedName 1
    Write-Host "`n$($ous.Count) OUs, $($users.Count) users, $($computers.Count) computers. Empty OUs are shown in gray."
}

function Show-DomainGroupMembers {
    param($Group)

    $recursive = Read-YesNo "Include members of nested groups?" -Default $false
    try {
        $members = @(Get-ADGroupMember -Identity $Group -Recursive:$recursive -Server $script:DC -ErrorAction Stop)
    } catch {
        Write-Host "Could not read members: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    if (-not $members.Count) {
        Write-Host "`n$($Group.Name) has no members." -ForegroundColor Yellow
        return
    }

    $rows = @($members | Sort-Object objectClass, name | ForEach-Object {
        [pscustomobject]@{ Name = $_.name; Username = $_.SamAccountName; Type = $_.objectClass }
    })

    $scope = if ($recursive) { 'including nested groups' } else { 'direct members only' }
    Write-Section "$($Group.Name): $($rows.Count) member(s), $scope"
    $rows | Format-Table -AutoSize | Out-Host

    if (Read-YesNo "Export to CSV?" -Default $false) {
        Save-HelpdeskCsv $rows "GroupMembers_$($Group.Name -replace '[^\w-]', '_')"
    }
}

function Show-DomainGroupDetails {
    param($Group)

    try {
        $g = Get-ADGroup -Identity $Group -Server $script:DC -ErrorAction Stop -Properties `
                Description, ManagedBy, mail, info, member, MemberOf, CanonicalName, whenCreated, whenChanged
    } catch {
        Write-Host "Could not read group: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $ou = if ($g.CanonicalName) { $g.CanonicalName.Substring(0, $g.CanonicalName.LastIndexOf('/')) } else { '' }

    Write-Section "Group: $($g.Name)"
    Write-Row 'Name'               $g.Name
    Write-Row 'Pre-2000 name'      $g.SamAccountName
    Write-Row 'Type'               $g.GroupCategory
    Write-Row 'Scope'              $g.GroupScope
    Write-Row 'Description'        $g.Description
    Write-Row 'Email'              $g.mail
    Write-Row 'Managed by'         (& { if ($g.ManagedBy) { Get-NameFromDN $g.ManagedBy } })
    Write-Row 'OU'                 $ou
    Write-Row 'Created'            (Format-Date $g.whenCreated)
    Write-Row 'Last modified'      (Format-Date $g.whenChanged)
    Write-Row 'Direct members'     $g.member.Count
    Write-Row 'Notes'              $g.info

    $parents = @($g.MemberOf | ForEach-Object { Get-NameFromDN $_ } | Sort-Object)
    Write-Section "Member of ($($parents.Count))"
    if ($parents.Count) {
        foreach ($p in $parents) { Write-Host "  $p" }
    } else {
        Write-Host "  (not a member of any group)"
    }
}

function Show-DomainGroupBrowser {
    $filter = (Read-Host "Filter groups by name (blank for all)").Trim()
    try {
        $groups = @(Get-ADGroup -Filter * -Properties member -Server $script:DC -ErrorAction Stop |
                    Where-Object { -not $filter -or $_.Name -like "*$filter*" } |
                    Sort-Object Name)
    } catch {
        Write-Host "AD query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    if (-not $groups.Count) {
        Write-Host "No groups match '$filter'." -ForegroundColor Yellow
        return
    }

    while ($true) {
        Write-Host ""
        Write-Host ("{0,5}  {1,-45} {2,-13} {3,-13} {4}" -f '#', 'Name', 'Type', 'Scope', 'Members') -ForegroundColor Cyan
        for ($i = 0; $i -lt $groups.Count; $i++) {
            $g = $groups[$i]
            Write-Host ("{0,5}  {1,-45} {2,-13} {3,-13} {4}" -f ($i + 1), $g.Name, $g.GroupCategory, $g.GroupScope, $g.member.Count)
        }

        $pick = (Read-Host "`nSelect a group number (blank to go back)").Trim()
        if (-not $pick) { return }
        if ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $groups.Count) {
            Write-Host "Invalid selection." -ForegroundColor Yellow
            continue
        }
        $group = $groups[[int]$pick - 1]

        $backToList = $false
        while (-not $backToList) {
            Write-Host ""
            Write-Host "=== Group: $($group.Name) ===" -ForegroundColor Cyan
            Write-Host "  1) Members"
            Write-Host "  2) Details"
            Write-Host "  B) Back to group list"
            switch (Read-Host "Choose an option") {
                '1'     { Show-DomainGroupMembers $group }
                '2'     { Show-DomainGroupDetails $group }
                'b'     { $backToList = $true }
                default { Write-Host "Invalid option." -ForegroundColor Yellow }
            }
        }
    }
}

function Show-DomainStaleComputers {
    $days   = Read-Days "Show computers with no logon in how many days?" 90
    $cutoff = (Get-Date).AddDays(-$days)
    $now    = Get-Date

    try {
        $computers = @(Get-ADComputer -Filter * -Server $script:DC -ErrorAction Stop `
                        -Properties LastLogonDate, OperatingSystem, whenCreated, CanonicalName, Description)
    } catch {
        Write-Host "AD query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Never-logged-on computers sort first, then oldest logon; new objects are skipped
    $rows = @($computers |
        Where-Object { $_.whenCreated -lt $cutoff -and (-not $_.LastLogonDate -or $_.LastLogonDate -lt $cutoff) } |
        Sort-Object LastLogonDate, Name |
        ForEach-Object {
            [pscustomobject]@{
                Computer           = $_.Name
                Enabled            = $_.Enabled
                OS                 = $_.OperatingSystem
                'Last Logon'       = if ($_.LastLogonDate) { Format-Date $_.LastLogonDate } else { 'Never' }
                'Days Since Logon' = if ($_.LastLogonDate) { ($now - $_.LastLogonDate).Days } else { 'Never' }
                OU                 = if ($_.CanonicalName) { $_.CanonicalName.Substring(0, $_.CanonicalName.LastIndexOf('/')) } else { '' }
                Description        = $_.Description
            }
        })

    if (-not $rows.Count) {
        Write-Host "`nNo computers without a logon in the last $days days." -ForegroundColor Green
        return
    }

    $enabled = @($rows | Where-Object { $_.Enabled }).Count
    Write-Section "Stale computers: $($rows.Count) with no logon in $days+ days ($enabled still enabled)"
    $rows | Format-Table -AutoSize Computer, Enabled, OS, 'Last Logon', 'Days Since Logon', OU | Out-Host

    if (Read-YesNo "Export to CSV?" -Default $false) { Save-HelpdeskCsv $rows 'StaleComputers' }
}

# ===========================================================================
# Domain functions - Security
# ===========================================================================

function Show-DomainPrivilegedAudit {
    try {
        $domainSid = (Get-ADDomain -Server $script:DC -ErrorAction Stop).DomainSID.Value
    } catch {
        Write-Host "AD query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Looked up by well-known SID so renamed groups are still found
    $privileged = @(
        "$domainSid-512",   # Domain Admins
        "$domainSid-519",   # Enterprise Admins (forest root domain only)
        "$domainSid-518",   # Schema Admins (forest root domain only)
        'S-1-5-32-544',     # Administrators
        'S-1-5-32-548',     # Account Operators
        'S-1-5-32-549',     # Server Operators
        'S-1-5-32-550',     # Print Operators
        'S-1-5-32-551',     # Backup Operators
        "$domainSid-520"    # Group Policy Creator Owners
    )

    $staleCutoff = (Get-Date).AddDays(-90)
    $allRows = @()

    foreach ($sid in $privileged) {
        try {
            $group = Get-ADGroup -Identity $sid -Server $script:DC -ErrorAction Stop
        } catch {
            continue
        }

        try {
            $direct  = @(Get-ADGroupMember -Identity $group -Server $script:DC -ErrorAction Stop).distinguishedName
            $members = @(Get-ADGroupMember -Identity $group -Recursive -Server $script:DC -ErrorAction Stop)
        } catch {
            Write-Host "`nCould not read members of $($group.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }

        $groupRows = @(foreach ($m in $members | Sort-Object name) {
            $u = $null
            if ($m.objectClass -eq 'user') {
                $u = Get-ADUser -Identity $m.distinguishedName -Server $script:DC `
                        -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires -ErrorAction SilentlyContinue
            }

            $flags = @()
            if ($u) {
                if (-not $u.Enabled)            { $flags += 'Disabled' }
                if ($u.PasswordNeverExpires)    { $flags += 'Password never expires' }
                if (-not $u.LastLogonDate -or $u.LastLogonDate -lt $staleCutoff) { $flags += 'No logon 90+ days' }
            }

            [pscustomobject]@{
                Group               = $group.Name
                Name                = $m.name
                Username            = $m.SamAccountName
                Type                = $m.objectClass
                Membership          = if ($direct -contains $m.distinguishedName) { 'Direct' } else { 'Nested' }
                Enabled             = if ($u) { $u.Enabled } else { '' }
                'Last Logon'        = if ($u) { Format-Date $u.LastLogonDate } else { '' }
                'Password Last Set' = if ($u) { Format-Date $u.PasswordLastSet } else { '' }
                Flags               = $flags -join '; '
            }
        })

        Write-Section "$($group.Name) ($($groupRows.Count))"
        if ($groupRows.Count) {
            $groupRows | Format-Table -AutoSize Name, Username, Type, Membership, Enabled, 'Last Logon', Flags | Out-Host
        } else {
            Write-Host "  (no members)"
        }
        $allRows += $groupRows
    }

    $userRows = @($allRows | Where-Object { $_.Type -eq 'user' })
    $unique   = @($userRows.Username | Sort-Object -Unique)
    $flagged  = @($userRows | Where-Object { $_.Flags } | ForEach-Object { $_.Username } | Sort-Object -Unique)

    Write-Host ""
    Write-Row 'Privileged accounts' $unique.Count
    Write-Row 'Accounts with flags' $flagged.Count (& { if ($flagged.Count) { 'Yellow' } })

    if ($allRows.Count -and (Read-YesNo "Export to CSV?" -Default $false)) { Save-HelpdeskCsv $allRows 'PrivilegedGroups' }
}

function Show-DomainLockouts {
    Write-Host "`nReading lockout events (4740) from $($script:DC)..." -ForegroundColor Cyan
    try {
        $events = @(Get-WinEvent -ComputerName $script:DC -ErrorAction Stop -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4740
            StartTime = (Get-Date).AddHours(-24)
        })
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Write-Host "No lockouts in the last 24 hours." -ForegroundColor Green
        } else {
            Write-Host "Could not read the Security log on $($script:DC): $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "This requires admin rights or membership in Event Log Readers on the DC." -ForegroundColor Red
        }
        return
    }

    # Event 4740: property 0 = locked account, property 1 = computer the bad attempts came from
    $rows = @($events | ForEach-Object {
        [pscustomobject]@{
            Time              = $_.TimeCreated.ToString('dd-MMM-yyyy hh:mm:ss tt')
            User              = $_.Properties[0].Value
            'Source Computer' = if ($_.Properties[1].Value) { $_.Properties[1].Value } else { '(not reported)' }
        }
    })

    Write-Section "Lockouts in the last 24 hours ($($rows.Count))"
    $rows | Format-Table -AutoSize | Out-Host

    Write-Section 'By user'
    $rows | Group-Object User | Sort-Object Count -Descending | ForEach-Object {
        [pscustomobject]@{
            User     = $_.Name
            Lockouts = $_.Count
            Sources  = ($_.Group.'Source Computer' | Sort-Object -Unique) -join ', '
        }
    } | Format-Table -AutoSize | Out-Host
}

function Format-PolicySpan {
    param($Span, [string]$Unit, [string]$ZeroText)
    if (-not $Span -or $Span.Ticks -eq 0 -or $Span.TotalDays -gt 36500) { return $ZeroText }
    if ($Unit -eq 'days') { "$([math]::Round($Span.TotalDays)) days" } else { "$([math]::Round($Span.TotalMinutes)) minutes" }
}

function Write-PolicyRows {
    param($Policy)
    Write-Row 'Minimum length'         "$($Policy.MinPasswordLength) characters"
    Write-Row 'Complexity required'    $Policy.ComplexityEnabled
    Write-Row 'Password history'       "$($Policy.PasswordHistoryCount) passwords remembered"
    Write-Row 'Maximum age'            (Format-PolicySpan $Policy.MaxPasswordAge 'days' 'Never expires')
    Write-Row 'Minimum age'            (Format-PolicySpan $Policy.MinPasswordAge 'days' 'None')
    Write-Row 'Lockout threshold'      (& { if ($Policy.LockoutThreshold) { "$($Policy.LockoutThreshold) bad attempts" } else { 'Lockout disabled' } })
    Write-Row 'Lockout duration'       (Format-PolicySpan $Policy.LockoutDuration 'minutes' 'Until an admin unlocks')
    Write-Row 'Lockout counter reset'  (Format-PolicySpan $Policy.LockoutObservationWindow 'minutes' '-')
    Write-Row 'Reversible encryption'  $Policy.ReversibleEncryptionEnabled
}

function Show-DomainPasswordPolicies {
    try {
        $default = Get-ADDefaultDomainPasswordPolicy -Server $script:DC -ErrorAction Stop
        Write-Section 'Default domain policy'
        Write-PolicyRows $default
    } catch {
        Write-Host "Could not read the default policy: $($_.Exception.Message)" -ForegroundColor Red
    }

    try {
        $fgpps = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $script:DC -ErrorAction Stop | Sort-Object Precedence)
    } catch {
        Write-Host "`nCould not read fine-grained policies (needs admin rights): $($_.Exception.Message)" -ForegroundColor Yellow
        return
    }

    if (-not $fgpps.Count) {
        Write-Host "`nNo fine-grained password policies are defined." -ForegroundColor Green
        return
    }

    foreach ($p in $fgpps) {
        Write-Section "Fine-grained policy: $($p.Name) (precedence $($p.Precedence))"
        $appliesTo = @($p.AppliesTo | ForEach-Object { Get-NameFromDN $_ })
        Write-Row 'Applies to' (& { if ($appliesTo.Count) { $appliesTo -join ', ' } else { '(nobody)' } })
        Write-PolicyRows $p
    }
    Write-Host "`nWhen several policies apply to a user, the lowest precedence number wins." -ForegroundColor DarkGray
}

function Show-DomainExpiringPasswords {
    $days  = Read-Days "Show passwords expiring within how many days?" 14
    $now   = Get-Date
    $limit = $now.AddDays($days)

    try {
        $users = @(Get-ADUser -Filter 'Enabled -eq $true -and PasswordNeverExpires -eq $false' -Server $script:DC `
                    -Properties DisplayName, Mail, 'msDS-UserPasswordExpiryTimeComputed' -ErrorAction Stop)
    } catch {
        Write-Host "AD query failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $alreadyExpired = 0
    $rows = @(foreach ($u in $users) {
        $raw = $u.'msDS-UserPasswordExpiryTimeComputed'
        if (-not $raw -or $raw -eq 9223372036854775807) { continue }   # must change at logon, or never expires
        $expires = [datetime]::FromFileTime($raw)
        if ($expires -lt $now) { $alreadyExpired++; continue }
        if ($expires -gt $limit) { continue }

        [pscustomobject]@{
            Name        = $u.DisplayName
            Username    = $u.SamAccountName
            Email       = $u.Mail
            Expires     = Format-Date $expires
            'Days Left' = [math]::Floor(($expires - $now).TotalDays)
        }
    })

    if ($rows.Count) {
        Write-Section "Passwords expiring in the next $days days ($($rows.Count))"
        $rows | Sort-Object 'Days Left', Name | Format-Table -AutoSize | Out-Host
    } else {
        Write-Host "`nNo passwords expire in the next $days days." -ForegroundColor Green
    }
    if ($alreadyExpired) {
        Write-Host "$alreadyExpired enabled user(s) already have an expired password." -ForegroundColor Yellow
    }

    if ($rows.Count -and (Read-YesNo "Export to CSV?" -Default $false)) {
        Save-HelpdeskCsv ($rows | Sort-Object 'Days Left', Name) 'ExpiringPasswords'
    }
}

# ===========================================================================
# Menus
# ===========================================================================

function Read-UserTarget {
    # Prompts for a user; pressing Enter reuses the selected user
    $prompt = if ($script:SelectedUser) {
        "Enter username, UPN, or email [Enter for $($script:SelectedUser.SamAccountName)]"
    } else { "Enter username, UPN, or email" }
    $target = (Read-Host $prompt).Trim()
    if (-not $target -and $script:SelectedUser) { $target = $script:SelectedUser.SamAccountName }
    return $target
}

function Show-UserMenu {
    while ($true) {
        $label = if ($script:SelectedUser) {
            "$($script:SelectedUser.DisplayName) ($($script:SelectedUser.SamAccountName))"
        } else { 'none' }

        Write-Host ""
        Write-Host "=== User Functions ===  Selected user: $label" -ForegroundColor Cyan
        Write-Host "  1) Quick lookup"
        Write-Host "  2) Full report"
        Write-Host "  3) Unlock account"
        Write-Host "  4) Reset password"
        Write-Host "  5) All users report"
        Write-Host "  B) Back"
        $selection = Read-Host "Choose an option"

        switch ($selection) {
            { $_ -in '1', '2' } {
                $target = Read-UserTarget
                if (-not $target) { break }
                $found = Find-HelpdeskUser $target
                if ($found) {
                    $script:SelectedUser = $found
                    if ($_ -eq '1') { Show-HelpdeskUserSummary $found } else { Show-HelpdeskUserReport $found }
                }
                break
            }
            { $_ -in '3', '4' } {
                if (-not $script:SelectedUser) {
                    Write-Host "Look up a user first (option 1 or 2)." -ForegroundColor Yellow
                    break
                }
                # Re-read before acting so lockout/expiry state is current
                $fresh = Find-HelpdeskUser $script:SelectedUser.SamAccountName
                if (-not $fresh) { break }
                $script:SelectedUser = $fresh
                if ($_ -eq '3') { Unlock-HelpdeskUser $fresh } else { Reset-HelpdeskPassword $fresh }
                break
            }
            '5' { Show-HelpdeskAllUsersReport }
            'b' { return }
            default { Write-Host "Invalid option." -ForegroundColor Yellow }
        }
    }
}

function Read-ComputerTarget {
    # Prompts for a hostname; pressing Enter reuses the selected computer
    $prompt = if ($script:SelectedComputer) {
        "Enter hostname or IP [Enter for $($script:SelectedComputer)]"
    } else { "Enter hostname or IP" }
    $target = (Read-Host $prompt).Trim()
    if (-not $target) { $target = $script:SelectedComputer }
    return $target
}

function Show-MachineMenu {
    while ($true) {
        $label = if ($script:SelectedComputer) { $script:SelectedComputer } else { 'none' }

        Write-Host ""
        Write-Host "=== Machine Functions ===  Selected computer: $label" -ForegroundColor Cyan
        Write-Host "  1) Quick lookup"
        Write-Host "  2) Full report"
        Write-Host "  3) Search installed software"
        Write-Host "  4) Fleet model report (all PCs)"
        Write-Host "  B) Back"
        $selection = Read-Host "Choose an option"

        switch ($selection) {
            '1' {
                $target = Read-ComputerTarget
                if ($target -and (Show-HelpdeskComputerSummary $target)) {
                    $script:SelectedComputer = $target
                }
            }
            '2' {
                $target = Read-ComputerTarget
                if ($target -and (Show-HelpdeskComputerReport $target)) {
                    $script:SelectedComputer = $target
                }
            }
            '3' {
                $target = Read-ComputerTarget
                if ($target -and (Search-HelpdeskSoftware $target)) {
                    $script:SelectedComputer = $target
                }
            }
            '4' { Show-HelpdeskFleetModelReport }
            'b' { return }
            default { Write-Host "Invalid option." -ForegroundColor Yellow }
        }
    }
}

function Show-DomainStructureMenu {
    while ($true) {
        Write-Host ""
        Write-Host "=== Domain > Structure & Inventory ===" -ForegroundColor Cyan
        Write-Host "  1) OU tree"
        Write-Host "  2) Groups"
        Write-Host "  3) Stale computer objects"
        Write-Host "  B) Back"
        switch (Read-Host "Choose an option") {
            '1'     { Show-DomainOuTree }
            '2'     { Show-DomainGroupBrowser }
            '3'     { Show-DomainStaleComputers }
            'b'     { return }
            default { Write-Host "Invalid option." -ForegroundColor Yellow }
        }
    }
}

function Show-DomainSecurityMenu {
    while ($true) {
        Write-Host ""
        Write-Host "=== Domain > Security ===" -ForegroundColor Cyan
        Write-Host "  1) Privileged group audit"
        Write-Host "  2) Lockouts (last 24 hours)"
        Write-Host "  3) Password policies"
        Write-Host "  4) Passwords expiring soon"
        Write-Host "  B) Back"
        switch (Read-Host "Choose an option") {
            '1'     { Show-DomainPrivilegedAudit }
            '2'     { Show-DomainLockouts }
            '3'     { Show-DomainPasswordPolicies }
            '4'     { Show-DomainExpiringPasswords }
            'b'     { return }
            default { Write-Host "Invalid option." -ForegroundColor Yellow }
        }
    }
}

function Show-DomainMenu {
    while ($true) {
        Write-Host ""
        Write-Host "=== Domain Functions ===" -ForegroundColor Cyan
        Write-Host "  1) Structure & inventory"
        Write-Host "  2) Security"
        Write-Host "  B) Back"
        switch (Read-Host "Choose an option") {
            '1'     { Show-DomainStructureMenu }
            '2'     { Show-DomainSecurityMenu }
            'b'     { return }
            default { Write-Host "Invalid option." -ForegroundColor Yellow }
        }
    }
}

# ===========================================================================
# Main
# ===========================================================================

# Optional shortcuts: .\HelpdeskMultitool.ps1 jsmith   or   -ComputerName PC01
if ($Username) {
    $script:SelectedUser = Find-HelpdeskUser $Username
    if ($script:SelectedUser) { Show-HelpdeskUserSummary $script:SelectedUser }
    Show-UserMenu
} elseif ($ComputerName) {
    if (Show-HelpdeskComputerSummary $ComputerName) { $script:SelectedComputer = $ComputerName.Trim() }
    Show-MachineMenu
}

while ($true) {
    Write-Host ""
    Write-Host "=== Helpdesk Multitool ===" -ForegroundColor Cyan
    Write-Host "  1) User functions"
    Write-Host "  2) Machine functions"
    Write-Host "  3) Domain functions"
    Write-Host "  Q) Quit"
    $selection = Read-Host "Choose an option"

    switch ($selection) {
        '1' { Show-UserMenu }
        '2' { Show-MachineMenu }
        '3' { Show-DomainMenu }
        'q' { return }
        default { Write-Host "Invalid option." -ForegroundColor Yellow }
    }
}