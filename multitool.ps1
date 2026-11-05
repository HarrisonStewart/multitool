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
    'LastLogonDate', 'AccountExpirationDate'
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

function Show-HelpdeskUserStatus {
    param($User)

    $rows = [ordered]@{
        'Lookup time'          = Get-Date -Format 'dd-MMM-yyyy hh:mm:ss tt'
        'Name'                 = $User.DisplayName
        'Username'             = $User.SamAccountName
        'UPN'                  = $User.UserPrincipalName
        'Email'                = $User.Mail
        'Enabled'              = $User.Enabled
        'Locked out'           = $User.LockedOut
        'Lockout time'         = $User.AccountLockoutTime
        'Bad password count'   = $User.BadLogonCount
        'Last bad password'    = $User.LastBadPasswordAttempt
        'Password expired'     = $User.PasswordExpired
        'Password last set'    = $User.PasswordLastSet
        'Password expires'     = Get-PasswordExpiryText $User
        'Account expires'      = if ($User.AccountExpirationDate) { $User.AccountExpirationDate } else { 'Never' }
        'Last logon (approx)'  = $User.LastLogonDate
    }

    Write-Host "`n------------------------------------------------"
    foreach ($key in $rows.Keys) { Write-Row $key $rows[$key] }
    Write-Host "------------------------------------------------"

    # Flag conditions an unlock or reset won't fix
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

# ===========================================================================
# Menus
# ===========================================================================

function Show-UserMenu {
    while ($true) {
        $label = if ($script:SelectedUser) {
            "$($script:SelectedUser.DisplayName) ($($script:SelectedUser.SamAccountName))"
        } else { 'none' }

        Write-Host ""
        Write-Host "=== User Functions ===  Selected user: $label" -ForegroundColor Cyan
        Write-Host "  1) Look up user"
        Write-Host "  2) Refresh status"
        Write-Host "  3) Unlock account"
        Write-Host "  4) Reset password"
        Write-Host "  B) Back"
        $selection = Read-Host "Choose an option"

        switch ($selection) {
            '1' {
                $lookup = Read-Host "Enter username, UPN, or email"
                $found  = Find-HelpdeskUser $lookup
                if ($found) {
                    $script:SelectedUser = $found
                    Show-HelpdeskUserStatus $script:SelectedUser
                }
            }
            { $_ -in '2', '3', '4' -and -not $script:SelectedUser } {
                Write-Host "Look up a user first (option 1)." -ForegroundColor Yellow
                break
            }
            '2' {
                $script:SelectedUser = Find-HelpdeskUser $script:SelectedUser.SamAccountName
                if ($script:SelectedUser) { Show-HelpdeskUserStatus $script:SelectedUser }
            }
            '3' {
                Unlock-HelpdeskUser $script:SelectedUser
                $script:SelectedUser = Find-HelpdeskUser $script:SelectedUser.SamAccountName
            }
            '4' {
                Reset-HelpdeskPassword $script:SelectedUser
                $script:SelectedUser = Find-HelpdeskUser $script:SelectedUser.SamAccountName
            }
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
            'b' { return }
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
    if ($script:SelectedUser) { Show-HelpdeskUserStatus $script:SelectedUser }
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
    Write-Host "  Q) Quit"
    $selection = Read-Host "Choose an option"

    switch ($selection) {
        '1' { Show-UserMenu }
        '2' { Show-MachineMenu }
        'q' { return }
        default { Write-Host "Invalid option." -ForegroundColor Yellow }
    }
}