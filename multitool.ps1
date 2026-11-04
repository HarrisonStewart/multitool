param (
    [Parameter(Position = 0)]
    [string]$Username
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "The Active Directory module is not installed. Install RSAT with:" -ForegroundColor Red
    Write-Host "  Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Red
    return
}

Import-Module ActiveDirectory

# All reads and writes go to the PDC Emulator, which always has current lockout data
try {
    $script:DC = (Get-ADDomain -ErrorAction Stop).PDCEmulator
} catch {
    Write-Host "Could not contact the domain: $($_.Exception.Message)" -ForegroundColor Red
    return
}

$script:UserProps = @(
    'DisplayName', 'Mail', 'Enabled', 'LockedOut', 'AccountLockoutTime',
    'BadLogonCount', 'LastBadPasswordAttempt', 'PasswordExpired', 'PasswordLastSet',
    'PasswordNeverExpires', 'msDS-UserPasswordExpiryTimeComputed',
    'LastLogonDate', 'AccountExpirationDate'
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

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
    foreach ($key in $rows.Keys) {
        Write-Host ("{0,-22}{1}" -f "$($key):", $rows[$key])
    }
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

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

$selectedUser = $null

if ($Username) {
    $selectedUser = Find-HelpdeskUser $Username
    if ($selectedUser) { Show-HelpdeskUserStatus $selectedUser }
}

while ($true) {
    $label = if ($selectedUser) { "$($selectedUser.DisplayName) ($($selectedUser.SamAccountName))" } else { 'none' }

    Write-Host ""
    Write-Host "=== Helpdesk Multitool ===  Selected user: $label" -ForegroundColor Cyan
    Write-Host "  1) Look up user"
    Write-Host "  2) Refresh status"
    Write-Host "  3) Unlock account"
    Write-Host "  4) Reset password"
    Write-Host "  Q) Quit"
    $selection = Read-Host "Choose an option"

    switch ($selection) {
        '1' {
            $lookup = Read-Host "Enter username, UPN, or email"
            $found  = Find-HelpdeskUser $lookup
            if ($found) {
                $selectedUser = $found
                Show-HelpdeskUserStatus $selectedUser
            }
        }
        { $_ -in '2', '3', '4' -and -not $selectedUser } {
            Write-Host "Look up a user first (option 1)." -ForegroundColor Yellow
            break
        }
        '2' {
            $selectedUser = Find-HelpdeskUser $selectedUser.SamAccountName
            if ($selectedUser) { Show-HelpdeskUserStatus $selectedUser }
        }
        '3' {
            Unlock-HelpdeskUser $selectedUser
            $selectedUser = Find-HelpdeskUser $selectedUser.SamAccountName
        }
        '4' {
            Reset-HelpdeskPassword $selectedUser
            $selectedUser = Find-HelpdeskUser $selectedUser.SamAccountName
        }
        'q' { return }
        default { Write-Host "Invalid option." -ForegroundColor Yellow }
    }
}