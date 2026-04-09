# PowerShell GUI for AD Contractor Account Management
# Deploy via Intune as .ps1
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    [System.Windows.Forms.MessageBox]::Show("ActiveDirectory module is not installed. Please install RSAT AD tools.", "Missing Module")
    return
}

# Load configuration from config.json
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $scriptDir "config.json"

if (-not (Test-Path $configPath)) {
    [System.Windows.Forms.MessageBox]::Show(
        "config.json not found in script directory.`n`nCopy config.example.json to config.json and fill in your AD values.",
        "Missing Configuration",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    return
}

try {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
} catch {
    [System.Windows.Forms.MessageBox]::Show("Failed to parse config.json: $($_.Exception.Message)", "Config Error")
    return
}

# Security groups for role-based access control (from config)
$SECURITY_GROUPS = @{
    SuperAdmin        = $config.SecurityGroups.SuperAdmin
    HelpDesk          = $config.SecurityGroups.HelpDesk
    ContractorManager = $config.SecurityGroups.ContractorManager
}

# OUs to search for user accounts (from config)
$SEARCH_BASE_OUs = @($config.SearchBaseOUs)

# App title (from config)
$APP_TITLE = $config.AppTitle

# Contractor identification logic
# Contractors are identified by:
# 1. Having an expiration date set (accountExpires > 0 and < max value)
# 2. OR having "Contractor" in their Description field
function Test-IsContractor {
    param($adUser)

    # Check expiration date
    $hasExpiry = $adUser.accountExpires -gt 0 -and $adUser.accountExpires -lt 9223372036854775807

    # Check description
    $hasContractorDesc = $adUser.Description -like "*Contractor*"

    return ($hasExpiry -or $hasContractorDesc)
}

$logDir  = Join-Path $env:ProgramData "ADAccountManagement"
$logFile = Join-Path $logDir "actions.log"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

# Logging with security levels
function Log-Action {
    param(
        [string]$message,
        [string]$level = "INFO"  # INFO, WARNING, ERROR, SECURITY
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $who = "$($env:USERNAME)@$($env:USERDOMAIN)"
    $computer = $env:COMPUTERNAME
    Add-Content -Path $logFile -Value "$timestamp [$level] [$who] [$computer] - $message"
}

# Check current user's role based on AD security group membership
function Get-UserRole {
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        # Get current user's AD groups
        $userGroups = @()
        try {
            $adUser = Get-ADUser -Identity $currentUser.Split('\')[1] -Properties MemberOf
            $userGroups = $adUser.MemberOf | ForEach-Object {
                (Get-ADGroup -Identity $_).Name
            }
        } catch {
            Log-Action "ERROR: Could not retrieve AD groups for $currentUser - $($_.Exception.Message)" -level "ERROR"
            return "None"
        }

        # Check in order of highest privilege first
        if ($userGroups -contains $SECURITY_GROUPS.SuperAdmin) {
            Log-Action "User authenticated as SuperAdmin (Member of: $($SECURITY_GROUPS.SuperAdmin))" -level "SECURITY"
            return "SuperAdmin"
        }

        if ($userGroups -contains $SECURITY_GROUPS.HelpDesk) {
            Log-Action "User authenticated as HelpDesk (Member of: $($SECURITY_GROUPS.HelpDesk))" -level "SECURITY"
            return "HelpDesk"
        }

        if ($userGroups -contains $SECURITY_GROUPS.ContractorManager) {
            Log-Action "User authenticated as ContractorManager (Member of: $($SECURITY_GROUPS.ContractorManager))" -level "SECURITY"
            return "ContractorManager"
        }

        Log-Action "User $currentUser has no authorized role - ACCESS DENIED. User groups: $($userGroups -join ', ')" -level "SECURITY"
        return "None"
    } catch {
        Log-Action "Error checking user role: $($_.Exception.Message)" -level "ERROR"
        return "None"
    }
}

# Validate if user can modify a specific account based on their role
function Test-CanModifyAccount {
    param(
        [string]$samAccountName,
        [string]$userRole
    )

    try {
        # SuperAdmin can modify anyone
        if ($userRole -eq "SuperAdmin") {
            return @{Allowed=$true; Reason="SuperAdmin access"}
        }

        # Get the target account details
        $targetUser = Get-ADUser -Identity $samAccountName -Properties adminCount,memberOf,DistinguishedName,Description,accountExpires -ErrorAction Stop

        # Block modification of admin accounts (adminCount=1)
        if ($targetUser.adminCount -eq 1) {
            Log-Action "DENIED: Attempted to modify protected admin account: $samAccountName" -level "SECURITY"
            return @{Allowed=$false; Reason="Cannot modify protected administrator accounts"}
        }

        # Block modification of high-privilege groups
        $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
        foreach ($group in $privilegedGroups) {
            if ($targetUser.memberOf -match $group) {
                Log-Action "DENIED: Attempted to modify privileged group member: $samAccountName" -level "SECURITY"
                return @{Allowed=$false; Reason="Cannot modify accounts in privileged groups"}
            }
        }

        # ContractorManager: Can only modify contractor accounts
        if ($userRole -eq "ContractorManager") {
            $isContractor = Test-IsContractor -adUser $targetUser
            if ($isContractor) {
                return @{Allowed=$true; Reason="Contractor account (expiry set or 'Contractor' in description)"}
            } else {
                Log-Action "DENIED: ContractorManager attempted to modify non-contractor: $samAccountName" -level "SECURITY"
                return @{Allowed=$false; Reason="You can only modify contractor accounts (accounts with expiry dates or 'Contractor' in description)"}
            }
        }

        # HelpDesk: Can modify any non-admin account
        if ($userRole -eq "HelpDesk") {
            return @{Allowed=$true; Reason="HelpDesk access to non-privileged account"}
        }

        # Default deny
        return @{Allowed=$false; Reason="Insufficient permissions"}

    } catch {
        Log-Action "ERROR: Permission check failed for $samAccountName : $($_.Exception.Message)" -level "ERROR"
        return @{Allowed=$false; Reason="Error checking permissions"}
    }
}

# Sanitize search input to prevent LDAP injection
function Sanitize-LDAPInput {
    param([string]$input)
    # Remove LDAP special characters
    $input = $input -replace '[()&|=!<>~*/\\]', ''
    # Limit length
    if ($input.Length -gt 50) { $input = $input.Substring(0,50) }
    return $input.Trim()
}

# Convert AD accountExpires value to DateTime
function Convert-Expiry {
    param([object]$accountExpires)
    try {
        if ($null -eq $accountExpires) { return $null }
        # 0 or 9223372036854775807 = Never
        if ([int64]$accountExpires -eq 0 -or [int64]$accountExpires -eq 9223372036854775807) { return $null }
        return [DateTime]::FromFileTimeUtc([int64]$accountExpires).ToLocalTime()
    } catch { return $null }
}

# Search for contractor accounts across configured OUs
function Get-ExpiringUsers {
    param(
        [string]$term,
        [string]$userRole
    )

    # Sanitize input
    $term = Sanitize-LDAPInput -input $term

    # Build filter: contractors have expiry date set OR "Contractor" in description
    if ($term -eq "") {
        $filter = "(accountExpires -gt 0 -and accountExpires -lt 9223372036854775807) -or (Description -like '*Contractor*')"
    } else {
        $filter = "((accountExpires -gt 0 -and accountExpires -lt 9223372036854775807) -or (Description -like '*Contractor*')) -and (Name -like '*$term*' -or SamAccountName -like '*$term*')"
    }

    $allUsers = @()

    try {
        # Search across all configured OUs
        foreach ($ouBase in $SEARCH_BASE_OUs) {
            try {
                $ouUsers = Get-ADUser -Filter $filter -SearchBase $ouBase -Properties accountExpires,displayName,samAccountName,enabled,Description,adminCount,memberOf -ErrorAction Stop
                $allUsers += $ouUsers
            } catch {
                Log-Action "WARNING: Could not search OU: $ouBase - $($_.Exception.Message)" -level "WARNING"
            }
        }

        # Remove duplicates
        $allUsers = $allUsers | Sort-Object -Property samAccountName -Unique

        # Filter out disabled accounts
        $allUsers = $allUsers | Where-Object { $_.Enabled -eq $true }

        # Role-based filtering
        if ($userRole -eq "ContractorManager") {
            $allUsers = $allUsers | Where-Object { Test-IsContractor -adUser $_ }
        }

        # Filter out admin accounts for non-SuperAdmin roles
        if ($userRole -ne "SuperAdmin") {
            $allUsers = $allUsers | Where-Object {
                $_.adminCount -ne 1 -and
                -not ($_.memberOf -match "Domain Admins") -and
                -not ($_.memberOf -match "Enterprise Admins") -and
                -not ($_.memberOf -match "Schema Admins")
            }
        }

        Log-Action "SEARCH: Query for '$term' returned $($allUsers.Count) results (Role: $userRole)" -level "INFO"
        return $allUsers

    } catch {
        Log-Action "ERROR: Search failed for '$term' - $($_.Exception.Message)" -level "ERROR"
        throw $_
    }
}

# Match text input to combo box item and select it
function Select-UserByText {
    $text = $searchCombo.Text.Trim()
    if ($text -eq "") { return }

    $matchedItem = $searchCombo.Items | Where-Object {
        $_.Display -eq $text -or $_.Sam -eq $text
    } | Select-Object -First 1

    if ($matchedItem) {
        $searchCombo.SelectedItem = $matchedItem
    }
}

# Check user role at startup - exit if unauthorized
$script:userRole = Get-UserRole
if ($script:userRole -eq "None") {
    [System.Windows.Forms.MessageBox]::Show(
        "You do not have permission to use this application.`n`nRequired Security Groups:`n• $($SECURITY_GROUPS.SuperAdmin)`n• $($SECURITY_GROUPS.HelpDesk)`n• $($SECURITY_GROUPS.ContractorManager)`n`nContact your IT administrator for access.",
        "Access Denied",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Error
    )
    exit
}

# --- GUI ---

$form = New-Object System.Windows.Forms.Form
$form.Text = "$APP_TITLE - $($script:userRole) Mode"
$form.Size = New-Object System.Drawing.Size(520,400)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Role indicator
$lblRole = New-Object System.Windows.Forms.Label
$lblRole.Text = "Access Level: $($script:userRole)"
$lblRole.Location = New-Object System.Drawing.Point(320,0)
$lblRole.AutoSize = $true
$lblRole.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$lblRole.ForeColor = [System.Drawing.Color]::DarkGreen
$form.Controls.Add($lblRole)

$lblSearch = New-Object System.Windows.Forms.Label
$lblSearch.Text = "Search User:"
$lblSearch.Location = New-Object System.Drawing.Point(20,20)
$lblSearch.AutoSize = $true
$form.Controls.Add($lblSearch)

# Dropdown
$searchCombo = New-Object System.Windows.Forms.ComboBox
$searchCombo.Location = New-Object System.Drawing.Point(120,16)
$searchCombo.Width = 250
$searchCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown
$searchCombo.AutoCompleteMode = [System.Windows.Forms.AutoCompleteMode]::SuggestAppend
$searchCombo.AutoCompleteSource = [System.Windows.Forms.AutoCompleteSource]::CustomSource
$searchCombo.DisplayMember = "Display"
$searchCombo.ValueMember   = "Sam"
$form.Controls.Add($searchCombo)

# Show All button
$btnShowAll = New-Object System.Windows.Forms.Button
$btnShowAll.Text = "Show All"
$btnShowAll.Location = New-Object System.Drawing.Point(380,15)
$btnShowAll.Width = 70
$btnShowAll.Height = 25
$form.Controls.Add($btnShowAll)

# User info panel
$userInfo = New-Object System.Windows.Forms.Label
$userInfo.Text = "Selected: (none)"
$userInfo.Location = New-Object System.Drawing.Point(20,55)
$userInfo.Size = New-Object System.Drawing.Size(470,60)
$userInfo.AutoSize = $false
$userInfo.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$userInfo.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)
$userInfo.Padding = New-Object System.Windows.Forms.Padding(5)
$form.Controls.Add($userInfo)

# Date picker label
$lblExpiry = New-Object System.Windows.Forms.Label
$lblExpiry.Text = "New Expiry:"
$lblExpiry.Location = New-Object System.Drawing.Point(20,128)
$lblExpiry.AutoSize = $true
$form.Controls.Add($lblExpiry)

# Date picker
$datePicker = New-Object System.Windows.Forms.DateTimePicker
$datePicker.Location = New-Object System.Drawing.Point(120,125)
$datePicker.Width = 320
$datePicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
$datePicker.CustomFormat = "dddd, MMMM dd, yyyy"
$form.Controls.Add($datePicker)

# Update Expiry button
$btnUpdate = New-Object System.Windows.Forms.Button
$btnUpdate.Text = "Update Expiry"
$btnUpdate.Location = New-Object System.Drawing.Point(120,170)
$btnUpdate.Width = 150
$form.Controls.Add($btnUpdate)

# Disable Account button
$btnDisable = New-Object System.Windows.Forms.Button
$btnDisable.Text = "Disable Account"
$btnDisable.Location = New-Object System.Drawing.Point(290,170)
$btnDisable.Width = 150
$form.Controls.Add($btnDisable)

# Status label
$status = New-Object System.Windows.Forms.Label
$status.Text = "Ready - $($script:userRole) access level"
$status.Location = New-Object System.Drawing.Point(20,210)
$status.AutoSize = $true
$form.Controls.Add($status)

# Total contractors counter
$lblTotalContractors = New-Object System.Windows.Forms.Label
$lblTotalContractors.Text = "Total Contractors: Loading..."
$lblTotalContractors.Location = New-Object System.Drawing.Point(20,240)
$lblTotalContractors.AutoSize = $true
$lblTotalContractors.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblTotalContractors.ForeColor = [System.Drawing.Color]::DarkBlue
$form.Controls.Add($lblTotalContractors)

# State
$script:currentSam = $null
$script:currentExpiry = $null
$script:totalContractors = 0
$script:lastSearchTerm = ""

# Load total contractors count on startup
$form.Add_Shown({
    $form.Activate()
    try {
        $allContractors = Get-ExpiringUsers -term "" -userRole $script:userRole
        $script:totalContractors = $allContractors.Count
        $lblTotalContractors.Text = "Total Contractors: $($script:totalContractors)"
    } catch {
        $lblTotalContractors.Text = "Total Contractors: Unable to load"
    }
})

# Debounced search timer (300ms delay to avoid query per keystroke)
$searchTimer = New-Object System.Windows.Forms.Timer
$searchTimer.Interval = 300
$searchTimer.Add_Tick({
    $searchTimer.Stop()
    $term = $searchCombo.Text.Trim()

    # Skip re-search if text matches current selection
    if ($script:currentSam -and $searchCombo.SelectedItem -and $searchCombo.SelectedItem.Display -eq $term) {
        return
    }

    $script:lastSearchTerm = $term

    $searchCombo.Items.Clear()
    $auto = New-Object System.Windows.Forms.AutoCompleteStringCollection
    if ($term.Length -ge 2) {
        try {
            $users = Get-ExpiringUsers -term $term -userRole $script:userRole

            foreach ($u in $users) {
                $expiry = Convert-Expiry $u.accountExpires
                $disp = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
                $displayText = "$disp ($($u.SamAccountName))"
                $item = New-Object PSObject -Property @{
                    Display = $displayText
                    Sam     = $u.SamAccountName
                    Expiry  = $expiry
                    Description = $u.Description
                }
                [void]$searchCombo.Items.Add($item)
                [void]$auto.Add($displayText)
            }
            $searchCombo.AutoCompleteCustomSource = $auto

            if ($users.Count -eq 0) {
                $status.Text = "No users found matching '$script:lastSearchTerm'."
            } elseif ($users.Count -eq 1) {
                $matchedName = $users[0].DisplayName
                $status.Text = "Found 1 user: $matchedName. Press Enter or click to select."
            } else {
                $matchedNames = ($users | ForEach-Object { $_.DisplayName }) -join ", "
                $status.Text = "Found $($users.Count) users: $matchedNames"
            }
        } catch {
            $status.Text = "AD query failed. Check logs."
            Log-Action "ERROR: Search failed - $($_.Exception.Message)" -level "ERROR"
            [System.Windows.Forms.MessageBox]::Show("Unable to search Active Directory. Contact IT support.", "Search Error")
        }
    } else {
        $status.Text = "Type at least 2 characters to search."
    }
})

# Restart search timer on text change
$searchCombo.Add_TextChanged({
    $searchTimer.Stop()
    $searchTimer.Start()
})

# Handle Enter key to select autocompleted user
$searchCombo.Add_KeyDown({
    param($sender, $e)
    if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Return -or $e.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $e.SuppressKeyPress = $true
        Select-UserByText
    }
})

# When user leaves the textbox, try to select matching item
$searchCombo.Add_Leave({
    Select-UserByText
})

# Show All button
$btnShowAll.Add_Click({
    $searchCombo.Items.Clear()
    $searchCombo.Text = ""
    $auto = New-Object System.Windows.Forms.AutoCompleteStringCollection
    try {
        $status.Text = "Loading all users..."
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor

        $users = Get-ExpiringUsers -term "" -userRole $script:userRole

        foreach ($u in $users) {
            $expiry = Convert-Expiry $u.accountExpires
            $disp = if ($u.DisplayName) { $u.DisplayName } else { $u.SamAccountName }
            $displayText = "$disp ($($u.SamAccountName))"
            $item = New-Object PSObject -Property @{
                Display = $displayText
                Sam     = $u.SamAccountName
                Expiry  = $expiry
                Description = $u.Description
            }
            [void]$searchCombo.Items.Add($item)
            [void]$auto.Add($displayText)
        }
        $searchCombo.AutoCompleteCustomSource = $auto
        $status.Text = "Loaded $($users.Count) contractor(s). Select from dropdown."
    } catch {
        $status.Text = "Failed to load users. Check logs."
        Log-Action "ERROR: Show All failed - $($_.Exception.Message)" -level "ERROR"
        [System.Windows.Forms.MessageBox]::Show("Unable to load users. Contact IT support.", "Load Error")
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
})

# Handle user selection from dropdown
$searchCombo.Add_SelectedIndexChanged({
    if ($searchCombo.SelectedItem -and ($searchCombo.SelectedItem.PSObject.Properties.Name -contains "Sam")) {
        $item = $searchCombo.SelectedItem
        $script:currentSam    = $item.Sam
        $script:currentExpiry = $item.Expiry

        $infoText = "Selected: $($item.Display)"

        if ($item.Description -and $item.Description.Trim() -ne "") {
            $infoText += "`nDescription: $($item.Description)"
        } else {
            $infoText += "`nDescription: (none)"
        }

        if ($script:currentExpiry) {
            $infoText += "`nCurrent Expiry: $($script:currentExpiry.ToString('dddd, MMMM dd, yyyy'))"
            $datePicker.Value = $script:currentExpiry
            $status.Text = "User selected. Ready to update expiry."
        } else {
            $infoText += "`nCurrent Expiry: Not set"
            $datePicker.Value = Get-Date
            $status.Text = "User selected. No expiry date found."
        }

        $userInfo.Text = $infoText
    } else {
        $status.Text = "Please select a valid user from the list."
    }
})

# Update Expiry button handler
$btnUpdate.Add_Click({
    if (-not $script:currentSam) {
        [System.Windows.Forms.MessageBox]::Show("Please select a user from the dropdown.", "No User Selected")
        return
    }

    $permCheck = Test-CanModifyAccount -samAccountName $script:currentSam -userRole $script:userRole
    if (-not $permCheck.Allowed) {
        [System.Windows.Forms.MessageBox]::Show(
            "Access Denied: $($permCheck.Reason)",
            "Insufficient Permissions",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        Log-Action "DENIED: Update expiry for $($script:currentSam) - $($permCheck.Reason)" -level "SECURITY"
        return
    }

    $newDate = $datePicker.Value
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Update expiry for ${script:currentSam} to $($newDate.ToString('yyyy-MM-dd'))?",
        "Confirm Update",
        [System.Windows.Forms.MessageBoxButtons]::YesNo
    )
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    try {
        Set-ADAccountExpiration -Identity $script:currentSam -DateTime $newDate
        [System.Windows.Forms.MessageBox]::Show("Expiry updated for ${script:currentSam} to $($newDate.ToString('yyyy-MM-dd')).", "Success")
        Log-Action "SUCCESS: Updated expiry for ${script:currentSam} to $($newDate.ToString('yyyy-MM-dd')) - $($permCheck.Reason)" -level "INFO"
        $status.Text = "Expiry updated."
    } catch {
        Log-Action "FAILED: Update expiry for ${script:currentSam} - $($_.Exception.Message)" -level "ERROR"
        [System.Windows.Forms.MessageBox]::Show("Failed to update expiry. Contact IT support if this persists.", "Error")
        $status.Text = "Failed to update expiry."
    }
})

# Disable Account button handler
$btnDisable.Add_Click({
    if (-not $script:currentSam) {
        [System.Windows.Forms.MessageBox]::Show("Please select a user from the dropdown.", "No User Selected")
        return
    }

    $permCheck = Test-CanModifyAccount -samAccountName $script:currentSam -userRole $script:userRole
    if (-not $permCheck.Allowed) {
        [System.Windows.Forms.MessageBox]::Show(
            "Access Denied: $($permCheck.Reason)",
            "Insufficient Permissions",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        Log-Action "DENIED: Disable account $($script:currentSam) - $($permCheck.Reason)" -level "SECURITY"
        return
    }

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Disable account ${script:currentSam}?",
        "Confirm Disable",
        [System.Windows.Forms.MessageBoxButtons]::YesNo
    )
    if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

    try {
        Disable-ADAccount -Identity $script:currentSam
        [System.Windows.Forms.MessageBox]::Show("Account disabled: ${script:currentSam}.", "Success")
        Log-Action "SUCCESS: Disabled account ${script:currentSam} - $($permCheck.Reason)" -level "INFO"
        $status.Text = "Account disabled."
    } catch {
        Log-Action "FAILED: Disable account ${script:currentSam} - $($_.Exception.Message)" -level "ERROR"
        [System.Windows.Forms.MessageBox]::Show("Failed to disable account. Contact IT support if this persists.", "Error")
        $status.Text = "Failed to disable account."
    }
})

# Show form
[void]$form.ShowDialog()
