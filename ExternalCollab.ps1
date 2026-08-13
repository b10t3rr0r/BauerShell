#requires -Version 7.2

# External Collaboration Manager 22b555 - Denim Demon
# ------------------------------------
# Copyright (c) 2026 Benny Hult
# Licensed under the BSD 3-Clause License. See LICENSE file in the project root for details.

# Release: 22b555 - compact console plumbing + FullVerbose diagnostics

<#
.SYNOPSIS
Audits and manages Microsoft Entra ID, SharePoint Online, and Microsoft Teams external collaboration settings.

.DESCRIPTION
External Collaboration Manager 22b555 - Denim Demon is the PowerShell 7-native branch of the tool.
Provider-specific Add/Remove commands use least-privilege authentication and touch only the selected provider.
Every domain parameter accepts one or more comma-separated domains. A batch is planned and previewed
in full against a single read-only snapshot before any write is authorized. Graph provider writes replace
the whole domain list, so a batch is applied as one write per provider; Microsoft Teams mutations are
per-domain and are re-planned against a fresh read before each one, because an earlier change can move
the federation mode (BLOCK_ALL becomes ALLOWLIST on the first allowed domain). Rollback unwinds Teams
changes in reverse order and then restores the Graph provider allowlists.

Batch operations plan under read-only scopes and elevate to write scopes only for the providers the
confirmed plan needs. Every Graph provider write re-reads its configuration immediately beforehand,
because the Entra B2B policy and the SharePoint tenant settings are written back as whole documents
and neither endpoint supports optimistic concurrency.
Windows PowerShell compatibility is intentionally not used.

Provider architecture:
- Microsoft Entra ID B2B management policy: Microsoft Graph beta API.
- SharePoint / OneDrive tenant sharing domain settings: Microsoft Graph v1.0 /admin/sharepoint/settings.
- Entra ID #EXT# guest inventory: Microsoft Graph.
- Microsoft Teams External Access: current MicrosoftTeams module loaded natively in PowerShell 7.

The script is audit-first. Read-only operations inspect configuration drift, orphaned guest domains,
guest activity, pending invitations, rogue guest accounts, and Teams federation state. Add/purge operations preview intent,
use safe tenant cross-checks, verify writes with read-back, and attempt rollback on partial failure.

-ReviewUsers implies -Audit and additionally lists guest accounts attached to DRIFT / ORPHANED domains
or domains containing ROGUE guest accounts.

.PARAMETER Audit
Runs the standard cross-provider external collaboration audit. This is the default operation.
Teams ALLOWLIST domains participate directly in drift detection. Teams ALLOW_ALL does not create
missing-domain drift; explicit Teams blocks are surfaced as conflicts.

.PARAMETER ReviewUsers
Runs the normal audit and additionally lists guest accounts attached to DRIFT / ORPHANED domains or
domains containing ROGUE guest accounts. ROGUE means the guest has no recognized Entra invitation state.

.PARAMETER AddDomain
Adds or synchronizes a domain across Entra ID, SharePoint Online, and Microsoft Teams External Access.
Teams behavior is mode-aware: ALLOWLIST adds the domain, ALLOW_ALL removes an explicit block, and
BLOCK_ALL adds the first explicit allowed domain. The script never enables the Teams federation master
switch automatically when External Access is disabled.

.PARAMETER AddEntra
Adds a domain only to the Entra ID B2B allowlist. No SharePoint, Teams, or guest objects are changed.
Only the Entra B2B policy Graph permission is requested for a live write.

.PARAMETER AddSPO
Adds a domain only to the SharePoint / OneDrive tenant sharing allowlist. No Entra B2B, Teams, or guest objects are changed.
Only the SharePoint tenant-settings Graph permission is requested for a live write.

.PARAMETER AddTeams
Adds/effectively allows a domain only in Microsoft Teams External Access. No Graph write permission is requested.
Teams federation mode is honored: ALLOWLIST adds the domain and ALLOW_ALL removes an explicit block.

.PARAMETER RemoveEntra
Removes a domain only from the Entra ID B2B allowlist. Guest objects and other providers are untouched.

.PARAMETER RemoveSPO
Removes a domain only from the SharePoint / OneDrive tenant sharing allowlist. Guest objects and other providers are untouched.

.PARAMETER RemoveTeams
Closes Microsoft Teams External Access only for the selected domain. In ALLOWLIST the domain is removed;
in ALLOW_ALL it is explicitly blocked. Guest objects and other providers are untouched.

.PARAMETER MultipleDomains
AddDomain, AddEntra, AddSPO, AddTeams, RemoveEntra, RemoveSPO, RemoveTeams, and PurgeDomain all accept a
comma-separated list, for example -AddDomain fabrikam.com,northwind.com. Domains are normalized to lower
case and de-duplicated. Any invalid domain rejects the whole batch before authentication.

PurgeGuests accepts a comma-separated list of selectors in the same way, mixing exact addresses and
domain wildcards freely, for example -PurgeGuests user@fabrikam.com,*@northwind.com. Overlapping
selectors are de-duplicated by object id, so an account matched by several selectors is previewed and
deleted exactly once. A selector that matches nothing is reported and the remaining ones still run.

.PARAMETER SyncDrifted
Synchronizes Entra ID / SharePoint DRIFT domains that already have one or more guest accounts.
Teams remains audit-only for this batch operation.

.PARAMETER ListGuests
Lists Entra ID #EXT# guest accounts. -ListUsers is an alias.

.PARAMETER GuestDomain
Optional domain filter for -ListGuests.

.PARAMETER PurgeGuests
Deletes guest accounts by exact external email address or exact domain wildcard *@domain.tld.
The purge preview includes retained Entra audit-log InvitedBy metadata when available. No collaboration
configuration is changed. Destructive execution always requires explicit y/yes confirmation.

.PARAMETER PurgeDomain
Closes the domain in Entra ID, SharePoint, and Microsoft Teams, verifies closure, then deletes matching
#EXT# guest accounts after an explicit y/N confirmation. The purge preview includes retained Entra
audit-log InvitedBy metadata when available. In Teams ALLOWLIST the domain is removed from the allowlist;
in ALLOW_ALL it is added to the blocked list. PurgeDomain always shows the purge preview before confirmation.

Accepts one or more comma-separated domains. Every domain is planned and previewed against a single
read-only snapshot, and the whole batch is authorized by one confirmation. Domains are then applied one
at a time: each re-reads provider state immediately before its write and rolls itself back on failure.
A failure aborts the batch and reports which domains were completed and which were not processed.

.PARAMETER PurgePending
Deletes Entra ID #EXT# guest accounts whose invitation state is PendingAcceptance. The preview includes
created date, age, and the retained Entra audit-log inviter when available. Accepted and Rogue guests are
never selected by this operation. Destructive execution always requires explicit y/yes confirmation.

.PARAMETER OlderThanDays
Optional age filter for -PurgePending. Only pending guest accounts at least this many days old are selected.

.PARAMETER TeamsAudit
Runs a detailed standalone Microsoft Teams External Access audit.

.PARAMETER TeamsReauth
Forces the native Microsoft Teams PowerShell 7 session to reconnect. When a SharePointAdminUrl is supplied
through an Add/Purge/Audit operation, Teams authentication is pinned to the tenant resolved from that URL.

.PARAMETER TeamsRefresh
Bypasses the five-minute Teams federation cache without forcing a new Teams sign-in.

.PARAMETER SharePointAdminUrl
SharePoint tenant admin URL. In 22b555 this URL is used as a tenant safety selector; SharePoint tenant
sharing settings themselves are read and written through Microsoft Graph v1.0.
Example: https://contoso-admin.sharepoint.com

.PARAMETER WhatIf
For Add/Remove/Sync/Purge operations, displays the plan without changing configuration. Provider-specific previews use read-only permissions. Purge previews never prompt.

.PARAMETER FullVerbose
Shows the full preflight and authentication plumbing output. Without this switch, successful environment and
authentication checks are condensed while warnings, failures, permission elevation, sign-in prompts, writes,
verification, purge safety output, and rollback details always remain visible.

.PARAMETER NoColor
Disables ANSI/Nord console coloring.

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -Audit -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -AddDomain fabrikam.com -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -AddDomain fabrikam.com,northwind.com -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -AddDomain fabrikam.com -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -PurgeDomain fabrikam.com -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -PurgeDomain fabrikam.com,northwind.com -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -PurgeGuests "*@fabrikam.com" -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -PurgeGuests "kim@fabrikam.com","*@northwind.com" -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -PurgePending -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -PurgePending -OlderThanDays 30 -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -AddEntra fabrikam.com -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -AddSPO fabrikam.com -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -AddTeams fabrikam.com -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -RemoveEntra fabrikam.com -WhatIf -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -RemoveSPO fabrikam.com -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -RemoveTeams fabrikam.com -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -RemoveEntra fabrikam.com,northwind.com -SharePointAdminUrl "https://contoso-admin.sharepoint.com"

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -TeamsAudit

.EXAMPLE
.\ExternalCollab-DenimDemon-22b555.ps1 -Audit -FullVerbose -SharePointAdminUrl "https://contoso-admin.sharepoint.com"
#>

[CmdletBinding(DefaultParameterSetName = 'Audit')]
param(
    [Parameter(ParameterSetName = 'Audit')]
    [switch]$Audit,

    [Parameter(ParameterSetName = 'Audit')]
    [switch]$ReviewUsers,

    [Parameter(Mandatory = $true, ParameterSetName = 'TeamsAudit')]
    [Alias('AuditTeams','TeamsExternalAccess')]
    [switch]$TeamsAudit,

    [Parameter(ParameterSetName = 'Audit')]
    [Parameter(ParameterSetName = 'TeamsAudit')]
    [Parameter(ParameterSetName = 'Add')]
    [Parameter(ParameterSetName = 'AddTeams')]
    [Parameter(ParameterSetName = 'RemoveTeams')]
    [Parameter(ParameterSetName = 'PurgeDomain')]
    [Alias('RefreshTeamsAuth','TeamsRelogin')]
    [switch]$TeamsReauth,

    [Parameter(ParameterSetName = 'Audit')]
    [Parameter(ParameterSetName = 'TeamsAudit')]
    [Parameter(ParameterSetName = 'AddTeams')]
    [Parameter(ParameterSetName = 'RemoveTeams')]
    [Alias('RefreshTeamsConfig','TeamsFresh')]
    [switch]$TeamsRefresh,

    [Parameter(Mandatory = $true, ParameterSetName = 'Add')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$AddDomain,

    [Parameter(Mandatory = $true, ParameterSetName = 'AddEntra')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$AddEntra,

    [Parameter(Mandatory = $true, ParameterSetName = 'AddSPO')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$AddSPO,

    [Parameter(Mandatory = $true, ParameterSetName = 'AddTeams')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$AddTeams,

    [Parameter(Mandatory = $true, ParameterSetName = 'RemoveEntra')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$RemoveEntra,

    [Parameter(Mandatory = $true, ParameterSetName = 'RemoveSPO')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$RemoveSPO,

    [Parameter(Mandatory = $true, ParameterSetName = 'RemoveTeams')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$RemoveTeams,

    [Parameter(Mandatory = $true, ParameterSetName = 'SyncDrifted')]
    [switch]$SyncDrifted,

    [Parameter(Mandatory = $true, ParameterSetName = 'Guests')]
    [Alias('ListUsers')]
    [switch]$ListGuests,

    [Parameter(ParameterSetName = 'Guests', Position = 0)]
    [Alias('Domain')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string]$GuestDomain,

    [Parameter(Mandatory = $true, ParameterSetName = 'PurgeGuests')]
    [string[]]$PurgeGuests,

    [Parameter(Mandatory = $true, ParameterSetName = 'PurgeDomain')]
    [ValidatePattern('^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')]
    [string[]]$PurgeDomain,

    [Parameter(Mandatory = $true, ParameterSetName = 'PurgePending')]
    [switch]$PurgePending,

    [Parameter(ParameterSetName = 'PurgePending')]
    [ValidateRange(0, 36500)]
    [Nullable[int]]$OlderThanDays,

    [Parameter(Mandatory = $true, ParameterSetName = 'Audit')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Add')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AddEntra')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AddSPO')]
    [Parameter(Mandatory = $true, ParameterSetName = 'AddTeams')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RemoveEntra')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RemoveSPO')]
    [Parameter(Mandatory = $true, ParameterSetName = 'RemoveTeams')]
    [Parameter(Mandatory = $true, ParameterSetName = 'SyncDrifted')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Guests')]
    [Parameter(Mandatory = $true, ParameterSetName = 'PurgeGuests')]
    [Parameter(Mandatory = $true, ParameterSetName = 'PurgeDomain')]
    [Parameter(Mandatory = $true, ParameterSetName = 'PurgePending')]
    [ValidatePattern('^https://[A-Za-z0-9-]+-admin\.sharepoint\.com/?$')]
    [string]$SharePointAdminUrl,

    [Parameter(ParameterSetName = 'Add')]
    [Parameter(ParameterSetName = 'AddEntra')]
    [Parameter(ParameterSetName = 'AddSPO')]
    [Parameter(ParameterSetName = 'AddTeams')]
    [Parameter(ParameterSetName = 'RemoveEntra')]
    [Parameter(ParameterSetName = 'RemoveSPO')]
    [Parameter(ParameterSetName = 'RemoveTeams')]
    [Parameter(ParameterSetName = 'SyncDrifted')]
    [Parameter(ParameterSetName = 'PurgeDomain')]
    [Parameter(ParameterSetName = 'PurgeGuests')]
    [Parameter(ParameterSetName = 'PurgePending')]
    [switch]$WhatIf,

    [switch]$FullVerbose,

    [switch]$NoColor
)

$ErrorActionPreference = 'Stop'

#region Configuration

$script:AppName = 'External Collaboration Manager'
$script:AppVersion = '22b555'
$script:DisplayVersion = $script:AppVersion
$script:CodeName = 'Denim Demon'
$script:FullVerbose = [bool]$FullVerbose
$script:MinimumPowerShellVersion = [version]'7.2'
$script:MinimumTeamsModuleVersion = [version]'7.0.0'
$script:TeamsFederationCacheTtlSeconds = 300
$script:RogueRecentActivityDays = 30
$script:UseAnsi = $false
$script:Nord = @{}

$script:AuditGraphScopes = @(
    'User.Read.All',
    'AuditLog.Read.All',
    'Policy.Read.B2BManagementPolicy',
    'SharePointTenantSettings.Read.All'
)

$script:EntraReadGraphScopes = @(
    'Policy.Read.B2BManagementPolicy'
)

$script:EntraWriteGraphScopes = @(
    'Policy.ReadWrite.B2BManagementPolicy'
)

$script:SPOReadGraphScopes = @(
    'SharePointTenantSettings.Read.All'
)

$script:SPOWriteGraphScopes = @(
    'SharePointTenantSettings.ReadWrite.All'
)

$script:AddDomainReadGraphScopes = @(
    'Policy.Read.B2BManagementPolicy',
    'SharePointTenantSettings.Read.All'
)

$script:SyncDriftedGraphScopes = @(
    'Policy.ReadWrite.B2BManagementPolicy',
    'SharePointTenantSettings.ReadWrite.All',
    'User.Read.All',
    'AuditLog.Read.All'
)

$script:GuestGraphScopes = @(
    'User.Read.All',
    'AuditLog.Read.All'
)

$script:PurgeGuestGraphScopes = @(
    'User.ReadWrite.All',
    'AuditLog.Read.All'
)

$script:PurgeDomainGraphScopes = @(
    'Policy.ReadWrite.B2BManagementPolicy',
    'SharePointTenantSettings.ReadWrite.All',
    'User.ReadWrite.All',
    'AuditLog.Read.All'
)

$script:ScriptName = 'ExternalCollab.ps1'
if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    $script:ScriptName = Split-Path -Leaf $PSCommandPath
}

$script:RequiredGraphModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Beta.Users'
)


#endregion Configuration

#region Console

function Initialize-ConsoleTheme {
    [CmdletBinding()]
    param(
        [switch]$NoColor
    )

    $esc = [char]27

    $script:Nord = @{
        Reset  = "$esc[0m"
        Snow   = "$esc[38;2;216;222;233m"
        Muted  = "$esc[38;2;76;86;106m"
        Frost1 = "$esc[38;2;143;188;187m"
        Frost2 = "$esc[38;2;136;192;208m"
        Frost3 = "$esc[38;2;129;161;193m"
        Frost4 = "$esc[38;2;94;129;172m"
        Green  = "$esc[38;2;163;190;140m"
        Yellow = "$esc[38;2;235;203;139m"
        Red    = "$esc[38;2;191;97;106m"
        Orange = "$esc[38;2;208;135;112m"
    }

    if ($NoColor) {
        $script:UseAnsi = $false
        return
    }

    try {
        if ($Host.UI.SupportsVirtualTerminal) {
            $script:UseAnsi = $true
        }
    }
    catch {
        $script:UseAnsi = $false
    }
}

function Write-AppBanner {
    Write-Host

    if ($script:UseAnsi) {
        Write-Host (" {0}{1}{2}  {3} {4}- {5}{2}" -f $script:Nord.Frost2, $script:AppName, $script:Nord.Reset, $script:DisplayVersion, $script:Nord.Frost3, $script:CodeName)
        Write-Host (" {0}Microsoft Entra ID / SharePoint Online / Microsoft Teams{1}" -f $script:Nord.Muted, $script:Nord.Reset)
    }
    else {
        Write-Host (" {0}  {1} - {2}" -f $script:AppName, $script:DisplayVersion, $script:CodeName) -ForegroundColor Cyan
        Write-Host ' Microsoft Entra ID / SharePoint Online / Microsoft Teams' -ForegroundColor DarkGray
    }
}

function Write-Step {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host

    if ($script:UseAnsi) {
        Write-Host (" {0}»»{1} {2}{3}{1}" -f $script:Nord.Frost2, $script:Nord.Reset, $script:Nord.Snow, $Message)
    }
    else {
        Write-Host ' »» ' -NoNewline -ForegroundColor Cyan
        Write-Host $Message
    }
}

function Write-SubStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    # A section label inside an existing step. Deliberately quieter than Write-Step:
    # no leading blank line and no marker, so a multi-item step stays compact.
    if ($script:UseAnsi) {
        Write-Host ("  {0}{1}{2}" -f $script:Nord.Frost4, $Message, $script:Nord.Reset)
    }
    else {
        Write-Host "  $Message" -ForegroundColor DarkCyan
    }
}

function Get-StatusStyle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'WARN', 'ROGUE', 'BLOCKED', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status
    )

    switch ($Status) {
        'OK' {
            [PSCustomObject]@{ Inner = ' ok '; Ansi = $script:Nord.Green;  Fallback = 'Green' }
        }
        'WARN' {
            [PSCustomObject]@{ Inner = ' !! '; Ansi = $script:Nord.Yellow; Fallback = 'Yellow' }
        }
        'ROGUE' {
            [PSCustomObject]@{ Inner = ' !! '; Ansi = $script:Nord.Orange; Fallback = 'DarkYellow' }
        }
        'BLOCKED' {
            # An explicit block is a deliberate, successful configuration, not a failure,
            # so it gets its own marker instead of borrowing the red FAIL tag.
            [PSCustomObject]@{ Inner = ' ×× '; Ansi = $script:Nord.Orange; Fallback = 'DarkYellow' }
        }
        'FAIL' {
            [PSCustomObject]@{ Inner = ' !! '; Ansi = $script:Nord.Red;    Fallback = 'Red' }
        }
        'INFO' {
            [PSCustomObject]@{ Inner = ' ** '; Ansi = $script:Nord.Frost2; Fallback = 'Cyan' }
        }
        'SKIP' {
            [PSCustomObject]@{ Inner = ' -- '; Ansi = $script:Nord.Muted;  Fallback = 'DarkGray' }
        }
    }
}

function Write-StatusTag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'WARN', 'ROGUE', 'BLOCKED', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status,

        [switch]$NoNewline
    )

    $style = Get-StatusStyle -Status $Status

    if ($script:UseAnsi) {
        # OpenRC-style tag: brackets stay neutral, only the inner status marker is colored.
        $tag = ('{0}[{1}{2}{0}]{3}' -f $script:Nord.Snow, $style.Ansi, $style.Inner, $script:Nord.Reset)
        Write-Host $tag -NoNewline:$NoNewline
    }
    else {
        Write-Host '[' -NoNewline -ForegroundColor Gray
        Write-Host $style.Inner -NoNewline -ForegroundColor $style.Fallback
        Write-Host ']' -NoNewline:$NoNewline -ForegroundColor Gray
    }
}

function Write-Status {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'WARN', 'ROGUE', 'BLOCKED', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host '  ' -NoNewline
    Write-StatusTag -Status $Status -NoNewline

    if ($script:UseAnsi) {
        Write-Host (" {0}{1}{2}" -f $script:Nord.Snow, $Message, $script:Nord.Reset)
    }
    else {
        Write-Host " $Message"
    }
}

function Write-DetailStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'WARN', 'ROGUE', 'BLOCKED', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($script:FullVerbose) {
        Write-Status -Status $Status -Message $Message
    }
}

function Write-WrappedStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'WARN', 'ROGUE', 'BLOCKED', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [int]$MaxWidth = 120
    )

    # Visible prefix is: two spaces + [ xx ] + one space = 9 columns.
    # Keep long advisory text readable and indent continuation lines under
    # the message instead of letting the terminal wrap at column zero.
    $prefixWidth = 9
    $windowWidth = $MaxWidth

    try {
        $detectedWidth = [int]$Host.UI.RawUI.WindowSize.Width
        if ($detectedWidth -gt 0) {
            $windowWidth = [Math]::Min($detectedWidth, $MaxWidth)
        }
    }
    catch {
        $windowWidth = $MaxWidth
    }

    $messageWidth = [Math]::Max(40, $windowWidth - $prefixWidth)
    $words = @($Message -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $lines = New-Object System.Collections.Generic.List[string]
    $current = ''

    foreach ($word in $words) {
        if ([string]::IsNullOrEmpty($current)) {
            $current = $word
            continue
        }

        if (($current.Length + 1 + $word.Length) -le $messageWidth) {
            $current = $current + ' ' + $word
        }
        else {
            $lines.Add($current)
            $current = $word
        }
    }

    if (-not [string]::IsNullOrEmpty($current)) {
        $lines.Add($current)
    }

    if ($lines.Count -eq 0) {
        Write-Status -Status $Status -Message ''
        return
    }

    Write-Host '  ' -NoNewline
    Write-StatusTag -Status $Status -NoNewline

    if ($script:UseAnsi) {
        Write-Host (" {0}{1}{2}" -f $script:Nord.Snow, $lines[0], $script:Nord.Reset)
    }
    else {
        Write-Host (" {0}" -f $lines[0])
    }

    for ($i = 1; $i -lt $lines.Count; $i++) {
        $indent = ' ' * $prefixWidth
        if ($script:UseAnsi) {
            Write-Host ("{0}{1}{2}{3}" -f $indent, $script:Nord.Snow, $lines[$i], $script:Nord.Reset)
        }
        else {
            Write-Host ("{0}{1}" -f $indent, $lines[$i])
        }
    }
}

function Write-SummaryMetric {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'WARN', 'ROGUE', 'BLOCKED', 'FAIL', 'INFO', 'SKIP')]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    # Keep the metric column fixed instead of relying on hand-written spaces.
    # The value is right-aligned so 0, 3, 28 and 118 all end at the same column.
    if ($Status -eq 'ROGUE') {
        $labelText = ('{0,-38}' -f $Label)
        $valueText = ('{0,5}' -f $Value)

        Write-Host '  ' -NoNewline
        Write-StatusTag -Status ROGUE -NoNewline
        Write-Host ' ' -NoNewline

        if ($script:UseAnsi) {
            Write-Host ("{0}{1}{2}" -f $script:Nord.Snow, $labelText, $script:Nord.Reset) -NoNewline
            Write-Host ("{0}{1}{2}" -f $script:Nord.Orange, $valueText, $script:Nord.Reset)
        }
        else {
            Write-Host $labelText -NoNewline
            Write-Host $valueText -ForegroundColor DarkYellow
        }
        return
    }

    $message = ('{0,-38}{1,5}' -f $Label, $Value)
    Write-Status -Status $Status -Message $message
}

function Get-ExternalCollabStateStyle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'DRIFT', 'ORPHANED')]
        [string]$State
    )

    switch ($State) {
        'OK' {
            [PSCustomObject]@{ Ansi = $script:Nord.Green; Fallback = 'Green' }
        }
        'DRIFT' {
            [PSCustomObject]@{ Ansi = $script:Nord.Yellow; Fallback = 'Yellow' }
        }
        'ORPHANED' {
            [PSCustomObject]@{ Ansi = $script:Nord.Orange; Fallback = 'DarkYellow' }
        }
    }
}

function Write-ExternalCollabStateText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'DRIFT', 'ORPHANED')]
        [string]$State,

        [Parameter(Mandatory = $true)]
        [string]$Text,

        [switch]$NoNewline
    )

    $style = Get-ExternalCollabStateStyle -State $State

    if ($script:UseAnsi) {
        Write-Host ("{0}{1}{2}" -f $style.Ansi, $Text, $script:Nord.Reset) -NoNewline:$NoNewline
    }
    else {
        Write-Host $Text -ForegroundColor $style.Fallback -NoNewline:$NoNewline
    }
}

#endregion Console

#region RuntimeAndModules

function Get-PreferredModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    Get-Module -Name $Name -ListAvailable |
        Sort-Object Version -Descending |
        Select-Object -First 1
}

function Confirm-ModuleInstall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [version]$MinimumVersion
    )

    $versionText = ''
    if ($null -ne $MinimumVersion) {
        $versionText = " >= $MinimumVersion"
    }

    while ($true) {
        $answer = Read-Host ("Install/update {0}{1} for CurrentUser? [y/N]" -f $Name, $versionText)
        if ([string]::IsNullOrWhiteSpace($answer)) { return $false }

        switch ($answer.Trim().ToLowerInvariant()) {
            'y'   { return $true }
            'yes' { return $true }
            'n'   { return $false }
            'no'  { return $false }
            default { Write-Status -Status WARN -Message 'Please answer y or n.' }
        }
    }
}

function Ensure-ModuleAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [version]$MinimumVersion,

        [switch]$Optional
    )

    $module = Get-PreferredModule -Name $Name
    $needsInstall = ($null -eq $module)

    if (-not $needsInstall -and $null -ne $MinimumVersion) {
        $needsInstall = ([version]$module.Version -lt $MinimumVersion)
    }

    if ($needsInstall) {
        if ($null -eq $module) {
            Write-Status -Status WARN -Message ("Missing module: {0}" -f $Name)
        }
        else {
            Write-Status -Status WARN -Message ("{0} {1} is older than required {2}" -f $Name, $module.Version, $MinimumVersion)
        }

        if (-not (Confirm-ModuleInstall -Name $Name -MinimumVersion $MinimumVersion)) {
            if ($Optional) { return $null }
            throw ("Required module {0} is not available at the required version." -f $Name)
        }

        $installParams = @{
            Name         = $Name
            Scope        = 'CurrentUser'
            Force        = $true
            AllowClobber = $true
            ErrorAction  = 'Stop'
        }
        if ($null -ne $MinimumVersion) {
            $installParams['MinimumVersion'] = $MinimumVersion.ToString()
        }

        Write-Status -Status INFO -Message ("Installing {0} from PSGallery..." -f $Name)
        Install-Module @installParams
        $module = Get-PreferredModule -Name $Name
    }

    if ($null -eq $module) {
        if ($Optional) { return $null }
        throw ("Module installation completed, but {0} was not found." -f $Name)
    }

    if ($null -ne $MinimumVersion -and [version]$module.Version -lt $MinimumVersion) {
        if ($Optional) { return $null }
        throw ("{0} {1} is installed; version {2} or newer is required." -f $Name, $module.Version, $MinimumVersion)
    }

    Write-DetailStatus -Status OK -Message ("{0} {1}" -f $Name, $module.Version)
    return $module
}

function Import-RequiredGraphModules {
    [CmdletBinding()]
    param()

    foreach ($name in $script:RequiredGraphModules) {
        if ($null -eq (Get-Module -Name $name)) {
            Import-Module $name -ErrorAction Stop
        }
    }
}

function Import-MicrosoftTeamsNativeModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ModuleInfo
    )

    $loaded = Get-Module -Name MicrosoftTeams | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -ne $loaded) {
        if ([version]$loaded.Version -lt $script:MinimumTeamsModuleVersion) {
            throw ("MicrosoftTeams {0} is already loaded in this PowerShell process. Restart pwsh so Denim Demon can load {1} or newer." -f $loaded.Version, $script:MinimumTeamsModuleVersion)
        }
        return $loaded
    }

    Import-Module -Name $ModuleInfo.Path -ErrorAction Stop
    $loaded = Get-Module -Name MicrosoftTeams | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $loaded) {
        throw 'MicrosoftTeams import completed, but the module is not visible in the current PowerShell process.'
    }

    foreach ($commandName in @('Connect-MicrosoftTeams','Disconnect-MicrosoftTeams','Get-CsTenant','Get-CsTenantFederationConfiguration','Set-CsTenantFederationConfiguration','New-CsEdgeDomainPattern')) {
        if ($null -eq (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw ("Required Microsoft Teams cmdlet is unavailable: {0}" -f $commandName)
        }
    }

    return $loaded
}

function Assert-PowerShell7Runtime {
    [CmdletBinding()]
    param()

    if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion -lt $script:MinimumPowerShellVersion) {
        throw ("Denim Demon {0} requires PowerShell {1}+ (pwsh). Windows PowerShell compatibility is intentionally unsupported." -f $script:DisplayVersion, $script:MinimumPowerShellVersion)
    }

    Write-DetailStatus -Status OK -Message ("PowerShell {0} (native runtime)" -f $PSVersionTable.PSVersion)
}

function Invoke-TeamsNativePreflight {
    [CmdletBinding()]
    param()

    Write-Step $(if ($script:FullVerbose) { 'Running preflight checks...' } else { 'Environment...' })
    Assert-PowerShell7Runtime

    $teamsModule = Ensure-ModuleAvailable -Name 'MicrosoftTeams' -MinimumVersion $script:MinimumTeamsModuleVersion
    $loadedTeams = Import-MicrosoftTeamsNativeModule -ModuleInfo $teamsModule
    Write-DetailStatus -Status OK -Message ("MicrosoftTeams native PowerShell 7 runtime: {0}" -f $loadedTeams.Version)

    if (-not $script:FullVerbose) {
        Write-Status -Status OK -Message ("PowerShell {0} / MicrosoftTeams {1}" -f $PSVersionTable.PSVersion, $loadedTeams.Version)
    }

    return $loadedTeams
}

function Invoke-ExternalCollabRuntimePreflight {
    [CmdletBinding()]
    param(
        [switch]$IncludeTeams,
        [switch]$RequireTeams
    )

    Write-Step $(if ($script:FullVerbose) { 'Running preflight checks...' } else { 'Environment...' })
    Assert-PowerShell7Runtime

    $graphModules = @{}
    foreach ($moduleName in $script:RequiredGraphModules) {
        $graphModules[$moduleName] = Ensure-ModuleAvailable -Name $moduleName
    }
    Import-RequiredGraphModules
    Write-DetailStatus -Status OK -Message 'SharePoint tenant settings provider: Microsoft Graph v1.0'

    $teamsModule = $null
    if ($IncludeTeams) {
        $teamsModule = Ensure-ModuleAvailable -Name 'MicrosoftTeams' -MinimumVersion $script:MinimumTeamsModuleVersion -Optional:(-not $RequireTeams)
        if ($null -ne $teamsModule) {
            $loadedTeams = Import-MicrosoftTeamsNativeModule -ModuleInfo $teamsModule
            Write-DetailStatus -Status OK -Message ("MicrosoftTeams native PowerShell 7 runtime: {0}" -f $loadedTeams.Version)
            $teamsModule = $loadedTeams
        }
        elseif ($RequireTeams) {
            throw 'MicrosoftTeams is required for this operation.'
        }
        else {
            Write-Status -Status WARN -Message 'Microsoft Teams audit will be skipped'
        }
    }

    if (-not $script:FullVerbose) {
        $graphVersion = [string]$graphModules['Microsoft.Graph.Authentication'].Version
        $environmentText = "PowerShell $($PSVersionTable.PSVersion) / Graph $graphVersion"
        if ($null -ne $teamsModule) { $environmentText += " / Teams $($teamsModule.Version)" }
        Write-Status -Status OK -Message $environmentText
    }

    return [PSCustomObject]@{
        TeamsModule = $teamsModule
    }
}

#endregion RuntimeAndModules

#region Authentication

function Test-GraphScopeSatisfied {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$GrantedScopes,

        [Parameter(Mandatory = $true)]
        [string]$RequiredScope
    )

    if ($GrantedScopes -contains $RequiredScope) { return $true }

    $strongerScopes = @{
        'Policy.Read.B2BManagementPolicy'        = 'Policy.ReadWrite.B2BManagementPolicy'
        'SharePointTenantSettings.Read.All'      = 'SharePointTenantSettings.ReadWrite.All'
        'User.Read.All'                          = 'User.ReadWrite.All'
    }

    if ($strongerScopes.ContainsKey($RequiredScope) -and $GrantedScopes -contains $strongerScopes[$RequiredScope]) {
        return $true
    }

    return $false
}

function Get-MissingGraphScopes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$GrantedScopes,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$RequiredScopes
    )

    @($RequiredScopes | Where-Object { -not (Test-GraphScopeSatisfied -GrantedScopes $GrantedScopes -RequiredScope $_) })
}

function Get-SharePointTenantRealm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminUrl
    )

    $realmUri = ('{0}/_vti_bin/client.svc' -f $AdminUrl.TrimEnd('/'))
    $response = $null

    try {
        Invoke-WebRequest -Uri $realmUri -Method Get -Headers @{ Authorization = 'Bearer' } -ErrorAction Stop | Out-Null
    }
    catch {
        $response = $_.Exception.Response
    }

    if ($null -eq $response) { return $null }

    $challenge = $null
    try { $challenge = [string]$response.Headers['WWW-Authenticate'] } catch {}

    if ([string]::IsNullOrWhiteSpace($challenge)) {
        try {
            $values = $null
            if ($response.Headers.TryGetValues('WWW-Authenticate', [ref]$values)) {
                $challenge = (@($values) -join ', ')
            }
        }
        catch {}
    }

    if ($challenge -match 'realm="?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"?') {
        return $Matches[1].ToLowerInvariant()
    }

    return $null
}

function Test-ExternalCollabGraphContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )

    try {
        if ($Scopes -contains 'SharePointTenantSettings.Read.All' -or $Scopes -contains 'SharePointTenantSettings.ReadWrite.All') {
            Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings?$select=sharingDomainRestrictionMode' | Out-Null
        }
        elseif ($Scopes -contains 'User.Read.All' -or $Scopes -contains 'User.ReadWrite.All') {
            Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users?$top=1&$select=id' | Out-Null
        }
        else {
            Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/beta/policies/b2bManagementPolicies?$top=1' | Out-Null
        }

        return [PSCustomObject]@{ Usable = $true; Error = $null }
    }
    catch {
        return [PSCustomObject]@{ Usable = $false; Error = [string]$_.Exception.Message }
    }
}

function Connect-ExternalCollabGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes,

        [string]$ExpectedTenantId
    )

    $expectedTenantNormalized = $null
    if (-not [string]::IsNullOrWhiteSpace($ExpectedTenantId)) {
        $expectedTenantNormalized = $ExpectedTenantId.ToLowerInvariant()
    }

    $context = Get-MgContext -ErrorAction SilentlyContinue
    $authenticationScopes = @($Scopes)

    if ($null -ne $context) {
        $missingScopes = @(Get-MissingGraphScopes -GrantedScopes @($context.Scopes) -RequiredScopes $Scopes)
        $tenantMatches = $true
        if ($null -ne $expectedTenantNormalized) {
            $tenantMatches = ([string]$context.TenantId).ToLowerInvariant() -eq $expectedTenantNormalized
        }

        if ($tenantMatches -and $missingScopes.Count -eq 0) {
            $probe = Test-ExternalCollabGraphContext -Scopes $Scopes
            if ($probe.Usable) {
                Write-DetailStatus -Status OK -Message 'Using existing Microsoft Graph connection'
                Write-DetailStatus -Status OK -Message ("Graph account: {0}" -f $context.Account)
                Write-DetailStatus -Status OK -Message ("Graph tenant:  {0}" -f $context.TenantId)
                Write-DetailStatus -Status OK -Message 'Required Graph scopes already granted'
                return $context
            }
            Write-WrappedStatus -Status WARN -Message ("Existing Graph connection failed validation; reconnecting. {0}" -f $probe.Error)
        }

        if (-not $tenantMatches) {
            Write-Status -Status WARN -Message ("Existing Graph connection targets tenant {0}; target is {1}" -f $context.TenantId, $expectedTenantNormalized)
        }
        if ($missingScopes.Count -gt 0) {
            Write-Status -Status WARN -Message ("Existing Graph connection is missing scope(s): {0}" -f ($missingScopes -join ', '))
        }

        $knownToolScopes = @(
            $script:AuditGraphScopes +
            $script:EntraReadGraphScopes +
            $script:EntraWriteGraphScopes +
            $script:SPOReadGraphScopes +
            $script:SPOWriteGraphScopes +
            $script:AddDomainReadGraphScopes +
            $script:SyncDriftedGraphScopes +
            $script:GuestGraphScopes +
            $script:PurgeGuestGraphScopes +
            $script:PurgeDomainGraphScopes |
                Sort-Object -Unique
        )
        $existingToolScopes = @(@($context.Scopes) | Where-Object { $knownToolScopes -contains $_ })
        $authenticationScopes = @($Scopes + $existingToolScopes | Sort-Object -Unique)

        Write-Status -Status INFO -Message 'Microsoft Graph re-authentication required'
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    else {
        Write-Status -Status INFO -Message 'Microsoft Graph authentication required'
    }

    Write-Status -Status INFO -Message 'Microsoft Graph: waiting for tenant-pinned sign-in'
    $connectParameters = @{
        Scopes       = $authenticationScopes
        ContextScope = 'Process'
        NoWelcome    = $true
    }
    if ($null -ne $expectedTenantNormalized) {
        $connectParameters['TenantId'] = $expectedTenantNormalized
    }

    Connect-MgGraph @connectParameters | Out-Host
    $context = Get-MgContext
    if ($null -eq $context) { throw 'Microsoft Graph authentication did not produce a valid context.' }

    $missingScopes = @(Get-MissingGraphScopes -GrantedScopes @($context.Scopes) -RequiredScopes $Scopes)
    if ($missingScopes.Count -gt 0) {
        throw ("Graph context is missing required scopes: {0}" -f ($missingScopes -join ', '))
    }
    if ($null -ne $expectedTenantNormalized -and ([string]$context.TenantId).ToLowerInvariant() -ne $expectedTenantNormalized) {
        throw ("Graph authentication returned tenant {0}; expected {1}." -f $context.TenantId, $expectedTenantNormalized)
    }

    Write-Status -Status OK -Message ("Graph account: {0}" -f $context.Account)
    Write-Status -Status OK -Message ("Graph tenant:  {0}" -f $context.TenantId)
    Write-Status -Status OK -Message 'Required Graph scopes granted'
    return $context
}

function Test-ExternalCollabTenantConsistency {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$GraphContext,

        [Parameter(Mandatory = $true)]
        [string]$SharePointAdminUrl,

        [string]$ResolvedSharePointTenantId
    )

    $targetTenantId = $ResolvedSharePointTenantId
    if ([string]::IsNullOrWhiteSpace($targetTenantId)) {
        $targetTenantId = Get-SharePointTenantRealm -AdminUrl $SharePointAdminUrl
    }

    if ([string]::IsNullOrWhiteSpace($targetTenantId)) {
        Write-Status -Status WARN -Message 'Tenant cross-check could not resolve SharePoint realm; Graph tenant remains the active safety boundary'
        return [string]$GraphContext.TenantId
    }

    if (-not ([string]$GraphContext.TenantId).Equals($targetTenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("Tenant safety check failed: Graph tenant {0} does not match SharePoint target {1}." -f $GraphContext.TenantId, $targetTenantId)
    }

    Write-DetailStatus -Status OK -Message ("Tenant cross-check: Graph / SharePoint target {0}" -f $targetTenantId)
    return $targetTenantId
}

#endregion Authentication

#region Teams

function Get-ExternalCollabTeamsFederationCache {
    [CmdletBinding()]
    param()

    if ($null -eq $global:ExternalCollabTeamsNativeFederationCacheV1) { return $null }
    return $global:ExternalCollabTeamsNativeFederationCacheV1
}

function Clear-ExternalCollabTeamsFederationCache {
    [CmdletBinding()]
    param()

    $global:ExternalCollabTeamsNativeFederationCacheV1 = $null
}

function Copy-ExternalCollabTeamsFederationConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config
    )

    [PSCustomObject]@{
        Mode                = [string]$Config.Mode
        AllowFederatedUsers = $Config.AllowFederatedUsers
        AllowedDomains      = @($Config.AllowedDomains)
        BlockedDomains      = @($Config.BlockedDomains)
        AllowedDomainsType  = [string]$Config.AllowedDomainsType
        FetchedAtUtc        = if ($Config.PSObject.Properties.Name -contains 'FetchedAtUtc') { [datetime]$Config.FetchedAtUtc } else { [datetime]::UtcNow }
    }
}

function Set-ExternalCollabTeamsFederationCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [object]$Config
    )

    $global:ExternalCollabTeamsNativeFederationCacheV1 = [PSCustomObject]@{
        TenantId = $TenantId.ToLowerInvariant()
        StoredAtUtc = [datetime]::UtcNow
        Config = Copy-ExternalCollabTeamsFederationConfig -Config $Config
    }
}

function Get-ExternalCollabTeamsFederationCacheState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $cached = Get-ExternalCollabTeamsFederationCache
    if ($null -eq $cached) { return $null }
    if (-not ([string]$cached.TenantId).Equals($TenantId, [System.StringComparison]::OrdinalIgnoreCase)) { return $null }

    $age = [Math]::Max(0, ([datetime]::UtcNow - ([datetime]$cached.StoredAtUtc).ToUniversalTime()).TotalSeconds)
    [PSCustomObject]@{
        AgeSeconds = $age
        IsValid = ($age -lt $script:TeamsFederationCacheTtlSeconds)
        Config = Copy-ExternalCollabTeamsFederationConfig -Config $cached.Config
    }
}

function Format-ExternalCollabTeamsCacheAge {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][double]$AgeSeconds)

    $seconds = [Math]::Max(0, [int][Math]::Floor($AgeSeconds))
    if ($seconds -lt 60) { return ('{0}s' -f $seconds) }
    return ('{0}m {1:D2}s' -f [int][Math]::Floor($seconds / 60), ($seconds % 60))
}

function Write-ExternalCollabTeamsCacheAgeStatus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [double]$AgeSeconds,
        [switch]$Expired
    )

    $ageText = Format-ExternalCollabTeamsCacheAge -AgeSeconds $AgeSeconds
    $prefix = if ($Expired) { 'Microsoft Teams federation cache expired (age ' } else { 'Using cached Microsoft Teams federation configuration (age ' }
    $suffix = if ($Expired) { '); fetching fresh configuration' } else { ')' }

    Write-Host '  ' -NoNewline
    Write-StatusTag -Status $(if ($Expired) { 'INFO' } else { 'OK' }) -NoNewline
    Write-Host ' ' -NoNewline

    $ageAnsi = $script:Nord.Snow
    $ageFallback = $null

    if ($AgeSeconds -ge 240) {
        $ageAnsi = $script:Nord.Red
        $ageFallback = 'Red'
    }
    elseif ($AgeSeconds -ge 120) {
        # Reuse the exact DRIFT colour.
        $ageAnsi = $script:Nord.Yellow
        $ageFallback = 'Yellow'
    }

    if ($script:UseAnsi) {
        Write-Host ("{0}{1}{2}" -f $script:Nord.Snow, $prefix, $script:Nord.Reset) -NoNewline
        Write-Host ("{0}{1}{2}" -f $ageAnsi, $ageText, $script:Nord.Reset) -NoNewline
        Write-Host ("{0}{1}{2}" -f $script:Nord.Snow, $suffix, $script:Nord.Reset)
    }
    else {
        Write-Host $prefix -NoNewline
        if ($null -ne $ageFallback) {
            Write-Host $ageText -NoNewline -ForegroundColor $ageFallback
        }
        else {
            Write-Host $ageText -NoNewline
        }
        Write-Host $suffix
    }
}

function Get-TeamsConnectionContextFromObject {
    [CmdletBinding()]
    param([AllowNull()][object]$Connection)

    $account = $null
    $tenantId = $null
    $displayName = $null

    foreach ($propertyName in @('Account','AccountId','UserPrincipalName')) {
        if ($null -ne $Connection -and $Connection.PSObject.Properties.Name -contains $propertyName) {
            $candidate = [string]$Connection.$propertyName
            if (-not [string]::IsNullOrWhiteSpace($candidate)) { $account = $candidate; break }
        }
    }
    foreach ($propertyName in @('TenantId','TenantID')) {
        if ($null -ne $Connection -and $Connection.PSObject.Properties.Name -contains $propertyName) {
            $candidate = [string]$Connection.$propertyName
            if ($candidate -match '^[0-9a-fA-F-]{36}$') { $tenantId = $candidate; break }
        }
    }
    if ($null -ne $Connection -and $Connection.PSObject.Properties.Name -contains 'Tenant') {
        $candidate = [string]$Connection.Tenant
        if (-not [string]::IsNullOrWhiteSpace($candidate)) {
            if ([string]::IsNullOrWhiteSpace($tenantId) -and $candidate -match '^[0-9a-fA-F-]{36}$') { $tenantId = $candidate }
            elseif ($candidate -notmatch '^[0-9a-fA-F-]{36}$') { $displayName = $candidate }
        }
    }

    [PSCustomObject]@{
        Account = $account
        TenantId = $tenantId
        DisplayName = $displayName
        AuthMode = 'NATIVE_INTERACTIVE'
    }
}

function Get-TeamsTenantContextProbe {
    [CmdletBinding()]
    param()

    try {
        $tenant = Get-CsTenant -ErrorAction Stop
        if ($null -eq $tenant) { return $null }

        $tenantId = $null
        foreach ($propertyName in @('TenantId','TenantID')) {
            if ($tenant.PSObject.Properties.Name -contains $propertyName) {
                $candidate = [string]$tenant.$propertyName
                if ($candidate -match '^[0-9a-fA-F-]{36}$') { $tenantId = $candidate; break }
            }
        }
        if ([string]::IsNullOrWhiteSpace($tenantId)) { return $null }

        $displayName = $null
        foreach ($propertyName in @('DisplayName','Name')) {
            if ($tenant.PSObject.Properties.Name -contains $propertyName) {
                $candidate = [string]$tenant.$propertyName
                if (-not [string]::IsNullOrWhiteSpace($candidate)) { $displayName = $candidate; break }
            }
        }

        [PSCustomObject]@{
            Account = $null
            TenantId = $tenantId
            DisplayName = $displayName
            AuthMode = 'NATIVE_REUSE'
        }
    }
    catch { return $null }
}

function Connect-ExternalCollabTeamsNative {
    [CmdletBinding()]
    param(
        [string]$ExpectedTenantId,
        [switch]$ForceReauth
    )

    $expected = $null
    if (-not [string]::IsNullOrWhiteSpace($ExpectedTenantId)) { $expected = $ExpectedTenantId.ToLowerInvariant() }

    if ($ForceReauth) {
        try { Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
        $global:ExternalCollabTeamsNativeContextV1 = $null
        Clear-ExternalCollabTeamsFederationCache
        Write-Status -Status INFO -Message 'Microsoft Teams native session cleared for re-authentication'
    }

    $cached = $global:ExternalCollabTeamsNativeContextV1
    if ($null -ne $cached -and -not [string]::IsNullOrWhiteSpace([string]$cached.TenantId)) {
        if ($null -eq $expected -or ([string]$cached.TenantId).Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            # Do not trust metadata alone. Validate that the native Teams session can still answer
            # a tenant-scoped read before reusing the cached context.
            $cachedProbe = Get-TeamsTenantContextProbe
            if ($null -ne $cachedProbe -and ([string]$cachedProbe.TenantId).Equals([string]$cached.TenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$cached.Account)) { $cachedProbe.Account = $cached.Account }
                $global:ExternalCollabTeamsNativeContextV1 = $cachedProbe
                Write-DetailStatus -Status OK -Message 'Using existing Microsoft Teams PowerShell 7 connection'
                return $cachedProbe
            }

            Write-Status -Status WARN -Message 'Existing Microsoft Teams session failed validation; reconnecting'
            try { Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
            $global:ExternalCollabTeamsNativeContextV1 = $null
            Clear-ExternalCollabTeamsFederationCache
        }
    }

    $probe = Get-TeamsTenantContextProbe
    if ($null -ne $probe) {
        if ($null -eq $expected -or ([string]$probe.TenantId).Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($null -ne $cached -and -not [string]::IsNullOrWhiteSpace([string]$cached.Account)) { $probe.Account = $cached.Account }
            $global:ExternalCollabTeamsNativeContextV1 = $probe
            Write-DetailStatus -Status OK -Message 'Using existing Microsoft Teams PowerShell 7 connection'
            return $probe
        }

        Write-Status -Status WARN -Message ("Existing Teams connection targets tenant {0}; target is {1}" -f $probe.TenantId, $expected)
        try { Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
        $global:ExternalCollabTeamsNativeContextV1 = $null
        Clear-ExternalCollabTeamsFederationCache
    }

    Write-Status -Status INFO -Message 'Microsoft Teams authentication required'
    Write-Status -Status INFO -Message 'Microsoft Teams: waiting for native PowerShell 7 sign-in'

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    if ($null -ne $expected) {
        $connection = Connect-MicrosoftTeams -TenantId $expected -ErrorAction Stop
    }
    else {
        $connection = Connect-MicrosoftTeams -ErrorAction Stop
    }
    $timer.Stop()

    $context = Get-TeamsConnectionContextFromObject -Connection $connection
    if ([string]::IsNullOrWhiteSpace([string]$context.TenantId)) {
        $probe = Get-TeamsTenantContextProbe
        if ($null -ne $probe) {
            $context.TenantId = $probe.TenantId
            if ([string]::IsNullOrWhiteSpace([string]$context.DisplayName)) { $context.DisplayName = $probe.DisplayName }
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$context.TenantId)) {
        throw 'Microsoft Teams authentication succeeded, but tenant ID could not be resolved.'
    }
    if ($null -ne $expected -and -not ([string]$context.TenantId).Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("Microsoft Teams authentication returned tenant {0}; expected {1}." -f $context.TenantId, $expected)
    }

    $global:ExternalCollabTeamsNativeContextV1 = $context
    Clear-ExternalCollabTeamsFederationCache
    Write-Status -Status OK -Message ("Microsoft Teams authentication completed in {0:N1}s" -f $timer.Elapsed.TotalSeconds)
    return $context
}

function Get-FederationDomains {
    [CmdletBinding()]
    param([AllowNull()][object]$InputObject)

    $values = [System.Collections.Generic.List[string]]::new()

    function Add-DomainValue {
        param([AllowNull()][object]$Value)
        if ($null -eq $Value) { return }

        if ($Value -is [string]) {
            $candidate = $Value.Trim().ToLowerInvariant()
            if ($candidate -match '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$') { $values.Add($candidate) }
            return
        }

        foreach ($propertyName in @('Domain','AllowedDomain','BlockedDomain')) {
            if ($Value.PSObject.Properties.Name -contains $propertyName) { Add-DomainValue -Value $Value.$propertyName }
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            foreach ($item in $Value) {
                if (-not [object]::ReferenceEquals($item, $Value)) { Add-DomainValue -Value $item }
            }
        }
    }

    Add-DomainValue -Value $InputObject
    return @($values | Sort-Object -Unique)
}

function Get-ExternalCollabTeamsNativeConfig {
    [CmdletBinding()]
    param(
        [string]$Phase = 'federation configuration read'
    )

    Write-Status -Status INFO -Message 'Fetching Microsoft Teams tenant federation configuration...'
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    $raw = Get-CsTenantFederationConfiguration -ErrorAction Stop
    $timer.Stop()
    Write-Status -Status OK -Message ("Fetched Microsoft Teams tenant federation configuration in {0:N1}s" -f $timer.Elapsed.TotalSeconds)

    if ($null -eq $raw) { throw 'Get-CsTenantFederationConfiguration returned no configuration.' }

    $allowFederatedUsers = $true
    if ($raw.PSObject.Properties.Name -contains 'AllowFederatedUsers') { $allowFederatedUsers = [bool]$raw.AllowFederatedUsers }

    $allowedObject = if ($raw.PSObject.Properties.Name -contains 'AllowedDomains') { $raw.AllowedDomains } else { $null }
    $blockedObject = if ($raw.PSObject.Properties.Name -contains 'BlockedDomains') { $raw.BlockedDomains } else { $null }

    $allowedTypeText = ''
    if ($null -ne $allowedObject) {
        try { $allowedTypeText = [string]$allowedObject.GetType().FullName } catch {}
        $allowedTypeText = (@($allowedTypeText) + @($allowedObject.PSObject.TypeNames) + @([string]$allowedObject) -join ' ').Trim()
    }

    $mode = 'UNKNOWN'
    $allowedDomains = @()
    $blockedDomains = @()

    if (-not $allowFederatedUsers) {
        $mode = 'DISABLED'
    }
    elseif ($allowedTypeText -match 'AllowAllKnownDomains') {
        $mode = 'ALLOW_ALL'
        $blockedDomains = @(Get-FederationDomains -InputObject $blockedObject)
    }
    elseif ($allowedTypeText -match 'AllowList') {
        $allowedDomains = @(Get-FederationDomains -InputObject $allowedObject)
        $blockedDomains = @(Get-FederationDomains -InputObject $blockedObject)
        $mode = if ($allowedDomains.Count -gt 0) { 'ALLOWLIST' } else { 'BLOCK_ALL' }
    }
    else {
        $allowedDomains = @(Get-FederationDomains -InputObject $allowedObject)
        $blockedDomains = @(Get-FederationDomains -InputObject $blockedObject)
        if ($allowedDomains.Count -gt 0) { $mode = 'ALLOWLIST' }
        elseif ($blockedDomains.Count -gt 0) { $mode = 'ALLOW_ALL' }
        else { $mode = 'BLOCK_ALL' }
    }

    [PSCustomObject]@{
        Mode = $mode
        AllowFederatedUsers = $allowFederatedUsers
        AllowedDomains = @($allowedDomains)
        BlockedDomains = @($blockedDomains)
        AllowedDomainsType = $allowedTypeText
        FetchedAtUtc = [datetime]::UtcNow
    }
}

function Get-ExternalCollabTeamsConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [switch]$ForceRefresh
    )

    $tenantId = [string]$Context.TenantId
    if ([string]::IsNullOrWhiteSpace($tenantId)) { throw 'Microsoft Teams federation cache requires a resolved tenant ID.' }

    if (-not $ForceRefresh) {
        $cacheState = Get-ExternalCollabTeamsFederationCacheState -TenantId $tenantId
        if ($null -ne $cacheState) {
            if ($cacheState.IsValid) {
                Write-ExternalCollabTeamsCacheAgeStatus -AgeSeconds $cacheState.AgeSeconds
                return $cacheState.Config
            }
            Write-ExternalCollabTeamsCacheAgeStatus -AgeSeconds $cacheState.AgeSeconds -Expired
            Clear-ExternalCollabTeamsFederationCache
        }
    }
    else {
        Clear-ExternalCollabTeamsFederationCache
        Write-Status -Status INFO -Message 'Microsoft Teams federation cache bypassed; fresh configuration requested'
    }

    $config = Get-ExternalCollabTeamsNativeConfig
    Set-ExternalCollabTeamsFederationCache -TenantId $tenantId -Config $config
    return $config
}

function Get-ExternalCollabTeamsDomainState {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Config,[Parameter(Mandatory = $true)][string]$Domain)

    $domainNormalized = $Domain.Trim().ToLowerInvariant()
    $mode = ([string]$Config.Mode).Trim().ToUpperInvariant()
    $allowed = @($Config.AllowedDomains | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    $blocked = @($Config.BlockedDomains | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
    $explicitAllowed = $allowed -contains $domainNormalized
    $explicitBlocked = $blocked -contains $domainNormalized

    $effectiveAllowed = $false
    switch ($mode) {
        'ALLOWLIST' { $effectiveAllowed = $explicitAllowed }
        'ALLOW_ALL' { $effectiveAllowed = -not $explicitBlocked }
        default { $effectiveAllowed = $false }
    }

    [PSCustomObject]@{
        Domain = $domainNormalized
        Mode = $mode
        ExplicitAllowed = $explicitAllowed
        ExplicitBlocked = $explicitBlocked
        EffectiveAllowed = $effectiveAllowed
    }
}

function Get-ExternalCollabTeamsDomainPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Config,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][ValidateSet('ADD','REMOVE')][string]$Intent
    )

    $state = Get-ExternalCollabTeamsDomainState -Config $Config -Domain $Domain
    $changeKind = 'NONE'
    $supported = $true
    $reason = ''
    $desiredEffectiveAllowed = ($Intent -eq 'ADD')

    if ($Intent -eq 'ADD') {
        switch ($state.Mode) {
            'ALLOWLIST' { if (-not $state.ExplicitAllowed) { $changeKind = 'ADD_ALLOWED' } else { $reason = 'already present in Teams allowlist' } }
            'ALLOW_ALL' { if ($state.ExplicitBlocked) { $changeKind = 'REMOVE_BLOCKED' } else { $reason = 'already effectively allowed by Teams ALLOW_ALL' } }
            'BLOCK_ALL' { $changeKind = 'ADD_ALLOWED'; $reason = 'adding the first allowed domain changes Teams from BLOCK_ALL to ALLOWLIST' }
            'DISABLED' { $supported = $false; $reason = 'Teams External Access is disabled; Denim Demon will not enable the tenant-wide master switch automatically' }
            default { $supported = $false; $reason = ('unsupported Teams federation mode: {0}' -f $state.Mode) }
        }
    }
    else {
        switch ($state.Mode) {
            'ALLOWLIST' { if ($state.ExplicitAllowed) { $changeKind = 'REMOVE_ALLOWED' } else { $reason = 'already absent from Teams allowlist and therefore blocked' } }
            'ALLOW_ALL' { if (-not $state.ExplicitBlocked) { $changeKind = 'ADD_BLOCKED' } else { $reason = 'already blocked in Teams ALLOW_ALL' } }
            'BLOCK_ALL' { $reason = 'already blocked by Teams BLOCK_ALL' }
            'DISABLED' { $reason = 'already blocked because Teams External Access is disabled' }
            default { $supported = $false; $reason = ('unsupported Teams federation mode: {0}' -f $state.Mode) }
        }
    }

    [PSCustomObject]@{
        Domain = $state.Domain
        Intent = $Intent
        Mode = $state.Mode
        Supported = $supported
        NeedsChange = ($changeKind -ne 'NONE')
        ChangeKind = $changeKind
        Reason = $reason
        CurrentEffectiveAllowed = $state.EffectiveAllowed
        DesiredEffectiveAllowed = $desiredEffectiveAllowed
        OriginalState = $state
    }
}

function Test-ExternalCollabTeamsDomainPlanApplied {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Config,[Parameter(Mandatory = $true)][object]$Plan)

    $state = Get-ExternalCollabTeamsDomainState -Config $Config -Domain $Plan.Domain
    switch ([string]$Plan.ChangeKind) {
        'ADD_ALLOWED' { return ($state.Mode -eq 'ALLOWLIST' -and $state.ExplicitAllowed) }
        'REMOVE_ALLOWED' { return (-not $state.ExplicitAllowed) }
        'ADD_BLOCKED' { return ($state.Mode -eq 'ALLOW_ALL' -and $state.ExplicitBlocked) }
        'REMOVE_BLOCKED' { return ($state.Mode -eq 'ALLOW_ALL' -and -not $state.ExplicitBlocked) }
        'NONE' { if (-not $Plan.Supported) { return $true }; return ($state.EffectiveAllowed -eq $Plan.DesiredEffectiveAllowed) }
        default { return $false }
    }
}

function Get-ExternalCollabTeamsInverseChangeKind {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ChangeKind)

    switch ($ChangeKind) {
        'ADD_ALLOWED' { 'REMOVE_ALLOWED' }
        'REMOVE_ALLOWED' { 'ADD_ALLOWED' }
        'ADD_BLOCKED' { 'REMOVE_BLOCKED' }
        'REMOVE_BLOCKED' { 'ADD_BLOCKED' }
        default { 'NONE' }
    }
}

function Invoke-ExternalCollabTeamsDomainMutation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][ValidateSet('ADD_ALLOWED','REMOVE_ALLOWED','ADD_BLOCKED','REMOVE_BLOCKED')][string]$Operation
    )

    $domainNormalized = $Domain.Trim().ToLowerInvariant()
    Clear-ExternalCollabTeamsFederationCache
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    switch ($Operation) {
        'ADD_ALLOWED' {
            # MicrosoftTeams 7.x AutoRest binding is sensitive here. Use the same shape as the
            # known-good native PowerShell 7 command tested interactively against the tenant.
            $list = New-Object Collections.Generic.List[String]
            [void]$list.Add($domainNormalized)
            Write-Status -Status INFO -Message ("Microsoft Teams: adding {0} to the allowed domains list" -f $domainNormalized)
            Set-CsTenantFederationConfiguration -AllowedDomainsAsAList @{Add=$list} -ErrorAction Stop | Out-Null
        }
        'REMOVE_ALLOWED' {
            $list = New-Object Collections.Generic.List[String]
            [void]$list.Add($domainNormalized)
            Write-Status -Status INFO -Message ("Microsoft Teams: removing {0} from the allowed domains list" -f $domainNormalized)
            Set-CsTenantFederationConfiguration -AllowedDomainsAsAList @{Remove=$list} -ErrorAction Stop | Out-Null
        }
        'ADD_BLOCKED' {
            $pattern = New-CsEdgeDomainPattern -Domain $domainNormalized -ErrorAction Stop
            Write-Status -Status INFO -Message ("Microsoft Teams: adding {0} to the blocked domains list" -f $domainNormalized)
            Set-CsTenantFederationConfiguration -BlockedDomains @{Add=$pattern} -ErrorAction Stop | Out-Null
        }
        'REMOVE_BLOCKED' {
            $pattern = New-CsEdgeDomainPattern -Domain $domainNormalized -ErrorAction Stop
            Write-Status -Status INFO -Message ("Microsoft Teams: removing {0} from the blocked domains list" -f $domainNormalized)
            Set-CsTenantFederationConfiguration -BlockedDomains @{Remove=$pattern} -ErrorAction Stop | Out-Null
        }
    }

    $timer.Stop()
    Write-Status -Status OK -Message ("Microsoft Teams domain change submitted in {0:N2}s: {1} {2}" -f $timer.Elapsed.TotalSeconds, $Operation, $domainNormalized)
}

function Wait-ExternalCollabTeamsDomainPlanApplied {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][object]$Plan,
        [int]$MaxAttempts = 6,
        [int]$DelaySeconds = 2
    )

    $lastConfig = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Status -Status INFO -Message ("Refreshing Microsoft Teams federation configuration for verification (attempt {0}/{1})..." -f $attempt, $MaxAttempts)
        $lastConfig = Get-ExternalCollabTeamsNativeConfig
        Set-ExternalCollabTeamsFederationCache -TenantId ([string]$Context.TenantId) -Config $lastConfig
        if (Test-ExternalCollabTeamsDomainPlanApplied -Config $lastConfig -Plan $Plan) {
            return [PSCustomObject]@{ Success = $true; Attempts = $attempt; Config = $lastConfig }
        }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return [PSCustomObject]@{ Success = $false; Attempts = $MaxAttempts; Config = $lastConfig }
}

function Wait-ExternalCollabTeamsOriginalDomainState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Context,
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][object]$OriginalState,
        [int]$MaxAttempts = 6,
        [int]$DelaySeconds = 2
    )

    $lastConfig = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        Write-Status -Status INFO -Message ("Refreshing Microsoft Teams federation configuration for rollback verification (attempt {0}/{1})..." -f $attempt, $MaxAttempts)
        $lastConfig = Get-ExternalCollabTeamsNativeConfig
        Set-ExternalCollabTeamsFederationCache -TenantId ([string]$Context.TenantId) -Config $lastConfig
        $state = Get-ExternalCollabTeamsDomainState -Config $lastConfig -Domain $Domain
        if ($state.EffectiveAllowed -eq $OriginalState.EffectiveAllowed -and $state.ExplicitAllowed -eq $OriginalState.ExplicitAllowed -and $state.ExplicitBlocked -eq $OriginalState.ExplicitBlocked) {
            return [PSCustomObject]@{ Success = $true; Attempts = $attempt; Config = $lastConfig }
        }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return [PSCustomObject]@{ Success = $false; Attempts = $MaxAttempts; Config = $lastConfig }
}

function Write-ExternalCollabTeamsDomainPlan {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Plan)

    if (-not $Plan.Supported) { Write-WrappedStatus -Status WARN -Message ("Microsoft Teams unchanged: {0}" -f $Plan.Reason); return }
    switch ([string]$Plan.ChangeKind) {
        'ADD_ALLOWED' { Write-WrappedStatus -Status INFO -Message ("Microsoft Teams will add {0} to the allowlist ({1})" -f $Plan.Domain, $Plan.Mode) }
        'REMOVE_ALLOWED' { Write-WrappedStatus -Status WARN -Message ("Microsoft Teams will remove {0} from the allowlist ({1})" -f $Plan.Domain, $Plan.Mode) }
        'ADD_BLOCKED' { Write-WrappedStatus -Status WARN -Message ("Microsoft Teams will block {0} because federation mode is ALLOW_ALL" -f $Plan.Domain) }
        'REMOVE_BLOCKED' { Write-WrappedStatus -Status INFO -Message ("Microsoft Teams will remove {0} from the blocked list because federation mode is ALLOW_ALL" -f $Plan.Domain) }
        default { Write-WrappedStatus -Status OK -Message ("Microsoft Teams unchanged: {0}" -f $Plan.Reason) }
    }
}

function Write-TeamsConnectionContext {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Context)

    if (-not [string]::IsNullOrWhiteSpace([string]$Context.Account)) { Write-DetailStatus -Status OK -Message ("Teams account: {0}" -f $Context.Account) }
    if (-not [string]::IsNullOrWhiteSpace([string]$Context.DisplayName)) { Write-DetailStatus -Status OK -Message ("Teams tenant:  {0}" -f $Context.DisplayName) }
    if (-not [string]::IsNullOrWhiteSpace([string]$Context.TenantId)) { Write-DetailStatus -Status OK -Message ("Teams tenant ID: {0}" -f $Context.TenantId) }
    else { Write-Status -Status WARN -Message 'Teams tenant ID could not be resolved' }

    $authLabel = switch ([string]$Context.AuthMode) {
        'NATIVE_REUSE' { 'existing PowerShell 7 session' }
        'NATIVE_INTERACTIVE' { 'native PowerShell 7 interactive' }
        default { [string]$Context.AuthMode }
    }
    if (-not [string]::IsNullOrWhiteSpace($authLabel)) { Write-DetailStatus -Status OK -Message ("Teams authentication: {0}" -f $authLabel) }
}

function Write-TeamsDomainList {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Title,[string[]]$Domains)

    $items = @($Domains | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    if ($items.Count -eq 0) { return }
    Write-Step $Title
    foreach ($domain in $items) { Write-Host ('  {0}' -f $domain) }
}

function Write-TeamsExternalAccessResult {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Config,[switch]$Compact)

    switch ($Config.Mode) {
        'ALLOW_ALL' {
            Write-Status -Status OK -Message 'Microsoft Teams External Access enabled'
            Write-Status -Status WARN -Message 'Teams federation mode: ALLOW_ALL'
            Write-WrappedStatus -Status INFO -Message 'All known external domains are allowed unless they are explicitly blocked.'
            Write-SummaryMetric -Status OK -Label 'Teams blocked domains' -Value $Config.BlockedDomains.Count
            if (-not $Compact) { Write-TeamsDomainList -Title 'Teams blocked domains...' -Domains $Config.BlockedDomains }
        }
        'ALLOWLIST' {
            Write-Status -Status OK -Message 'Microsoft Teams External Access enabled'
            Write-Status -Status OK -Message 'Teams federation mode: ALLOWLIST'
            Write-SummaryMetric -Status OK -Label 'Teams allowed domains' -Value $Config.AllowedDomains.Count
            Write-SummaryMetric -Status INFO -Label 'Teams blocked domains' -Value $Config.BlockedDomains.Count
            if ($Compact) { Write-Status -Status INFO -Message 'Use -TeamsAudit to list the configured Teams domain sets' }
            else {
                Write-TeamsDomainList -Title 'Teams allowed domains...' -Domains $Config.AllowedDomains
                Write-TeamsDomainList -Title 'Teams blocked domains...' -Domains $Config.BlockedDomains
            }
        }
        'BLOCK_ALL' {
            Write-Status -Status OK -Message 'Microsoft Teams External Access tenant switch enabled'
            Write-Status -Status WARN -Message 'Teams federation mode: BLOCK_ALL'
            Write-WrappedStatus -Status INFO -Message 'No tenant-wide allowed domains are configured. Explicit ExternalAccessPolicy assignments may still permit federation for selected users.'
            Write-SummaryMetric -Status OK -Label 'Teams allowed domains' -Value 0
            Write-SummaryMetric -Status INFO -Label 'Teams blocked domains' -Value $Config.BlockedDomains.Count
        }
        'DISABLED' {
            Write-Status -Status WARN -Message 'Microsoft Teams External Access disabled'
            Write-Status -Status WARN -Message 'Teams federation mode: DISABLED'
            Write-WrappedStatus -Status INFO -Message 'AllowFederatedUsers is disabled, so tenant-wide federation is blocked regardless of the configured domain lists.'
        }
        default {
            Write-Status -Status WARN -Message 'Microsoft Teams External Access mode could not be classified'
            Write-Status -Status WARN -Message ("Teams federation mode: {0}" -f $Config.Mode)
            Write-SummaryMetric -Status INFO -Label 'Parsed Teams allowed domains' -Value $Config.AllowedDomains.Count
            Write-SummaryMetric -Status INFO -Label 'Parsed Teams blocked domains' -Value $Config.BlockedDomains.Count
        }
    }
}

function Invoke-ExternalCollabTeamsAudit {
    [CmdletBinding()]
    param([switch]$ForceReauth,[switch]$ForceRefresh)

    $null = Invoke-TeamsNativePreflight
    Write-Step $(if ($script:FullVerbose) { 'Authenticating...' } else { 'Authentication...' })
    $context = Connect-ExternalCollabTeamsNative -ForceReauth:$ForceReauth
    Write-TeamsConnectionContext -Context $context
    if (-not $script:FullVerbose) { Write-Status -Status OK -Message 'Microsoft Teams authentication ready' }

    Write-Step 'Fetching external collaboration configuration...'
    $config = Get-ExternalCollabTeamsConfig -Context $context -ForceRefresh:($ForceRefresh -or $ForceReauth)
    Write-TeamsExternalAccessResult -Config $config

    Write-Host
    Write-Status -Status OK -Message 'Teams External Access audit complete'
    Write-Status -Status INFO -Message 'No changes were made.'
    return [PSCustomObject]@{ TeamsContext = $context; Config = $config }
}

#endregion Teams

#region Entra

function Get-EntraExternalCollabConfig {
    [CmdletBinding()]
    param()

    # Use the Graph beta endpoint directly. This avoids coupling the script to
    # the generated cmdlet name while still using the current beta resource.
    $response = Invoke-MgGraphRequest `
        -Method GET `
        -Uri 'https://graph.microsoft.com/beta/policies/b2bManagementPolicies'

    $policies = @($response.value)

    $policy = $policies |
        Where-Object { $_.isOrganizationDefault -eq $true } |
        Select-Object -First 1

    if ($null -eq $policy) {
        throw 'No organization-default Entra B2B management policy was returned.'
    }

    if ($null -eq $policy.definition -or @($policy.definition).Count -lt 1) {
        throw 'Entra B2B management policy contains no definition.'
    }

    $definition = $policy.definition[0] | ConvertFrom-Json
    $domainPolicy = $definition.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy

    if ($null -eq $domainPolicy) {
        throw 'InvitationsAllowedAndBlockedDomainsPolicy was not found in the Entra B2B policy definition.'
    }

    $mode = 'Unknown'
    $domains = @()

    if ($null -ne $domainPolicy.PSObject.Properties['AllowedDomains']) {
        $mode = 'AllowList'
        $domains = @($domainPolicy.AllowedDomains)
    }
    elseif ($null -ne $domainPolicy.PSObject.Properties['BlockedDomains']) {
        $mode = 'BlockList'
        $domains = @($domainPolicy.BlockedDomains)
    }

    $normalizedDomains = @(
        $domains |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Sort-Object -Unique
    )

    [PSCustomObject]@{
        PolicyId = $policy.id
        Mode     = $mode
        Domains  = $normalizedDomains
        Raw      = $policy
    }
}

function Set-EntraExternalCollabDomains {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Config,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Domains
    )

    if ($Config.Mode -ne 'AllowList') {
        throw ("Entra ID domain update requires AllowList mode. Current mode: {0}" -f $Config.Mode)
    }

    $definitions = @($Config.Raw.definition)
    if ($definitions.Count -lt 1) {
        throw 'Entra B2B management policy contains no definition to update.'
    }

    $definition = $definitions[0] | ConvertFrom-Json
    $domainPolicy = $definition.B2BManagementPolicy.InvitationsAllowedAndBlockedDomainsPolicy

    if ($null -eq $domainPolicy -or $null -eq $domainPolicy.PSObject.Properties['AllowedDomains']) {
        throw 'AllowedDomains was not found in the Entra B2B policy definition.'
    }

    $normalizedDomains = @(
        $Domains |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Sort-Object -Unique
    )

    $domainPolicy.AllowedDomains = @($normalizedDomains)
    $definitions[0] = $definition | ConvertTo-Json -Depth 100 -Compress

    $body = @{
        definition = @($definitions)
    } | ConvertTo-Json -Depth 100 -Compress

    Invoke-MgGraphRequest `
        -Method PATCH `
        -Uri ("https://graph.microsoft.com/beta/policies/b2bManagementPolicies/{0}" -f $Config.PolicyId) `
        -Body $body `
        -ContentType 'application/json' | Out-Null
}

#endregion Entra

#region SharePoint

function Get-SharePointExternalCollabConfig {
    [CmdletBinding()]
    param()

    $settings = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings?$select=sharingDomainRestrictionMode,sharingAllowedDomainList,sharingBlockedDomainList'
    if ($null -eq $settings) { throw 'Microsoft Graph returned no SharePoint tenant settings.' }

    $rawMode = [string]$settings.sharingDomainRestrictionMode
    $mode = switch ($rawMode.ToLowerInvariant()) {
        'allowlist' { 'AllowList' }
        'blocklist' { 'BlockList' }
        'none' { 'None' }
        default { if ([string]::IsNullOrWhiteSpace($rawMode)) { 'Unknown' } else { $rawMode } }
    }

    $domains = @()
    if ($mode -eq 'AllowList') { $domains = @($settings.sharingAllowedDomainList) }
    elseif ($mode -eq 'BlockList') { $domains = @($settings.sharingBlockedDomainList) }

    $normalizedDomains = @(
        $domains |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
            Sort-Object -Unique
    )

    [PSCustomObject]@{
        Mode = $mode
        Domains = $normalizedDomains
        Raw = $settings
    }
}

function Set-SharePointExternalCollabDomains {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Config,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Domains
    )

    # The write always targets sharingAllowedDomainList, so the caller's mode assumption
    # is verified here rather than only at the call sites (rollback paths included).
    if ($Config.Mode -ne 'AllowList') {
        throw ("SharePoint domain update requires AllowList mode. Current mode: {0}" -f $Config.Mode)
    }

    $normalizedDomains = @(
        $Domains |
            Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
            ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
            Sort-Object -Unique
    )

    $body = @{ sharingAllowedDomainList = @($normalizedDomains) } | ConvertTo-Json -Depth 10 -Compress
    Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/admin/sharepoint/settings' -Body $body -ContentType 'application/json' | Out-Null
}

function Wait-SharePointExternalCollabDomainState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Domain,
        [Parameter(Mandatory = $true)][bool]$ShouldExist,
        [int]$MaxAttempts = 10,
        [int]$DelaySeconds = 2
    )

    # A single tenant-settings write can carry several domains, so convergence is checked
    # for the whole set: the read-back only counts once every domain has settled.
    $domainSet = @($Domain | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $lastConfig = $null
    $pending = @($domainSet)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $lastConfig = Get-SharePointExternalCollabConfig
        $pending = @($domainSet | Where-Object { ($lastConfig.Domains -contains $_) -ne $ShouldExist })
        if ($pending.Count -eq 0) { return [PSCustomObject]@{ Success = $true; Attempts = $attempt; Config = $lastConfig; Pending = @() } }
        if ($attempt -eq 1 -and $MaxAttempts -gt 1) { Write-Status -Status INFO -Message 'Waiting for SharePoint configuration to converge...' }
        if ($attempt -lt $MaxAttempts) { Start-Sleep -Seconds $DelaySeconds }
    }
    return [PSCustomObject]@{ Success = $false; Attempts = $MaxAttempts; Config = $lastConfig; Pending = @($pending) }
}

#endregion SharePoint

#region Guests

function Get-ExternalGuestInviteClassification {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$ExternalUserState
    )

    switch ($ExternalUserState) {
        'Accepted' { return 'Accepted' }
        'PendingAcceptance' { return 'PendingAcceptance' }
        default { return 'Rogue' }
    }
}

function Get-ExternalGuestAgeDays {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$CreatedDateTime
    )

    if ($null -eq $CreatedDateTime -or [string]::IsNullOrWhiteSpace([string]$CreatedDateTime)) {
        return $null
    }

    try {
        $created = ([datetimeoffset]$CreatedDateTime).ToUniversalTime()
        return [Math]::Max(0, [int][Math]::Floor(([datetimeoffset]::UtcNow - $created).TotalDays))
    }
    catch {
        return $null
    }
}

function Get-ExternalGuestInviteAuditIndex {
    [CmdletBinding()]
    param()

    # Do not add an activityDateTime clause here. Directory audit retention already bounds
    # the result set (30 days at most), and combining the clauses made Graph return 400.
    $filter = "activityDisplayName eq 'Invite external user'"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$([uri]::EscapeDataString($filter))&`$top=999"
    $events = @()

    while (-not [string]::IsNullOrWhiteSpace($uri)) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $uri
        $events += @($page.value)
        $uri = [string]$page.'@odata.nextLink'
    }

    $index = @{}

    foreach ($event in $events) {
        $invitedBy = $null
        if ($null -ne $event.initiatedBy.user -and -not [string]::IsNullOrWhiteSpace([string]$event.initiatedBy.user.userPrincipalName)) {
            $invitedBy = [string]$event.initiatedBy.user.userPrincipalName
        }
        elseif ($null -ne $event.initiatedBy.user -and -not [string]::IsNullOrWhiteSpace([string]$event.initiatedBy.user.displayName)) {
            $invitedBy = [string]$event.initiatedBy.user.displayName
        }
        elseif ($null -ne $event.initiatedBy.app -and -not [string]::IsNullOrWhiteSpace([string]$event.initiatedBy.app.displayName)) {
            $invitedBy = ('[APP] {0}' -f [string]$event.initiatedBy.app.displayName)
        }
        else {
            $invitedBy = '<unknown>'
        }

        $eventTime = $null
        try { $eventTime = [datetimeoffset]$event.activityDateTime } catch { $eventTime = $null }

        foreach ($target in @($event.targetResources)) {
            $targetId = [string]$target.id
            if ([string]::IsNullOrWhiteSpace($targetId)) { continue }

            $candidate = [PSCustomObject]@{
                Invited   = $eventTime
                InvitedBy = $invitedBy
                Result    = [string]$event.result
                Activity  = [string]$event.activityDisplayName
            }

            if (-not $index.ContainsKey($targetId)) {
                $index[$targetId] = $candidate
                continue
            }

            $existing = $index[$targetId]
            if ($null -ne $candidate.Invited -and ($null -eq $existing.Invited -or $candidate.Invited -gt $existing.Invited)) {
                $index[$targetId] = $candidate
            }
        }
    }

    [PSCustomObject]@{
        EventCount = $events.Count
        Index      = $index
    }
}

function Resolve-ExternalGuestInviterMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests
    )

    $rows = @($Guests)
    if ($rows.Count -eq 0) {
        return [PSCustomObject]@{
            Guests             = @()
            AuditAvailable     = $true
            EventCount         = 0
            InviterIdentified  = 0
            InviterUnavailable = 0
        }
    }

    Write-Step 'Resolving retained invitation audit trail...'

    $inviteIndex = @{}
    $auditAvailable = $true
    $auditEventCount = 0

    try {
        $auditResult = Get-ExternalGuestInviteAuditIndex
        $inviteIndex = $auditResult.Index
        $auditEventCount = [int]$auditResult.EventCount
        Write-Status -Status OK -Message ("Retained 'Invite external user' audit events {0}" -f $auditEventCount)
    }
    catch {
        $auditAvailable = $false
        Write-WrappedStatus -Status WARN -Message ("Invitation audit trail could not be read; purge preview will continue without InvitedBy metadata: {0}" -f $_.Exception.Message)
    }

    $resolved = foreach ($guest in $rows) {
        $invite = $null
        if ($auditAvailable -and $inviteIndex.ContainsKey([string]$guest.Id)) {
            $invite = $inviteIndex[[string]$guest.Id]
        }

        $invitedBy = if ($null -ne $invite) {
            [string]$invite.InvitedBy
        }
        elseif ($auditAvailable) {
            '<not in retained audit>'
        }
        else {
            '<audit unavailable>'
        }

        [PSCustomObject]@{
            Id                    = $guest.Id
            DisplayName           = $guest.DisplayName
            Mail                  = $guest.Mail
            UserPrincipalName     = $guest.UserPrincipalName
            Domain                = $guest.Domain
            DomainSource          = $guest.DomainSource
            AccountEnabled        = $guest.AccountEnabled
            ExternalUserState     = $guest.ExternalUserState
            InviteClassification  = $guest.InviteClassification
            CreatedDateTime       = $guest.CreatedDateTime
            LastSuccessfulSignIn  = $guest.LastSuccessfulSignIn
            LastInteractiveSignIn = $guest.LastInteractiveSignIn
            InvitedBy             = $invitedBy
            InvitedAt             = if ($null -ne $invite) { $invite.Invited } else { $null }
        }
    }

    $resolved = @($resolved)
    $identified = @($resolved | Where-Object { $_.InvitedBy -notlike '<*' }).Count

    return [PSCustomObject]@{
        Guests             = $resolved
        AuditAvailable     = $auditAvailable
        EventCount         = $auditEventCount
        InviterIdentified  = $identified
        InviterUnavailable = $resolved.Count - $identified
    }
}

function Get-ExternalGuestInventory {
    [CmdletBinding()]
    param()

    $properties = @(
        'Id',
        'DisplayName',
        'UserPrincipalName',
        'Mail',
        'AccountEnabled',
        'ExternalUserState',
        'CreatedDateTime',
        'SignInActivity'
    )

    $users = @(
        Get-MgBetaUser `
            -Filter "userType eq 'Guest'" `
            -All `
            -Property $properties |
            Where-Object { $_.UserPrincipalName -like '*#EXT#*' }
    )

    $inventory = foreach ($user in $users) {
        $domain = $null
        $domainSource = $null

        if ($user.Mail -match '@([^@]+)$') {
            $domain = $Matches[1].ToLowerInvariant()
            $domainSource = 'Mail'
        }
        elseif ($user.UserPrincipalName -match '_([^_]+)#EXT#@') {
            $domain = $Matches[1].ToLowerInvariant()
            $domainSource = 'UPN'
        }

        if ($null -eq $domain) {
            continue
        }

        $lastSuccessful = $null
        $lastInteractive = $null

        if ($null -ne $user.SignInActivity) {
            if ($user.SignInActivity.LastSuccessfulSignInDateTime) {
                $lastSuccessful = $user.SignInActivity.LastSuccessfulSignInDateTime
            }

            if ($user.SignInActivity.LastSignInDateTime) {
                $lastInteractive = $user.SignInActivity.LastSignInDateTime
            }
        }

        [PSCustomObject]@{
            Id                    = $user.Id
            DisplayName           = $user.DisplayName
            Mail                  = $user.Mail
            UserPrincipalName     = $user.UserPrincipalName
            Domain                = $domain
            DomainSource          = $domainSource
            AccountEnabled        = $user.AccountEnabled
            ExternalUserState     = $user.ExternalUserState
            InviteClassification  = Get-ExternalGuestInviteClassification -ExternalUserState $user.ExternalUserState
            CreatedDateTime       = $user.CreatedDateTime
            LastSuccessfulSignIn  = $lastSuccessful
            LastInteractiveSignIn = $lastInteractive
        }
    }

    @($inventory)
}

function Get-GuestDomainSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests
    )

    $rogueRecentThreshold = [datetimeoffset]::UtcNow.AddDays(-1 * $script:RogueRecentActivityDays)

    @(
        $Guests |
            Group-Object Domain |
            ForEach-Object {
                $accepted = @(
                    $_.Group | Where-Object { $_.InviteClassification -eq 'Accepted' }
                ).Count

                $pending = @(
                    $_.Group | Where-Object { $_.InviteClassification -eq 'PendingAcceptance' }
                ).Count

                $rogue = @(
                    $_.Group | Where-Object { $_.InviteClassification -eq 'Rogue' }
                ).Count

                $rogueRecent = @(
                    $_.Group |
                        Where-Object {
                            $_.InviteClassification -eq 'Rogue' -and
                            $null -ne $_.LastSuccessfulSignIn -and
                            ([datetimeoffset]$_.LastSuccessfulSignIn).ToUniversalTime() -ge $rogueRecentThreshold
                        }
                ).Count

                $lastSuccessful = $_.Group |
                    Where-Object { $null -ne $_.LastSuccessfulSignIn } |
                    Sort-Object LastSuccessfulSignIn -Descending |
                    Select-Object -First 1 -ExpandProperty LastSuccessfulSignIn

                [PSCustomObject]@{
                    Domain               = $_.Name
                    Guests               = $_.Count
                    Accepted             = $accepted
                    Pending              = $pending
                    Rogue                = $rogue
                    RogueRecent          = $rogueRecent
                    LastSuccessfulSignIn = $lastSuccessful
                }
            }
    )
}


function Format-ExternalCollabDateTime {
    [CmdletBinding()]
    param(
        [object]$Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return '-'
    }

    try {
        return ([datetimeoffset]$Value).ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    }
    catch {
        $text = [string]$Value
        if ($text.Length -gt 16) {
            return $text.Substring(0, 16)
        }
        return $text
    }
}

function Get-BoundedColumnWidth {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Values,

        [Parameter(Mandatory = $true)]
        [string]$Header,

        [Parameter(Mandatory = $true)]
        [int]$Minimum,

        [Parameter(Mandatory = $true)]
        [int]$Maximum
    )

    $width = $Header.Length
    foreach ($value in $Values) {
        $candidate = [string]$value
        if ($candidate.Length -gt $width) {
            $width = $candidate.Length
        }
    }

    if ($width -lt $Minimum) {
        $width = $Minimum
    }
    if ($width -gt $Maximum) {
        $width = $Maximum
    }

    return $width
}

function Limit-ExternalCollabText {
    [CmdletBinding()]
    param(
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [int]$Width
    )

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return '-'
    }

    if ($text.Length -le $Width) {
        return $text
    }

    if ($Width -le 1) {
        return $text.Substring(0, $Width)
    }

    return ($text.Substring(0, $Width - 1) + '~')
}

function Write-GuestInviteState {
    [CmdletBinding()]
    param(
        [string]$State,
        [switch]$NoNewline
    )

    $display = Get-ExternalGuestInviteClassification -ExternalUserState $State
    $ansi = $script:Nord.Orange
    $fallback = 'DarkYellow'

    switch ($display) {
        'Accepted' {
            $ansi = $script:Nord.Green
            $fallback = 'Green'
        }
        'PendingAcceptance' {
            $ansi = $script:Nord.Yellow
            $fallback = 'Yellow'
        }
        'Rogue' {
            $ansi = $script:Nord.Orange
            $fallback = 'DarkYellow'
        }
    }

    if ($script:UseAnsi) {
        Write-Host ("{0}{1}{2}" -f $ansi, $display, $script:Nord.Reset) -NoNewline:$NoNewline
    }
    else {
        Write-Host $display -ForegroundColor $fallback -NoNewline:$NoNewline
    }
}

function Write-ExternalGuestTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests,

        [switch]$IncludeDomain,

        [hashtable]$DomainStateMap
    )

    $rows = @($Guests)
    if ($rows.Count -eq 0) {
        return
    }

    $domainWidth = 0
    if ($IncludeDomain) {
        $domainWidth = Get-BoundedColumnWidth -Values @($rows.Domain) -Header 'Domain' -Minimum 16 -Maximum 30
    }

    $nameWidth = Get-BoundedColumnWidth -Values @($rows.DisplayName) -Header 'Name' -Minimum 18 -Maximum 30
    $mailWidth = Get-BoundedColumnWidth -Values @($rows.Mail) -Header 'Mail' -Minimum 24 -Maximum 46

    if ($IncludeDomain) {
        $header = ("  {0,-$domainWidth}  {1,-$nameWidth}  {2,-$mailWidth}  {3,-16}  {4,-16}  {5}" -f `
            'Domain', 'Name', 'Mail', 'Created', 'LastSuccess', 'Invite')
        $separator = ('  ' + ('-' * $domainWidth) + '  ' + ('-' * $nameWidth) + '  ' + ('-' * $mailWidth) + '  ----------------  ----------------  -----------------')
    }
    else {
        $header = ("  {0,-$nameWidth}  {1,-$mailWidth}  {2,-16}  {3,-16}  {4}" -f `
            'Name', 'Mail', 'Created', 'LastSuccess', 'Invite')
        $separator = ('  ' + ('-' * $nameWidth) + '  ' + ('-' * $mailWidth) + '  ----------------  ----------------  -----------------')
    }

    if ($script:UseAnsi) {
        Write-Host ("{0}{1}{2}" -f $script:Nord.Frost3, $header, $script:Nord.Reset)
        Write-Host ("{0}{1}{2}" -f $script:Nord.Muted, $separator, $script:Nord.Reset)
    }
    else {
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray
    }

    foreach ($guest in $rows) {
        $name = Limit-ExternalCollabText -Value $guest.DisplayName -Width $nameWidth
        $mail = Limit-ExternalCollabText -Value $guest.Mail -Width $mailWidth
        $created = Format-ExternalCollabDateTime -Value $guest.CreatedDateTime
        $lastSuccess = Format-ExternalCollabDateTime -Value $guest.LastSuccessfulSignIn

        if ($IncludeDomain) {
            $domain = Limit-ExternalCollabText -Value $guest.Domain -Width $domainWidth
            $domainPadded = ("{0,-$domainWidth}" -f $domain)
            $domainState = $null

            if ($null -ne $DomainStateMap -and $DomainStateMap.ContainsKey($guest.Domain)) {
                $domainState = [string]$DomainStateMap[$guest.Domain]
            }

            Write-Host '  ' -NoNewline
            $inviteClassification = if (-not [string]::IsNullOrWhiteSpace([string]$guest.InviteClassification)) {
                [string]$guest.InviteClassification
            }
            else {
                Get-ExternalGuestInviteClassification -ExternalUserState $guest.ExternalUserState
            }

            # Highlight only the actual Rogue guest row. Other users from the same domain
            # keep the normal OK / DRIFT / ORPHANED domain colour.
            if ($inviteClassification -eq 'Rogue') {
                if ($script:UseAnsi) {
                    Write-Host ("{0}{1}{2}" -f $script:Nord.Orange, $domainPadded, $script:Nord.Reset) -NoNewline
                }
                else {
                    Write-Host $domainPadded -ForegroundColor DarkYellow -NoNewline
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace($domainState)) {
                Write-ExternalCollabStateText -State $domainState -Text $domainPadded -NoNewline
            }
            else {
                Write-Host $domainPadded -NoNewline
            }

            Write-Host ("  {0,-$nameWidth}  {1,-$mailWidth}  {2,-16}  {3,-16}  " -f `
                $name, $mail, $created, $lastSuccess) -NoNewline
        }
        else {
            Write-Host ("  {0,-$nameWidth}  {1,-$mailWidth}  {2,-16}  {3,-16}  " -f `
                $name, $mail, $created, $lastSuccess) -NoNewline
        }

        Write-GuestInviteState -State $guest.ExternalUserState
    }
}

function Write-ExternalGuestPurgeTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests,

        [switch]$IncludeDomain
    )

    $rows = @($Guests)
    if ($rows.Count -eq 0) { return }

    $domainWidth = 0
    if ($IncludeDomain) {
        $domainWidth = Get-BoundedColumnWidth -Values @($rows.Domain) -Header 'Domain' -Minimum 16 -Maximum 28
    }

    $nameWidth = Get-BoundedColumnWidth -Values @($rows.DisplayName) -Header 'Name' -Minimum 18 -Maximum 28
    $mailWidth = Get-BoundedColumnWidth -Values @($rows.Mail) -Header 'Mail' -Minimum 24 -Maximum 42
    $inviterWidth = Get-BoundedColumnWidth -Values @($rows.InvitedBy) -Header 'InvitedBy' -Minimum 24 -Maximum 42
    $inviteWidth = 17

    if ($IncludeDomain) {
        $header = ("  {0,-$domainWidth}  {1,-$nameWidth}  {2,-$mailWidth}  {3,-16}  {4,-16}  {5,-$inviterWidth}  {6,-$inviteWidth}" -f `
            'Domain', 'Name', 'Mail', 'Created', 'LastSuccess', 'InvitedBy', 'Invite')
        $separator = ('  ' + ('-' * $domainWidth) + '  ' + ('-' * $nameWidth) + '  ' + ('-' * $mailWidth) + '  ----------------  ----------------  ' + ('-' * $inviterWidth) + '  ' + ('-' * $inviteWidth))
    }
    else {
        $header = ("  {0,-$nameWidth}  {1,-$mailWidth}  {2,-16}  {3,-16}  {4,-$inviterWidth}  {5,-$inviteWidth}" -f `
            'Name', 'Mail', 'Created', 'LastSuccess', 'InvitedBy', 'Invite')
        $separator = ('  ' + ('-' * $nameWidth) + '  ' + ('-' * $mailWidth) + '  ----------------  ----------------  ' + ('-' * $inviterWidth) + '  ' + ('-' * $inviteWidth))
    }

    if ($script:UseAnsi) {
        Write-Host ("{0}{1}{2}" -f $script:Nord.Frost3, $header, $script:Nord.Reset)
        Write-Host ("{0}{1}{2}" -f $script:Nord.Muted, $separator, $script:Nord.Reset)
    }
    else {
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray
    }

    foreach ($guest in $rows) {
        $name = Limit-ExternalCollabText -Value $guest.DisplayName -Width $nameWidth
        $mail = Limit-ExternalCollabText -Value $guest.Mail -Width $mailWidth
        $created = Format-ExternalCollabDateTime -Value $guest.CreatedDateTime
        $lastSuccess = Format-ExternalCollabDateTime -Value $guest.LastSuccessfulSignIn
        $invitedBy = Limit-ExternalCollabText -Value $guest.InvitedBy -Width $inviterWidth
        $inviteClassification = if (-not [string]::IsNullOrWhiteSpace([string]$guest.InviteClassification)) {
            [string]$guest.InviteClassification
        }
        else {
            Get-ExternalGuestInviteClassification -ExternalUserState $guest.ExternalUserState
        }

        if ($IncludeDomain) {
            $domain = Limit-ExternalCollabText -Value $guest.Domain -Width $domainWidth
            $domainPadded = ("{0,-$domainWidth}" -f $domain)
            Write-Host '  ' -NoNewline
            if ($inviteClassification -eq 'Rogue') {
                if ($script:UseAnsi) {
                    Write-Host ("{0}{1}{2}" -f $script:Nord.Orange, $domainPadded, $script:Nord.Reset) -NoNewline
                }
                else {
                    Write-Host $domainPadded -ForegroundColor DarkYellow -NoNewline
                }
            }
            else {
                Write-Host $domainPadded -NoNewline
            }
            Write-Host ("  {0,-$nameWidth}  {1,-$mailWidth}  {2,-16}  {3,-16}  " -f $name, $mail, $created, $lastSuccess) -NoNewline
        }
        else {
            Write-Host ("  {0,-$nameWidth}  {1,-$mailWidth}  {2,-16}  {3,-16}  " -f $name, $mail, $created, $lastSuccess) -NoNewline
        }

        $invitedByPadded = ("{0,-$inviterWidth}" -f $invitedBy)
        if ($invitedBy -like '<*') {
            if ($script:UseAnsi) {
                Write-Host ("{0}{1}{2}" -f $script:Nord.Muted, $invitedByPadded, $script:Nord.Reset) -NoNewline
            }
            else {
                Write-Host $invitedByPadded -ForegroundColor DarkGray -NoNewline
            }
        }
        else {
            if ($script:UseAnsi) {
                Write-Host ("{0}{1}{2}" -f $script:Nord.Snow, $invitedByPadded, $script:Nord.Reset) -NoNewline
            }
            else {
                Write-Host $invitedByPadded -NoNewline
            }
        }
        Write-Host '  ' -NoNewline
        Write-GuestInviteState -State $guest.ExternalUserState
    }
}

function Show-ReviewExternalGuestUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Audit,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests
    )

    $reviewDomains = @(
        $Audit |
            Where-Object { $_.Guests -gt 0 -and ($_.State -ne 'OK' -or [int]$_.Rogue -gt 0) } |
            Sort-Object StateRank, Domain
    )

    Write-Step 'External users requiring review...'

    if ($reviewDomains.Count -eq 0) {
        Write-Status -Status OK -Message 'No guest accounts are attached to DRIFT / ORPHANED domains and no ROGUE guests were detected'
        return
    }

    foreach ($row in $reviewDomains) {
        $domainGuests = @(
            $Guests |
                Where-Object { $_.Domain -eq $row.Domain } |
                Sort-Object DisplayName, Mail
        )

        Write-Host
        if ($script:UseAnsi) {
            Write-Host ("  {0}Domain:{1} {2}" -f $script:Nord.Frost3, $script:Nord.Reset, $row.Domain) -NoNewline
        }
        else {
            Write-Host '  Domain: ' -NoNewline -ForegroundColor Cyan
            Write-Host $row.Domain -NoNewline
        }
        Write-Host '  ' -NoNewline
        Write-AuditState -State $row.State

        Write-ExternalGuestTable -Guests $domainGuests
    }
}

function Show-ExternalGuestListSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests
    )

    $accepted = @($Guests | Where-Object { $_.InviteClassification -eq 'Accepted' }).Count
    $pending = @($Guests | Where-Object { $_.InviteClassification -eq 'PendingAcceptance' }).Count
    $rogue = @($Guests | Where-Object { $_.InviteClassification -eq 'Rogue' }).Count
    $disabled = @($Guests | Where-Object { $_.AccountEnabled -eq $false }).Count

    Write-Step 'Guest summary...'
    Write-SummaryMetric -Status OK -Label 'Guest accounts' -Value $Guests.Count
    Write-SummaryMetric -Status OK -Label 'Accepted' -Value $accepted

    if ($pending -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Pending invitations' -Value $pending
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Pending invitations' -Value 0
    }

    if ($rogue -gt 0) {
        Write-SummaryMetric -Status ROGUE -Label 'Rogue guest accounts' -Value $rogue
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Rogue guest accounts' -Value 0
    }

    if ($disabled -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Disabled guest accounts' -Value $disabled
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Disabled guest accounts' -Value 0
    }
}

#endregion Guests

#region Preflight

function Invoke-ExternalCollabPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SharePointAdminUrl,
        [Parameter(Mandatory = $true)][string[]]$GraphScopes,
        [switch]$IncludeGuests,
        [switch]$IncludeTeams,
        [switch]$RequireTeams,
        [switch]$RequireTenantPin,
        [switch]$TeamsReauth,
        [switch]$TeamsRefresh
    )

    $runtime = Invoke-ExternalCollabRuntimePreflight -IncludeTeams:$IncludeTeams -RequireTeams:$RequireTeams

    Write-Step $(if ($script:FullVerbose) { 'Authenticating...' } else { 'Authentication...' })
    $resolvedSharePointTenantId = Get-SharePointTenantRealm -AdminUrl $SharePointAdminUrl
    if (-not [string]::IsNullOrWhiteSpace($resolvedSharePointTenantId)) {
        Write-DetailStatus -Status OK -Message ("SharePoint target tenant: {0}" -f $resolvedSharePointTenantId)
    }
    elseif ($RequireTenantPin) {
        throw 'Target tenant could not be resolved from the SharePoint Admin URL; refusing a write operation without a tenant safety boundary.'
    }
    else {
        Write-Status -Status WARN -Message 'SharePoint target tenant could not be resolved before authentication'
    }

    $context = Connect-ExternalCollabGraph -Scopes $GraphScopes -ExpectedTenantId $resolvedSharePointTenantId
    $sharePointTenantId = Test-ExternalCollabTenantConsistency -GraphContext $context -SharePointAdminUrl $SharePointAdminUrl -ResolvedSharePointTenantId $resolvedSharePointTenantId
    Write-DetailStatus -Status OK -Message 'SharePoint tenant settings authenticated through Microsoft Graph'

    $teamsContext = $null
    $teamsConfig = $null
    $teamsModule = $runtime.TeamsModule

    if ($IncludeTeams -and $null -ne $teamsModule) {
        try {
            $teamsContext = Connect-ExternalCollabTeamsNative -ExpectedTenantId $sharePointTenantId -ForceReauth:$TeamsReauth
            Write-TeamsConnectionContext -Context $teamsContext
            if (-not ([string]$teamsContext.TenantId).Equals([string]$sharePointTenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw ("Microsoft Teams tenant {0} does not match target tenant {1}." -f $teamsContext.TenantId, $sharePointTenantId)
            }
            Write-DetailStatus -Status OK -Message ("Tenant cross-check: Teams / target {0}" -f $sharePointTenantId)
        }
        catch {
            if ($RequireTeams) { throw ("Microsoft Teams authentication is required for this operation: {0}" -f $_.Exception.Message) }
            Write-WrappedStatus -Status WARN -Message ("Microsoft Teams authentication could not be completed: {0}" -f $_.Exception.Message)
            $teamsContext = $null
        }
    }
    elseif ($RequireTeams) {
        throw 'MicrosoftTeams is required for this operation.'
    }

    if (-not $script:FullVerbose) {
        $authProviders = if ($null -ne $teamsContext) { 'Microsoft Graph / Microsoft Teams' } else { 'Microsoft Graph' }
        Write-Status -Status OK -Message ("{0} authentication ready; target tenant verified" -f $authProviders)
    }

    Write-Step 'Fetching external collaboration configuration...'
    $entraConfig = Get-EntraExternalCollabConfig
    Write-Status -Status OK -Message ("Fetched Entra ID ext collab list       {0} domains ({1})" -f $entraConfig.Domains.Count, $entraConfig.Mode)

    $spoConfig = Get-SharePointExternalCollabConfig
    Write-Status -Status OK -Message ("Fetched SharePoint ext collab list     {0} domains ({1})" -f $spoConfig.Domains.Count, $spoConfig.Mode)

    if ($null -ne $teamsModule -and $null -ne $teamsContext) {
        try {
            $teamsConfig = Get-ExternalCollabTeamsConfig -Context $teamsContext -ForceRefresh:($TeamsRefresh -or $TeamsReauth)
            Write-TeamsExternalAccessResult -Config $teamsConfig -Compact
        }
        catch {
            if ($RequireTeams) { throw ("Microsoft Teams federation configuration is required for this operation: {0}" -f $_.Exception.Message) }
            Write-WrappedStatus -Status WARN -Message ("Microsoft Teams federation configuration could not be fetched: {0}" -f $_.Exception.Message)
            $teamsConfig = $null
        }
    }

    if ($RequireTeams -and $null -eq $teamsConfig) { throw 'Microsoft Teams federation configuration is required for this operation.' }
    if ($entraConfig.Mode -ne 'AllowList') { throw ("External Collaboration Manager {0} expects Entra ID AllowList mode. Current mode: {1}" -f $script:DisplayVersion, $entraConfig.Mode) }
    if ($spoConfig.Mode -ne 'AllowList') { throw ("External Collaboration Manager {0} expects SharePoint AllowList mode. Current mode: {1}" -f $script:DisplayVersion, $spoConfig.Mode) }

    $guests = @()
    if ($IncludeGuests) {
        $guests = @(Get-ExternalGuestInventory)
        $guestDomainCount = @($guests.Domain | Sort-Object -Unique).Count
        Write-Status -Status OK -Message ("Fetched Entra ID guest users           {0} users / {1} domains" -f $guests.Count, $guestDomainCount)
    }

    [PSCustomObject]@{
        GraphContext = $context
        SharePointTenantId = $sharePointTenantId
        EntraConfig = $entraConfig
        SPOConfig = $spoConfig
        TeamsModule = $teamsModule
        TeamsContext = $teamsContext
        TeamsConfig = $teamsConfig
        Guests = $guests
    }
}

function Invoke-ExternalGuestPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SharePointAdminUrl,
        [string[]]$GraphScopes
    )

    $effectiveGraphScopes = $GraphScopes
    if ($null -eq $effectiveGraphScopes -or $effectiveGraphScopes.Count -eq 0) { $effectiveGraphScopes = $script:GuestGraphScopes }

    $null = Invoke-ExternalCollabRuntimePreflight
    Write-Step $(if ($script:FullVerbose) { 'Authenticating...' } else { 'Authentication...' })
    $resolvedSharePointTenantId = Get-SharePointTenantRealm -AdminUrl $SharePointAdminUrl
    if (-not [string]::IsNullOrWhiteSpace($resolvedSharePointTenantId)) { Write-DetailStatus -Status OK -Message ("Target tenant: {0}" -f $resolvedSharePointTenantId) }
    else { Write-Status -Status WARN -Message 'Target tenant could not be resolved from SharePoint Admin URL' }

    $context = Connect-ExternalCollabGraph -Scopes $effectiveGraphScopes -ExpectedTenantId $resolvedSharePointTenantId
    if (-not $script:FullVerbose) { Write-Status -Status OK -Message 'Microsoft Graph authentication ready; target tenant verified' }
    Write-Step 'Fetching external guest users...'
    $guests = @(Get-ExternalGuestInventory)
    $guestDomainCount = @($guests.Domain | Sort-Object -Unique).Count
    Write-Status -Status OK -Message ("Fetched Entra ID guest users           {0} users / {1} domains" -f $guests.Count, $guestDomainCount)
    [PSCustomObject]@{ GraphContext = $context; Guests = $guests }
}

#endregion Preflight

#region Audit

function New-ExternalCollabAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$EntraDomains,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$SPODomains,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests,

        [object]$TeamsConfig
    )

    $entraNormalized = @(
        $EntraDomains |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Sort-Object -Unique
    )

    $spoNormalized = @(
        $SPODomains |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Sort-Object -Unique
    )

    $guestDomains = @(Get-GuestDomainSummary -Guests $Guests)

    $teamsMode = 'NONE'
    $teamsCompared = $false
    $teamsAllowed = @()
    $teamsBlocked = @()

    if ($null -ne $TeamsConfig) {
        $teamsMode = ([string]$TeamsConfig.Mode).Trim().ToUpperInvariant()
        $teamsAllowed = @(
            $TeamsConfig.AllowedDomains |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { $_.Trim().ToLowerInvariant() } |
                Sort-Object -Unique
        )
        $teamsBlocked = @(
            $TeamsConfig.BlockedDomains |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { $_.Trim().ToLowerInvariant() } |
                Sort-Object -Unique
        )

        # TeamsCompared drives the inventory column only; drift calculation below uses
        # $teamsMode directly. In ALLOW_ALL with no explicit blocks every domain is
        # effectively allowed, so the column would be a constant [ ok ] on every row and
        # is suppressed instead. BLOCK_ALL and DISABLED are the mirror case and already
        # fall through as $false.
        if ($teamsMode -eq 'ALLOWLIST') {
            $teamsCompared = $true
        }
        elseif ($teamsMode -eq 'ALLOW_ALL' -and $teamsBlocked.Count -gt 0) {
            $teamsCompared = $true
        }
    }

    $allDomainInput = @(
        $entraNormalized
        $spoNormalized
        $guestDomains.Domain
    )

    # In ALLOWLIST mode the Teams list is finite and therefore participates in the
    # configured-domain union. ALLOW_ALL is conceptually unbounded, so we compare
    # its effective state only for domains already known from Entra/SPO/guest data.
    if ($teamsMode -eq 'ALLOWLIST') {
        $allDomainInput += $teamsAllowed
    }

    $allDomains = @($allDomainInput | Sort-Object -Unique)

    $audit = foreach ($domain in $allDomains) {
        $inEntra = $entraNormalized -contains $domain
        $inSPO = $spoNormalized -contains $domain
        $inTeams = $false
        $teamsIsBlocked = $false
        $teamsStatus = 'SKIP'

        if ($teamsMode -eq 'ALLOWLIST') {
            $inTeams = $teamsAllowed -contains $domain
            $teamsStatus = if ($inTeams) { 'OK' } else { 'SKIP' }
        }
        elseif ($teamsMode -eq 'ALLOW_ALL') {
            $teamsIsBlocked = $teamsBlocked -contains $domain
            $inTeams = -not $teamsIsBlocked
            $teamsStatus = if ($teamsIsBlocked) { 'BLOCKED' } else { 'OK' }
        }

        $guestInfo = $guestDomains |
            Where-Object { $_.Domain -eq $domain } |
            Select-Object -First 1

        $guestCount = 0
        $accepted = 0
        $pending = 0
        $rogue = 0
        $rogueRecent = 0
        $lastSuccessful = $null

        if ($null -ne $guestInfo) {
            $guestCount = $guestInfo.Guests
            $accepted = $guestInfo.Accepted
            $pending = $guestInfo.Pending
            $rogue = $guestInfo.Rogue
            $rogueRecent = $guestInfo.RogueRecent
            $lastSuccessful = $guestInfo.LastSuccessfulSignIn
        }

        # ORPHANED remains specifically about Entra #EXT# guests whose external
        # domain is absent from both guest-sharing allowlists. Teams External Access
        # is federation, not guest access, so it must not hide an orphaned guest.
        if (-not $inEntra -and -not $inSPO -and $guestCount -gt 0) {
            $state = 'ORPHANED'
            $rank = 1
        }
        elseif ($teamsMode -eq 'ALLOWLIST') {
            if ($inEntra -and $inSPO -and $inTeams) {
                $state = 'OK'
                $rank = 2
            }
            else {
                $state = 'DRIFT'
                $rank = 0
            }
        }
        elseif ($teamsMode -eq 'ALLOW_ALL') {
            if ($inEntra -and $inSPO -and -not $teamsIsBlocked) {
                $state = 'OK'
                $rank = 2
            }
            else {
                $state = 'DRIFT'
                $rank = 0
            }
        }
        else {
            if ($inEntra -and $inSPO) {
                $state = 'OK'
                $rank = 2
            }
            else {
                $state = 'DRIFT'
                $rank = 0
            }
        }

        # A Teams-specific drift is one where Entra and SharePoint agree with each
        # other but Teams disagrees, or an ALLOW_ALL block explicitly conflicts with
        # an allowed Entra/SPO domain. Mixed Entra/SPO drift is still reported as
        # cross-provider drift but is not double-counted as Teams-specific.
        $teamsSpecificDrift = $false
        if ($teamsMode -eq 'ALLOWLIST') {
            if (($inEntra -eq $inSPO) -and ($inTeams -ne $inEntra)) {
                $teamsSpecificDrift = $true
            }
        }
        elseif ($teamsMode -eq 'ALLOW_ALL') {
            if ($teamsIsBlocked -and ($inEntra -or $inSPO)) {
                $teamsSpecificDrift = $true
            }
        }

        $configured = $inEntra -or $inSPO -or (($teamsMode -eq 'ALLOWLIST') -and $inTeams)

        [PSCustomObject]@{
            Domain               = $domain
            InEntra              = $inEntra
            InSPO                = $inSPO
            InTeams              = $inTeams
            TeamsBlocked         = $teamsIsBlocked
            TeamsStatus          = $teamsStatus
            TeamsMode            = $teamsMode
            TeamsCompared        = $teamsCompared
            TeamsSpecificDrift   = $teamsSpecificDrift
            Configured           = $configured
            Entra                = if ($inEntra) { '[ ok ]' } else { '[ -- ]' }
            SPO                  = if ($inSPO) { '[ ok ]' } else { '[ -- ]' }
            Teams                = if ($teamsStatus -eq 'OK') { '[ ok ]' } elseif ($teamsStatus -eq 'WARN' -or $teamsStatus -eq 'FAIL') { '[ !! ]' } else { '[ -- ]' }
            Guests               = $guestCount
            Accepted             = $accepted
            Pending              = $pending
            Rogue                = $rogue
            RogueRecent          = $rogueRecent
            LastSuccessfulSignIn = $lastSuccessful
            State                = $state
            StateRank            = $rank
        }
    }

    @($audit)
}

function Write-AuditState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('OK', 'DRIFT', 'ORPHANED')]
        [string]$State,

        [switch]$NoNewline
    )

    Write-ExternalCollabStateText -State $State -Text $State -NoNewline:$NoNewline
}

function Write-ExternalCollabAuditTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Audit
    )

    $domainWidth = 20
    foreach ($row in $Audit) {
        if ($row.Domain.Length -gt $domainWidth) {
            $domainWidth = $row.Domain.Length
        }
    }

    if ($domainWidth -gt 40) {
        $domainWidth = 40
    }

    $showTeams = @($Audit | Where-Object { $_.TeamsCompared } | Select-Object -First 1).Count -gt 0

    if ($showTeams) {
        $header = ("  {0,-$domainWidth}  {1,-6}  {2,-6}  {3,-6}  {4,6}  {5,8}  {6,7}  {7,5}  {8,-16}  {9}" -f `
            'Domain', 'Entra', 'SPO', 'Teams', 'Guests', 'Accepted', 'Pending', 'Rogue', 'LastSuccess', 'State')
        $separator = ('  ' + ('-' * $domainWidth) + '  ------  ------  ------  ------  --------  -------  -----  ----------------  ----------')
    }
    else {
        $header = ("  {0,-$domainWidth}  {1,-6}  {2,-6}  {3,6}  {4,8}  {5,7}  {6,5}  {7,-16}  {8}" -f `
            'Domain', 'Entra', 'SPO', 'Guests', 'Accepted', 'Pending', 'Rogue', 'LastSuccess', 'State')
        $separator = ('  ' + ('-' * $domainWidth) + '  ------  ------  ------  --------  -------  -----  ----------------  ----------')
    }

    if ($script:UseAnsi) {
        Write-Host ("{0}{1}{2}" -f $script:Nord.Frost3, $header, $script:Nord.Reset)
        Write-Host ("{0}{1}{2}" -f $script:Nord.Muted, $separator, $script:Nord.Reset)
    }
    else {
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray
    }

    foreach ($row in ($Audit | Sort-Object StateRank, Domain)) {
        $domain = [string]$row.Domain
        if ($domain.Length -gt $domainWidth) {
            $domain = $domain.Substring(0, $domainWidth - 1) + '~'
        }

        $lastSuccess = Format-ExternalCollabDateTime -Value $row.LastSuccessfulSignIn

        Write-Host ("  {0,-$domainWidth}  " -f $domain) -NoNewline
        Write-StatusTag -Status $(if ($row.InEntra) { 'OK' } else { 'SKIP' }) -NoNewline
        Write-Host '  ' -NoNewline
        Write-StatusTag -Status $(if ($row.InSPO) { 'OK' } else { 'SKIP' }) -NoNewline

        if ($showTeams) {
            Write-Host '  ' -NoNewline
            Write-StatusTag -Status $row.TeamsStatus -NoNewline
        }

        Write-Host ("  {0,6}  {1,8}  {2,7}  " -f $row.Guests, $row.Accepted, $row.Pending) -NoNewline
        $rogueText = ("{0,5}" -f $row.Rogue)
        if ([int]$row.Rogue -gt 0) {
            if ($script:UseAnsi) {
                Write-Host ("{0}{1}{2}" -f $script:Nord.Orange, $rogueText, $script:Nord.Reset) -NoNewline
            }
            else {
                Write-Host $rogueText -ForegroundColor DarkYellow -NoNewline
            }
        }
        else {
            Write-Host $rogueText -NoNewline
        }
        Write-Host ("  {0,-16}  " -f $lastSuccess) -NoNewline
        Write-AuditState -State $row.State
    }
}

function Show-DriftRecommendations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Audit
    )

    $drift = @($Audit | Where-Object { $_.State -eq 'DRIFT' } | Sort-Object Domain)

    if ($drift.Count -eq 0) {
        return
    }

    Write-Step 'Drift recommendations...'

    foreach ($row in $drift) {
        if ($row.TeamsMode -eq 'ALLOW_ALL' -and $row.TeamsBlocked) {
            $allowedSides = @()
            if ($row.InEntra) { $allowedSides += 'Entra ID' }
            if ($row.InSPO) { $allowedSides += 'SharePoint' }
            $allowedText = if ($allowedSides.Count -gt 0) { $allowedSides -join ' and ' } else { 'the guest-sharing configuration' }
            Write-WrappedStatus -Status WARN -Message ("{0}: explicitly blocked in Microsoft Teams while allowed in {1}; review the Teams External Access blocklist" -f $row.Domain, $allowedText)
            continue
        }

        if ($row.TeamsMode -eq 'ALLOWLIST') {
            $present = @()
            $missing = @()

            if ($row.InEntra) { $present += 'Entra ID' } else { $missing += 'Entra ID' }
            if ($row.InSPO) { $present += 'SharePoint' } else { $missing += 'SharePoint' }
            if ($row.InTeams) { $present += 'Microsoft Teams' } else { $missing += 'Microsoft Teams' }

            $presentText = if ($present.Count -gt 0) { $present -join ', ' } else { 'none' }
            $missingText = if ($missing.Count -gt 0) { $missing -join ', ' } else { 'none' }
            $message = ("{0}: present in {1}; missing from {2}" -f $row.Domain, $presentText, $missingText)

            if ($row.Guests -gt 0) {
                $message += ("; {0} guest(s)" -f $row.Guests)
            }
            else {
                $message += '; no guests'
            }

            if ($row.Guests -gt 0 -and $missing.Count -gt 0) {
                $message += ("; -AddDomain {0} can synchronize the missing configured providers" -f $row.Domain)
            }
            elseif ($row.Guests -eq 0) {
                $message += '; review whether this cross-provider drift is intentional before changing configuration'
            }

            Write-WrappedStatus -Status $(if ($row.Guests -gt 0) { 'INFO' } else { 'WARN' }) -Message $message
            continue
        }

        # ALLOW_ALL does not create missing-domain drift, so any non-blocked row here
        # is still an Entra ID / SharePoint mismatch. NONE covers unavailable,
        # DISABLED, BLOCK_ALL, and UNKNOWN Teams modes where domain-level comparison
        # is intentionally skipped.
        $configuredSide = if ($row.InEntra) { 'Entra ID only' } else { 'SharePoint only' }
        $missingSide = if ($row.InEntra) { 'SharePoint' } else { 'Entra ID' }
        if ($row.Guests -gt 0) {
            Write-WrappedStatus -Status INFO -Message ("{0}: {1}, {2} guest(s); sync missing {3} side with -AddDomain {0}" -f $row.Domain, $configuredSide, $row.Guests, $missingSide)
        }
        else {
            Write-WrappedStatus -Status WARN -Message ("{0}: {1}, no guests; review whether to sync with -AddDomain {0} or remove it from the configured side" -f $row.Domain, $configuredSide)
        }
    }

    Write-WrappedStatus -Status INFO -Message 'Recommendations are advisory; Audit never changes configuration. Add/purge operations can manage Microsoft Teams External Access when the current federation mode supports the requested change.'
}


function Show-RogueGuestRecommendations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Audit
    )

    $rogueDomains = @(
        $Audit |
            Where-Object { [int]$_.Rogue -gt 0 } |
            Sort-Object Domain
    )

    if ($rogueDomains.Count -eq 0) {
        return
    }

    Write-Step 'Rogue guest recommendations...'
    foreach ($row in $rogueDomains) {
        $noun = if ([int]$row.Rogue -eq 1) { 'account' } else { 'accounts' }
        Write-WrappedStatus -Status ROGUE -Message ("{0}: {1} rogue guest {2} with no recognized Entra invitation state; review with -ListGuests -GuestDomain {0}" -f $row.Domain, $row.Rogue, $noun)
        if ([int]$row.RogueRecent -gt 0) {
            $recentNoun = if ([int]$row.RogueRecent -eq 1) { 'account has' } else { 'accounts have' }
            Write-WrappedStatus -Status ROGUE -Message ("{0}: {1} rogue guest {2} successful sign-in activity within the last {3} days" -f $row.Domain, $row.RogueRecent, $recentNoun, $script:RogueRecentActivityDays)
        }
    }
}

function Show-ExternalCollabAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Audit,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests,

        [object]$TeamsConfig,

        [switch]$ReviewUsers
    )

    Write-Step 'Comparing configuration and guest inventory...'

    $synchronized = @($Audit | Where-Object { $_.State -eq 'OK' })
    $drift = @($Audit | Where-Object { $_.State -eq 'DRIFT' })
    $orphaned = @($Audit | Where-Object { $_.State -eq 'ORPHANED' })
    $configured = @($Audit | Where-Object { $_.Configured })
    $teamsSpecificDrift = @($Audit | Where-Object { $_.State -eq 'DRIFT' -and $_.TeamsSpecificDrift })
    $orphanedGuests = ($orphaned | Measure-Object -Property Guests -Sum).Sum
    $pendingGuests = ($Audit | Measure-Object -Property Pending -Sum).Sum
    $rogueGuests = ($Audit | Measure-Object -Property Rogue -Sum).Sum
    $rogueDomains = @($Audit | Where-Object { [int]$_.Rogue -gt 0 })

    $teamsMode = 'NONE'
    $teamsCompared = $false
    if ($null -ne $TeamsConfig) {
        $teamsMode = ([string]$TeamsConfig.Mode).Trim().ToUpperInvariant()
        $teamsCompared = ($teamsMode -eq 'ALLOWLIST' -or $teamsMode -eq 'ALLOW_ALL')
    }

    if ($null -eq $orphanedGuests) {
        $orphanedGuests = 0
    }

    if ($null -eq $pendingGuests) {
        $pendingGuests = 0
    }

    if ($null -eq $rogueGuests) {
        $rogueGuests = 0
    }

    if ($drift.Count -eq 0) {
        if ($teamsCompared) {
            Write-Status -Status OK -Message 'No cross-provider configuration drift detected'
        }
        else {
            Write-Status -Status OK -Message 'No Entra ID / SharePoint configuration drift detected'
        }
    }
    else {
        if ($teamsCompared) {
            Write-Status -Status WARN -Message ("Cross-provider configuration drift detected {0} domains" -f $drift.Count)
        }
        else {
            Write-Status -Status WARN -Message ("Configuration drift detected            {0} domains" -f $drift.Count)
        }
    }

    if ($teamsMode -eq 'ALLOWLIST') {
        Write-Status -Status INFO -Message 'Teams ALLOWLIST participates in domain-level drift comparison'
    }
    elseif ($teamsMode -eq 'ALLOW_ALL') {
        Write-Status -Status INFO -Message 'Teams ALLOW_ALL is treated as implicitly allowed; explicit blocks are checked as conflicts'
    }
    elseif ($null -ne $TeamsConfig) {
        Write-WrappedStatus -Status INFO -Message ("Teams mode {0} is reported at provider level and is not used for domain-level drift calculation" -f $teamsMode)
    }

    if ($orphaned.Count -eq 0) {
        Write-Status -Status OK -Message 'No orphaned guest domains detected'
    }
    else {
        Write-Status -Status WARN -Message ("Orphaned guest domains                  {0} domains / {1} users" -f $orphaned.Count, $orphanedGuests)
    }

    if ([int]$rogueGuests -gt 0) {
        Write-Status -Status ROGUE -Message ("Rogue guest accounts detected           {0} users / {1} domains" -f [int]$rogueGuests, $rogueDomains.Count)
    }
    else {
        Write-Status -Status OK -Message 'No rogue guest accounts detected'
    }

    Write-Step 'External collaboration inventory...'

    $inventoryTeamsMode = @($Audit | Select-Object -First 1 -ExpandProperty TeamsMode -ErrorAction SilentlyContinue)
    $inventoryShowsTeams = @($Audit | Where-Object { $_.TeamsCompared } | Select-Object -First 1).Count -gt 0
    if (-not $inventoryShowsTeams -and $inventoryTeamsMode -eq 'ALLOW_ALL') {
        Write-WrappedStatus -Status INFO -Message 'Microsoft Teams column omitted: ALLOW_ALL with no explicit blocks, so every domain is effectively allowed. Use -TeamsAudit to review the stored allowlist that would apply if the mode changes.'
    }
    elseif ($inventoryShowsTeams -and $inventoryTeamsMode -eq 'ALLOW_ALL') {
        Write-Status -Status INFO -Message 'Microsoft Teams ALLOW_ALL: [ ×× ] marks an explicit block, every other domain is implicitly allowed'
    }

    Write-ExternalCollabAuditTable -Audit $Audit

    Show-DriftRecommendations -Audit $Audit
    Show-RogueGuestRecommendations -Audit $Audit

    if ($ReviewUsers) {
        Show-ReviewExternalGuestUsers -Audit $Audit -Guests $Guests
    }
    elseif (($drift.Count + $orphaned.Count + $rogueDomains.Count) -gt 0) {
        Write-Status -Status INFO -Message 'Use -ReviewUsers to list guest accounts attached to DRIFT / ORPHANED domains or domains containing ROGUE guests'
    }

    Write-Step 'Audit summary...'
    Write-SummaryMetric -Status OK -Label 'Configured unique domains' -Value $configured.Count

    if ($teamsCompared) {
        Write-SummaryMetric -Status OK -Label 'Synchronized across providers' -Value $synchronized.Count
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Synchronized domains' -Value $synchronized.Count
    }

    if ($drift.Count -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Configuration drift' -Value $drift.Count
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Configuration drift' -Value 0
    }

    if ($teamsCompared) {
        if ($teamsSpecificDrift.Count -gt 0) {
            Write-SummaryMetric -Status WARN -Label 'Teams-specific drift' -Value $teamsSpecificDrift.Count
        }
        else {
            Write-SummaryMetric -Status OK -Label 'Teams-specific drift' -Value 0
        }
    }

    if ($orphaned.Count -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Orphaned guest domains' -Value $orphaned.Count
        Write-SummaryMetric -Status WARN -Label 'Orphaned guest accounts' -Value ([int]$orphanedGuests)
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Orphaned guest domains' -Value 0
        Write-SummaryMetric -Status OK -Label 'Orphaned guest accounts' -Value 0
    }

    if ($pendingGuests -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Pending guest invitations' -Value ([int]$pendingGuests)
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Pending guest invitations' -Value 0
    }

    if ($rogueGuests -gt 0) {
        Write-SummaryMetric -Status ROGUE -Label 'Rogue guest accounts' -Value ([int]$rogueGuests)
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Rogue guest accounts' -Value 0
    }

    if ($pendingGuests -gt 0) {
        Write-Status -Status INFO -Message 'Use -PurgePending -WhatIf to review pending guest cleanup before deletion'
    }

    Write-Status -Status OK -Message 'No changes were made'
}

function Invoke-ExternalCollabAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointAdminUrl,

        [switch]$ReviewUsers,

        [switch]$TeamsReauth,

        [switch]$TeamsRefresh
    )

    $preflight = Invoke-ExternalCollabPreflight `
        -SharePointAdminUrl $SharePointAdminUrl `
        -GraphScopes $script:AuditGraphScopes `
        -IncludeGuests `
        -IncludeTeams `
        -TeamsReauth:$TeamsReauth `
        -TeamsRefresh:$TeamsRefresh

    $audit = New-ExternalCollabAudit `
        -EntraDomains $preflight.EntraConfig.Domains `
        -SPODomains $preflight.SPOConfig.Domains `
        -Guests $preflight.Guests `
        -TeamsConfig $preflight.TeamsConfig

    Show-ExternalCollabAudit `
        -Audit $audit `
        -Guests $preflight.Guests `
        -TeamsConfig $preflight.TeamsConfig `
        -ReviewUsers:$ReviewUsers

    return $audit
}

#endregion Audit

#region ListGuests

function Invoke-ExternalCollabListGuests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointAdminUrl,

        [string]$Domain
    )

    $domainNormalized = $null
    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        $domainNormalized = $Domain.Trim().ToLowerInvariant()
    }

    if ($null -ne $domainNormalized) {
        Write-Step ("List external guest users: {0}" -f $domainNormalized)
    }
    else {
        Write-Step 'List external guest users'
    }

    # Guest state is defined by both external collaboration allowlists, so ListGuests
    # intentionally reuses the full read-only collaboration preflight instead of the
    # Graph-only guest preflight.
    $preflight = Invoke-ExternalCollabPreflight `
        -SharePointAdminUrl $SharePointAdminUrl `
        -GraphScopes $script:AuditGraphScopes `
        -IncludeGuests

    $allGuests = @($preflight.Guests)
    $audit = @(New-ExternalCollabAudit `
        -EntraDomains $preflight.EntraConfig.Domains `
        -SPODomains $preflight.SPOConfig.Domains `
        -Guests $allGuests)

    $domainStateMap = @{}
    $domainRankMap = @{}
    foreach ($row in $audit) {
        $domainStateMap[$row.Domain] = $row.State
        $domainRankMap[$row.Domain] = $row.StateRank
    }

    $guests = @($allGuests)
    if ($null -ne $domainNormalized) {
        $guests = @($guests | Where-Object { $_.Domain -eq $domainNormalized })
    }

    Write-Step 'External guest users...'

    if ($guests.Count -eq 0) {
        if ($null -ne $domainNormalized) {
            Write-Status -Status WARN -Message ("No #EXT# guest accounts found for {0}" -f $domainNormalized)
        }
        else {
            Write-Status -Status WARN -Message 'No #EXT# guest accounts found'
        }
        return
    }

    if ($null -ne $domainNormalized) {
        $domainAudit = $audit |
            Where-Object { $_.Domain -eq $domainNormalized } |
            Select-Object -First 1

        if ($null -ne $domainAudit) {
            Write-Host '  Domain state: ' -NoNewline
            Write-AuditState -State $domainAudit.State
            Write-Host
        }

        Write-ExternalGuestTable -Guests @($guests | Sort-Object DisplayName, Mail)
    }
    else {
        $sortedGuests = @(
            $guests |
                Sort-Object `
                    @{ Expression = { if ($domainRankMap.ContainsKey($_.Domain)) { $domainRankMap[$_.Domain] } else { 99 } } }, `
                    Domain, `
                    DisplayName, `
                    Mail
        )

        Write-ExternalGuestTable `
            -Guests $sortedGuests `
            -IncludeDomain `
            -DomainStateMap $domainStateMap

        Write-Host
        Write-Status -Status INFO -Message 'Domain colors: OK = green, DRIFT = yellow, ORPHANED = orange; Rogue row domain + Invite = reddish orange'
    }

    Show-ExternalGuestListSummary -Guests $guests
}

#endregion ListGuests

#region PurgeGuests

function Test-ExternalCollabDomainName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    return [regex]::IsMatch(
        $Domain,
        '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$'
    )
}

function Resolve-ExternalCollabDomainList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Domain
    )

    $list = @(
        $Domain |
            ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    if ($list.Count -eq 0) { throw 'At least one domain is required.' }

    foreach ($candidate in $list) {
        if (-not (Test-ExternalCollabDomainName -Domain $candidate)) {
            throw ("Invalid domain: {0}" -f $candidate)
        }
    }

    return $list
}

function Resolve-ExternalGuestPurgeSelector {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Selector
    )

    $value = $Selector.Trim()

    if ([string]::IsNullOrWhiteSpace($value)) {
        throw 'PurgeGuests selector cannot be empty.'
    }

    if ($value.StartsWith('*@')) {
        $domain = $value.Substring(2).Trim().ToLowerInvariant()

        if (-not (Test-ExternalCollabDomainName -Domain $domain)) {
            throw ("Invalid PurgeGuests domain selector: {0}" -f $Selector)
        }

        return [PSCustomObject]@{
            Type     = 'DomainWildcard'
            Selector = ('*@{0}' -f $domain)
            Domain   = $domain
            Email    = $null
        }
    }

    if ($value.Contains('*')) {
        throw 'PurgeGuests supports wildcard only in the form *@domain.tld.'
    }

    $atIndex = $value.LastIndexOf('@')
    if ($atIndex -le 0 -or $atIndex -ge ($value.Length - 1)) {
        throw 'PurgeGuests expects user@domain.tld or *@domain.tld.'
    }

    $localPart = $value.Substring(0, $atIndex)
    $domain = $value.Substring($atIndex + 1).Trim().ToLowerInvariant()

    if ([string]::IsNullOrWhiteSpace($localPart) -or -not (Test-ExternalCollabDomainName -Domain $domain)) {
        throw 'PurgeGuests expects user@domain.tld or *@domain.tld.'
    }

    return [PSCustomObject]@{
        Type     = 'ExactEmail'
        Selector = ('{0}@{1}' -f $localPart, $domain)
        Domain   = $domain
        Email    = ('{0}@{1}' -f $localPart, $domain)
    }
}

function Resolve-ExternalGuestPurgeSelectorList {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Selector
    )

    $resolved = @()
    $seen = @{}

    foreach ($candidate in $Selector) {
        if ([string]::IsNullOrWhiteSpace([string]$candidate)) { continue }

        $entry = Resolve-ExternalGuestPurgeSelector -Selector ([string]$candidate)
        if ($seen.ContainsKey($entry.Selector)) { continue }

        $seen[$entry.Selector] = $true
        $resolved += $entry
    }

    if ($resolved.Count -eq 0) { throw 'PurgeGuests requires at least one selector.' }

    return $resolved
}

function Select-ExternalGuestsForPurge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests,

        [Parameter(Mandatory = $true)]
        [object]$Selector
    )

    if ($Selector.Type -eq 'DomainWildcard') {
        return @(
            $Guests |
                Where-Object { $_.Domain -eq $Selector.Domain }
        )
    }

    return @(
        $Guests |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.Mail) -and
                $_.Mail.Trim() -ieq $Selector.Email
            }
    )
}

function Confirm-ExternalCollabAction {
    [CmdletBinding()]
    param(
        [string]$Prompt = 'Continue?'
    )

    while ($true) {
        $answer = Read-Host ("{0} [y/N]" -f $Prompt)

        if ([string]::IsNullOrWhiteSpace($answer)) {
            return $false
        }

        switch ($answer.Trim().ToLowerInvariant()) {
            'y'   { return $true }
            'yes' { return $true }
            'n'   { return $false }
            'no'  { return $false }
            default { Write-Status -Status WARN -Message 'Please answer y or n.' }
        }
    }
}

function Confirm-ExternalCollabPurgeAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    # Purge is always destructive. Only explicit y/yes proceeds; Enter/default cancels.
    return (Confirm-ExternalCollabAction -Prompt $Prompt)
}

function Wait-ExternalGuestIdsAbsent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$UserIds,

        [int]$MaxAttempts = 5,

        [int]$DelaySeconds = 2
    )

    $targetIds = @($UserIds | Sort-Object -Unique)
    $remainingIds = @($targetIds)

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $currentGuests = @(Get-ExternalGuestInventory)
        $currentIds = @($currentGuests.Id)
        $remainingIds = @($targetIds | Where-Object { $currentIds -contains $_ })

        if ($remainingIds.Count -eq 0) {
            return [PSCustomObject]@{
                Success   = $true
                Attempts  = $attempt
                Remaining = @()
            }
        }

        if ($attempt -eq 1 -and $MaxAttempts -gt 1) {
            Write-Status -Status INFO -Message 'Waiting for guest deletion state to converge...'
        }

        if ($attempt -lt $MaxAttempts) {
            Start-Sleep -Seconds $DelaySeconds
        }
    }

    return [PSCustomObject]@{
        Success   = $false
        Attempts  = $MaxAttempts
        Remaining = @($remainingIds)
    }
}

function Invoke-ExternalGuestDeletionBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests
    )

    $targets = @($Guests)
    $deleted = @()
    $failed = @()
    $validation = $null

    foreach ($guest in $targets) {
        $label = $guest.DisplayName
        if ([string]::IsNullOrWhiteSpace($label)) {
            $label = $guest.Mail
        }

        try {
            Remove-MgBetaUser -UserId $guest.Id -Confirm:$false
            $deleted += $guest
            Write-Status -Status OK -Message ("Deleted {0} <{1}>" -f $label, $guest.Mail)
        }
        catch {
            $failed += [PSCustomObject]@{
                Guest = $guest
                Error = $_.Exception.Message
            }
            Write-Status -Status FAIL -Message ("Failed to delete {0} <{1}>: {2}" -f $label, $guest.Mail, $_.Exception.Message)
        }
    }

    if ($deleted.Count -gt 0) {
        Write-Step 'Final guest validation...'

        $validation = Wait-ExternalGuestIdsAbsent -UserIds @($deleted.Id)

        if ($validation.Success) {
            Write-Status -Status OK -Message ("Verified deletion of {0} guest account(s) ({1} attempt(s))" -f $deleted.Count, $validation.Attempts)
        }
        else {
            Write-Status -Status WARN -Message ("{0} deleted guest object(s) are still visible after validation timeout" -f @($validation.Remaining).Count)
        }
    }

    return [PSCustomObject]@{
        Matched    = $targets.Count
        Deleted    = @($deleted)
        Failed     = @($failed)
        Validation = $validation
    }
}

function Invoke-ExternalCollabPurgeGuests {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointAdminUrl,

        [Parameter(Mandatory = $true)]
        [string[]]$Selector,

        [switch]$WhatIf
    )

    $resolvedSelectors = @(Resolve-ExternalGuestPurgeSelectorList -Selector $Selector)
    $selectorText = (@($resolvedSelectors | ForEach-Object { $_.Selector }) -join ', ')

    if ($resolvedSelectors.Count -eq 1) { Write-Step ("Purge external guest users: {0}" -f $selectorText) }
    else { Write-Step ("Purge external guest users: {0} selectors ({1})" -f $resolvedSelectors.Count, $selectorText) }

    $graphScopes = $script:PurgeGuestGraphScopes
    if ($WhatIf) {
        # Preview does not need delete permission.
        $graphScopes = $script:GuestGraphScopes
    }

    $preflight = Invoke-ExternalGuestPreflight `
        -SharePointAdminUrl $SharePointAdminUrl `
        -GraphScopes $graphScopes

    # Selectors may overlap (user@x.fi and *@x.fi both match the same object), so matches
    # are de-duplicated by object id. Each account is previewed and deleted exactly once.
    # NOTE: $matches is a PowerShell automatic variable. Never reuse that name here.
    $seenIds = @{}
    $collected = @()
    $unmatchedSelectors = @()

    foreach ($entry in $resolvedSelectors) {
        $entryMatches = @(Select-ExternalGuestsForPurge -Guests $preflight.Guests -Selector $entry)
        if ($entryMatches.Count -eq 0) {
            $unmatchedSelectors += $entry.Selector
            continue
        }

        foreach ($guest in $entryMatches) {
            $key = [string]$guest.Id
            if ($seenIds.ContainsKey($key)) { continue }
            $seenIds[$key] = $true
            $collected += $guest
        }
    }

    $targets = @($collected | Sort-Object Domain, DisplayName, Mail)

    Write-Step 'Guest accounts scheduled for purge...'

    foreach ($selectorValue in $unmatchedSelectors) {
        Write-Status -Status WARN -Message ("No #EXT# guest accounts matched {0}" -f $selectorValue)
    }

    if ($targets.Count -eq 0) {
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    $inviterMetadata = Resolve-ExternalGuestInviterMetadata -Guests $targets
    $targets = @($inviterMetadata.Guests)

    # Show the domain column whenever the result set is not confined to a single domain,
    # or when an exact address was requested and the domain is not otherwise visible.
    $distinctDomains = @($targets | ForEach-Object { $_.Domain } | Sort-Object -Unique)
    $includeDomain = ($distinctDomains.Count -gt 1) -or @($resolvedSelectors | Where-Object { $_.Type -eq 'ExactEmail' }).Count -gt 0

    Write-ExternalGuestPurgeTable -Guests $targets -IncludeDomain:$includeDomain

    Write-Host
    if ($resolvedSelectors.Count -gt 1) {
        Write-SummaryMetric -Status OK -Label 'Selectors matched' -Value ($resolvedSelectors.Count - $unmatchedSelectors.Count)
        Write-SummaryMetric -Status OK -Label 'Domains affected' -Value $distinctDomains.Count
    }
    Write-SummaryMetric -Status OK -Label 'Inviter identified' -Value $inviterMetadata.InviterIdentified
    if ($inviterMetadata.InviterUnavailable -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Inviter unavailable' -Value $inviterMetadata.InviterUnavailable
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Inviter unavailable' -Value 0
    }
    Write-Status -Status WARN -Message ("{0} guest account(s) will be deleted" -f $targets.Count)
    Write-Status -Status INFO -Message 'External collaboration allowlists will not be modified'

    if ($WhatIf) {
        Write-Status -Status INFO -Message 'WhatIf mode: purge preview only'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    if (-not (Confirm-ExternalCollabPurgeAction -Prompt ("Purge {0} matching guest account(s)?" -f $targets.Count))) {
        Write-Status -Status INFO -Message 'Purge cancelled'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    Write-Step 'Purging guest accounts...'

    $deleteResult = Invoke-ExternalGuestDeletionBatch -Guests $targets

    Write-Step 'Purge summary...'
    Write-SummaryMetric -Status OK -Label 'Matched guest accounts' -Value $targets.Count
    Write-SummaryMetric -Status OK -Label 'Delete requests succeeded' -Value @($deleteResult.Deleted).Count

    if (@($deleteResult.Failed).Count -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Delete requests failed' -Value @($deleteResult.Failed).Count
        throw ("PurgeGuests completed partially: {0} of {1} delete request(s) failed." -f @($deleteResult.Failed).Count, $targets.Count)
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Delete requests failed' -Value 0
    }

    Write-Status -Status OK -Message 'Guest purge complete'
}

#endregion PurgeGuests

#region PurgePending

function Write-PendingGuestPurgeTable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests
    )

    $rows = @($Guests)
    if ($rows.Count -eq 0) { return }

    $domainWidth = Get-BoundedColumnWidth -Values @($rows.Domain) -Header 'Domain' -Minimum 16 -Maximum 28
    $nameWidth = Get-BoundedColumnWidth -Values @($rows.DisplayName) -Header 'Name' -Minimum 18 -Maximum 28
    $mailWidth = Get-BoundedColumnWidth -Values @($rows.Mail) -Header 'Mail' -Minimum 24 -Maximum 42
    $inviterWidth = Get-BoundedColumnWidth -Values @($rows.InvitedBy) -Header 'InvitedBy' -Minimum 24 -Maximum 42

    $header = ("  {0,-$domainWidth}  {1,-$nameWidth}  {2,-$mailWidth}  {3,-10}  {4,6}  {5,-$inviterWidth}" -f `
        'Domain', 'Name', 'Mail', 'Created', 'Age', 'InvitedBy')
    $separator = ('  ' + ('-' * $domainWidth) + '  ' + ('-' * $nameWidth) + '  ' + ('-' * $mailWidth) + '  ----------  ------  ' + ('-' * $inviterWidth))

    if ($script:UseAnsi) {
        Write-Host ("{0}{1}{2}" -f $script:Nord.Frost3, $header, $script:Nord.Reset)
        Write-Host ("{0}{1}{2}" -f $script:Nord.Muted, $separator, $script:Nord.Reset)
    }
    else {
        Write-Host $header -ForegroundColor Cyan
        Write-Host $separator -ForegroundColor DarkGray
    }

    foreach ($guest in $rows) {
        $domain = Limit-ExternalCollabText -Value $guest.Domain -Width $domainWidth
        $name = Limit-ExternalCollabText -Value $guest.DisplayName -Width $nameWidth
        $mail = Limit-ExternalCollabText -Value $guest.Mail -Width $mailWidth
        $created = '-'
        if ($null -ne $guest.CreatedDateTime) {
            try { $created = ([datetimeoffset]$guest.CreatedDateTime).ToLocalTime().ToString('yyyy-MM-dd') } catch { $created = '-' }
        }
        $age = if ($null -ne $guest.AgeDays) { ('{0}d' -f [int]$guest.AgeDays) } else { '-' }
        $invitedBy = Limit-ExternalCollabText -Value $guest.InvitedBy -Width $inviterWidth
        $line = ("  {0,-$domainWidth}  {1,-$nameWidth}  {2,-$mailWidth}  {3,-10}  {4,6}  {5,-$inviterWidth}" -f `
            $domain, $name, $mail, $created, $age, $invitedBy)

        if ($script:UseAnsi) {
            Write-Host ("{0}{1}{2}" -f $script:Nord.Snow, $line, $script:Nord.Reset)
        }
        else {
            Write-Host $line
        }
    }
}

function Invoke-ExternalCollabPurgePending {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointAdminUrl,

        [Nullable[int]]$OlderThanDays,

        [switch]$WhatIf
    )

    Write-Step 'Pending guest purge...'

    $graphScopes = $script:PurgeGuestGraphScopes
    if ($WhatIf) {
        # Preview is passive: no delete scope and no confirmation prompt.
        $graphScopes = $script:GuestGraphScopes
    }

    $preflight = Invoke-ExternalGuestPreflight `
        -SharePointAdminUrl $SharePointAdminUrl `
        -GraphScopes $graphScopes

    $allPending = @(
        $preflight.Guests |
            Where-Object { $_.InviteClassification -eq 'PendingAcceptance' }
    )

    $selected = @($allPending)
    if ($null -ne $OlderThanDays) {
        $minimumAge = [int]$OlderThanDays
        $selected = @(
            $allPending |
                Where-Object {
                    $age = Get-ExternalGuestAgeDays -CreatedDateTime $_.CreatedDateTime
                    $null -ne $age -and $age -ge $minimumAge
                }
        )
        Write-Status -Status INFO -Message ("Age filter: pending guest accounts at least {0} day(s) old" -f $minimumAge)
    }

    $selected = @($selected | Sort-Object CreatedDateTime, Domain, DisplayName, Mail)

    if ($selected.Count -eq 0) {
        Write-Step 'Pending guest accounts selected for purge...'
        if ($null -ne $OlderThanDays) {
            Write-Status -Status OK -Message ("No PendingAcceptance guest accounts matched the {0}-day age filter" -f [int]$OlderThanDays)
        }
        else {
            Write-Status -Status OK -Message 'No PendingAcceptance guest accounts found'
        }
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    Write-Step 'Resolving retained invitation audit trail...'
    $inviteIndex = @{}
    $auditAvailable = $true
    $auditEventCount = 0
    try {
        $auditResult = Get-ExternalGuestInviteAuditIndex
        $inviteIndex = $auditResult.Index
        $auditEventCount = [int]$auditResult.EventCount
        Write-Status -Status OK -Message ("Retained 'Invite external user' audit events {0}" -f $auditEventCount)
    }
    catch {
        $auditAvailable = $false
        Write-WrappedStatus -Status WARN -Message ("Invitation audit trail could not be read; purge preview will continue without InvitedBy metadata: {0}" -f $_.Exception.Message)
    }

    $targets = foreach ($guest in $selected) {
        $invite = $null
        if ($auditAvailable -and $inviteIndex.ContainsKey([string]$guest.Id)) {
            $invite = $inviteIndex[[string]$guest.Id]
        }

        $invitedBy = if ($null -ne $invite) {
            [string]$invite.InvitedBy
        }
        elseif ($auditAvailable) {
            '<not in retained audit>'
        }
        else {
            '<audit unavailable>'
        }

        [PSCustomObject]@{
            Id                    = $guest.Id
            DisplayName           = $guest.DisplayName
            Mail                  = $guest.Mail
            UserPrincipalName     = $guest.UserPrincipalName
            Domain                = $guest.Domain
            AccountEnabled        = $guest.AccountEnabled
            ExternalUserState     = $guest.ExternalUserState
            InviteClassification  = $guest.InviteClassification
            CreatedDateTime       = $guest.CreatedDateTime
            LastSuccessfulSignIn  = $guest.LastSuccessfulSignIn
            LastInteractiveSignIn = $guest.LastInteractiveSignIn
            AgeDays               = Get-ExternalGuestAgeDays -CreatedDateTime $guest.CreatedDateTime
            InvitedBy             = $invitedBy
            InvitedAt             = if ($null -ne $invite) { $invite.Invited } else { $null }
        }
    }

    $targets = @($targets)

    Write-Step 'Pending guest accounts selected for purge...'
    Write-PendingGuestPurgeTable -Guests $targets

    $inviterIdentified = @($targets | Where-Object { $_.InvitedBy -notlike '<*' }).Count
    $inviterUnavailable = $targets.Count - $inviterIdentified
    $knownAges = @($targets | Where-Object { $null -ne $_.AgeDays } | Select-Object -ExpandProperty AgeDays)
    $newestAge = $null
    $oldestAge = $null
    if ($knownAges.Count -gt 0) {
        $newestAge = ($knownAges | Measure-Object -Minimum).Minimum
        $oldestAge = ($knownAges | Measure-Object -Maximum).Maximum
    }

    Write-Step 'Purge preview summary...'
    Write-SummaryMetric -Status WARN -Label 'Pending guest accounts selected' -Value $targets.Count
    Write-SummaryMetric -Status OK -Label 'Inviter identified' -Value $inviterIdentified
    if ($inviterUnavailable -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Inviter unavailable' -Value $inviterUnavailable
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Inviter unavailable' -Value 0
    }
    if ($null -ne $newestAge) { Write-SummaryMetric -Status INFO -Label 'Newest selected invitation age' -Value ("{0}d" -f [int]$newestAge) }
    if ($null -ne $oldestAge) { Write-SummaryMetric -Status WARN -Label 'Oldest selected invitation age' -Value ("{0}d" -f [int]$oldestAge) }

    Write-Status -Status INFO -Message 'Accepted and Rogue guest accounts are excluded from PurgePending'
    Write-Status -Status WARN -Message ("This operation will permanently delete {0} Entra ID guest object(s)" -f $targets.Count)

    if ($WhatIf) {
        Write-Status -Status INFO -Message 'WhatIf mode: purge preview only'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    if (-not (Confirm-ExternalCollabPurgeAction -Prompt ("Purge {0} PendingAcceptance guest account(s)?" -f $targets.Count))) {
        Write-Status -Status INFO -Message 'Purge cancelled'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    Write-Step 'Purging pending guest accounts...'
    $deleteResult = Invoke-ExternalGuestDeletionBatch -Guests $targets

    Write-Step 'Purge summary...'
    Write-SummaryMetric -Status OK -Label 'Matched pending guest accounts' -Value $targets.Count
    Write-SummaryMetric -Status OK -Label 'Delete requests succeeded' -Value @($deleteResult.Deleted).Count

    if (@($deleteResult.Failed).Count -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Delete requests failed' -Value @($deleteResult.Failed).Count
        throw ("PurgePending completed partially: {0} of {1} delete request(s) failed." -f @($deleteResult.Failed).Count, $targets.Count)
    }
    else {
        Write-SummaryMetric -Status OK -Label 'Delete requests failed' -Value 0
    }

    Write-Status -Status OK -Message 'Pending guest purge complete'
}

#endregion PurgePending

#region ProviderDomainChanges

function Invoke-ExternalCollabGraphProviderDomainChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Entra','SPO')][string]$Provider,
        [Parameter(Mandatory = $true)][ValidateSet('ADD','REMOVE')][string]$Intent,
        [Parameter(Mandatory = $true)][string]$SharePointAdminUrl,
        [Parameter(Mandatory = $true)][string[]]$Domain,
        [switch]$WhatIf
    )

    $domainList = Resolve-ExternalCollabDomainList -Domain $Domain
    $providerLabel = if ($Provider -eq 'Entra') { 'Entra ID' } else { 'SharePoint' }
    $verb = if ($Intent -eq 'ADD') { 'Add' } else { 'Remove' }

    if ($domainList.Count -eq 1) { Write-Step ("{0} {1} domain: {2}" -f $verb, $providerLabel, $domainList[0]) }
    else { Write-Step ("{0} {1} domains: {2}" -f $verb, $providerLabel, ($domainList -join ', ')) }

    $readScopes = if ($Provider -eq 'Entra') { $script:EntraReadGraphScopes } else { $script:SPOReadGraphScopes }
    $writeScopes = if ($Provider -eq 'Entra') { $script:EntraWriteGraphScopes } else { $script:SPOWriteGraphScopes }
    $scopes = if ($WhatIf) { $readScopes } else { $writeScopes }

    $null = Invoke-ExternalCollabRuntimePreflight
    Write-Step $(if ($script:FullVerbose) { 'Authenticating...' } else { 'Authentication...' })
    $targetTenantId = Get-SharePointTenantRealm -AdminUrl $SharePointAdminUrl
    if ([string]::IsNullOrWhiteSpace($targetTenantId)) {
        throw 'Target tenant could not be resolved from SharePoint Admin URL; refusing provider write without a tenant safety boundary.'
    }
    Write-DetailStatus -Status OK -Message ("Target tenant: {0}" -f $targetTenantId)

    $graphContext = Connect-ExternalCollabGraph -Scopes $scopes -ExpectedTenantId $targetTenantId
    $null = Test-ExternalCollabTenantConsistency -GraphContext $graphContext -SharePointAdminUrl $SharePointAdminUrl -ResolvedSharePointTenantId $targetTenantId
    if (-not $script:FullVerbose) { Write-Status -Status OK -Message 'Microsoft Graph authentication ready; target tenant verified' }

    Write-Step ("Fetching {0} external collaboration configuration..." -f $providerLabel)
    $config = if ($Provider -eq 'Entra') { Get-EntraExternalCollabConfig } else { Get-SharePointExternalCollabConfig }
    if ($config.Mode -ne 'AllowList') {
        throw ("{0} provider-specific domain change requires AllowList mode. Current mode: {1}" -f $providerLabel, $config.Mode)
    }

    $originalDomains = @($config.Domains)
    $changing = @($domainList | Where-Object { ($originalDomains -contains $_) -ne ($Intent -eq 'ADD') })
    $unchanged = @($domainList | Where-Object { $changing -notcontains $_ })

    Write-Step 'Planning provider-specific change...'
    foreach ($domainNormalized in $unchanged) {
        $message = if ($Intent -eq 'ADD') { "{0} already allows {1}" -f $providerLabel, $domainNormalized } else { "{0} already does not allow {1}" -f $providerLabel, $domainNormalized }
        Write-Status -Status OK -Message $message
    }
    foreach ($domainNormalized in $changing) {
        $planMessage = if ($Intent -eq 'ADD') { "{0} will add {1}" -f $providerLabel, $domainNormalized } else { "{0} will remove {1}" -f $providerLabel, $domainNormalized }
        Write-Status -Status $(if ($Intent -eq 'ADD') { 'INFO' } else { 'WARN' }) -Message $planMessage
    }
    Write-Status -Status SKIP -Message 'Other providers and guest objects are untouched'

    if ($changing.Count -eq 0) { return }

    if ($WhatIf) {
        Write-Status -Status INFO -Message 'WhatIf mode: planned change only'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    # Both providers replace the whole domain list in a single write, so the batch is
    # applied as one PATCH rather than one PATCH per domain.
    $targetDomains = if ($Intent -eq 'ADD') {
        @($originalDomains + $changing | Sort-Object -Unique)
    }
    else {
        @($originalDomains | Where-Object { $changing -notcontains $_ })
    }

    try {
        Write-Step ("Applying {0} configuration..." -f $providerLabel)
        if ($Provider -eq 'Entra') {
            Set-EntraExternalCollabDomains -Config $config -Domains $targetDomains
            $verify = Get-EntraExternalCollabConfig
            $notVerified = @($changing | Where-Object { ($verify.Domains -contains $_) -ne ($Intent -eq 'ADD') })
            if ($notVerified.Count -gt 0) { throw ("Entra ID verification failed for: {0}" -f ($notVerified -join ', ')) }
            Write-Status -Status OK -Message ("Verified Entra ID domain state for {0}" -f ($changing -join ', '))
        }
        else {
            Set-SharePointExternalCollabDomains -Config $config -Domains $targetDomains
            $verify = Wait-SharePointExternalCollabDomainState -Domain $changing -ShouldExist:($Intent -eq 'ADD')
            if (-not $verify.Success) { throw ("SharePoint verification failed after {0} attempt(s) for: {1}" -f $verify.Attempts, (@($verify.Pending) -join ', ')) }
            Write-Status -Status OK -Message ("Verified SharePoint domain state for {0} ({1} attempt(s))" -f ($changing -join ', '), $verify.Attempts)
        }
        Write-Status -Status OK -Message ("{0} provider-specific change complete" -f $providerLabel)
    }
    catch {
        $operationError = $_.Exception.Message
        Write-Step ("Attempting {0} rollback..." -f $providerLabel)
        try {
            $current = if ($Provider -eq 'Entra') { Get-EntraExternalCollabConfig } else { Get-SharePointExternalCollabConfig }
            if (Test-StringSetEqual -Left $current.Domains -Right $targetDomains) {
                if ($Provider -eq 'Entra') {
                    Set-EntraExternalCollabDomains -Config $current -Domains $originalDomains
                    $rollback = Get-EntraExternalCollabConfig
                    if (-not (Test-StringSetEqual -Left $rollback.Domains -Right $originalDomains)) { throw 'Entra rollback read-back did not match the original allowlist.' }
                }
                else {
                    Set-SharePointExternalCollabDomains -Config $current -Domains $originalDomains
                    $rollback = Wait-SharePointExternalCollabDomainState -Domain $changing -ShouldExist:($Intent -eq 'REMOVE')
                    if (-not $rollback.Success) { throw 'SharePoint rollback read-back did not converge to the original domain state.' }
                }
                Write-Status -Status OK -Message ("Restored original {0} allowlist" -f $providerLabel)
            }
            elseif (Test-StringSetEqual -Left $current.Domains -Right $originalDomains) {
                Write-Status -Status OK -Message ("{0} already matches original state" -f $providerLabel)
            }
            else {
                throw ("{0} rollback refused because the allowlist changed concurrently." -f $providerLabel)
            }
        }
        catch {
            throw ("{0} provider change failed: {1} Rollback needs review: {2}" -f $providerLabel, $operationError, $_.Exception.Message)
        }
        throw ("{0} provider change failed: {1} Original configuration was restored." -f $providerLabel, $operationError)
    }
}

function Invoke-ExternalCollabTeamsProviderDomainChange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('ADD','REMOVE')][string]$Intent,
        [Parameter(Mandatory = $true)][string]$SharePointAdminUrl,
        [Parameter(Mandatory = $true)][string[]]$Domain,
        [switch]$TeamsReauth,
        [switch]$TeamsRefresh,
        [switch]$WhatIf
    )

    $domainList = Resolve-ExternalCollabDomainList -Domain $Domain
    $verb = if ($Intent -eq 'ADD') { 'Add' } else { 'Remove' }

    if ($domainList.Count -eq 1) { Write-Step ("{0} Microsoft Teams domain: {1}" -f $verb, $domainList[0]) }
    else { Write-Step ("{0} Microsoft Teams domains: {1}" -f $verb, ($domainList -join ', ')) }

    $null = Invoke-TeamsNativePreflight
    Write-Step $(if ($script:FullVerbose) { 'Authenticating...' } else { 'Authentication...' })
    $targetTenantId = Get-SharePointTenantRealm -AdminUrl $SharePointAdminUrl
    if ([string]::IsNullOrWhiteSpace($targetTenantId)) {
        throw 'Target tenant could not be resolved from SharePoint Admin URL; refusing Teams write without a tenant safety boundary.'
    }
    Write-DetailStatus -Status OK -Message ("SharePoint target tenant: {0}" -f $targetTenantId)

    $teamsContext = Connect-ExternalCollabTeamsNative -ExpectedTenantId $targetTenantId -ForceReauth:$TeamsReauth
    Write-TeamsConnectionContext -Context $teamsContext
    if (-not ([string]$teamsContext.TenantId).Equals($targetTenantId, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("Microsoft Teams tenant {0} does not match target tenant {1}." -f $teamsContext.TenantId, $targetTenantId)
    }
    Write-DetailStatus -Status OK -Message ("Tenant cross-check: Teams / target {0}" -f $targetTenantId)
    if (-not $script:FullVerbose) { Write-Status -Status OK -Message 'Microsoft Teams authentication ready; target tenant verified' }

    Write-Step 'Fetching Microsoft Teams External Access configuration...'
    $config = Get-ExternalCollabTeamsConfig -Context $teamsContext -ForceRefresh:($TeamsRefresh -or (-not $WhatIf))
    Write-TeamsExternalAccessResult -Config $config -Compact

    $plans = @(
        foreach ($domainNormalized in $domainList) {
            $plan = Get-ExternalCollabTeamsDomainPlan -Config $config -Domain $domainNormalized -Intent $Intent
            if (-not $plan.Supported -and $plan.Mode -eq 'UNKNOWN') {
                throw ("Microsoft Teams federation mode is UNKNOWN; refusing a provider-specific write for {0}. Run -TeamsAudit first." -f $domainNormalized)
            }
            $plan
        }
    )

    Write-Step 'Planning provider-specific change...'
    foreach ($plan in $plans) { Write-ExternalCollabTeamsDomainPlan -Plan $plan }
    Write-Status -Status SKIP -Message 'Entra ID, SharePoint, and guest objects are untouched'

    $actionable = @($plans | Where-Object { $_.Supported -and $_.NeedsChange })

    if ($actionable.Count -eq 0) {
        if (@($plans | Where-Object { -not $_.Supported }).Count -eq $plans.Count) {
            Write-WrappedStatus -Status WARN -Message 'No Microsoft Teams change is supported in the current federation state'
        }
        else {
            Write-Status -Status OK -Message 'Microsoft Teams already has the requested effective domain state'
        }
        return
    }

    if ($WhatIf) {
        Write-Status -Status INFO -Message 'WhatIf mode: planned change only'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    # Teams mutations are per-domain cmdlet calls and an earlier one can change the
    # federation mode (BLOCK_ALL turns into ALLOWLIST on the first allowed domain), so
    # each domain is re-planned against a fresh read immediately before its own write.
    Write-Step 'Applying Microsoft Teams External Access configuration...'
    $applied = @()

    try {
        foreach ($plan in $actionable) {
            $freshConfig = Get-ExternalCollabTeamsConfig -Context $teamsContext -ForceRefresh
            $current = Get-ExternalCollabTeamsDomainPlan -Config $freshConfig -Domain $plan.Domain -Intent $Intent
            if (-not $current.Supported) {
                throw ("Microsoft Teams state changed before write and {0} can no longer be updated safely: {1}" -f $plan.Domain, $current.Reason)
            }
            if (-not $current.NeedsChange) {
                Write-Status -Status OK -Message ("Microsoft Teams already has the requested effective state for {0}" -f $plan.Domain)
                continue
            }

            Invoke-ExternalCollabTeamsDomainMutation -Domain $current.Domain -Operation $current.ChangeKind
            $applied += $current

            $verify = Wait-ExternalCollabTeamsDomainPlanApplied -Context $teamsContext -Plan $current
            if (-not $verify.Success) {
                throw ("Microsoft Teams verification failed for {0} after {1} attempt(s)." -f $current.Domain, $verify.Attempts)
            }
            Write-Status -Status OK -Message ("Verified Microsoft Teams domain state for {0} ({1} attempt(s))" -f $current.Domain, $verify.Attempts)
        }
    }
    catch {
        $operationError = $_.Exception.Message
        $rollbackErrors = @()

        if ($applied.Count -gt 0) {
            Write-Step 'Attempting Microsoft Teams rollback...'
            for ($index = $applied.Count - 1; $index -ge 0; $index--) {
                $done = $applied[$index]
                try {
                    $inverse = Get-ExternalCollabTeamsInverseChangeKind -ChangeKind $done.ChangeKind
                    if ($inverse -eq 'NONE') { continue }
                    Invoke-ExternalCollabTeamsDomainMutation -Domain $done.Domain -Operation $inverse
                    $rollbackVerify = Wait-ExternalCollabTeamsOriginalDomainState -Context $teamsContext -Domain $done.Domain -OriginalState $done.OriginalState
                    if (-not $rollbackVerify.Success) { throw 'rollback write completed but the original domain state was not restored' }
                    Write-Status -Status OK -Message ("Restored original Microsoft Teams domain state for {0} ({1} attempt(s))" -f $done.Domain, $rollbackVerify.Attempts)
                }
                catch {
                    $message = ("Microsoft Teams rollback failed for {0}: {1}" -f $done.Domain, $_.Exception.Message)
                    $rollbackErrors += $message
                    Write-Status -Status FAIL -Message $message
                }
            }
        }

        if ($rollbackErrors.Count -gt 0) { throw ("Microsoft Teams provider change failed: {0} Rollback needs review: {1}" -f $operationError, ($rollbackErrors -join '; ')) }
        throw ("Microsoft Teams provider change failed: {0} Original configuration was restored." -f $operationError)
    }

    Write-Status -Status OK -Message 'Microsoft Teams provider-specific change complete'
}

#endregion ProviderDomainChanges

#region AddDomain

function Test-StringSetEqual {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Left,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Right
    )

    $leftNormalized = @($Left | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    $rightNormalized = @($Right | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

    if ($leftNormalized.Count -ne $rightNormalized.Count) {
        return $false
    }

    return (@(Compare-Object -ReferenceObject $leftNormalized -DifferenceObject $rightNormalized).Count -eq 0)
}

function Invoke-ExternalCollabAddDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SharePointAdminUrl,
        [Parameter(Mandatory = $true)][string[]]$Domain,
        [switch]$TeamsReauth,
        [switch]$WhatIf
    )

    $domainList = Resolve-ExternalCollabDomainList -Domain $Domain

    if ($domainList.Count -eq 1) { Write-Step ("Add / synchronize domain: {0}" -f $domainList[0]) }
    else { Write-Step ("Add / synchronize domains: {0}" -f ($domainList -join ', ')) }

    # Phase 1 is always read-only. Denim Demon asks for write scopes only after it
    # knows which Graph-backed providers actually need a change.
    $preflight = Invoke-ExternalCollabPreflight `
        -SharePointAdminUrl $SharePointAdminUrl `
        -GraphScopes $script:AddDomainReadGraphScopes `
        -IncludeTeams `
        -RequireTeams `
        -RequireTenantPin:(-not $WhatIf) `
        -TeamsReauth:$TeamsReauth `
        -TeamsRefresh:$false

    $entraConfig = $preflight.EntraConfig
    $spoConfig = $preflight.SPOConfig
    $originalEntraDomains = @($entraConfig.Domains)
    $originalSPODomains = @($spoConfig.Domains)
    $originalTeamsConfig = Copy-ExternalCollabTeamsFederationConfig -Config $preflight.TeamsConfig

    $plans = @(
        foreach ($domainNormalized in $domainList) {
            $teamsPlan = Get-ExternalCollabTeamsDomainPlan -Config $originalTeamsConfig -Domain $domainNormalized -Intent ADD
            if (-not $teamsPlan.Supported -and $teamsPlan.Mode -eq 'UNKNOWN') {
                throw ("Microsoft Teams federation mode is UNKNOWN; refusing a write operation for {0}. Run -TeamsAudit and review the configuration first." -f $domainNormalized)
            }

            [PSCustomObject]@{
                Domain           = $domainNormalized
                InEntra          = ($originalEntraDomains -contains $domainNormalized)
                InSPO            = ($originalSPODomains -contains $domainNormalized)
                TeamsPlan        = $teamsPlan
                NeedsTeamsChange = ($teamsPlan.Supported -and $teamsPlan.NeedsChange)
            }
        }
    )

    Write-Step 'Planning configuration change...'
    foreach ($plan in $plans) {
        if ($plan.InEntra) { Write-Status -Status OK -Message ("Entra ID already allows {0}" -f $plan.Domain) }
        else { Write-Status -Status INFO -Message ("Entra ID will add {0}" -f $plan.Domain) }
        if ($plan.InSPO) { Write-Status -Status OK -Message ("SharePoint already allows {0}" -f $plan.Domain) }
        else { Write-Status -Status INFO -Message ("SharePoint will add {0}" -f $plan.Domain) }
        Write-ExternalCollabTeamsDomainPlan -Plan $plan.TeamsPlan
    }

    $addToEntra = @($plans | Where-Object { -not $_.InEntra } | ForEach-Object { $_.Domain })
    $addToSPO = @($plans | Where-Object { -not $_.InSPO } | ForEach-Object { $_.Domain })
    $teamsPlansToApply = @($plans | Where-Object { $_.NeedsTeamsChange })

    if ($domainList.Count -gt 1) {
        Write-Host
        Write-SummaryMetric -Status INFO -Label 'Domains requested' -Value $domainList.Count
        Write-SummaryMetric -Status INFO -Label 'Additions to Entra ID' -Value $addToEntra.Count
        Write-SummaryMetric -Status INFO -Label 'Additions to SharePoint' -Value $addToSPO.Count
        Write-SummaryMetric -Status INFO -Label 'Microsoft Teams changes' -Value $teamsPlansToApply.Count
    }

    if ($addToEntra.Count -eq 0 -and $addToSPO.Count -eq 0 -and $teamsPlansToApply.Count -eq 0) {
        $teamsBlocked = @($plans | Where-Object { -not $_.TeamsPlan.Supported })
        if ($teamsBlocked.Count -eq 0) {
            Write-Status -Status OK -Message 'All requested domains are already synchronized across active providers; no changes required'
        }
        else {
            Write-WrappedStatus -Status WARN -Message ("Entra ID and SharePoint already allow the requested domains; Microsoft Teams unchanged: {0}" -f $teamsBlocked[0].TeamsPlan.Reason)
        }
        return
    }

    if ($WhatIf) {
        Write-Status -Status INFO -Message 'WhatIf mode: planned changes only'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    $requiredGraphWriteScopes = @()
    if ($addToEntra.Count -gt 0) { $requiredGraphWriteScopes += $script:EntraWriteGraphScopes }
    if ($addToSPO.Count -gt 0) { $requiredGraphWriteScopes += $script:SPOWriteGraphScopes }
    $requiredGraphWriteScopes = @($requiredGraphWriteScopes | Sort-Object -Unique)

    if ($requiredGraphWriteScopes.Count -gt 0) {
        Write-Step 'Elevating only required Graph provider permissions...'
        Write-Status -Status INFO -Message ("Required write scope(s): {0}" -f ($requiredGraphWriteScopes -join ', '))
        $preflight.GraphContext = Connect-ExternalCollabGraph -Scopes $requiredGraphWriteScopes -ExpectedTenantId $preflight.SharePointTenantId
        $null = Test-ExternalCollabTenantConsistency -GraphContext $preflight.GraphContext -SharePointAdminUrl $SharePointAdminUrl -ResolvedSharePointTenantId $preflight.SharePointTenantId
    }
    else {
        Write-Status -Status OK -Message 'No Graph write permission elevation required'
    }

    # Both Graph providers are written back as whole documents and neither supports
    # optimistic concurrency, so the plan snapshot must not survive the (potentially
    # interactive) consent step above. Re-read and re-plan immediately before the write.
    Write-Step 'Re-reading Graph provider configuration before write...'
    $entraConfig = Get-EntraExternalCollabConfig
    $spoConfig = Get-SharePointExternalCollabConfig
    if ($entraConfig.Mode -ne 'AllowList') { throw ("Entra ID is no longer in AllowList mode: {0}" -f $entraConfig.Mode) }
    if ($spoConfig.Mode -ne 'AllowList') { throw ("SharePoint is no longer in AllowList mode: {0}" -f $spoConfig.Mode) }

    $originalEntraDomains = @($entraConfig.Domains)
    $originalSPODomains = @($spoConfig.Domains)

    $alreadyPresent = @(
        @($addToEntra | Where-Object { $originalEntraDomains -contains $_ }) +
        @($addToSPO | Where-Object { $originalSPODomains -contains $_ }) |
            Sort-Object -Unique
    )
    if ($alreadyPresent.Count -gt 0) {
        Write-WrappedStatus -Status WARN -Message ("Added concurrently since planning; skipped: {0}" -f ($alreadyPresent -join ', '))
    }

    $addToEntra = @($addToEntra | Where-Object { $originalEntraDomains -notcontains $_ })
    $addToSPO = @($addToSPO | Where-Object { $originalSPODomains -notcontains $_ })
    Write-Status -Status OK -Message 'Graph provider configuration re-read'

    if ($addToEntra.Count -eq 0 -and $addToSPO.Count -eq 0 -and $teamsPlansToApply.Count -eq 0) {
        Write-Status -Status OK -Message 'Domains became synchronized while planning; no changes required'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    $targetEntraDomains = @($originalEntraDomains + $addToEntra | Sort-Object -Unique)
    $targetSPODomains = @($originalSPODomains + $addToSPO | Sort-Object -Unique)
    $teamsApplied = @()

    try {
        Write-Step 'Applying configuration...'

        if ($addToEntra.Count -gt 0) {
            Set-EntraExternalCollabDomains -Config $entraConfig -Domains $targetEntraDomains
            $entraVerify = Get-EntraExternalCollabConfig
            $missingEntra = @($addToEntra | Where-Object { $entraVerify.Domains -notcontains $_ })
            if ($missingEntra.Count -gt 0) { throw ("Entra ID verification failed after adding: {0}" -f ($missingEntra -join ', ')) }
            Write-Status -Status OK -Message ("Added {0} to Entra ID" -f ($addToEntra -join ', '))
            Write-Status -Status OK -Message 'Verified Entra ID configuration'
        }
        else { Write-Status -Status OK -Message 'Entra ID unchanged' }

        if ($addToSPO.Count -gt 0) {
            Set-SharePointExternalCollabDomains -Config $spoConfig -Domains $targetSPODomains
            $spoVerify = Wait-SharePointExternalCollabDomainState -Domain $addToSPO -ShouldExist $true
            if (-not $spoVerify.Success) { throw ("SharePoint verification failed after {0} attempt(s) for: {1}" -f $spoVerify.Attempts, (@($spoVerify.Pending) -join ', ')) }
            Write-Status -Status OK -Message ("Added {0} to SharePoint" -f ($addToSPO -join ', '))
            Write-Status -Status OK -Message ("Verified SharePoint configuration ({0} attempt(s))" -f $spoVerify.Attempts)
        }
        else { Write-Status -Status OK -Message 'SharePoint unchanged' }

        # Teams mutations are per-domain and an earlier one can change the federation mode,
        # so each domain is re-planned against a fresh read immediately before its write.
        if ($teamsPlansToApply.Count -gt 0) {
            Write-Step 'Updating Microsoft Teams External Access...'
            foreach ($plan in $teamsPlansToApply) {
                $freshTeamsConfig = Get-ExternalCollabTeamsConfig -Context $preflight.TeamsContext -ForceRefresh
                $current = Get-ExternalCollabTeamsDomainPlan -Config $freshTeamsConfig -Domain $plan.Domain -Intent ADD
                if (-not $current.Supported) {
                    throw ("Microsoft Teams state changed before write and {0} can no longer be updated safely: {1}" -f $plan.Domain, $current.Reason)
                }
                if (-not $current.NeedsChange) {
                    Write-Status -Status OK -Message ("Microsoft Teams unchanged for {0}: {1}" -f $plan.Domain, $current.Reason)
                    continue
                }

                Invoke-ExternalCollabTeamsDomainMutation -Domain $current.Domain -Operation $current.ChangeKind
                $teamsApplied += $current

                $teamsVerify = Wait-ExternalCollabTeamsDomainPlanApplied -Context $preflight.TeamsContext -Plan $current
                if (-not $teamsVerify.Success) { throw ("Microsoft Teams verification failed for {0} after {1} attempt(s)." -f $current.Domain, $teamsVerify.Attempts) }
                Write-Status -Status OK -Message ("Verified Microsoft Teams External Access for {0} ({1} attempt(s))" -f $current.Domain, $teamsVerify.Attempts)
            }
        }
        else {
            $teamsUnsupported = @($plans | Where-Object { -not $_.TeamsPlan.Supported })
            if ($teamsUnsupported.Count -gt 0) { Write-WrappedStatus -Status WARN -Message ("Microsoft Teams unchanged: {0}" -f $teamsUnsupported[0].TeamsPlan.Reason) }
            else { Write-Status -Status OK -Message 'Microsoft Teams unchanged' }
        }

        Write-Step 'Final validation...'
        $finalEntra = Get-EntraExternalCollabConfig
        $missingFinalEntra = @($domainList | Where-Object { $finalEntra.Domains -notcontains $_ })
        $finalSPOResult = Wait-SharePointExternalCollabDomainState -Domain $domainList -ShouldExist $true -MaxAttempts 5 -DelaySeconds 2
        if ($missingFinalEntra.Count -gt 0 -or (-not $finalSPOResult.Success)) {
            $missingText = @(@($missingFinalEntra) + @($finalSPOResult.Pending) | Sort-Object -Unique) -join ', '
            throw ("Final validation failed: not present in both Entra ID and SharePoint allowlists: {0}" -f $missingText)
        }

        $finalTeams = Get-ExternalCollabTeamsConfig -Context $preflight.TeamsContext -ForceRefresh
        $teamsNotAllowed = @(
            $plans |
                Where-Object { $_.TeamsPlan.Supported } |
                Where-Object { -not (Get-ExternalCollabTeamsDomainState -Config $finalTeams -Domain $_.Domain).EffectiveAllowed } |
                ForEach-Object { $_.Domain }
        )
        if ($teamsNotAllowed.Count -gt 0) {
            throw ("Final validation failed: not effectively allowed in Microsoft Teams: {0}" -f ($teamsNotAllowed -join ', '))
        }

        Write-Status -Status OK -Message ("Allowed in Entra ID: {0}" -f ($domainList -join ', '))
        Write-Status -Status OK -Message ("Allowed in SharePoint: {0}" -f ($domainList -join ', '))
        $teamsSupportedDomains = @($plans | Where-Object { $_.TeamsPlan.Supported } | ForEach-Object { $_.Domain })
        if ($teamsSupportedDomains.Count -gt 0) { Write-Status -Status OK -Message ("Effectively allowed in Microsoft Teams: {0}" -f ($teamsSupportedDomains -join ', ')) }
        $teamsUnsupportedDomains = @($plans | Where-Object { -not $_.TeamsPlan.Supported } | ForEach-Object { $_.Domain })
        if ($teamsUnsupportedDomains.Count -gt 0) { Write-WrappedStatus -Status WARN -Message ("Microsoft Teams was not changed for: {0}" -f ($teamsUnsupportedDomains -join ', ')) }
        Write-Status -Status OK -Message 'Configuration update complete'
    }
    catch {
        $operationError = $_.Exception.Message
        $rollbackErrors = @()
        Write-Step 'Attempting rollback...'

        for ($index = $teamsApplied.Count - 1; $index -ge 0; $index--) {
            $done = $teamsApplied[$index]
            try {
                $inverse = Get-ExternalCollabTeamsInverseChangeKind -ChangeKind $done.ChangeKind
                if ($inverse -eq 'NONE') { continue }
                Invoke-ExternalCollabTeamsDomainMutation -Domain $done.Domain -Operation $inverse
                $teamsRollbackVerify = Wait-ExternalCollabTeamsOriginalDomainState -Context $preflight.TeamsContext -Domain $done.Domain -OriginalState $done.OriginalState
                if (-not $teamsRollbackVerify.Success) { throw 'rollback write completed but the original domain state was not restored' }
                Write-Status -Status OK -Message ("Restored original Microsoft Teams domain state for {0} ({1} attempt(s))" -f $done.Domain, $teamsRollbackVerify.Attempts)
            }
            catch {
                $message = ("Microsoft Teams rollback failed for {0}: {1}" -f $done.Domain, $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        if ($addToEntra.Count -gt 0) {
            try {
                $currentEntra = Get-EntraExternalCollabConfig
                if (Test-StringSetEqual -Left $currentEntra.Domains -Right $targetEntraDomains) {
                    Set-EntraExternalCollabDomains -Config $currentEntra -Domains $originalEntraDomains
                    Write-Status -Status OK -Message 'Restored original Entra ID allowlist'
                }
                elseif (Test-StringSetEqual -Left $currentEntra.Domains -Right $originalEntraDomains) { Write-Status -Status OK -Message 'Entra ID already matches original state' }
                else {
                    $message = 'Entra ID rollback skipped because the allowlist changed concurrently'
                    $rollbackErrors += $message
                    Write-Status -Status WARN -Message $message
                }
            }
            catch {
                $message = ("Entra ID rollback failed: {0}" -f $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        if ($addToSPO.Count -gt 0) {
            try {
                $currentSPO = Get-SharePointExternalCollabConfig
                if (Test-StringSetEqual -Left $currentSPO.Domains -Right $targetSPODomains) {
                    Set-SharePointExternalCollabDomains -Config $currentSPO -Domains $originalSPODomains
                    $spoRollbackVerify = Wait-SharePointExternalCollabDomainState -Domain $addToSPO -ShouldExist $false
                    if (-not $spoRollbackVerify.Success) { throw 'SharePoint rollback write completed but read-back did not converge.' }
                    Write-Status -Status OK -Message 'Restored original SharePoint allowlist'
                }
                elseif (Test-StringSetEqual -Left $currentSPO.Domains -Right $originalSPODomains) { Write-Status -Status OK -Message 'SharePoint already matches original state' }
                else {
                    $message = 'SharePoint rollback skipped because the allowlist changed concurrently'
                    $rollbackErrors += $message
                    Write-Status -Status WARN -Message $message
                }
            }
            catch {
                $message = ("SharePoint rollback failed: {0}" -f $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        if ($rollbackErrors.Count -gt 0) { throw ("AddDomain failed: {0} Rollback needs review: {1}" -f $operationError, ($rollbackErrors -join '; ')) }
        throw ("AddDomain failed: {0} Original configuration was restored." -f $operationError)
    }
}

#endregion AddDomain


#region SyncDrifted

function Invoke-ExternalCollabSyncDrifted {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointAdminUrl,

        [switch]$WhatIf
    )

    Write-Step 'Synchronize drifted domains'

    # Planning is always read-only. Write scopes are requested later, and only for the
    # providers that the confirmed plan actually needs.
    $preflight = Invoke-ExternalCollabPreflight `
        -SharePointAdminUrl $SharePointAdminUrl `
        -GraphScopes $script:AuditGraphScopes `
        -RequireTenantPin:(-not $WhatIf) `
        -IncludeGuests

    $audit = @(
        New-ExternalCollabAudit `
            -EntraDomains $preflight.EntraConfig.Domains `
            -SPODomains $preflight.SPOConfig.Domains `
            -Guests $preflight.Guests
    )

    $drifted = @($audit | Where-Object { $_.State -eq 'DRIFT' } | Sort-Object Domain)

    if ($drifted.Count -eq 0) {
        Write-Step 'Drift synchronization plan...'
        Write-Status -Status OK -Message 'No configuration drift found'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    # A DRIFT domain with no guest accounts may be an incomplete removal. Do not
    # resurrect it automatically. Audit/PurgeDomain can be used to decide its fate.
    $eligible = @($drifted | Where-Object { $_.Guests -gt 0 })
    $skipped = @($drifted | Where-Object { $_.Guests -eq 0 })

    Write-Step 'Drift synchronization plan...'

    foreach ($item in $eligible) {
        if ($item.InEntra -and -not $item.InSPO) {
            Write-WrappedStatus -Status INFO -Message ("{0}: Entra ID only, {1} guest(s); add to SharePoint" -f $item.Domain, $item.Guests)
        }
        elseif (-not $item.InEntra -and $item.InSPO) {
            Write-WrappedStatus -Status INFO -Message ("{0}: SharePoint only, {1} guest(s); add to Entra ID" -f $item.Domain, $item.Guests)
        }
        else {
            Write-WrappedStatus -Status WARN -Message ("{0}: unexpected DRIFT state; skipped" -f $item.Domain)
        }
    }

    foreach ($item in $skipped) {
        Write-WrappedStatus -Status WARN -Message ("{0}: drifted but has no guest accounts; skipped to avoid resurrecting a possibly retired partner" -f $item.Domain)
    }

    if ($eligible.Count -eq 0) {
        Write-Status -Status OK -Message 'No eligible drifted domains to synchronize'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    $addToEntra = @($eligible | Where-Object { -not $_.InEntra -and $_.InSPO } | Select-Object -ExpandProperty Domain)
    $addToSPO = @($eligible | Where-Object { $_.InEntra -and -not $_.InSPO } | Select-Object -ExpandProperty Domain)

    Write-Host
    Write-SummaryMetric -Status INFO -Label 'Eligible drifted domains' -Value $eligible.Count
    Write-SummaryMetric -Status INFO -Label 'Additions to Entra ID' -Value $addToEntra.Count
    Write-SummaryMetric -Status INFO -Label 'Additions to SharePoint' -Value $addToSPO.Count
    if ($skipped.Count -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Skipped zero-guest drift' -Value $skipped.Count
    }

    if ($WhatIf) {
        Write-Status -Status INFO -Message 'WhatIf mode: planned synchronization only'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    if (-not (Confirm-ExternalCollabAction -Prompt ("Synchronize {0} drifted domain(s)?" -f $eligible.Count))) {
        Write-Status -Status INFO -Message 'Operation cancelled'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    $requiredGraphWriteScopes = @()
    if ($addToEntra.Count -gt 0) { $requiredGraphWriteScopes += $script:EntraWriteGraphScopes }
    if ($addToSPO.Count -gt 0) { $requiredGraphWriteScopes += $script:SPOWriteGraphScopes }
    $requiredGraphWriteScopes = @($requiredGraphWriteScopes | Sort-Object -Unique)

    if ($requiredGraphWriteScopes.Count -gt 0) {
        Write-Step 'Elevating only required Graph provider permissions...'
        Write-Status -Status INFO -Message ("Required write scope(s): {0}" -f ($requiredGraphWriteScopes -join ', '))
        $preflight.GraphContext = Connect-ExternalCollabGraph -Scopes $requiredGraphWriteScopes -ExpectedTenantId $preflight.SharePointTenantId
        $null = Test-ExternalCollabTenantConsistency -GraphContext $preflight.GraphContext -SharePointAdminUrl $SharePointAdminUrl -ResolvedSharePointTenantId $preflight.SharePointTenantId
    }

    # Neither Graph provider supports optimistic concurrency, so the plan snapshot must
    # not survive the confirmation prompt and the consent step above.
    Write-Step 'Re-reading Graph provider configuration before write...'
    $entraConfig = Get-EntraExternalCollabConfig
    $spoConfig = Get-SharePointExternalCollabConfig
    if ($entraConfig.Mode -ne 'AllowList') { throw ("Entra ID is no longer in AllowList mode: {0}" -f $entraConfig.Mode) }
    if ($spoConfig.Mode -ne 'AllowList') { throw ("SharePoint is no longer in AllowList mode: {0}" -f $spoConfig.Mode) }

    $originalEntraDomains = @($entraConfig.Domains)
    $originalSPODomains = @($spoConfig.Domains)

    $alreadyPresent = @(
        @($addToEntra | Where-Object { $originalEntraDomains -contains $_ }) +
        @($addToSPO | Where-Object { $originalSPODomains -contains $_ }) |
            Sort-Object -Unique
    )
    if ($alreadyPresent.Count -gt 0) {
        Write-WrappedStatus -Status WARN -Message ("Added concurrently since planning; skipped: {0}" -f ($alreadyPresent -join ', '))
    }

    $addToEntra = @($addToEntra | Where-Object { $originalEntraDomains -notcontains $_ })
    $addToSPO = @($addToSPO | Where-Object { $originalSPODomains -notcontains $_ })

    if ($addToEntra.Count -eq 0 -and $addToSPO.Count -eq 0) {
        Write-Status -Status OK -Message 'All planned additions are already present; nothing left to synchronize'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    $targetEntraDomains = @($originalEntraDomains + $addToEntra | Sort-Object -Unique)
    $targetSPODomains = @($originalSPODomains + $addToSPO | Sort-Object -Unique)

    $entraChanged = $addToEntra.Count -gt 0
    $spoChanged = $addToSPO.Count -gt 0

    try {
        Write-Step 'Synchronizing drifted domains...'

        if ($entraChanged) {
            Set-EntraExternalCollabDomains `
                -Config $entraConfig `
                -Domains $targetEntraDomains

            $entraVerify = Get-EntraExternalCollabConfig
            $missingEntra = @($addToEntra | Where-Object { $entraVerify.Domains -notcontains $_ })
            if ($missingEntra.Count -gt 0) {
                throw ("Entra ID verification failed for: {0}" -f ($missingEntra -join ', '))
            }

            foreach ($domain in $addToEntra) {
                Write-Status -Status OK -Message ("Added {0} to Entra ID" -f $domain)
            }
            Write-Status -Status OK -Message 'Verified Entra ID configuration'
        }
        else {
            Write-Status -Status SKIP -Message 'Entra ID unchanged'
        }

        if ($spoChanged) {
            Set-SharePointExternalCollabDomains -Config $spoConfig -Domains $targetSPODomains

            $verify = Wait-SharePointExternalCollabDomainState -Domain $addToSPO -ShouldExist $true
            if (-not $verify.Success) {
                throw ("SharePoint verification failed after {0} attempt(s) for: {1}" -f $verify.Attempts, (@($verify.Pending) -join ', '))
            }

            foreach ($domain in $addToSPO) {
                Write-Status -Status OK -Message ("Added {0} to SharePoint" -f $domain)
            }
            Write-Status -Status OK -Message ("Verified SharePoint configuration ({0} attempt(s))" -f $verify.Attempts)
        }
        else {
            Write-Status -Status SKIP -Message 'SharePoint unchanged'
        }

        Write-Step 'Final validation...'

        $finalEntra = Get-EntraExternalCollabConfig
        $finalSPO = Get-SharePointExternalCollabConfig
        $notSynchronized = @(
            $eligible | Where-Object {
                ($finalEntra.Domains -notcontains $_.Domain) -or
                ($finalSPO.Domains -notcontains $_.Domain)
            }
        )

        if ($notSynchronized.Count -gt 0) {
            throw ("Final validation failed for: {0}" -f (($notSynchronized | Select-Object -ExpandProperty Domain) -join ', '))
        }

        foreach ($item in $eligible) {
            Write-Status -Status OK -Message ("{0} is synchronized" -f $item.Domain)
        }

        Write-Step 'Synchronization summary...'
        Write-SummaryMetric -Status OK -Label 'Synchronized domains' -Value $eligible.Count
        Write-SummaryMetric -Status OK -Label 'Entra ID additions' -Value $addToEntra.Count
        Write-SummaryMetric -Status OK -Label 'SharePoint additions' -Value $addToSPO.Count
        if ($skipped.Count -gt 0) {
            Write-SummaryMetric -Status WARN -Label 'Skipped zero-guest drift' -Value $skipped.Count
        }
        Write-Status -Status OK -Message 'Drift synchronization complete'
    }
    catch {
        $operationError = $_.Exception.Message
        $rollbackErrors = @()

        Write-Step 'Attempting rollback...'

        if ($entraChanged) {
            try {
                $currentEntra = Get-EntraExternalCollabConfig
                if (Test-StringSetEqual -Left $currentEntra.Domains -Right $targetEntraDomains) {
                    Set-EntraExternalCollabDomains -Config $currentEntra -Domains $originalEntraDomains
                    Write-Status -Status OK -Message 'Restored original Entra ID allowlist'
                }
                elseif (Test-StringSetEqual -Left $currentEntra.Domains -Right $originalEntraDomains) {
                    Write-Status -Status OK -Message 'Entra ID already matches original state'
                }
                else {
                    $message = 'Entra ID rollback skipped because the allowlist changed concurrently'
                    $rollbackErrors += $message
                    Write-Status -Status WARN -Message $message
                }
            }
            catch {
                $message = ("Entra ID rollback failed: {0}" -f $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        if ($spoChanged) {
            try {
                $currentSPO = Get-SharePointExternalCollabConfig
                if (Test-StringSetEqual -Left $currentSPO.Domains -Right $targetSPODomains) {
                    Set-SharePointExternalCollabDomains -Config $currentSPO -Domains $originalSPODomains
                    Write-Status -Status OK -Message 'Restored original SharePoint allowlist'
                }
                elseif (Test-StringSetEqual -Left $currentSPO.Domains -Right $originalSPODomains) {
                    Write-Status -Status OK -Message 'SharePoint already matches original state'
                }
                else {
                    $message = 'SharePoint rollback skipped because the allowlist changed concurrently'
                    $rollbackErrors += $message
                    Write-Status -Status WARN -Message $message
                }
            }
            catch {
                $message = ("SharePoint rollback failed: {0}" -f $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        if ($rollbackErrors.Count -gt 0) {
            throw ("SyncDrifted failed: {0} Rollback needs review: {1}" -f $operationError, ($rollbackErrors -join '; '))
        }

        throw ("SyncDrifted failed: {0} Original configuration was restored." -f $operationError)
    }
}

#endregion SyncDrifted

#region PurgeDomain

function Invoke-ExternalCollabPurgeDomainSingle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Preflight,

        [Parameter(Mandatory = $true)]
        [string]$Domain,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Guests
    )

    $domainNormalized = $Domain
    # NOTE: $matches is a PowerShell automatic variable and is deliberately not used here.
    $targets = @($Guests)

    Write-Step ("Purging {0}..." -f $domainNormalized)

    # Neither Graph provider supports optimistic concurrency and both are written back as
    # whole documents, so the write must plan from a snapshot taken immediately before it.
    # In a multi-domain batch this also picks up the previous domain's committed removal.
    Write-Step 'Re-reading provider configuration before write...'
    $entraConfig = Get-EntraExternalCollabConfig
    $spoConfig = Get-SharePointExternalCollabConfig
    if ($entraConfig.Mode -ne 'AllowList') { throw ("Entra ID is no longer in AllowList mode: {0}" -f $entraConfig.Mode) }
    if ($spoConfig.Mode -ne 'AllowList') { throw ("SharePoint is no longer in AllowList mode: {0}" -f $spoConfig.Mode) }

    $originalEntraDomains = @($entraConfig.Domains)
    $originalSPODomains = @($spoConfig.Domains)
    $inEntra = $originalEntraDomains -contains $domainNormalized
    $inSPO = $originalSPODomains -contains $domainNormalized

    $teamsConfig = Get-ExternalCollabTeamsConfig -Context $Preflight.TeamsContext -ForceRefresh
    $teamsPlan = Get-ExternalCollabTeamsDomainPlan -Config $teamsConfig -Domain $domainNormalized -Intent REMOVE
    if (-not $teamsPlan.Supported) {
        throw ("Microsoft Teams federation mode {0} cannot be safely modified for {1}. Run -TeamsAudit and review the configuration first." -f $teamsPlan.Mode, $domainNormalized)
    }
    $needsTeamsChange = $teamsPlan.NeedsChange
    Write-Status -Status OK -Message 'Provider configuration re-read'

    $targetEntraDomains = @($originalEntraDomains | Where-Object { $_ -ne $domainNormalized })
    $targetSPODomains = @($originalSPODomains | Where-Object { $_ -ne $domainNormalized })
    $teamsChanged = $false

    try {
        Write-Step 'Removing external collaboration configuration...'

        if ($inEntra) {
            Set-EntraExternalCollabDomains -Config $entraConfig -Domains $targetEntraDomains
            $entraVerify = Get-EntraExternalCollabConfig
            if ($entraVerify.Domains -contains $domainNormalized) { throw ("Entra ID verification failed after removing {0}." -f $domainNormalized) }
            Write-Status -Status OK -Message ("Removed {0} from Entra ID" -f $domainNormalized)
            Write-Status -Status OK -Message 'Verified Entra ID configuration'
        }
        else { Write-Status -Status SKIP -Message 'Entra ID unchanged' }

        if ($inSPO) {
            Set-SharePointExternalCollabDomains -Config $spoConfig -Domains $targetSPODomains
            $spoVerify = Wait-SharePointExternalCollabDomainState -Domain $domainNormalized -ShouldExist $false
            if (-not $spoVerify.Success) { throw ("SharePoint verification failed after removing {0} after {1} attempts." -f $domainNormalized, $spoVerify.Attempts) }
            Write-Status -Status OK -Message ("Removed {0} from SharePoint" -f $domainNormalized)
            Write-Status -Status OK -Message ("Verified SharePoint configuration ({0} attempt(s))" -f $spoVerify.Attempts)
        }
        else { Write-Status -Status SKIP -Message 'SharePoint unchanged' }

        if ($needsTeamsChange) {
            Write-Step 'Closing Microsoft Teams External Access for domain...'
            Invoke-ExternalCollabTeamsDomainMutation `
                -Domain $domainNormalized `
                -Operation $teamsPlan.ChangeKind
            $teamsChanged = $true
            $teamsVerify = Wait-ExternalCollabTeamsDomainPlanApplied `
                -Context $Preflight.TeamsContext `
                -Plan $teamsPlan
            if (-not $teamsVerify.Success) {
                throw ("Microsoft Teams verification failed after removing {0} after {1} attempt(s)." -f $domainNormalized, $teamsVerify.Attempts)
            }
            Write-Status -Status OK -Message ("Verified Microsoft Teams External Access is closed for {0} ({1} attempt(s))" -f $domainNormalized, $teamsVerify.Attempts)
        }
        else { Write-Status -Status OK -Message ("Microsoft Teams unchanged: {0}" -f $teamsPlan.Reason) }

        Write-Step 'Validating closed configuration...'
        $finalEntra = Get-EntraExternalCollabConfig
        $finalSPOResult = Wait-SharePointExternalCollabDomainState -Domain $domainNormalized -ShouldExist $false -MaxAttempts 5 -DelaySeconds 2
        if (($finalEntra.Domains -contains $domainNormalized) -or (-not $finalSPOResult.Success)) {
            throw ("Final validation failed: {0} is still present in Entra ID or SharePoint external collaboration configuration." -f $domainNormalized)
        }

        $finalTeams = Get-ExternalCollabTeamsConfig -Context $Preflight.TeamsContext
        $finalTeamsState = Get-ExternalCollabTeamsDomainState -Config $finalTeams -Domain $domainNormalized
        if ($finalTeamsState.EffectiveAllowed) {
            throw ("Final validation failed: {0} is still effectively allowed in Microsoft Teams." -f $domainNormalized)
        }

        Write-Status -Status OK -Message ("{0} is absent from Entra ID" -f $domainNormalized)
        Write-Status -Status OK -Message ("{0} is absent from SharePoint" -f $domainNormalized)
        Write-Status -Status OK -Message ("{0} is not effectively allowed in Microsoft Teams" -f $domainNormalized)
        Write-Status -Status OK -Message 'External collaboration configuration is closed'
    }
    catch {
        $operationError = $_.Exception.Message
        $rollbackErrors = @()
        Write-Step 'Attempting configuration rollback...'

        if ($teamsChanged) {
            try {
                $inverse = Get-ExternalCollabTeamsInverseChangeKind -ChangeKind $teamsPlan.ChangeKind
                if ($inverse -ne 'NONE') {
                    Invoke-ExternalCollabTeamsDomainMutation `
                        -Domain $domainNormalized `
                        -Operation $inverse
                    $teamsRollbackVerify = Wait-ExternalCollabTeamsOriginalDomainState `
                        -Context $Preflight.TeamsContext `
                        -Domain $domainNormalized `
                        -OriginalState $teamsPlan.OriginalState
                    if (-not $teamsRollbackVerify.Success) {
                        throw 'Microsoft Teams rollback write completed but the original domain state was not restored.'
                    }
                    Write-Status -Status OK -Message ("Restored original Microsoft Teams domain state ({0} attempt(s))" -f $teamsRollbackVerify.Attempts)
                }
            }
            catch {
                $message = ("Microsoft Teams rollback failed: {0}" -f $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        if ($inEntra) {
            try {
                $currentEntra = Get-EntraExternalCollabConfig
                if (Test-StringSetEqual -Left $currentEntra.Domains -Right $targetEntraDomains) {
                    Set-EntraExternalCollabDomains -Config $currentEntra -Domains $originalEntraDomains
                    Write-Status -Status OK -Message 'Restored original Entra ID allowlist'
                }
                elseif (Test-StringSetEqual -Left $currentEntra.Domains -Right $originalEntraDomains) { Write-Status -Status OK -Message 'Entra ID already matches original state' }
                else {
                    $message = 'Entra ID rollback skipped because the allowlist changed concurrently'
                    $rollbackErrors += $message
                    Write-Status -Status WARN -Message $message
                }
            }
            catch {
                $message = ("Entra ID rollback failed: {0}" -f $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        if ($inSPO) {
            try {
                $currentSPO = Get-SharePointExternalCollabConfig
                if (Test-StringSetEqual -Left $currentSPO.Domains -Right $targetSPODomains) {
                    Set-SharePointExternalCollabDomains -Config $currentSPO -Domains $originalSPODomains
                    $spoRollbackVerify = Wait-SharePointExternalCollabDomainState -Domain $domainNormalized -ShouldExist $true
                    if (-not $spoRollbackVerify.Success) { throw 'SharePoint rollback write completed but read-back did not converge.' }
                    Write-Status -Status OK -Message 'Restored original SharePoint allowlist'
                }
                elseif (Test-StringSetEqual -Left $currentSPO.Domains -Right $originalSPODomains) { Write-Status -Status OK -Message 'SharePoint already matches original state' }
                else {
                    $message = 'SharePoint rollback skipped because the allowlist changed concurrently'
                    $rollbackErrors += $message
                    Write-Status -Status WARN -Message $message
                }
            }
            catch {
                $message = ("SharePoint rollback failed: {0}" -f $_.Exception.Message)
                $rollbackErrors += $message
                Write-Status -Status FAIL -Message $message
            }
        }

        Write-Status -Status WARN -Message ("Guest purge skipped for {0} because the configuration purge did not complete safely" -f $domainNormalized)
        if ($rollbackErrors.Count -gt 0) { throw ("PurgeDomain failed for {0}: {1} Rollback needs review: {2}" -f $domainNormalized, $operationError, ($rollbackErrors -join '; ')) }
        throw ("PurgeDomain failed for {0}: {1} Original configuration was restored." -f $domainNormalized, $operationError)
    }

    $deleteResult = $null
    if ($targets.Count -gt 0) {
        Write-Step 'Purging guest accounts...'
        $deleteResult = Invoke-ExternalGuestDeletionBatch -Guests $targets
    }
    else {
        Write-Step 'Guest purge...'
        Write-Status -Status SKIP -Message 'No matching guest accounts to delete'
    }

    $deletedCount = 0
    $failedCount = 0
    if ($null -ne $deleteResult) {
        $deletedCount = @($deleteResult.Deleted).Count
        $failedCount = @($deleteResult.Failed).Count
    }

    Write-Step ("Purge summary: {0}..." -f $domainNormalized)
    Write-SummaryMetric -Status OK -Label 'Entra ID configuration changes' -Value $(if ($inEntra) { 1 } else { 0 })
    Write-SummaryMetric -Status OK -Label 'SharePoint configuration changes' -Value $(if ($inSPO) { 1 } else { 0 })
    Write-SummaryMetric -Status OK -Label 'Microsoft Teams configuration changes' -Value $(if ($teamsChanged) { 1 } else { 0 })
    Write-SummaryMetric -Status OK -Label 'Matched guest accounts' -Value $targets.Count
    Write-SummaryMetric -Status OK -Label 'Delete requests succeeded' -Value $deletedCount

    if ($failedCount -gt 0) {
        Write-SummaryMetric -Status WARN -Label 'Delete requests failed' -Value $failedCount
        Write-Status -Status WARN -Message 'Domain configuration is closed, but guest purge completed partially'
        throw ("PurgeDomain guest purge for {0} completed partially: {1} of {2} delete request(s) failed." -f $domainNormalized, $failedCount, $targets.Count)
    }

    Write-SummaryMetric -Status OK -Label 'Delete requests failed' -Value 0
    Write-Status -Status OK -Message ("{0} purge complete" -f $domainNormalized)

    return [PSCustomObject]@{
        Domain       = $domainNormalized
        EntraChanged = [bool]$inEntra
        SPOChanged   = [bool]$inSPO
        TeamsChanged = [bool]$teamsChanged
        Matched      = $targets.Count
        Deleted      = $deletedCount
    }
}

function Invoke-ExternalCollabPurgeDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SharePointAdminUrl,

        [Parameter(Mandatory = $true)]
        [string[]]$Domain,

        [switch]$TeamsReauth,

        [switch]$WhatIf
    )

    $domainList = Resolve-ExternalCollabDomainList -Domain $Domain

    Write-Step "Seems like you've got an urge to purge? Let's proceed!"
    if ($domainList.Count -eq 1) { Write-Step ("Preparing domain purge: {0}" -f $domainList[0]) }
    else { Write-Step ("Preparing domain purge: {0} domains ({1})" -f $domainList.Count, ($domainList -join ', ')) }

    $graphScopes = $script:PurgeDomainGraphScopes
    if ($WhatIf) { $graphScopes = $script:AuditGraphScopes }

    $forceTeamsRefresh = -not $WhatIf
    $preflight = Invoke-ExternalCollabPreflight `
        -SharePointAdminUrl $SharePointAdminUrl `
        -GraphScopes $graphScopes `
        -IncludeGuests `
        -IncludeTeams `
        -RequireTeams `
        -RequireTenantPin:(-not $WhatIf) `
        -TeamsReauth:$TeamsReauth `
        -TeamsRefresh:$forceTeamsRefresh

    $entraDomains = @($preflight.EntraConfig.Domains)
    $spoDomains = @($preflight.SPOConfig.Domains)
    $teamsSnapshot = Copy-ExternalCollabTeamsFederationConfig -Config $preflight.TeamsConfig

    # ---- Planning phase. Every domain is planned against the same read-only snapshot,
    # so the operator sees the whole batch before a single write is authorized.
    $plans = foreach ($domainNormalized in $domainList) {
        $inEntra = $entraDomains -contains $domainNormalized
        $inSPO = $spoDomains -contains $domainNormalized

        $teamsPlan = Get-ExternalCollabTeamsDomainPlan -Config $teamsSnapshot -Domain $domainNormalized -Intent REMOVE
        if (-not $teamsPlan.Supported) {
            throw ("Microsoft Teams federation mode {0} cannot be safely modified for PurgeDomain ({1}). Run -TeamsAudit and review the configuration first." -f $teamsPlan.Mode, $domainNormalized)
        }
        $needsTeamsChange = $teamsPlan.NeedsChange

        $domainGuests = @($preflight.Guests | Where-Object { $_.Domain -eq $domainNormalized } | Sort-Object DisplayName, Mail)

        $cleanupMode = 'Domain purge'
        if (($inEntra -or $inSPO -or $needsTeamsChange) -and -not ($inEntra -and $inSPO)) { $cleanupMode = 'Drift purge' }
        elseif (-not $inEntra -and -not $inSPO -and -not $needsTeamsChange -and $domainGuests.Count -gt 0) { $cleanupMode = 'Orphaned domain purge' }

        [PSCustomObject]@{
            Domain           = $domainNormalized
            InEntra          = $inEntra
            InSPO            = $inSPO
            TeamsPlan        = $teamsPlan
            NeedsTeamsChange = $needsTeamsChange
            Guests           = $domainGuests
            CleanupMode      = $cleanupMode
            Actionable       = ($inEntra -or $inSPO -or $needsTeamsChange -or $domainGuests.Count -gt 0)
        }
    }

    $plans = @($plans)

    # The retained invitation audit trail is expensive to read, so resolve it once for the
    # whole batch and map the enriched rows back onto each domain plan.
    $allGuests = @($plans | ForEach-Object { $_.Guests })
    $inviterIdentified = 0
    $inviterUnavailable = 0

    if ($allGuests.Count -gt 0) {
        $inviterMetadata = Resolve-ExternalGuestInviterMetadata -Guests $allGuests
        $inviterIdentified = $inviterMetadata.InviterIdentified
        $inviterUnavailable = $inviterMetadata.InviterUnavailable

        $enrichedById = @{}
        foreach ($guest in @($inviterMetadata.Guests)) { $enrichedById[[string]$guest.Id] = $guest }

        foreach ($plan in $plans) {
            $plan.Guests = @(
                $plan.Guests | ForEach-Object {
                    if ($enrichedById.ContainsKey([string]$_.Id)) { $enrichedById[[string]$_.Id] } else { $_ }
                }
            )
        }
    }

    # ---- Preview.
    foreach ($plan in $plans) {
        Write-Step ("{0}: {1}" -f $plan.CleanupMode, $plan.Domain)
        Write-SubStep 'Current state'

        if ($plan.InEntra) { Write-Status -Status OK -Message ("Entra ID allows {0}" -f $plan.Domain) }
        else { Write-Status -Status SKIP -Message ("Entra ID does not allow {0}" -f $plan.Domain) }

        if ($plan.InSPO) { Write-Status -Status OK -Message ("SharePoint allows {0}" -f $plan.Domain) }
        else { Write-Status -Status SKIP -Message ("SharePoint does not allow {0}" -f $plan.Domain) }

        $teamsState = Get-ExternalCollabTeamsDomainState -Config $teamsSnapshot -Domain $plan.Domain
        if ($teamsState.EffectiveAllowed) { Write-Status -Status OK -Message ("Microsoft Teams effectively allows {0} ({1})" -f $plan.Domain, $teamsState.Mode) }
        else { Write-Status -Status SKIP -Message ("Microsoft Teams does not effectively allow {0} ({1})" -f $plan.Domain, $teamsState.Mode) }

        if ($plan.Guests.Count -gt 0) {
            Write-Status -Status OK -Message ("Found {0} matching guest account(s)" -f $plan.Guests.Count)
            Write-ExternalGuestPurgeTable -Guests $plan.Guests
        }
        else { Write-Status -Status SKIP -Message 'No matching #EXT# guest accounts found' }

        Write-SubStep 'Planned changes'

        if ($plan.InEntra) { Write-Status -Status WARN -Message ("Remove {0} from Entra ID" -f $plan.Domain) }
        else { Write-Status -Status SKIP -Message 'Entra ID unchanged' }

        if ($plan.InSPO) { Write-Status -Status WARN -Message ("Remove {0} from SharePoint" -f $plan.Domain) }
        else { Write-Status -Status SKIP -Message 'SharePoint unchanged' }

        Write-ExternalCollabTeamsDomainPlan -Plan $plan.TeamsPlan

        if ($plan.Guests.Count -gt 0) { Write-Status -Status WARN -Message ("Delete {0} Entra ID guest account(s)" -f $plan.Guests.Count) }
        else { Write-Status -Status SKIP -Message 'No guest accounts to delete' }

        if (-not $plan.Actionable) {
            Write-Status -Status OK -Message ("{0} is already closed across active providers and has no matching guest accounts" -f $plan.Domain)
        }
    }

    $actionable = @($plans | Where-Object { $_.Actionable })
    $skipped = @($plans | Where-Object { -not $_.Actionable })

    $totalGuests = @($actionable | ForEach-Object { $_.Guests }).Count
    $entraRemovals = @($actionable | Where-Object { $_.InEntra }).Count
    $spoRemovals = @($actionable | Where-Object { $_.InSPO }).Count
    $teamsChanges = @($actionable | Where-Object { $_.NeedsTeamsChange }).Count

    Write-Step 'Purge preview summary...'
    Write-SummaryMetric -Status WARN -Label 'Domains to purge' -Value $actionable.Count
    if ($skipped.Count -gt 0) { Write-SummaryMetric -Status SKIP -Label 'Domains already closed' -Value $skipped.Count }
    Write-SummaryMetric -Status WARN -Label 'Entra ID removals' -Value $entraRemovals
    Write-SummaryMetric -Status WARN -Label 'SharePoint removals' -Value $spoRemovals
    Write-SummaryMetric -Status WARN -Label 'Microsoft Teams changes' -Value $teamsChanges
    Write-SummaryMetric -Status WARN -Label 'Guest accounts to delete' -Value $totalGuests
    if ($totalGuests -gt 0) {
        Write-SummaryMetric -Status OK -Label 'Inviter identified' -Value $inviterIdentified
        if ($inviterUnavailable -gt 0) { Write-SummaryMetric -Status WARN -Label 'Inviter unavailable' -Value $inviterUnavailable }
        else { Write-SummaryMetric -Status OK -Label 'Inviter unavailable' -Value 0 }
    }

    if ($actionable.Count -eq 0) {
        Write-Status -Status OK -Message 'All selected domains are already closed and no matching guest accounts exist'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    if ($WhatIf) {
        Write-Status -Status INFO -Message 'WhatIf mode: purge preview only'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    $confirmPrompt = if ($actionable.Count -eq 1) {
        "Purge {0} across external collaboration providers and delete {1} matching guest account(s)?" -f $actionable[0].Domain, $totalGuests
    }
    else {
        "Purge {0} domain(s) ({1}) across external collaboration providers and delete {2} matching guest account(s)?" -f $actionable.Count, (($actionable | ForEach-Object { $_.Domain }) -join ', '), $totalGuests
    }

    if (-not (Confirm-ExternalCollabPurgeAction -Prompt $confirmPrompt)) {
        Write-Status -Status INFO -Message 'Purge cancelled'
        Write-Status -Status OK -Message 'No changes were made'
        return
    }

    # ---- Apply. Domains are processed one at a time; each one re-reads provider state and
    # rolls itself back on failure. A failure aborts the batch rather than continuing blind.
    $completed = @()
    $results = @()

    for ($index = 0; $index -lt $actionable.Count; $index++) {
        $plan = $actionable[$index]

        if ($actionable.Count -gt 1) {
            Write-Step ("Domain {0}/{1}: {2}" -f ($index + 1), $actionable.Count, $plan.Domain)
        }

        try {
            $results += Invoke-ExternalCollabPurgeDomainSingle `
                -Preflight $preflight `
                -Domain $plan.Domain `
                -Guests $plan.Guests
            $completed += $plan.Domain
        }
        catch {
            $remaining = @($actionable | Select-Object -Skip ($index + 1) | ForEach-Object { $_.Domain })
            if ($completed.Count -gt 0) {
                Write-WrappedStatus -Status INFO -Message ("Completed before the failure: {0}" -f ($completed -join ', '))
            }
            if ($remaining.Count -gt 0) {
                Write-WrappedStatus -Status WARN -Message ("Not processed: {0}" -f ($remaining -join ', '))
            }
            throw
        }
    }

    if ($actionable.Count -gt 1) {
        Write-Step 'Batch purge summary...'
        Write-SummaryMetric -Status OK -Label 'Domains purged' -Value $completed.Count
        Write-SummaryMetric -Status OK -Label 'Entra ID removals' -Value @($results | Where-Object { $_.EntraChanged }).Count
        Write-SummaryMetric -Status OK -Label 'SharePoint removals' -Value @($results | Where-Object { $_.SPOChanged }).Count
        Write-SummaryMetric -Status OK -Label 'Microsoft Teams changes' -Value @($results | Where-Object { $_.TeamsChanged }).Count
        Write-SummaryMetric -Status OK -Label 'Guest accounts deleted' -Value (@($results | Measure-Object -Property Deleted -Sum).Sum)
        Write-Status -Status OK -Message ("Batch purge complete: {0}" -f ($completed -join ', '))
    }
}

#endregion PurgeDomain

#region Main

Initialize-ConsoleTheme -NoColor:$NoColor
Write-AppBanner

try {
    switch ($PSCmdlet.ParameterSetName) {
        'Add' {
            Invoke-ExternalCollabAddDomain `
                -SharePointAdminUrl $SharePointAdminUrl `
                -Domain $AddDomain `
                -TeamsReauth:$TeamsReauth `
                -WhatIf:$WhatIf
        }

        'AddEntra' {
            Invoke-ExternalCollabGraphProviderDomainChange -Provider Entra -Intent ADD -SharePointAdminUrl $SharePointAdminUrl -Domain $AddEntra -WhatIf:$WhatIf
        }

        'AddSPO' {
            Invoke-ExternalCollabGraphProviderDomainChange -Provider SPO -Intent ADD -SharePointAdminUrl $SharePointAdminUrl -Domain $AddSPO -WhatIf:$WhatIf
        }

        'AddTeams' {
            Invoke-ExternalCollabTeamsProviderDomainChange -Intent ADD -SharePointAdminUrl $SharePointAdminUrl -Domain $AddTeams -TeamsReauth:$TeamsReauth -TeamsRefresh:$TeamsRefresh -WhatIf:$WhatIf
        }

        'RemoveEntra' {
            Invoke-ExternalCollabGraphProviderDomainChange -Provider Entra -Intent REMOVE -SharePointAdminUrl $SharePointAdminUrl -Domain $RemoveEntra -WhatIf:$WhatIf
        }

        'RemoveSPO' {
            Invoke-ExternalCollabGraphProviderDomainChange -Provider SPO -Intent REMOVE -SharePointAdminUrl $SharePointAdminUrl -Domain $RemoveSPO -WhatIf:$WhatIf
        }

        'RemoveTeams' {
            Invoke-ExternalCollabTeamsProviderDomainChange -Intent REMOVE -SharePointAdminUrl $SharePointAdminUrl -Domain $RemoveTeams -TeamsReauth:$TeamsReauth -TeamsRefresh:$TeamsRefresh -WhatIf:$WhatIf
        }

        'SyncDrifted' {
            Invoke-ExternalCollabSyncDrifted `
                -SharePointAdminUrl $SharePointAdminUrl `
                -WhatIf:$WhatIf
        }

        'PurgeDomain' {
            Invoke-ExternalCollabPurgeDomain `
                -SharePointAdminUrl $SharePointAdminUrl `
                -Domain $PurgeDomain `
                -TeamsReauth:$TeamsReauth `
                -WhatIf:$WhatIf
        }

        'Guests' {
            Invoke-ExternalCollabListGuests `
                -SharePointAdminUrl $SharePointAdminUrl `
                -Domain $GuestDomain
        }

        'PurgeGuests' {
            Invoke-ExternalCollabPurgeGuests `
                -SharePointAdminUrl $SharePointAdminUrl `
                -Selector $PurgeGuests `
                -WhatIf:$WhatIf
        }

        'PurgePending' {
            Invoke-ExternalCollabPurgePending `
                -SharePointAdminUrl $SharePointAdminUrl `
                -OlderThanDays $OlderThanDays `
                -WhatIf:$WhatIf
        }

        'TeamsAudit' {
            Invoke-ExternalCollabTeamsAudit `
                -ForceReauth:$TeamsReauth `
                -ForceRefresh:$TeamsRefresh |
                Out-Null
        }

        default {
            Invoke-ExternalCollabAudit `
                -SharePointAdminUrl $SharePointAdminUrl `
                -ReviewUsers:$ReviewUsers `
                -TeamsReauth:$TeamsReauth `
                -TeamsRefresh:$TeamsRefresh |
                Out-Null
        }
    }
}
catch {
    Write-Host
    Write-Status -Status FAIL -Message $_.Exception.Message

    if ($PSCmdlet.ParameterSetName -eq 'Audit' -or $PSCmdlet.ParameterSetName -eq 'Guests' -or $PSCmdlet.ParameterSetName -eq 'TeamsAudit' -or $WhatIf) {
        Write-Status -Status INFO -Message 'No changes were made.'
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'PurgeGuests' -or $PSCmdlet.ParameterSetName -eq 'PurgePending') {
        Write-Status -Status WARN -Message 'Guest purge may have completed partially. Review the deletion status above before retrying.'
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'PurgeDomain') {
        Write-Status -Status WARN -Message 'PurgeDomain may have closed the allowlists before guest purge failed. Review the status above before retrying.'
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'SyncDrifted') {
        Write-Status -Status WARN -Message 'SyncDrifted failed. Review the rollback status above before retrying.'
    }
    elseif ($PSCmdlet.ParameterSetName -in @('AddEntra','AddSPO','AddTeams','RemoveEntra','RemoveSPO','RemoveTeams')) {
        Write-Status -Status WARN -Message 'Provider-specific operation failed. Other providers and guest objects were not intentionally changed.'
    }
    else {
        Write-Status -Status WARN -Message 'Operation failed. Review the rollback status above before retrying.'
    }

    exit 1
}

#endregion Main
