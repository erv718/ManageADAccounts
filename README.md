# AD Account Manager

A PowerShell GUI tool for managing Active Directory contractor accounts. Built with Windows Forms for easy deployment via Intune.

## Features

- **Role-Based Access Control** — Three roles (SuperAdmin, HelpDesk, ContractorManager) controlled by AD security group membership
- **Multi-OU Search** — Search across multiple Organizational Units simultaneously
- **Contractor Identification** — Finds contractors by account expiry date or Description field
- **Account Expiry Management** — Update account expiration dates with date picker
- **Account Disable** — Disable contractor accounts with confirmation
- **Audit Logging** — All actions logged with timestamp, user, computer, and severity level
- **LDAP Input Sanitization** — Search input sanitized to prevent injection
- **Admin Account Protection** — Blocks modification of Domain Admins, Enterprise Admins, Schema Admins, and accounts with adminCount=1

## Prerequisites

- Windows with PowerShell 5.1+
- RSAT Active Directory module installed
- Membership in one of the configured security groups

## Setup

1. Copy `config.example.json` to `config.json`
2. Edit `config.json` with your AD environment values:
   - **SecurityGroups** — AD group names for each role
   - **SearchBaseOUs** — Distinguished names of OUs to search
   - **AppTitle** — Window title
3. Run `ManageADAccounts.ps1`

## Roles

| Role | Permissions |
|------|------------|
| SuperAdmin | Full access to all accounts |
| HelpDesk | Manage any non-admin account |
| ContractorManager | Manage contractor accounts only |

## Logs

Actions are logged to `%ProgramData%\ADAccountManagement\actions.log` with severity levels: INFO, WARNING, ERROR, SECURITY.
