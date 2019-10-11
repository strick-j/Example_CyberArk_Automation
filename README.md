# Example_CyberArk_Automation
Example script that demonstrates possible automation options for CyberArk Vault Managment

## SYNOPSIS
Creates and onboards new accounts based on OU changes.

## DESCRIPTION
Script built to demonstrate utilizing CyberArk Application Access Manager Central Credential Provider (CCP) to retrieve 
a credential capable of using the CyberArk REST API. Script scans an OU in AD and if new accounts are found it creates 
a New Safe, Administrator AD Account, and onboards the account into the newly created safe.

## PARAMETER OrgUnit
Parater used to pass customer Organizational Unit for scan. OU must be quoted.

## EXAMPLE
Example-Script.ps1 -OrgUnit "OU=Users,OU=CyberArk,DC=CyberArkDemo,DC=com"
Scans the "OU=Users,OU=CyberArk,DC=CyberArkDemo,DC=com" Organizational Unit for new users.
