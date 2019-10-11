# Example_CyberArk_Automation
Example script that demonstrates possible automation options for CyberArk Vault Managment

## Synopsis
Creates and onboards new accounts based on OU changes.

## Description
Script built to demonstrate utilizing CyberArk Application Access Manager Central Credential Provider (CCP) to retrieve 
a credential capable of using the CyberArk REST API. Script scans an OU in AD and if new accounts are found it creates 
a New Safe, Administrator AD Account, and onboards the account into the newly created safe.

## Parameter: OrgUnit
Parater used to pass customer Organizational Unit for scan. OU must be quoted.

## Example Utilization
Example-Script.ps1 -OrgUnit "OU=Users,OU=CyberArk,DC=CyberArkDemo,DC=com"
Scans the "OU=Users,OU=CyberArk,DC=CyberArkDemo,DC=com" Organizational Unit for new users.

## Notes:
This script relies on a PowerShell module created by Pete Maan
For more info refer to: [psPAS Homepage](https://pspas.pspete.dev) and [psPAS GitHub](https://github.com/pspete/psPAS)
