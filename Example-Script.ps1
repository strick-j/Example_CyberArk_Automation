<#
.SYNOPSIS
Creates and onboards new accounts based on OU changes.
.DESCRIPTION
Script built to demonstrate utilizing CyberArk Application Access Manager Central Credential Provider (CCP) to retrieve 
a credential capable of using the CyberArk REST API. Script scans an OU in AD and if new accounts are found it creates 
a New Safe, Administrator AD Account, and onboards the account into the newly created safe.
.PARAMETER OrgUnit
Parater used to pass customer Organizational Unit for scan. OU must be quoted.
.EXAMPLE
Script-working.ps1 -OrgUnit "OU=Users,OU=CyberArk,DC=CyberArkDemo,DC=com"
Scans the "OU=Users,OU=CyberArk,DC=CyberArkDemo,DC=com" Organizational Unit for new users.
#>

param([string]$OrgUnit="CN=Users,DC=CyberArkDemo,DC=com")

# Import psPAS powershell module
Try {
  Install-Module -Name psPAS -ErrorAction Stop
} catch {
  $ErrorMessage = $_.Exception.Message
  Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
} 

# Query for new users
Write-Host "$(Get-Date) | INFO | Querying $($OrgUnit) for new users"
$When = ((Get-Date).AddDays(-1)).Date
$NewUsers = Get-ADUser -Filter {whenCreated -ge $When} -SearchBase $OrgUnit -Properties whenCreated

# Check to see if any new users have been found
if($NewUsers.count -eq 0){
    Write-Host -ForegroundColor Yellow "$(Get-Date) | WARNING | No new users detected, exiting"
    exit
    # Add script exit here
} else{
    Write-Host -ForegroundColor Green "$(Get-Date) | INFO | $($NewUsers.count) new users detected..."
}

# Cycle through users and add them to Active Directory and then add them to domain admins
foreach($User in $NewUsers){
  # Add newly created users to domain admins group
  write-host("`n$(Get-Date) | INFO | Adding $($User.GivenName) $($User.Surname) to Vault Users Group")
	Try {
    Add-ADGroupMember -Identity "CyberarkVaultUsers" -Member $User -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $($User.GivenName) $($User.Surname) to Vault Users Group"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
  }
	# Create attributes for each user
	$Attributes = @{
		Enabled = $true
		ChangePasswordAtLogon = $false
		Path = "OU=Users,OU=CyberArk,DC=CyberArkdemo,DC=Com"
		Name = "$($User.GivenName) $($User.SurName).adm"
		UserPrincipalName = "$($User.GivenName).$($User.SurName).adm@cyberarkdemo.com"
		SamAccountName = "$($User.GivenName).$($User.SurName).adm"
		GivenName = $User.GivenName
		Surname = $User.SurName
		Company = "CyberArk"
		AccountPassword = "TotallyFakePassword123" | ConvertTo-SecureString -AsPlainText -Force
	}
	# Create users based on attributes and add to domain admins group
  write-host("$(Get-Date) | INFO | Creating $($User.GivenName) $($User.Surname) administrator account $($Attributes.SamAccountName)")
	Try {
    New-ADUser @Attributes -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | Created new administrator account - $($Attributes.SamAccountName)"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
  }
  write-host("$(Get-Date) | INFO | Adding $($User.GivenName) $($User.Surname) to the Domain Admins Group")
  Try {
    Add-ADGroupMember -Identity "Domain Admins" -Member $Attributes.SamAccountName -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | Added administrator account to Domain Admins group"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
  }
}

# Use AAM to authenticate script and retrieve credentials that can use the CyberArk Management REST API
# Note: This is done using SOAP but can also be accomplished via REST API calls
write-host "`n$(Get-Date) | INFO | Authenticating with CyberArk Vault via AAM Central Credential Provider"
$URI = "https://components.cyberarkdemo.com/aimwebservice/v1.1/aim.asmx?WSDL"
$proxy = New-WebServiceProxy -Uri $URI -UseDefaultCredential
$t = $proxy.getType().namespace
$request = New-Object ($t + ".passwordRequest")
$request.AppID = "RESTAPI";
$request.Query = "Safe=AAM Dual Accounts;Folder=Root;Object=Operating System-WinDomain-cyberarkdemo.com-user_one"
$response = $proxy.GetPassword($request)
If ($response.content) { 
  Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | Retrieved Rest API Credentials via AAM" 
} else {
  Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | Rest API Credentials could not be retrieved"
  break
}  

# Generate credentials for REST API access
write-host "`n$(Get-Date) | INFO | Generating secured credentials for API use"
Try {
  $PWord = ConvertTo-SecureString -String $response.content -AsPlainText -Force -ErrorAction Stop
  $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $response.UserName, $PWord -ErrorAction Stop
  Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | CyberArk management API credentials created"
} Catch {
  $ErrorMessage = $_.Exception.Message
  Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
}

# Use the pspete (https://github.com/pspete/psPAS) PowerShell Module to authenticate to the CyberArk Management REST API
write-host "$(Get-Date) | INFO | Generating authorization token vault username"
Try {
  New-PASSession -Credential $Credential -BaseURI https://components.cyberarkdemo.com -type ldap -ErrorAction Stop
  Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | New PAS Session Established"
} Catch {
  $ErrorMessage = $_.Exception.Message
  Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
}

# Use the pspete PowerShell Module to interact with the Rest API and create new safes / onboard accounts
foreach($User in $NewUsers){
	# Create new safe based on user name - append personal to safe name
	Write-Host("`n$(Get-Date) | INFO | Creating new safe - $($User.GivenName)-$($User.SurName)-Personal")
	Try {
    $addsafe = Add-PASSafe -SafeName "$($User.GivenName)-$($User.SurName)-Personal" -Description "$($User.GivenName)-$($User.SurName)-Personal" -ManagingCPM PasswordManager -NumberOfVersionsRetention 10 -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $($addsafe.SafeName) Created"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
  }
    
	# Allow the built in Administrator to view and use accounts in their own safe
  Write-Host("`n$(Get-Date) | INFO | Setting permissions on safe - $($User.GivenName)-$($User.SurName)-Personal")
  Try {
    $addadmin = Add-PASSafeMember -SafeName "$($User.GivenName)-$($User.SurName)-Personal" -MemberName "Administrator" -UseAccounts $true -ListAccounts $true -RetrieveAccounts $true -ViewAuditLog $true -ViewSafeMembers $true -ManageSafe $true -DeleteAccounts $true -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $($addadmin.MemberName) added to $($addadmin.SafeName) Safe"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
  }

  # Allow the user to view and use accounts in their own safe
  Try {
    $adduser = Add-PASSafeMember -SafeName "$($User.GivenName)-$($User.SurName)-Personal" -MemberName "$($User.GivenName).$($User.SurName)" -SearchIn ActiveDirectory -UseAccounts $true -ListAccounts $true -RetrieveAccounts $true -ViewAuditLog $true -ViewSafeMembers $true -ErrorAction Stop
	  Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $($adduser.MemberName) added to $($adduser.SafeName) Safe"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
  }

  # Add the users account to the safe
	# Convert temporary Password to SecureString
	$Password = ConvertTo-SecureString -String "Secret1337$" -AsPlainText -Force
	# Additional account details
	$platformAccountProperties = @{
		"LOGONDOMAIN"="cyberarkdemo.com"
	}

	# Add Account to users new safe
  Write-Host("`n$(Get-Date) | INFO | Adding $($User.GivenName).$($User.SurName).adm Administrator Account to the $($User.GivenName)-$($User.SurName)-Personal Safe")
  Try { 
    $newaccount = Add-PASAccount -secretType Password -secret $Password -SafeName "$($User.GivenName)-$($User.SurName)-Personal" -PlatformID "WinDomain" -Address "cyberarkdemo.com" -Username "$($User.GivenName).$($User.SurName).adm" -platformAccountProperties $platformAccountProperties -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | Account $($newaccount.userName) added to safe $($newaccount.safeName) at $($newaccount.createdTime)"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | ERROR | $ErrorMessage"
  }	
	
	# Reconcile account password to an unkown password
  write-host("`nINFO: Reconciling $($User.GivenName).$($User.SurName).adm Administrator Account Password")
  Write-Host("INFO: Account ID = $($newaccount.id)")
	Try {
    Invoke-PASCPMOperation -AccountID $($newaccount.id) -ReconcileTask -ErrorAction Stop
    Write-Host -ForegroundColor Green "$(Get-Date) | SUCCESS | $($User.GivenName).$($User.SurName).adm Administrator Account reconcile action started"
  } Catch {
    $ErrorMessage = $_.Exception.Message
    Write-Host -ForegroundColor Red "$(Get-Date) | Error | $ErrorMessage"
  }
}
# Close Rest API session
Close-PASSession
