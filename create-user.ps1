[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [string]$firstname,

    [Parameter(Mandatory=$True)]
    [string]$lastname,

    [string]$accountname = ($firstname.Substring(0, 1) + $lastname).ToLower()
)

# Edit These Values
$domain = "museumofman.org"
$company = "Museum of Man"
$container = "OU=Staff,OU=San Diego Museum of Man,DC=MUSEUMOFMAN,DC=SD"

# Groups To Add The User To
$groups = @(
    "CN=Staff,OU=Security Groups,OU=San Diego Museum of Man,DC=MUSEUMOFMAN,DC=SD"
)

# Auto Generated Values (Edit at own risk)
$displayname = $firstname + " " + $lastname
$emailaddress = $accountname + "@" + $domain
$proxyaddress = "SMTP:" + $emailaddress

# Create the new user
Write-Host "Creating Account"
New-ADUser -SamAccountName $accountname -GivenName $firstname -Surname $lastname -Path $container -AccountPassword (Read-Host -AsSecureString "AccountPassword") -ChangePasswordAtLogon $True -Company $company -DisplayName $displayname -EmailAddress $emailaddress -Enabled $True -Name $displayname -UserPrincipalName $emailaddress -OtherAttributes @{'ProxyAddresses'=$proxyaddress}

Write-Host "--- Account was created"
Write-Host "--- Display Name:" $displayname
Write-Host "--- Username:" $accountname
Write-Host "--- Email Address:" $emailaddress

# Find the created user
$user = $false
while($user -eq $false)
{
    $user = Get-ADUser -Identity $accountname
}

# Add to groups 
Write-Host "Adding to Groups"
foreach($group in $groups)
{
    Add-ADGroupMember -Identity $group -Member $user
    Write-Host "---" $displayname "was added to" $group
}

Write-Host "Finished creating account"