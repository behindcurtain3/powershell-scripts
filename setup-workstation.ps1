$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$name = "DisableWindowsConsumerFeatures"
$value = "1"

IF(!(Test-Path $registryPath))
{
	New-Item -Path $registryPath -Force | Out-Null
}
New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null	

Get-AppxPackage -AllUsers | Remove-AppxPackage
Get-AppXProvisionedPackage -online | Remove-AppxProvisionedPackage -online

START http://boxstarter.org/package/nr/url?https://gist.githubusercontent.com/behindcurtain3/0d651812a4fb3cd42a8626d29e48886f/raw/20f0a2b1f4e8f4605d7e85c423abe879c826f5ea/Boxstarter