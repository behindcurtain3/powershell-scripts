powershell.exe "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force"
powershell.exe "Invoke-RestMethod -URI https://raw.githubusercontent.com/behindcurtain3/powershell-scripts/master/setup-workstation.ps1 -Method Get -OutFile $env:USERPROFILE\setup-workstation.ps1"
powershell.exe "Unblock-File $env:USERPROFILE\setup-workstation.ps1"
powershell.exe "%USERPROFILE%\setup-workstation.ps1"
del "%USERPROFILE%\setup-workstation.ps1"
powershell.exe "Set-ExecutionPolicy -ExecutionPolicy Default -Force"