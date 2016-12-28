cd "C:\Users\netadmin\Desktop"
powershell.exe "Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force"
powershell.exe ./setup-workstation.ps1
powershell.exe "Set-ExecutionPolicy -ExecutionPolicy Default -Force"