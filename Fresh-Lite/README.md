# Fresh-Lite

## RUNNING

### ONLINE

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force; Start-BitsTransfer -Source "https://raw.githubusercontent.com/YurinDoctrine/Fresh-Script-Lite/main/Fresh-Lite/ooshutup.cfg"; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/YurinDoctrine/Fresh-Script-Lite/main/Fresh-Lite/Lite.ps1'))

```

### OFFLINE

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser -Force

```

 Open a PowerShell prompt as Administrator then paste the above code, after that Right-Click and Run as
 Administrator setup.bat inside of the directory.
