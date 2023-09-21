# Checking
# Проверка
function Check {
    Set-StrictMode -Version Latest

    # Сlear the $Error variable
    # Очистка переменной $Error
    $Global:Error.Clear()

    # Detect the OS bitness
    # Определить разрядность ОС
    switch ([Environment]::Is64BitOperatingSystem) {
        $false {
            Write-Warning -Message "This script supports x64 only" -Verbose
            break
        }
    }
    Read-Host 'Please make sure your network connection is available... [HIT RETURN]'
}
Check
#region UWP apps
<#
	Uninstall UWP apps
	A dialog box that enables the user to select packages to remove
	App packages will not be installed for new users if "Uninstall for All Users" is checked
	Add UWP apps packages names to the $UncheckedAppXPackages array list by retrieving their packages names using the following command:
		(Get-AppxPackage -PackageTypeFilter Bundle -AllUsers).Name

	Удалить UWP-приложения
	Диалоговое окно, позволяющее пользователю отметить пакеты на удаление
	Приложения не будут установлены для новых пользователе, если отмечено "Удалять для всех пользователей"
	Добавьте имена пакетов UWP-приложений в массив $UncheckedAppXPackages, получив названия их пакетов с помощью команды:
		(Get-AppxPackage -PackageTypeFilter Bundle -AllUsers).Name
#>
function UninstallUWPApps {
    # UWP apps that won't be shown in the form
    # UWP-приложения, которые не будут выводиться в форме
    $ExcludedAppxPackages = @(

        # Realtek Audio Control
        "RealtekSemiconductorCorp.RealtekAudioControl",

        # Desktop App Installer
        "Microsoft.DesktopAppInstaller"
    )

    if (Get-AppxPackage -PackageTypeFilter Bundle -AllUsers | Where-Object -FilterScript { $_.Name -cnotmatch ($ExcludedAppxPackages -join "|") } | Remove-AppxPackage -AllUsers ) {
        Write-Verbose -Message 'Removed UWP apps' -Verbose
    }
    else {
        Write-Verbose -Message "Nothing to do" -Verbose
    }
}
UninstallUWPApps
# Do not let UWP apps run in the background, except the followings... (current user only)
# Не разрешать UWP-приложениям работать в фоновом режиме, кроме следующих... (только для текущего пользователя)
function DisableBackgroundUWPApps {
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications -Name BackgroundAppGlobalToggle -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications -Name GlobalUserDisabled -PropertyType DWord -Value 1 -Force
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
        Remove-ItemProperty -Path $_.PsPath -Name * -Force
    }

    $OFS = "|"
    Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications | ForEach-Object -Process {
        New-ItemProperty -Path $_.PsPath -Name Disabled -PropertyType DWord -Value 1 -Force
        New-ItemProperty -Path $_.PsPath -Name DisabledByUser -PropertyType DWord -Value 1 -Force
    }
    $OFS = " "
}
DisableBackgroundUWPApps
# Disable the following Windows features
# Отключить следующие компоненты Windows
function DisableWindowsFeatures {
    $OptionalFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" }
    $FeatureNames = $OptionalFeatures | Select-Object -ExpandProperty FeatureName
    Disable-WindowsOptionalFeature -Online -FeatureName $FeatureNames -NoRestart
}
DisableWindowsFeatures
# Disable certain Feature On Demand v2 (FODv2) capabilities
# Отключить определенные компоненты "Функции по требованию" (FODv2)
function DisableWindowsCapabilities {
    # The following FODv2 items will be shown, but their checkboxes would be clear
    # Следующие дополнительные компоненты будут видны, но их чекбоксы не будут отмечены
    $ExcludedCapabilities = @(

        # Language components
        "Language.*",

        # The DirectX Database to configure and optimize apps when multiple Graphics Adapters are present
        "DirectX.Configuration.Database*",

        # Features critical to Windows functionality
        "Windows.Client.ShellComponents*"
    )

    if (Get-WindowsCapability -Online | Where-Object -FilterScript { ($_.State -eq "Installed") -and ($_.Name -cnotmatch ($ExcludedCapabilities -join "|")) } | Remove-WindowsCapability -Online ) {
        Write-Verbose -Message 'Removed Capabilities' -Verbose
    }
    else {
        Write-Verbose -Message "Nothing to do" -Verbose
    }
}
DisableWindowsCapabilities
# Turn off Cortana autostarting
# Удалить Кортана из автозагрузки
function DisableCortanaAutostart {
    if (Get-AppxPackage -Name Microsoft.549981C3F5F10) {
        if (-not (Test-Path -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId")) {
            New-Item -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Force
        }
        New-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\Microsoft.549981C3F5F10_8wekyb3d8bbwe\CortanaStartupId" -Name State -PropertyType DWord -Value 1 -Force
    }
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name AcceptedPrivacyPolicy -PropertyType DWord -Value 0 -Force
}
DisableCortanaAutostart
# Winget
function Winget {
    Write-Warning -Message "INSTALLING WINGET..." -Verbose
    Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
}
Winget
#endregion UWP apps
#region O&OShutup
function OOShutup {
    Write-Warning -Message "Running O&O Shutup with Recommended Settings" -Verbose
    Import-Module BitsTransfer
    Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe
    .\OOSU10.exe ooshutup.cfg /quiet
}
OOShutup
#endregion O&OShutup
#region OneDrive
# Uninstall OneDrive
# Удалить OneDrive
function UninstallOneDrive {
    [string]$UninstallString = Get-Package -Name "Microsoft OneDrive" -ProviderName Programs -ErrorAction Ignore | ForEach-Object -Process { $_.Meta.Attributes["UninstallString"] }
    if ($UninstallString) {
        Write-Verbose -Message "Uninstalling OneDrive..." -Verbose
        Stop-Process -Name OneDrive -Force -ErrorAction Ignore
        Stop-Process -Name OneDriveSetup -Force -ErrorAction Ignore
        Stop-Process -Name FileCoAuth -Force -ErrorAction Ignore

        # Getting link to the OneDriveSetup.exe and its' argument(s)
        # Получаем ссылку на OneDriveSetup.exe и его аргумент(ы)
        [string[]]$OneDriveSetup = ($UninstallString -Replace ("\s*/", ",/")).Split(",").Trim()
        if ($OneDriveSetup.Count -eq 2) {
            Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..1] -Wait
        }
        else {
            Start-Process -FilePath $OneDriveSetup[0] -ArgumentList $OneDriveSetup[1..2] -Wait
        }

        # Getting the OneDrive user folder path
        # Получаем путь до папки пользователя OneDrive
        $OneDriveUserFolder = Get-ItemPropertyValue -Path HKCU:\Environment -Name OneDrive
        if ((Get-ChildItem -Path $OneDriveUserFolder | Measure-Object).Count -eq 0) {
            Remove-Item -Path $OneDriveUserFolder -Recurse -Force
        }
        else {
            $Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create("The $OneDriveUserFolder folder is not empty Delete it manually"))
            Write-Error -Message $Message -ErrorAction SilentlyContinue
            Invoke-Item -Path $OneDriveUserFolder
        }

        Remove-ItemProperty -Path HKCU:\Environment -Name OneDrive, OneDriveConsumer -Force -ErrorAction Ignore
        Remove-Item -Path HKCU:\SOFTWARE\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
        Remove-Item -Path HKLM:\SOFTWARE\WOW6432Node\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
        Remove-Item -Path "$ENV:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction Ignore
        Remove-Item -Path $ENV:SYSTEMDRIVE\OneDriveTemp -Recurse -Force -ErrorAction Ignore
        Unregister-ScheduledTask -TaskName *OneDrive* -Confirm:$false

        # Getting the OneDrive folder path
        # Получаем путь до папки OneDrive
        $OneDriveFolder = Split-Path -Path (Split-Path -Path $OneDriveSetup[0] -Parent)

        # Save all opened folders in order to restore them after File Explorer restarting
        # Сохранить все открытые папки, чтобы восстановить их после перезапуска проводника
        Clear-Variable -Name OpenedFolders -Force -ErrorAction Ignore
        $OpenedFolders = { (New-Object -ComObject Shell.Application).Windows() | ForEach-Object -Process { $_.Document.Folder.Self.Path } }.Invoke()

        # Restart explorer process
        TASKKILL /F /IM explorer.exe
        Start-Process "explorer.exe"

        # Attempt to unregister FileSyncShell64.dll and remove
        # Попытка разрегистрировать FileSyncShell64.dll и удалить
        $FileSyncShell64dlls = Get-ChildItem -Path "$OneDriveFolder\*\amd64\FileSyncShell64.dll" -Force
        foreach ($FileSyncShell64dll in $FileSyncShell64dlls.FullName) {
            Start-Process -FilePath regsvr32.exe -ArgumentList "/u /s $FileSyncShell64dll" -Wait
            Remove-Item -Path $FileSyncShell64dll -Force -ErrorAction Ignore

            if (Test-Path -Path $FileSyncShell64dll) {
                $Message = Invoke-Command -ScriptBlock ([ScriptBlock]::Create("$FileSyncShell64dll is blocked Delete it manually"))
                Write-Error -Message $Message -ErrorAction SilentlyContinue
            }
        }

        # Restoring closed folders
        # Восстановляем закрытые папки
        foreach ($OpenedFolder in $OpenedFolders) {
            if (Test-Path -Path $OpenedFolder) {
                Invoke-Item -Path $OpenedFolder
            }
        }

        Remove-Item -Path $OneDriveFolder -Recurse -Force -ErrorAction Ignore
        Remove-Item -Path $ENV:LOCALAPPDATA\OneDrive -Recurse -Force -ErrorAction Ignore
        Remove-Item -Path $ENV:LOCALAPPDATA\Microsoft\OneDrive -Recurse -Force -ErrorAction Ignore
        Remove-Item -Path "$ENV:APPDATA\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Ignore
    }
    cmd /c winget uninstall OneDrive
}
UninstallOneDrive
# Do not show sync provider notification within File Explorer (current user only)
# Не показывать уведомления поставщика синхронизации в проводнике (только для текущего пользователя)
function HideOneDriveFileExplorerAd {
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
}
HideOneDriveFileExplorerAd
#endregion OneDrive
#region MSTeams
# Uninstall MSTeams
# Удалить MSTeams
function UninstallMSTeams {
    Write-Host "Removing Teams Machine-wide Installer" -ForegroundColor Yellow
    $MachineWide = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq "Teams Machine-Wide Installer" }
    $MachineWide.Uninstall()
    # Remove Teams for Current Users
    $localAppData = "$($ENV:LOCALAPPDATA)\Microsoft\Teams"
    $programData = "$($ENV:ProgramData)\$($ENV:USERNAME)\Microsoft\Teams"
    If (Test-Path "$($localAppData)\Current\Teams.exe") {
        unInstallTeams($localAppData)
    }
    elseif (Test-Path "$($programData)\Current\Teams.exe") {
        unInstallTeams($programData)
    }
    else {
        Write-Warning "Teams installation not found"
    }
    # Get all Users
    $Users = Get-ChildItem -Path "$($ENV:SYSTEMDRIVE)\Users"
    # Process all the Users
    $Users | ForEach-Object {
        Write-Host "Process user: $($_.Name)" -ForegroundColor Yellow
        #Locate installation folder
        $localAppData = "$($ENV:SYSTEMDRIVE)\Users\$($_.Name)\AppData\Local\Microsoft\Teams"
        $programData = "$($ENV:ProgramData)\$($_.Name)\Microsoft\Teams"
        If (Test-Path "$($localAppData)\Current\Teams.exe") {
            unInstallTeams($localAppData)
        }
        elseif (Test-Path "$($programData)\Current\Teams.exe") {
            unInstallTeams($programData)
        }
        else {
            Write-Warning "Teams installation not found for user $($_.Name)"
        }
    }
    cmd /c winget uninstall -h "Microsoft Teams"
}
UninstallMSTeams
#endregion Teams
#region Performance
function Performance {
    if (!(Test-Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control")) {
        New-Item -Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control" -Force
    }
    if (!(Test-Path "HKCU:\AppEvents\Schemes")) {
        New-Item -Path "HKCU:\AppEvents\Schemes" -Force
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force
    }
    if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched" -Force
    }
    if (!(Test-Path "HKCU:\System\GameConfigStore")) {
        New-Item -Force "HKCU:\System\GameConfigStore"
    }
    if (-not (Test-Path -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy)) {
        New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -ItemType Directory -Force
    }
    if (-not (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -ItemType Directory -Force
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.1")) {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.1" -Force
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.25000")) {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.25000" -Force
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.5.1")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.5.1" -Force
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.5.25000")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.5.25000" -Force
    }
    if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Force
    }
    if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Force
    }
    if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force
    }
    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC")) {
        New-Item -Force "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC"
    }
    if (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" -Force
    }
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Cache" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name NonBestEffortLimit -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched" -Name NonBestEffortLimit -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name TimerResolution -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched" -Name TimerResolution -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name MaxOutstandingSends -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Psched" -Name MaxOutstandingSends -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DSEBehavior" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2 -Force
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2 -Force
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 2 -Force
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 04 -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 01 -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 2048 -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 08 -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 256 -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy -Name 32 -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name AllowStorageSenseGlobal -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense" -Name AllowStorageSenseTemporaryFilesCleanup -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.5.1" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.1" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.5.25000" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.5.25000" -Name "SchUseStrongCrypto" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name PowerThrottlingOff -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\EdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" -Name "DefaultApplied" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control -Name SvcHostSplitThresholdInKB -PropertyType DWord -Value 8388608 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\ControlSet002\Control -Name SvcHostSplitThresholdInKB -PropertyType DWord -Value 8388608 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control -Name SvcHostSplitThresholdInKB -PropertyType DWord -Value 8388608 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 32 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "PlatformSupportMiracast" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrLevel" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDelay" -Type DWord -Value 60 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "TdrDebugMode" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" -Name "EnablePreemption" -Type DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name "Win31FileSystem" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\FileSystem -Name "Win31FileSystem" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name "Win95TruncatedExtensions" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\FileSystem -Name "Win95TruncatedExtensions" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name "NtfsDisable8dot3NameCreation" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\FileSystem -Name "NtfsDisable8dot3NameCreation" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem -Name "NtfsAllowExtendedCharacter8dot3Rename" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\ControlSet001\Control\FileSystem -Name "NtfsAllowExtendedCharacter8dot3Rename" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name AlwaysHibernateThumbnails -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name AnimationAttributionEnabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name AnimationAttributionHashingEnabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name Blur -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name EnableWindowColorization -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name EnableAeroPeek -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name ColorPrevalence -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name Composition -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name CompositionPolicy -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name DWMWA_TRANSITIONS_FORCEDISABLED -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name DisableAccentGradient -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name DisallowAnimations -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name DisallowColorizationColorChanges -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name DisallowFlip3d -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\DWM -Name OneCoreNoBootDWM -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name EnableTransparency -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name AltTabSettings -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name FirstRunTelemetryComplete -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name DesktopReadyTimeout -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name ExplorerStartupTraceRecorded -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer -Name TelemetrySalt -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ListviewAlphaSelect -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ListviewShadow -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisableThumbnailCache -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisallowShaking -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DesktopLivePreviewHoverTimes -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DesktopLivePreviewHoverTime -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name DisableThumbsDBOnNetworkFolders -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name EnableBalloonTips -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name SharingWizardOn -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name StartButtonBalloonTip -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowSyncProviderNotifications -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowInfoTip -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name ShowTaskViewButton -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name "Start_ShowRun" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name IconsOnly -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name UseCompactMode -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarDa -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name TaskbarMn -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name ActiveWndTrackTimeout -PropertyType String -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name MouseWheelRouting -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name FontSmoothing -PropertyType String -Value 2 -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name EnablePerProcessSystemDPI -PropertyType String -Value 1 -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name MenuShowDelay -PropertyType String -Value 10 -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name AutoColorization -PropertyType String -Value 1 -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name BranchReadinessLevel -PropertyType DWord -Value 20 -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name DeferFeatureUpdatesPeriodInDays -PropertyType DWord -Value 365 -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name DeferQualityUpdatesPeriodInDays -PropertyType DWord -Value 4 -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursEnd -Value 1 -Force
    New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name ActiveHoursStart -Value 10 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name IRQ8Priority -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name IRQ16Priority -PropertyType DWord -Value 2 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name Win32PrioritySeparation -PropertyType DWord -Value 26 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name SystemResponsiveness -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name LazyModeTimeout -PropertyType DWord -Value 10000 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name NetworkThrottlingIndex -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control -Name WaitToKillServiceTimeout -PropertyType DWord -Value 1000 -Force
    New-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" -Name "WaitToKillServiceTimeout" -PropertyType String -Value 1000 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\GameBar -Name ShowStartupPanel -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR -Name AppCaptureEnabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKCU:\System\GameConfigStore -Name GameDVR_Enabled -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -PropertyType DWord -Value 18 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Latency Sensitive" -PropertyType String -Value "True" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -PropertyType DWord -Value 8 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "NoLazyMode" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name "WaitToKillServiceTimeout" -PropertyType String -Value 1000 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name CoalescingTimerInterval -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name CoalescingTimerInterval -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name SleepStudyDisabled -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name "NoResolveTrack" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" -Name "Enable" -PropertyType String -Value "y" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" -Name TelemetryMaxTagPerApplication -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" -Name DisableTaggedEnergyLogging -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" -Name TelemetryMaxApplication -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name MaintenanceDisabled -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name WakeUp -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Win8DpiScaling -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name DpiMapIommuContiguous -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Name PreferSystemMemoryContiguous -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name "ProtectionMode" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SizReqBuf" -Type DWord -Value 16384 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileInfoCacheEntriesMax" -Type "DWORD" -Value 64 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DirectoryCacheEntriesMax" -Type "DWORD" -Value 16 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "FileNotFoundCacheEntriesMax" -Type "DWORD" -Value 128 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "BufFilesDenyWrite" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "BufNamedPipes" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DormantFileLimit" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableOpLockForceClose" -Type "DWORD" -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableOpLocks" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Linkage" -Name "UtilizeNtCaching" -Type "DWORD" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name Enabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name ConvertibleSlateMode -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\TabletPC" -Name TurnOffPenFeedback -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" -Name PassiveIntRealTimeWorkerPriority -PropertyType DWord -Value 18 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\KernelVelocity" -Name DisableFGBoostDecay -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\FileSystem" -Name "NtfsDisableEncryption" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -PropertyType DWord -Value 3 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "OpenAtLogon" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableStartMenu" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FileExplorerInTouchImprovement" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettings" -PropertyType DWord -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -PropertyType DWord -Value "72" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -PropertyType DWord -Value "3" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCfg" -PropertyType DWord -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableBoottrace" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "SfTracingState" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAcrylicBackgroundOnLogon" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name CacheAwareScheduling -Type "DWORD" -Value "7" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name CoalescingTimerInterval -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DisableExceptionChainValidation -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name KernelSEHOPEnabled -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name ForceForegroundBoostDecay -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\kernel" -Name DisableExceptionChainValidation -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name RebalanceMinPriority -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name IdealNodeRandomized -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name GlobalTimerResolutionRequests -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DisableLowQosTimerResolution -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name ThreadDpcEnable -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name MinimumDpcRate -Type "DWORD" -Value "3" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name VerifierDpcScalingFactor -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DisableTsx -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name EnablePerCpuClockTickScheduling -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name HeteroSchedulerOptions -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name SerializeTimerExpiration -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name MaximumSharedReadyQueueSize -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name MinDynamicTickDuration -Type "DWORD" -Value "1000" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name DpcWatchdogProfileOffset -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name TtmEnabled -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name FlushPolicy -Type "DWORD" -Value "1" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name Attributes -Type "DWORD" -Value "0" -Force
    New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager" -Name ImageExecutionOptions -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "AllocationPreference" -PropertyType DWord -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnableCooling" -PropertyType DWord -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "EnablePerVolumeLazyWriter" -PropertyType DWord -Value "2" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -PropertyType DWord -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "UseLargePages" -PropertyType DWord -Value "0" -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DontVerifyRandomDrivers" -PropertyType DWord -Value "1" -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "DnsCacheEnabled" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "SyncMode5" -PropertyType DWord -Value 3 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "SendAdditionalOption" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Games" -Name "FpsAll" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Games" -Name "GameFluidity" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Name "IoLatencyCap" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Audiosrv" -Name "ErrorControl" -Type DWord -Value 2 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" -Name "Disabled" -Type DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\WiFiNetworkManager\Config" -Name "SignalStrengthDelta" -Type DWord -Value "-1" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "ServiceKeepAlive" -Type DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BackgroundModeEnabled" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableFontProviders" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing" -Name "RepairContentServerSource" -PropertyType DWord -Value 2 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -PropertyType DWord -Value 1 -Force

    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "Win32_AutoGameModeDefaultProfile" -Value ([byte[]](0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force;
    New-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "Win32_GameModeRelatedProcesses" -Value ([byte[]](0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force;

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "Latency" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "DisableSensorWatchdog" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "SleepReliabilityDetailedDiagnostics" -PropertyType DWord -Value 0 -Force

    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0000" -Name "*RssBaseProcNumber" -PropertyType DWord -Value 2 -Force

    if (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Scheduling Category" -PropertyType String -Value "High" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "SFIO Priority" -PropertyType String -Value "High" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Background Only" -PropertyType String -Value "True" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "BackgroundPriority" -PropertyType DWord -Value 24 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Latency Sensitive" -PropertyType String -Value "True" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Affinity" -PropertyType DWord -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Priority" -PropertyType DWord -Value 8 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "NoLazyMode" -PropertyType DWord -Value 1 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "Clock Rate" -PropertyType DWord -Value 10000 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" -Name "GPU Priority" -PropertyType DWord -Value 12 -Force

    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion")) {
        New-Item -Force "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion" -Name "DisableContentFileUpdates" -PropertyType DWord -Value 1 -Force

    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -PropertyType DWord -Value 2 -Force

    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2 -Force

    if (!(Test-Path "HKLM:\SYSTEM\ControlSet001\Control\BootControl")) {
        New-Item -Force "HKLM:\SYSTEM\ControlSet001\Control\BootControl"
    }
    New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\BootControl" -Name "BootProgressAnimation" -PropertyType DWord -Value 0 -Force

    if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" -Force
    }
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "ForceUpdateFromMU" -Type DWord -Value 0 -Force

    if (!(Test-Path "HKCU:\Keyboard Layout\ShowToast")) {
        New-Item -Force "HKCU:\Keyboard Layout\ShowToast"
    }
    New-ItemProperty -Path "HKCU:\Keyboard Layout\ShowToast" -Name "Show" -PropertyType DWord -Value 0 -Force

    Remove-ItemProperty -Path "HKCU:\Keyboard Layout\Preload" -Name "2" -Force

    Remove-Item -Path HKCR:\Directory\Background\shellex\ContextMenuHandlers\ACE -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path HKCR:\Directory\Background\shellex\ContextMenuHandlers\igfxcui -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path HKCR:\Directory\Background\shellex\ContextMenuHandlers\igfxDTCM -Recurse -Force -ErrorAction Ignore
    Remove-Item -Path HKCR:\Directory\Background\shellex\ContextMenuHandlers\NvCplDesktopContext -Recurse -Force -ErrorAction Ignore

    regsvr32.exe /s atl.dll
    regsvr32.exe /s urlmon.dll
    regsvr32.exe /s mshtml.dll
    regsvr32.exe /s shdocvw.dll
    regsvr32.exe /s browseui.dll
    regsvr32.exe /s jscript.dll
    regsvr32.exe /s vbscript.dll
    regsvr32.exe /s scrrun.dll
    regsvr32.exe /s msxml.dll
    regsvr32.exe /s msxml3.dll
    regsvr32.exe /s msxml6.dll
    regsvr32.exe /s actxprxy.dll
    regsvr32.exe /s softpub.dll
    regsvr32.exe /s wintrust.dll
    regsvr32.exe /s dssenh.dll
    regsvr32.exe /s rsaenh.dll
    regsvr32.exe /s gpkcsp.dll
    regsvr32.exe /s sccbase.dll
    regsvr32.exe /s slbcsp.dll
    regsvr32.exe /s cryptdlg.dll
    regsvr32.exe /s oleaut32.dll
    regsvr32.exe /s ole32.dll
    regsvr32.exe /s shell32.dll
    regsvr32.exe /s initpki.dll
    regsvr32.exe /s wuapi.dll
    regsvr32.exe /s wuaueng.dll
    regsvr32.exe /s wuaueng1.dll
    regsvr32.exe /s wucltui.dll
    regsvr32.exe /s wups.dll
    regsvr32.exe /s wups2.dll
    regsvr32.exe /s wuweb.dll
    regsvr32.exe /s qmgr.dll
    regsvr32.exe /s qmgrprxy.dll
    regsvr32.exe /s wucltux.dll
    regsvr32.exe /s muweb.dll
    regsvr32.exe /s wuwebv.dll

    Enable-WindowsOptionalFeature -Online -FeatureName NetFx4-AdvSrvs -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName NetFx4Extended-ASPNET45 -All -NoRestart
    Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All -NoRestart

    Disable-MMAgent -MemoryCompression
    Disable-MMAgent -PageCombining

    auditpol /set /category:"Account Logon" /success:disable
    auditpol /set /category:"Account Logon" /failure:disable
    auditpol /set /category:"Account Management" /success:disable
    auditpol /set /category:"Account Management" /failure:disable
    auditpol /set /category:"DS Access" /success:disable
    auditpol /set /category:"DS Access" /failure:disable
    auditpol /set /category:"Logon/Logoff" /success:disable
    auditpol /set /category:"Logon/Logoff" /failure:disable
    auditpol /set /category:"Object Access" /success:disable
    auditpol /set /category:"Object Access" /failure:disable
    auditpol /set /category:"Policy Change" /success:disable
    auditpol /set /category:"Policy Change" /failure:disable
    auditpol /set /category:"Privilege Use" /success:disable
    auditpol /set /category:"Privilege Use" /failure:disable
    auditpol /set /category:"Detailed Tracking" /success:disable
    auditpol /set /category:"Detailed Tracking" /failure:disable
    auditpol /set /category:"System" /success:disable
    auditpol /set /category:"System" /failure:disable

    Set-MpPreference -DefinitionUpdatesChannel Staged
    Set-MpPreference -EngineUpdatesChannel Staged
    Set-MpPreference -PlatformUpdatesChannel Staged
    Set-MpPreference -DisableCatchupFullScan $True
    Set-MpPreference -ScanAvgCPULoadFactor 5
    Set-MpPreference -EnableLowCpuPriority $True
    Set-MpPreference -ScanOnlyIfIdleEnabled $True
    Set-MpPreference -DisableCpuThrottleOnIdleScans $False
    Set-MpPreference -SubmitSamplesConsent 2
    Set-MpPreference -ServiceHealthReportInterval 0

    Set-SmbServerConfiguration -ServerHidden $False -AnnounceServer $False -Force
    Set-SmbServerConfiguration -EnableLeasing $false -Force
    Set-SmbClientConfiguration -EnableLargeMtu $true -Force
}
Performance
function FixTimers {
    diskperf -N
    bcdedit /timeout 1
    bcdedit /set `{current`} useplatformtick true
    bcdedit /set `{current`} disabledynamictick true
    bcdedit /set `{current`} tscsyncpolicy enhanced
    bcdedit /set `{current`} debug No
    bcdedit /set `{current`} highestmode Yes
    bcdedit /set `{current`} perfmem 1
    bcdedit /set `{current`} usephysicaldestination No
    bcdedit /deletevalue `{current`} useplatformclock
}
FixTimers
function Network {
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name LocalPriority -PropertyType DWord -Value 4 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name HostsPriority -PropertyType DWord -Value 5 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name DnsPriority -PropertyType DWord -Value 6 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name NetbtPriority -PropertyType DWord -Value 7 -Force
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" -Name "Class" -PropertyType DWord -Value 8 -Force

    Disable-NetAdapterLso -Name *
    Disable-NetAdapterRsc -Name *

    netsh int tcp set supplemental Template=Internet CongestionProvider=dctcp
    netsh int tcp set supplemental Template=Datacenter CongestionProvider=dctcp
    netsh int tcp set supplemental Template=Compat CongestionProvider=dctcp
    netsh int tcp set supplemental Template=InternetCustom CongestionProvider=dctcp
    netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=dctcp
    netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
    netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2
    netsh int tcp set supplemental Template=Compat CongestionProvider=bbr2
    netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2
    netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2
    netsh int tcp set security mpp=disabled
    netsh int tcp set security profiles=disabled
    netsh int tcp set global initialRto=2000
    netsh int tcp set global timestamps=disabled
    netsh int tcp set global netdma=disabled
    netsh int tcp set global rsc=disabled
    netsh int tcp set global rss=enabled
    netsh int tcp set global dca=enabled
    netsh int tcp set global ecn=enabled
    netsh int tcp set global autotuninglevel=disabled
    netsh int tcp set global ecncapability=enabled
    netsh int tcp set global nonsackrttresiliency=disabled
    netsh int tcp set global maxsynretransmissions=2
    netsh int udp set global uro=enabled
    netsh int ip set global icmpredirects=disabled
    netsh winsock set autotuning on

    Get-NetAdapter | Get-DnsClientServerAddress | Set-DnsClientServerAddress -ServerAddresses ("1.1.1.1", "1.0.0.1")
}
Network
function Memory {
    bcdedit /set `{current`} firstmegabytepolicy UseAll

    fsutil behavior set memoryusage 2
    fsutil behavior set disablelastaccess 1
    fsutil behavior set mftzone 3
    fsutil behavior set quotanotify 10800
    fsutil behavior set bugcheckoncorrupt 0
    fsutil behavior set disablespotcorruptionhandling 1
    fsutil resource setlog shrink 99.9 $ENV:SYSTEMDRIVE\
}
Memory
function Processor {
    setx GPU_MAX_ALLOC_PERCENT 99
    setx GPU_SINGLE_ALLOC_PERCENT 90
    setx GPU_MAX_SINGLE_ALLOC_PERCENT 99
    setx CPU_MAX_ALLOC_PERCENT 99
    setx GPU_MAX_HEAP_SIZE 99
    setx GPU_MAX_USE_SYNC_OBJECTS 1
    setx GPU_ENABLE_LARGE_ALLOCATION 99
    setx GPU_MAX_WORKGROUP_SIZE 1024
    setx GPU_FORCE_64BIT_PTR 0

    powercfg -setactive SCHEME_BALANCED
    powercfg -setACvalueindex SCHEME_CURRENT SUB_NONE PERSONALITY 2
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_NONE PERSONALITY 0
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_GRAPHICS GPUPREFERENCEPOLICY 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_INTSTEER MODE 3
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_INTSTEER MODE 3
    powercfg -setACvalueindex SCHEME_CURRENT SUB_INTSTEER PERPROCLOAD 5000
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_INTSTEER PERPROCLOAD 5000
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 2
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 2
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR THROTTLING 2
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR THROTTLING 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPPERF 2
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPPERF 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPPERF1 2
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPPERF1 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR SCHEDPOLICY 3
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR SCHEDPOLICY 3
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR SHORTSCHEDPOLICY 3
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR SHORTSCHEDPOLICY 3
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 0
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMINCORES 0
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPMAXCORES 100
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPCONCURRENCY 90
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPCONCURRENCY 90
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPDISTRIBUTION 100
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPDISTRIBUTION 100
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPHEADROOM 50
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPHEADROOM 50
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPOVERUTIL 90
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPOVERUTIL 90
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 50
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFEPP 100
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPINCREASEPOL 1
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPINCREASEPOL 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR CPDECREASEPOL 1
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR CPDECREASEPOL 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 1
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR DISTRIBUTEUTIL 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 3
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFBOOSTMODE 3
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR SCHEDPOLICY 2
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR SCHEDPOLICY 4
    powercfg -setACvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFDUTYCYCLING 1
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_PROCESSOR PERFDUTYCYCLING 1
    powercfg -setACvalueindex SCHEME_CURRENT SUB_SLEEP RTCWAKE 0
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_SLEEP RTCWAKE 0
    powercfg -setACvalueindex SCHEME_CURRENT SUB_SLEEP d4e98f31-5ffe-4ce1-be31-1b38b384c009 3
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_SLEEP d4e98f31-5ffe-4ce1-be31-1b38b384c009 3
    powercfg -setACvalueindex SCHEME_CURRENT SUB_ENERGYSAVER ESPOLICY 1
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_ENERGYSAVER ESPOLICY 1
    powercfg -setACvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 3
    powercfg -setDCvalueindex SCHEME_CURRENT 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 3
    powercfg -setDCvalueindex SCHEME_CURRENT 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 0
    powercfg -setACvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOADAPT 1
    powercfg -setDCvalueindex SCHEME_CURRENT SUB_VIDEO VIDEOADAPT 1
    powercfg -setactive SCHEME_CURRENT
    powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
}
Processor
#endregion Performance
function Errors {
    if ($Global:Error) {
		($Global:Error | ForEach-Object -Process {
            [PSCustomObject] @{
                Line              = $_.InvocationInfo.ScriptLineNumber
                File              = Split-Path -Path $PSCommandPath -Leaf
                'Errors/Warnings' = $_.Exception.Message
            }
        } | Sort-Object -Property Line | Format-Table -AutoSize -Wrap | Out-File -FilePath $HOME\Documents\errorlog.txt
		)
    }
    exit
}
Errors
