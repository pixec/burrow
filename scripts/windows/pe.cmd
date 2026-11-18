@echo off
rem Runs in WinPE in place of Setup (winpeshl.ini). Cloud Hypervisor has only
rem virtio-blk disks and WinPE has no virtio driver, so load viostor first,
rem then find the install media and start Setup from it with the unattend.
wpeinit
for %%k in (BypassTPMCheck BypassSecureBootCheck BypassRAMCheck BypassStorageCheck BypassCPUCheck) do reg add HKLM\SYSTEM\Setup\LabConfig /v %%k /t REG_DWORD /d 1 /f >nul
drvload X:\burrow\drivers\viostor\viostor.inf
set MEDIA=
for /l %%i in (1,1,30) do (
  if not defined MEDIA (
    for %%d in (C D E F G H I J K L M N O P) do if exist %%d:\burrow-media.txt set MEDIA=%%d:
    if not defined MEDIA ping -n 2 127.0.0.1 >nul
  )
)
if not defined MEDIA (
  echo no install media found
  cmd /k
)
echo %DATE% %TIME% pe: media %MEDIA% >> %MEDIA%\burrow-pe.log
if exist %MEDIA%\burrow-apply.txt goto apply
%MEDIA%\sources\setup.exe /unattend:X:\burrow\autounattend.xml /noreboot
echo %DATE% %TIME% pe: setup exit %ERRORLEVEL% >> %MEDIA%\burrow-pe.log
copy /y X:\Windows\Panther\setupact.log %MEDIA%\pe-setupact.log >nul
copy /y X:\Windows\Panther\setuperr.log %MEDIA%\pe-setuperr.log >nul
for %%d in (C D E F G H I J K L M N O P) do if exist %%d:\$WINDOWS.~BT\Sources\Panther\setupact.log copy /y %%d:\$WINDOWS.~BT\Sources\Panther\set*.log %MEDIA%\ >nul
for %%d in (C D E F G H I J K L M N O P) do if exist %%d:\Windows\Panther\setupact.log copy /y %%d:\Windows\Panther\setupact.log %MEDIA%\os-setupact.log >nul
echo %DATE% %TIME% pe: rebooting >> %MEDIA%\burrow-pe.log
wpeutil reboot

rem Windows 11 Setup refuses a disk whose controller's hardware IDs are not
rem in a driver package, and viostor names QEMU's subsystem ID, not Cloud
rem Hypervisor's. So the image is applied as Setup would: disk 0 partitioned
rem as the unattend says, the image applied, the drivers added offline, the
rem boot files written and the unattend left for the specialize and oobe
rem passes, with the $OEM$ files where Setup puts them.
:apply
set L=%MEDIA%\burrow-pe.log
(
echo select disk 0
echo clean
echo convert gpt
echo create partition efi size=200
echo format quick fs=fat32 label=System
echo assign letter=S
echo create partition msr size=16
echo create partition primary
echo format quick fs=ntfs label=Windows
echo assign letter=W
) > X:\diskpart.txt
diskpart /s X:\diskpart.txt >> %L% 2>&1
set WIM=/ImageFile:%MEDIA%\sources\install.wim
if exist %MEDIA%\sources\install.swm set WIM=/ImageFile:%MEDIA%\sources\install.swm /SWMFile:%MEDIA%\sources\install*.swm
echo %DATE% %TIME% pe: applying >> %L%
dism /Apply-Image %WIM% /Index:1 /ApplyDir:W:\ >> %L% 2>&1
dism /Image:W:\ /Add-Driver /Driver:X:\burrow\drivers /Recurse >> %L% 2>&1
bcdboot W:\Windows /s S: /f UEFI >> %L% 2>&1
mkdir W:\Windows\Panther
copy /y X:\burrow\autounattend.xml W:\Windows\Panther\unattend.xml >> %L% 2>&1
xcopy /e /h /i /y "%MEDIA%\sources\$OEM$\$1" W:\ >> %L% 2>&1
xcopy /e /h /i /y "%MEDIA%\sources\$OEM$\$$" W:\Windows >> %L% 2>&1
echo %DATE% %TIME% pe: applied, rebooting >> %L%
wpeutil reboot
