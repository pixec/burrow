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
%MEDIA%\sources\setup.exe /unattend:X:\burrow\autounattend.xml /noreboot
echo %DATE% %TIME% pe: setup exit %ERRORLEVEL% >> %MEDIA%\burrow-pe.log
copy /y X:\Windows\Panther\setupact.log %MEDIA%\pe-setupact.log >nul
copy /y X:\Windows\Panther\setuperr.log %MEDIA%\pe-setuperr.log >nul
for %%d in (C D E F G H I J K L M N O P) do if exist %%d:\$WINDOWS.~BT\Sources\Panther\setupact.log copy /y %%d:\$WINDOWS.~BT\Sources\Panther\set*.log %MEDIA%\ >nul
for %%d in (C D E F G H I J K L M N O P) do if exist %%d:\Windows\Panther\setupact.log copy /y %%d:\Windows\Panther\setupact.log %MEDIA%\os-setupact.log >nul
echo %DATE% %TIME% pe: rebooting >> %MEDIA%\burrow-pe.log
wpeutil reboot
