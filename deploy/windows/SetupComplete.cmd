@echo off
rem Runs as SYSTEM at the end of Setup, before the first logon.
set L=C:\burrow\progress.log
echo %DATE% %TIME% setupcomplete >> %L%
pnputil /add-driver C:\burrow\drivers\*.inf /subdirs /install >> %L% 2>&1
netsh advfirewall firewall add rule name="ICMPv4 in" protocol=icmpv4:8,any dir=in action=allow >> %L% 2>&1
netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes >> %L% 2>&1
netsh interface ipv4 set address name="Ethernet" static 172.31.250.2 255.255.255.252 172.31.250.1 >> %L% 2>&1
powercfg /hibernate off >> %L% 2>&1
powercfg /change standby-timeout-ac 0 >> %L% 2>&1
"C:\burrow\burrow-guest.exe" install --start >> %L% 2>&1
echo %DATE% %TIME% setupcomplete done >> %L%
