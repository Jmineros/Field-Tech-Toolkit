@echo off
setlocal

echo ============================================
echo       MINEROSTECH PRINTER SPOOLER RESET
echo ============================================

REM 1. Stop the Spooler Service
echo [1/3] Stopping Print Spooler...
net stop spooler /y

REM 2. Delete stuck print jobs
echo [2/3] Clearing corrupted print queue...
del /q /f /s "%systemroot%\system32\spool\PRINTERS\*.*"

REM 3. Restart the Spooler Service
echo [3/3] Restarting Print Spooler...
net start spooler

echo ============================================
echo Done! Please try your print job again.
echo If alignment issues persist, check Epson manual settings.
pause
