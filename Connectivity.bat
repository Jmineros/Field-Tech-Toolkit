@echo off
setlocal EnableExtensions

echo ============================================
echo       MINEROSTECH NETWORK DIAGNOSTIC
echo ============================================

REM 1. Check Local Loopback (Test the NIC)
echo [1/4] Testing Local Stack...
ping 127.0.0.1 -n 2 | find "Reply" >nul
if %errorlevel%==0 (echo  [OK] Network Card is responding.) else (echo  [FAIL] Internal stack error.)

REM 2. Find and Ping Default Gateway
echo [2/4] Finding Default Gateway...
for /f "tokens=2 delims=:" %%G in ('ipconfig ^| findstr "Default Gateway"') do set "GW=%%G"
set "GW=%GW: =%"

if "%GW%"=="" (
    echo  [FAIL] No Default Gateway found. Check physical cable/Wi-Fi.
) else (
    ping %GW% -n 2 | find "Reply" >nul
    if %errorlevel%==0 (echo  [OK] Gateway (%GW%^) is reachable.) else (echo  [FAIL] Gateway is not responding.)
)

REM 3. Test External DNS (Google DNS)
echo [3/4] Testing Internet Path (8.8.8.8)...
ping 8.8.8.8 -n 2 | find "Reply" >nul
if %errorlevel%==0 (echo  [OK] Internet path is clear.) else (echo  [FAIL] No route to internet.)

REM 4. Test DNS Resolution
echo [4/4] Testing DNS Resolution (google.com)...
ping google.com -n 2 | find "Reply" >nul
if %errorlevel%==0 (echo  [OK] DNS is resolving correctly.) else (echo  [FAIL] DNS resolution failed. Check Pi-hole or ISP DNS.)

echo ============================================
echo Diagnostic Complete.
pause
