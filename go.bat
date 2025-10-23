@echo off
echo ========================================
echo Secure RDP Watch 2025 - Compilation
echo Ayi NEDJIMI Consultants
echo ========================================
echo.

cl.exe /EHsc /std:c++17 /W4 /Fe:SecureRDPWatch2025.exe SecureRDPWatch2025.cpp ^
    wevtapi.lib wtsapi32.lib comctl32.lib user32.lib gdi32.lib advapi32.lib /link /SUBSYSTEM:WINDOWS

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Compilation reussie!
    echo Executable: SecureRDPWatch2025.exe
    echo.
    echo Lancement...
    SecureRDPWatch2025.exe
) else (
    echo.
    echo Erreur de compilation!
    pause
)
