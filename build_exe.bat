@echo off
echo ========================================================
echo  Building Zero-Trust_V3.exe Standalone Single-File Binary
echo ========================================================
echo.

where pyinstaller >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    pyinstaller --noconfirm --clean --onefile --noconsole --name "Zero-Trust_V3" --paths usb_client --collect-all customtkinter --hidden-import PIL --hidden-import PIL._tkinter_finder --hidden-import qrcode --hidden-import jwt --hidden-import cryptography --hidden-import requests usb_client/gui.py
) else (
    py -3.12 -m PyInstaller --noconfirm --clean --onefile --noconsole --name "Zero-Trust_V3" --paths usb_client --collect-all customtkinter --hidden-import PIL --hidden-import PIL._tkinter_finder --hidden-import qrcode --hidden-import jwt --hidden-import cryptography --hidden-import requests usb_client/gui.py
)

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo  Build Successful!
    echo  Output file: dist\Zero-Trust_V3.exe
    echo ========================================================
) else (
    echo.
    echo [ERROR] Build failed with error code %ERRORLEVEL%.
)

pause
